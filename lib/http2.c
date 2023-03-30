/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_NGHTTP2
#include <nghttp2/nghttp2.h>
#include "urldata.h"
#include "bufq.h"
#include "http2.h"
#include "http.h"
#include "sendf.h"
#include "select.h"
#include "curl_base64.h"
#include "strcase.h"
#include "multiif.h"
#include "url.h"
#include "cfilters.h"
#include "connect.h"
#include "strtoofft.h"
#include "strdup.h"
#include "transfer.h"
#include "dynbuf.h"
#include "h2h3.h"
#include "headers.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#if (NGHTTP2_VERSION_NUM < 0x010c00)
#error too old nghttp2 version, upgrade!
#endif

#ifdef CURL_DISABLE_VERBOSE_STRINGS
#define nghttp2_session_callbacks_set_error_callback(x,y)
#endif

#if (NGHTTP2_VERSION_NUM >= 0x010c00)
#define NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE 1
#endif


/* buffer dimensioning:
 * use 16K as chunk size, as that fits H2 DATA frames well */
#define H2_CHUNK_SIZE           (16 * 1024)
/* this is how much we want "in flight" for a stream */
#define H2_STREAM_WINDOW_SIZE   (512 * 1024)
/* on receving from TLS, we prep for holding a full stream window */
#define H2_NW_RECV_CHUNKS       (H2_STREAM_WINDOW_SIZE / H2_CHUNK_SIZE)
/* on send into TLS, we just want to accumulate small frames */
#define H2_NW_SEND_CHUNKS       1
/* stream recv/send chunks are a result of window / chunk sizes */
#define H2_STREAM_RECV_CHUNKS   (H2_STREAM_WINDOW_SIZE / H2_CHUNK_SIZE)
#define H2_STREAM_SEND_CHUNKS   (H2_STREAM_WINDOW_SIZE / H2_CHUNK_SIZE)
/* spare chunks we keep for a full window */
#define H2_STREAM_POOL_SPARES   (H2_STREAM_WINDOW_SIZE / H2_CHUNK_SIZE)

#define HTTP2_HUGE_WINDOW_SIZE (16 * H2_STREAM_WINDOW_SIZE)

#define H2_SETTINGS_IV_LEN  3
#define H2_BINSETTINGS_LEN 80

static int populate_settings(nghttp2_settings_entry *iv,
                             struct Curl_easy *data)
{
  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = Curl_multi_max_concurrent_streams(data->multi);

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = H2_STREAM_WINDOW_SIZE;

  iv[2].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
  iv[2].value = data->multi->push_cb != NULL;

  return 3;
}

static size_t populate_binsettings(uint8_t *binsettings,
                                   struct Curl_easy *data)
{
  nghttp2_settings_entry iv[H2_SETTINGS_IV_LEN];
  int ivlen;

  ivlen = populate_settings(iv, data);
  /* this returns number of bytes it wrote */
  return nghttp2_pack_settings_payload(binsettings, H2_BINSETTINGS_LEN,
                                       iv, ivlen);
}

struct cf_h2_ctx {
  nghttp2_session *h2;
  uint32_t max_concurrent_streams;
  /* The easy handle used in the current filter call, cleared at return */
  struct cf_call_data call_data;

  struct bufq inbufq;           /* network input */
  struct bufq outbufq;          /* network output */
  struct bufc_pool stream_bufcp; /* spares for stream buffers */

  size_t drain_total; /* sum of all stream's UrlState.drain */
  int32_t goaway_error;
  int32_t last_stream_id;
  BIT(conn_closed);
  BIT(goaway);
  BIT(enable_push);
};

/* How to access `call_data` from a cf_h2 filter */
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_h2_ctx *)(cf)->ctx)->call_data


static void cf_h2_ctx_clear(struct cf_h2_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  if(ctx->h2) {
    nghttp2_session_del(ctx->h2);
  }
  Curl_bufq_free(&ctx->inbufq);
  Curl_bufq_free(&ctx->outbufq);
  Curl_bufcp_free(&ctx->stream_bufcp);
  memset(ctx, 0, sizeof(*ctx));
  ctx->call_data = save;
}

static void cf_h2_ctx_free(struct cf_h2_ctx *ctx)
{
  if(ctx) {
    cf_h2_ctx_clear(ctx);
    free(ctx);
  }
}

static int h2_client_new(struct Curl_cfilter *cf,
                         nghttp2_session_callbacks *cbs)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  nghttp2_option *o;

  int rc = nghttp2_option_new(&o);
  if(rc)
    return rc;
  /* We handle window updates ourself to enfore buffer limits */
  nghttp2_option_set_no_auto_window_update(o, 1);
#if NGHTTP2_VERSION_NUM >= 0x013200
  /* with 1.50.0 */
  /* turn off RFC 9113 leading and trailing white spaces validation against
     HTTP field value. */
  nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(o, 1);
#endif
  rc = nghttp2_session_client_new2(&ctx->h2, cbs, cf, o);
  nghttp2_option_del(o);
  return rc;
}

static ssize_t nw_in_reader(void *reader_ctx,
                              unsigned char *buf, size_t buflen,
                              CURLcode *err)
{
  struct Curl_cfilter *cf = reader_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  return Curl_conn_cf_recv(cf->next, data, (char *)buf, buflen, err);
}

static ssize_t nw_out_writer(void *writer_ctx,
                             const unsigned char *buf, size_t buflen,
                             CURLcode *err)
{
  struct Curl_cfilter *cf = writer_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  return Curl_conn_cf_send(cf->next, data, (const char *)buf, buflen, err);
}

static ssize_t send_callback(nghttp2_session *h2,
                             const uint8_t *mem, size_t length, int flags,
                             void *userp);
static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp);
static int on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              const uint8_t *mem, size_t len, void *userp);
static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp);
static int on_begin_headers(nghttp2_session *session,
                            const nghttp2_frame *frame, void *userp);
static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags,
                     void *userp);
static int error_callback(nghttp2_session *session, const char *msg,
                          size_t len, void *userp);

/*
 * multi_connchanged() is called to tell that there is a connection in
 * this multi handle that has changed state (multiplexing become possible, the
 * number of allowed streams changed or similar), and a subsequent use of this
 * multi handle should move CONNECT_PEND handles back to CONNECT to have them
 * retry.
 */
static void multi_connchanged(struct Curl_multi *multi)
{
  multi->recheckstate = TRUE;
}

static CURLcode http2_data_setup(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;

  (void)cf;
  DEBUGASSERT(stream);
  DEBUGASSERT(data->state.buffer);

  stream->stream_id = -1;

  Curl_bufq_initp(&stream->h2_sendbuf, &ctx->stream_bufcp,
                  H2_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  Curl_bufq_initp(&stream->h2_recvbuf, &ctx->stream_bufcp,
                  H2_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);
  Curl_dynhds_init(&stream->resp_trailers, 0, DYN_H2_TRAILERS);
  stream->h2_send_hds_len = 0;
  stream->h2_recv_hds_len = 0;
  stream->bodystarted = FALSE;
  stream->status_code = -1;
  stream->closed = FALSE;
  stream->close_handled = FALSE;
  stream->error = NGHTTP2_NO_ERROR;
  stream->upload_left = 0;

  return CURLE_OK;
}

/*
 * Initialize the cfilter context
 */
static CURLcode cf_h2_ctx_init(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool via_h1_upgrade)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  int rc;
  nghttp2_session_callbacks *cbs = NULL;

  DEBUGASSERT(!ctx->h2);
  Curl_bufcp_init(&ctx->stream_bufcp, H2_CHUNK_SIZE, H2_STREAM_POOL_SPARES);
  Curl_bufq_initp(&ctx->inbufq, &ctx->stream_bufcp, H2_NW_RECV_CHUNKS, 0);
  Curl_bufq_initp(&ctx->outbufq, &ctx->stream_bufcp, H2_NW_SEND_CHUNKS, 0);
  ctx->last_stream_id = 2147483647;

  rc = nghttp2_session_callbacks_new(&cbs);
  if(rc) {
    failf(data, "Couldn't initialize nghttp2 callbacks");
    goto out;
  }

  nghttp2_session_callbacks_set_send_callback(cbs, send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    cbs, on_data_chunk_recv);
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close);
  nghttp2_session_callbacks_set_on_begin_headers_callback(
    cbs, on_begin_headers);
  nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);
  nghttp2_session_callbacks_set_error_callback(cbs, error_callback);

  /* The nghttp2 session is not yet setup, do it */
  rc = h2_client_new(cf, cbs);
  if(rc) {
    failf(data, "Couldn't initialize nghttp2");
    goto out;
  }
  ctx->max_concurrent_streams = DEFAULT_MAX_CONCURRENT_STREAMS;

  result = http2_data_setup(cf, data);
  if(result)
    goto out;

  if(via_h1_upgrade) {
    /* HTTP/1.1 Upgrade issued. H2 Settings have already been submitted
     * in the H1 request and we upgrade from there. This stream
     * is opened implicitly as #1. */
    uint8_t binsettings[H2_BINSETTINGS_LEN];
    size_t  binlen; /* length of the binsettings data */

    binlen = populate_binsettings(binsettings, data);

    stream->stream_id = 1;
    /* queue SETTINGS frame (again) */
    rc = nghttp2_session_upgrade2(ctx->h2, binsettings, binlen,
                                  data->state.httpreq == HTTPREQ_HEAD,
                                  NULL);
    if(rc) {
      failf(data, "nghttp2_session_upgrade2() failed: %s(%d)",
            nghttp2_strerror(rc), rc);
      result = CURLE_HTTP2;
      goto out;
    }

    rc = nghttp2_session_set_stream_user_data(ctx->h2, stream->stream_id,
                                              data);
    if(rc) {
      infof(data, "http/2: failed to set user_data for stream %u",
            stream->stream_id);
      DEBUGASSERT(0);
    }
  }
  else {
    nghttp2_settings_entry iv[H2_SETTINGS_IV_LEN];
    int ivlen;

    /* H2 Settings need to be submitted. Stream is not open yet. */
    DEBUGASSERT(stream->stream_id == -1);

    ivlen = populate_settings(iv, data);
    rc = nghttp2_submit_settings(ctx->h2, NGHTTP2_FLAG_NONE,
                                 iv, ivlen);
    if(rc) {
      failf(data, "nghttp2_submit_settings() failed: %s(%d)",
            nghttp2_strerror(rc), rc);
      result = CURLE_HTTP2;
      goto out;
    }
  }

  rc = nghttp2_session_set_local_window_size(ctx->h2, NGHTTP2_FLAG_NONE, 0,
                                             HTTP2_HUGE_WINDOW_SIZE);
  if(rc) {
    failf(data, "nghttp2_session_set_local_window_size() failed: %s(%d)",
          nghttp2_strerror(rc), rc);
    result = CURLE_HTTP2;
    goto out;
  }

  /* all set, traffic will be send on connect */
  result = CURLE_OK;

out:
  if(cbs)
    nghttp2_session_callbacks_del(cbs);
  return result;
}

/*
 * http2_stream_free() free HTTP2 stream related data
 */
static void http2_stream_free(struct HTTP *stream)
{
  if(stream) {
    Curl_bufq_free(&stream->h2_sendbuf);
    Curl_bufq_free(&stream->h2_recvbuf);
    for(; stream->push_headers_used > 0; --stream->push_headers_used) {
      free(stream->push_headers[stream->push_headers_used - 1]);
    }
    free(stream->push_headers);
    stream->push_headers = NULL;
  }
}

/*
 * Returns nonzero if current HTTP/2 session should be closed.
 */
static int should_close_session(struct cf_h2_ctx *ctx)
{
  return ctx->drain_total == 0 && !nghttp2_session_want_read(ctx->h2) &&
    !nghttp2_session_want_write(ctx->h2);
}

/*
 * Processes pending input left in network input buffer.
 * This function returns 0 if it succeeds, or -1 and error code will
 * be assigned to *err.
 */
static int h2_process_pending_input(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  const unsigned char *buf;
  size_t blen;
  ssize_t rv;

  while(Curl_bufq_peek(&ctx->inbufq, &buf, &blen)) {

    rv = nghttp2_session_mem_recv(ctx->h2, (const uint8_t *)buf, blen);
    DEBUGF(LOG_CF(data, cf,
                 "fed %zu bytes from nw to nghttp2 -> %zd", blen, rv));
    if(rv < 0) {
      failf(data,
            "process_pending_input: nghttp2_session_mem_recv() returned "
            "%zd:%s", rv, nghttp2_strerror((int)rv));
      *err = CURLE_RECV_ERROR;
      return -1;
    }
    Curl_bufq_skip(&ctx->inbufq, (size_t)rv);
    if(Curl_bufq_is_empty(&ctx->inbufq)) {
      DEBUGF(LOG_CF(data, cf, "all data in connection buffer processed"));
      break;
    }
    else {
      DEBUGF(LOG_CF(data, cf, "process_pending_input: %zu bytes left "
                    "in connection buffer", Curl_bufq_len(&ctx->inbufq)));
    }
  }

  if(nghttp2_session_check_request_allowed(ctx->h2) == 0) {
    /* No more requests are allowed in the current session, so
       the connection may not be reused. This is set when a
       GOAWAY frame has been received or when the limit of stream
       identifiers has been reached. */
    connclose(cf->conn, "http/2: No new requests allowed");
  }

  return 0;
}

/*
 * The server may send us data at any point (e.g. PING frames). Therefore,
 * we cannot assume that an HTTP/2 socket is dead just because it is readable.
 *
 * Check the lower filters first and, if successful, peek at the socket
 * and distinguish between closed and data.
 */
static bool http2_connisalive(struct Curl_cfilter *cf, struct Curl_easy *data,
                              bool *input_pending)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  bool alive = TRUE;

  *input_pending = FALSE;
  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    return FALSE;

  if(*input_pending) {
    /* This happens before we've sent off a request and the connection is
       not in use by any other transfer, there shouldn't be any data here,
       only "protocol frames" */
    CURLcode result;
    ssize_t nread = -1;

    *input_pending = FALSE;
    Curl_attach_connection(data, cf->conn);
    nread = Curl_bufq_slurp(&ctx->inbufq, nw_in_reader, cf, &result);
    if(nread != -1) {
      DEBUGF(LOG_CF(data, cf, "%zd bytes stray data read before trying "
                    "h2 connection", nread));
      if(h2_process_pending_input(cf, data, &result) < 0)
        /* immediate error, considered dead */
        alive = FALSE;
      else {
        alive = !should_close_session(ctx);
      }
    }
    else {
      /* the read failed so let's say this is dead anyway */
      alive = FALSE;
    }
    Curl_detach_connection(data);
  }

  return alive;
}

static CURLcode http2_send_ping(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  int rc;

  rc = nghttp2_submit_ping(ctx->h2, 0, ZERO_NULL);
  if(rc) {
    failf(data, "nghttp2_submit_ping() failed: %s(%d)",
          nghttp2_strerror(rc), rc);
   return CURLE_HTTP2;
  }

  rc = nghttp2_session_send(ctx->h2);
  if(rc) {
    failf(data, "nghttp2_session_send() failed: %s(%d)",
          nghttp2_strerror(rc), rc);
    return CURLE_SEND_ERROR;
  }
  return CURLE_OK;
}

/*
 * Store nghttp2 version info in this buffer.
 */
void Curl_http2_ver(char *p, size_t len)
{
  nghttp2_info *h2 = nghttp2_version(0);
  (void)msnprintf(p, len, "nghttp2/%s", h2->version_str);
}

static CURLcode nw_out_flush(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  ssize_t nwritten;
  CURLcode result;

  (void)data;
  if(Curl_bufq_is_empty(&ctx->outbufq))
    return CURLE_OK;

  DEBUGF(LOG_CF(data, cf, "h2 conn flush %zu bytes",
                Curl_bufq_len(&ctx->outbufq)));
  nwritten = Curl_bufq_pass(&ctx->outbufq, nw_out_writer, cf, &result);
  if(nwritten < 0 && result != CURLE_AGAIN) {
    return result;
  }
  return CURLE_OK;
}

/*
 * The implementation of nghttp2_send_callback type. Here we write |data| with
 * size |length| to the network and return the number of bytes actually
 * written. See the documentation of nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *h2,
                             const uint8_t *buf, size_t blen, int flags,
                             void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nwritten;
  CURLcode result = CURLE_OK;

  (void)h2;
  (void)flags;
  DEBUGASSERT(data);

  nwritten = Curl_bufq_write_pass(&ctx->outbufq, buf, blen,
                                  nw_out_writer, cf, &result);
  if(nwritten < 0) {
    if(result == CURLE_AGAIN) {
      return NGHTTP2_ERR_WOULDBLOCK;
    }
    failf(data, "Failed sending HTTP2 data");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if(!nwritten)
    return NGHTTP2_ERR_WOULDBLOCK;

  return nwritten;
}


/* We pass a pointer to this struct in the push callback, but the contents of
   the struct are hidden from the user. */
struct curl_pushheaders {
  struct Curl_easy *data;
  const nghttp2_push_promise *frame;
};

/*
 * push header access function. Only to be used from within the push callback
 */
char *curl_pushheader_bynum(struct curl_pushheaders *h, size_t num)
{
  /* Verify that we got a good easy handle in the push header struct, mostly to
     detect rubbish input fast(er). */
  if(!h || !GOOD_EASY_HANDLE(h->data))
    return NULL;
  else {
    struct HTTP *stream = h->data->req.p.http;
    if(num < stream->push_headers_used)
      return stream->push_headers[num];
  }
  return NULL;
}

/*
 * push header access function. Only to be used from within the push callback
 */
char *curl_pushheader_byname(struct curl_pushheaders *h, const char *header)
{
  /* Verify that we got a good easy handle in the push header struct,
     mostly to detect rubbish input fast(er). Also empty header name
     is just a rubbish too. We have to allow ":" at the beginning of
     the header, but header == ":" must be rejected. If we have ':' in
     the middle of header, it could be matched in middle of the value,
     this is because we do prefix match.*/
  if(!h || !GOOD_EASY_HANDLE(h->data) || !header || !header[0] ||
     !strcmp(header, ":") || strchr(header + 1, ':'))
    return NULL;
  else {
    struct HTTP *stream = h->data->req.p.http;
    size_t len = strlen(header);
    size_t i;
    for(i = 0; i<stream->push_headers_used; i++) {
      if(!strncmp(header, stream->push_headers[i], len)) {
        /* sub-match, make sure that it is followed by a colon */
        if(stream->push_headers[i][len] != ':')
          continue;
        return &stream->push_headers[i][len + 1];
      }
    }
  }
  return NULL;
}

/*
 * This specific transfer on this connection has been "drained".
 */
static void drained_transfer(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  if(data->state.drain) {
    struct cf_h2_ctx *ctx = cf->ctx;
    DEBUGASSERT(ctx->drain_total > 0);
    ctx->drain_total--;
    data->state.drain = 0;
  }
}

/*
 * Mark this transfer to get "drained".
 */
static void drain_this(struct Curl_cfilter *cf,
                       struct Curl_easy *data)
{
  if(!data->state.drain) {
    struct cf_h2_ctx *ctx = cf->ctx;
    data->state.drain = 1;
    ctx->drain_total++;
    DEBUGASSERT(ctx->drain_total > 0);
  }
}

static struct Curl_easy *h2_duphandle(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct Curl_easy *second = curl_easy_duphandle(data);
  if(second) {
    /* setup the request struct */
    struct HTTP *http = calloc(1, sizeof(struct HTTP));
    if(!http) {
      (void)Curl_close(&second);
    }
    else {
      second->req.p.http = http;
      http2_data_setup(cf, second);
      second->state.priority.weight = data->state.priority.weight;
    }
  }
  return second;
}

static int set_transfer_url(struct Curl_easy *data,
                            struct curl_pushheaders *hp)
{
  const char *v;
  CURLUcode uc;
  char *url = NULL;
  int rc = 0;
  CURLU *u = curl_url();

  if(!u)
    return 5;

  v = curl_pushheader_byname(hp, H2H3_PSEUDO_SCHEME);
  if(v) {
    uc = curl_url_set(u, CURLUPART_SCHEME, v, 0);
    if(uc) {
      rc = 1;
      goto fail;
    }
  }

  v = curl_pushheader_byname(hp, H2H3_PSEUDO_AUTHORITY);
  if(v) {
    uc = curl_url_set(u, CURLUPART_HOST, v, 0);
    if(uc) {
      rc = 2;
      goto fail;
    }
  }

  v = curl_pushheader_byname(hp, H2H3_PSEUDO_PATH);
  if(v) {
    uc = curl_url_set(u, CURLUPART_PATH, v, 0);
    if(uc) {
      rc = 3;
      goto fail;
    }
  }

  uc = curl_url_get(u, CURLUPART_URL, &url, 0);
  if(uc)
    rc = 4;
  fail:
  curl_url_cleanup(u);
  if(rc)
    return rc;

  if(data->state.url_alloc)
    free(data->state.url);
  data->state.url_alloc = TRUE;
  data->state.url = url;
  return 0;
}

static int push_promise(struct Curl_cfilter *cf,
                        struct Curl_easy *data,
                        const nghttp2_push_promise *frame)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  int rv; /* one of the CURL_PUSH_* defines */

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] PUSH_PROMISE received",
                frame->promised_stream_id));
  if(data->multi->push_cb) {
    struct HTTP *stream;
    struct HTTP *newstream;
    struct curl_pushheaders heads;
    CURLMcode rc;
    size_t i;
    /* clone the parent */
    struct Curl_easy *newhandle = h2_duphandle(cf, data);
    if(!newhandle) {
      infof(data, "failed to duplicate handle");
      rv = CURL_PUSH_DENY; /* FAIL HARD */
      goto fail;
    }

    heads.data = data;
    heads.frame = frame;
    /* ask the application */
    DEBUGF(LOG_CF(data, cf, "Got PUSH_PROMISE, ask application"));

    stream = data->req.p.http;
    if(!stream) {
      failf(data, "Internal NULL stream");
      (void)Curl_close(&newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    rv = set_transfer_url(newhandle, &heads);
    if(rv) {
      (void)Curl_close(&newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    Curl_set_in_callback(data, true);
    rv = data->multi->push_cb(data, newhandle,
                              stream->push_headers_used, &heads,
                              data->multi->push_userp);
    Curl_set_in_callback(data, false);

    /* free the headers again */
    for(i = 0; i<stream->push_headers_used; i++)
      free(stream->push_headers[i]);
    free(stream->push_headers);
    stream->push_headers = NULL;
    stream->push_headers_used = 0;

    if(rv) {
      DEBUGASSERT((rv > CURL_PUSH_OK) && (rv <= CURL_PUSH_ERROROUT));
      /* denied, kill off the new handle again */
      http2_stream_free(newhandle->req.p.http);
      newhandle->req.p.http = NULL;
      (void)Curl_close(&newhandle);
      goto fail;
    }

    newstream = newhandle->req.p.http;
    newstream->stream_id = frame->promised_stream_id;
    newhandle->req.maxdownload = -1;
    newhandle->req.size = -1;

    /* approved, add to the multi handle and immediately switch to PERFORM
       state with the given connection !*/
    rc = Curl_multi_add_perform(data->multi, newhandle, cf->conn);
    if(rc) {
      infof(data, "failed to add handle to multi");
      http2_stream_free(newhandle->req.p.http);
      newhandle->req.p.http = NULL;
      Curl_close(&newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    rv = nghttp2_session_set_stream_user_data(ctx->h2,
                                              newstream->stream_id,
                                              newhandle);
    if(rv) {
      infof(data, "failed to set user_data for stream %u",
            newstream->stream_id);
      DEBUGASSERT(0);
      rv = CURL_PUSH_DENY;
      goto fail;
    }
    Curl_bufq_initp(&newstream->h2_sendbuf, &ctx->stream_bufcp,
                    H2_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
    Curl_bufq_initp(&newstream->h2_recvbuf, &ctx->stream_bufcp,
                    H2_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);
    newstream->h2_send_hds_len = 0;
    Curl_dynhds_init(&newstream->resp_trailers, 0, DYN_H2_TRAILERS);
  }
  else {
    DEBUGF(LOG_CF(data, cf, "Got PUSH_PROMISE, ignore it"));
    rv = CURL_PUSH_DENY;
  }
  fail:
  return rv;
}

static CURLcode recvbuf_write_hds(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  const char *buf, size_t blen)
{
  struct HTTP *stream = data->req.p.http;
  ssize_t nwritten;
  CURLcode result;

  (void)cf;
  nwritten = Curl_bufq_write(&stream->h2_recvbuf,
                             (const unsigned char *)buf, blen, &result);
  if(nwritten < 0)
    return result;
  stream->h2_recv_hds_len += (size_t)nwritten;
  /* TODO: make sure recvbuf is more flexible with overflow */
  DEBUGASSERT((size_t)nwritten == blen);
  return CURLE_OK;
}

static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct Curl_easy *data_s = NULL;
  struct HTTP *stream = NULL;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  int rv;
  int32_t stream_id = frame->hd.stream_id;
  CURLcode result;

  DEBUGASSERT(data);
  if(!stream_id) {
    /* stream ID zero is for connection-oriented stuff */
    DEBUGASSERT(data);
    switch(frame->hd.type) {
    case NGHTTP2_SETTINGS: {
      uint32_t max_conn = ctx->max_concurrent_streams;
      DEBUGF(LOG_CF(data, cf, "recv frame SETTINGS"));
      ctx->max_concurrent_streams = nghttp2_session_get_remote_settings(
          session, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
      ctx->enable_push = nghttp2_session_get_remote_settings(
          session, NGHTTP2_SETTINGS_ENABLE_PUSH) != 0;
      DEBUGF(LOG_CF(data, cf, "MAX_CONCURRENT_STREAMS == %d",
                    ctx->max_concurrent_streams));
      DEBUGF(LOG_CF(data, cf, "ENABLE_PUSH == %s",
                    ctx->enable_push ? "TRUE" : "false"));
      if(data && max_conn != ctx->max_concurrent_streams) {
        /* only signal change if the value actually changed */
        DEBUGF(LOG_CF(data, cf, "MAX_CONCURRENT_STREAMS now %u",
                      ctx->max_concurrent_streams));
        multi_connchanged(data->multi);
      }
      break;
    }
    case NGHTTP2_GOAWAY:
      ctx->goaway = TRUE;
      ctx->goaway_error = frame->goaway.error_code;
      ctx->last_stream_id = frame->goaway.last_stream_id;
      if(data) {
        DEBUGF(LOG_CF(data, cf, "recv GOAWAY, error=%d, last_stream=%u",
                      ctx->goaway_error, ctx->last_stream_id));
        infof(data, "recveived GOAWAY, error=%d, last_stream=%u",
                    ctx->goaway_error, ctx->last_stream_id);
        multi_connchanged(data->multi);
      }
      break;
    case NGHTTP2_WINDOW_UPDATE:
      DEBUGF(LOG_CF(data, cf, "recv frame WINDOW_UPDATE"));
      break;
    default:
      DEBUGF(LOG_CF(data, cf, "recv frame %x on 0", frame->hd.type));
    }
    return 0;
  }
  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!data_s) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] No Curl_easy associated",
                  stream_id));
    return 0;
  }

  stream = data_s->req.p.http;
  if(!stream) {
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] No proto pointer", stream_id));
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  switch(frame->hd.type) {
  case NGHTTP2_DATA:
    /* If !body started on this stream, then receiving DATA is illegal. */
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] recv frame DATA", stream_id));
    if(!stream->bodystarted) {
      rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                     stream_id, NGHTTP2_PROTOCOL_ERROR);

      if(nghttp2_is_fatal(rv)) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      /* Stream has ended. If there is pending data, ensure that read
         will occur to consume it. */
      if(!data->state.drain && !Curl_bufq_is_empty(&stream->h2_recvbuf)) {
        drain_this(cf, data_s);
        Curl_expire(data, 0, EXPIRE_RUN_NOW);
      }
    }
    break;
  case NGHTTP2_HEADERS:
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] recv frame HEADERS", stream_id));
    if(stream->bodystarted) {
      /* Only valid HEADERS after body started is trailer HEADERS.  We
         buffer them in on_header callback. */
      break;
    }

    /* nghttp2 guarantees that :status is received, and we store it to
       stream->status_code. Fuzzing has proven this can still be reached
       without status code having been set. */
    if(stream->status_code == -1)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    /* Only final status code signals the end of header */
    if(stream->status_code / 100 != 1) {
      stream->bodystarted = TRUE;
      stream->status_code = -1;
    }

    result = recvbuf_write_hds(cf, data_s, STRCONST("\r\n"));
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] %zu header bytes",
                  stream_id, Curl_bufq_len(&stream->h2_recvbuf)));
    if(CF_DATA_CURRENT(cf) != data_s) {
      drain_this(cf, data_s);
      Curl_expire(data_s, 0, EXPIRE_RUN_NOW);
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] recv PUSH_PROMISE", stream_id));
    rv = push_promise(cf, data_s, &frame->push_promise);
    if(rv) { /* deny! */
      int h2;
      DEBUGASSERT((rv > CURL_PUSH_OK) && (rv <= CURL_PUSH_ERROROUT));
      h2 = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                     frame->push_promise.promised_stream_id,
                                     NGHTTP2_CANCEL);
      if(nghttp2_is_fatal(h2))
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      else if(rv == CURL_PUSH_ERROROUT) {
        DEBUGF(LOG_CF(data_s, cf, "Fail the parent stream (too)"));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] recv RST", stream_id));
    stream->closed = TRUE;
    stream->reset = TRUE;
    drain_this(cf, data);
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
    break;
  case NGHTTP2_WINDOW_UPDATE:
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv WINDOW_UPDATE", stream_id));
    if((data_s->req.keepon & KEEP_SEND_HOLD) &&
       (data_s->req.keepon & KEEP_SEND)) {
      data_s->req.keepon &= ~KEEP_SEND_HOLD;
      drain_this(cf, data_s);
      Curl_expire(data_s, 0, EXPIRE_RUN_NOW);
      DEBUGF(LOG_CF(data, cf, "[h2sid=%u] un-holding after win update",
                    stream_id));
    }
    break;
  default:
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] recv frame %x",
                  stream_id, frame->hd.type));
    break;
  }
  return 0;
}

static int on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              const uint8_t *mem, size_t len, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct HTTP *stream;
  struct Curl_easy *data_s;
  ssize_t nwritten;
  CURLcode result;
  (void)flags;

  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */
  DEBUGASSERT(CF_DATA_CURRENT(cf));

  /* get the stream from the hash based on Stream ID */
  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!data_s) {
    /* Receiving a Stream ID not in the hash should not happen - unless
       we have aborted a transfer artificially and there were more data
       in the pipeline. Silently ignore. */
    DEBUGF(LOG_CF(CF_DATA_CURRENT(cf), cf, "[h2sid=%u] Data for unknown",
                  stream_id));
    /* consumed explicitly as no one will read it */
    nghttp2_session_consume(session, stream_id, len);
    return 0;
  }

  stream = data_s->req.p.http;
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  nwritten = Curl_bufq_write(&stream->h2_recvbuf, mem, len, &result);
  if(nwritten < 0) {
    if(result != CURLE_AGAIN)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    nwritten = 0;
  }

  /* if we receive data for another handle, wake that up */
  if(CF_DATA_CURRENT(cf) != data_s) {
    drain_this(cf, data_s);
    Curl_expire(data_s, 0, EXPIRE_RUN_NOW);
  }

  DEBUGASSERT((size_t)nwritten == len);
  DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] %zd/%zu DATA recvd, "
                "(buffer now holds %zu)",
                stream_id, nwritten, len, Curl_bufq_len(&stream->h2_recvbuf)));

  return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct Curl_easy *data_s;
  struct HTTP *stream;
  int rv;
  (void)session;

  /* get the stream from the hash based on Stream ID, stream ID zero is for
     connection-oriented stuff */
  data_s = stream_id?
             nghttp2_session_get_stream_user_data(session, stream_id) : NULL;
  if(!data_s) {
    return 0;
  }
  stream = data_s->req.p.http;
  DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] on_stream_close(), %s (err %d)",
                stream_id, nghttp2_http2_strerror(error_code), error_code));
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  stream->closed = TRUE;
  stream->error = error_code;
  if(stream->error)
    stream->reset = TRUE;

  if(CF_DATA_CURRENT(cf) != data_s) {
    drain_this(cf, data_s);
    Curl_expire(data_s, 0, EXPIRE_RUN_NOW);
  }

  /* remove `data_s` from the nghttp2 stream */
  rv = nghttp2_session_set_stream_user_data(session, stream_id, 0);
  if(rv) {
    infof(data_s, "http/2: failed to clear user_data for stream %u",
          stream_id);
    DEBUGASSERT(0);
  }
  DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] closed now", stream_id));
  return 0;
}

static int on_begin_headers(nghttp2_session *session,
                            const nghttp2_frame *frame, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct HTTP *stream;
  struct Curl_easy *data_s = NULL;

  (void)cf;
  data_s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(!data_s) {
    return 0;
  }

  DEBUGF(LOG_CF(data_s, cf, "on_begin_headers() was called"));

  if(frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  stream = data_s->req.p.http;
  if(!stream || !stream->bodystarted) {
    return 0;
  }

  return 0;
}

/* frame->hd.type is either NGHTTP2_HEADERS or NGHTTP2_PUSH_PROMISE */
static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags,
                     void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct HTTP *stream;
  struct Curl_easy *data_s;
  int32_t stream_id = frame->hd.stream_id;
  CURLcode result;
  (void)flags;

  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */

  /* get the stream from the hash based on Stream ID */
  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!data_s)
    /* Receiving a Stream ID not in the hash should not happen, this is an
       internal error more than anything else! */
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  stream = data_s->req.p.http;
  if(!stream) {
    failf(data_s, "Internal NULL stream");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  /* Store received PUSH_PROMISE headers to be used when the subsequent
     PUSH_PROMISE callback comes */
  if(frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    char *h;

    if(!strcmp(H2H3_PSEUDO_AUTHORITY, (const char *)name)) {
      /* pseudo headers are lower case */
      int rc = 0;
      char *check = aprintf("%s:%d", cf->conn->host.name,
                            cf->conn->remote_port);
      if(!check)
        /* no memory */
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      if(!strcasecompare(check, (const char *)value) &&
         ((cf->conn->remote_port != cf->conn->given->defport) ||
          !strcasecompare(cf->conn->host.name, (const char *)value))) {
        /* This is push is not for the same authority that was asked for in
         * the URL. RFC 7540 section 8.2 says: "A client MUST treat a
         * PUSH_PROMISE for which the server is not authoritative as a stream
         * error of type PROTOCOL_ERROR."
         */
        (void)nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                        stream_id, NGHTTP2_PROTOCOL_ERROR);
        rc = NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      free(check);
      if(rc)
        return rc;
    }

    if(!stream->push_headers) {
      stream->push_headers_alloc = 10;
      stream->push_headers = malloc(stream->push_headers_alloc *
                                    sizeof(char *));
      if(!stream->push_headers)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      stream->push_headers_used = 0;
    }
    else if(stream->push_headers_used ==
            stream->push_headers_alloc) {
      char **headp;
      if(stream->push_headers_alloc > 1000) {
        /* this is beyond crazy many headers, bail out */
        failf(data_s, "Too many PUSH_PROMISE headers");
        Curl_safefree(stream->push_headers);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      stream->push_headers_alloc *= 2;
      headp = Curl_saferealloc(stream->push_headers,
                               stream->push_headers_alloc * sizeof(char *));
      if(!headp) {
        stream->push_headers = NULL;
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      stream->push_headers = headp;
    }
    h = aprintf("%s:%s", name, value);
    if(h)
      stream->push_headers[stream->push_headers_used++] = h;
    return 0;
  }

  if(stream->bodystarted) {
    /* This is a trailer */
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] trailer: %.*s: %.*s",
                  stream->stream_id,
                  (int)namelen, name,
                  (int)valuelen, value));
    result = Curl_dynhds_add(&stream->resp_trailers,
                             (const char *)name, namelen,
                             (const char *)value, valuelen);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
  }

  if(namelen == sizeof(H2H3_PSEUDO_STATUS) - 1 &&
     memcmp(H2H3_PSEUDO_STATUS, name, namelen) == 0) {
    /* nghttp2 guarantees :status is received first and only once. */
    char buffer[32];
    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)value, valuelen);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    msnprintf(buffer, sizeof(buffer), H2H3_PSEUDO_STATUS ":%u\r",
              stream->status_code);
    result = Curl_headers_push(data_s, buffer, CURLH_PSEUDO);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    result = recvbuf_write_hds(cf, data_s, STRCONST("HTTP/2 "));
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    result = recvbuf_write_hds(cf, data_s, (const char *)value, valuelen);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    /* the space character after the status code is mandatory */
    result = recvbuf_write_hds(cf, data_s, STRCONST(" \r\n"));
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    /* if we receive data for another handle, wake that up */
    if(CF_DATA_CURRENT(cf) != data_s)
      Curl_expire(data_s, 0, EXPIRE_RUN_NOW);

    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] status: HTTP/2 %03d",
                  stream->stream_id, stream->status_code));
    return 0;
  }

  /* nghttp2 guarantees that namelen > 0, and :status was already
     received, and this is not pseudo-header field . */
  /* convert to an HTTP1-style header */
  result = recvbuf_write_hds(cf, data_s, (const char *)name, namelen);
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  result = recvbuf_write_hds(cf, data_s, STRCONST(": "));
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  result = recvbuf_write_hds(cf, data_s, (const char *)value, valuelen);
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  result = recvbuf_write_hds(cf, data_s, STRCONST("\r\n"));
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  /* if we receive data for another handle, wake that up */
  if(CF_DATA_CURRENT(cf) != data_s)
    Curl_expire(data_s, 0, EXPIRE_RUN_NOW);

  DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] header: %.*s: %.*s",
                stream->stream_id,
                (int)namelen, name,
                (int)valuelen, value));

  return 0; /* 0 is successful */
}

static ssize_t req_body_read_callback(nghttp2_session *session,
                                      int32_t stream_id,
                                      uint8_t *buf, size_t length,
                                      uint32_t *data_flags,
                                      nghttp2_data_source *source,
                                      void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct Curl_easy *data_s;
  struct HTTP *stream = NULL;
  CURLcode result;
  ssize_t nread;
  (void)source;

  (void)cf;
  if(stream_id) {
    /* get the stream from the hash based on Stream ID, stream ID zero is for
       connection-oriented stuff */
    data_s = nghttp2_session_get_stream_user_data(session, stream_id);
    if(!data_s)
      /* Receiving a Stream ID not in the hash should not happen, this is an
         internal error more than anything else! */
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    stream = data_s->req.p.http;
    if(!stream)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  else
    return NGHTTP2_ERR_INVALID_ARGUMENT;

  nread = Curl_bufq_read(&stream->h2_sendbuf, buf, length, &result);
  if(nread < 0) {
    if(result != CURLE_AGAIN)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    nread = 0;
  }

  if(nread > 0 && data_s->state.infilesize != -1)
    stream->upload_left -= nread;

  DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] req_body_read(len=%zu) left=%zd"
                " -> %zd, %d",
                stream_id, length, stream->upload_left, nread, result));

  if(stream->upload_left == 0)
    *data_flags = NGHTTP2_DATA_FLAG_EOF;
  else if(nread == 0)
    return NGHTTP2_ERR_DEFERRED;

  return nread;
}

#if !defined(CURL_DISABLE_VERBOSE_STRINGS)
static int error_callback(nghttp2_session *session,
                          const char *msg,
                          size_t len,
                          void *userp)
{
  (void)session;
  (void)msg;
  (void)len;
  (void)userp;
  return 0;
}
#endif

static void http2_data_done(struct Curl_cfilter *cf,
                            struct Curl_easy *data, bool premature)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;

  /* there might be allocated resources done before this got the 'h2' pointer
     setup */
  Curl_bufq_free(&stream->h2_sendbuf);
  Curl_bufq_free(&stream->h2_recvbuf);
  Curl_dynhds_free(&stream->resp_trailers);
  if(stream->push_headers) {
    /* if they weren't used and then freed before */
    for(; stream->push_headers_used > 0; --stream->push_headers_used) {
      free(stream->push_headers[stream->push_headers_used - 1]);
    }
    free(stream->push_headers);
    stream->push_headers = NULL;
  }

  if(!ctx || !ctx->h2)
    return;

  (void)premature;
  if(!stream->closed && stream->stream_id) {
    /* RST_STREAM */
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] premature DATA_DONE, RST stream",
                  stream->stream_id));
    if(!nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                                  stream->stream_id, NGHTTP2_STREAM_CLOSED))
      (void)nghttp2_session_send(ctx->h2);
  }

  drained_transfer(cf, data);

  /* -1 means unassigned and 0 means cleared */
  if(nghttp2_session_get_stream_user_data(ctx->h2, stream->stream_id)) {
    int rv = nghttp2_session_set_stream_user_data(ctx->h2,
                                                  stream->stream_id, 0);
    if(rv) {
      infof(data, "http/2: failed to clear user_data for stream %u",
            stream->stream_id);
      DEBUGASSERT(0);
    }
  }
}

/*
 * Append headers to ask for an HTTP1.1 to HTTP2 upgrade.
 */
CURLcode Curl_http2_request_upgrade(struct dynbuf *req,
                                    struct Curl_easy *data)
{
  CURLcode result;
  char *base64;
  size_t blen;
  struct SingleRequest *k = &data->req;
  uint8_t binsettings[H2_BINSETTINGS_LEN];
  size_t  binlen; /* length of the binsettings data */

  binlen = populate_binsettings(binsettings, data);
  if(binlen <= 0) {
    failf(data, "nghttp2 unexpectedly failed on pack_settings_payload");
    Curl_dyn_free(req);
    return CURLE_FAILED_INIT;
  }

  result = Curl_base64url_encode((const char *)binsettings, binlen,
                                 &base64, &blen);
  if(result) {
    Curl_dyn_free(req);
    return result;
  }

  result = Curl_dyn_addf(req,
                         "Connection: Upgrade, HTTP2-Settings\r\n"
                         "Upgrade: %s\r\n"
                         "HTTP2-Settings: %s\r\n",
                         NGHTTP2_CLEARTEXT_PROTO_VERSION_ID, base64);
  free(base64);

  k->upgr101 = UPGR101_H2;

  return result;
}

static CURLcode http2_data_done_send(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct HTTP *stream = data->req.p.http;

  if(!ctx || !ctx->h2)
    goto out;

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] data done", stream->stream_id));
  if(stream->upload_left) {
    /* If the stream still thinks there's data left to upload. */
    if(stream->upload_left == -1)
      stream->upload_left = 0; /* DONE! */

    /* resume sending here to trigger the callback to get called again so
       that it can signal EOF to nghttp2 */
    (void)nghttp2_session_resume_data(ctx->h2, stream->stream_id);
    drain_this(cf, data);
  }

out:
  return result;
}

static ssize_t http2_handle_stream_close(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct HTTP *stream, CURLcode *err)
{
  ssize_t rv = 0;

  drained_transfer(cf, data);

  if(stream->error == NGHTTP2_REFUSED_STREAM) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] REFUSED_STREAM, try again on a new "
                  "connection", stream->stream_id));
    connclose(cf->conn, "REFUSED_STREAM"); /* don't use this anymore */
    data->state.refused_stream = TRUE;
    *err = CURLE_RECV_ERROR; /* trigger Curl_retry_request() later */
    return -1;
  }
  else if(stream->error != NGHTTP2_NO_ERROR) {
    failf(data, "HTTP/2 stream %u was not closed cleanly: %s (err %u)",
          stream->stream_id, nghttp2_http2_strerror(stream->error),
          stream->error);
    *err = CURLE_HTTP2_STREAM;
    return -1;
  }
  else if(stream->reset) {
    failf(data, "HTTP/2 stream %u was reset", stream->stream_id);
    *err = stream->bodystarted? CURLE_PARTIAL_FILE : CURLE_RECV_ERROR;
    return -1;
  }

  if(!stream->bodystarted) {
    failf(data, "HTTP/2 stream %u was closed cleanly, but before getting "
          " all response header fields, treated as error",
          stream->stream_id);
    *err = CURLE_HTTP2_STREAM;
    return -1;
  }

  if(Curl_dynhds_count(&stream->resp_trailers)) {
    struct dynhds_entry *e;
    struct dynbuf dbuf;
    size_t i;

    *err = CURLE_OK;
    Curl_dyn_init(&dbuf, DYN_TRAILERS);
    for(i = 0; i < Curl_dynhds_count(&stream->resp_trailers); ++i) {
      e = Curl_dynhds_getn(&stream->resp_trailers, i);
      if(!e)
        break;
      Curl_dyn_reset(&dbuf);
      *err = Curl_dyn_addf(&dbuf, "%.*s: %.*s\x0d\x0a",
                          (int)e->namelen, e->name,
                          (int)e->valuelen, e->value);
      if(*err)
        break;
      Curl_debug(data, CURLINFO_HEADER_IN, Curl_dyn_ptr(&dbuf),
                 Curl_dyn_len(&dbuf));
      *err = Curl_client_write(data, CLIENTWRITE_HEADER|CLIENTWRITE_TRAILER,
                               Curl_dyn_ptr(&dbuf), Curl_dyn_len(&dbuf));
      if(*err)
        break;
    }
    Curl_dyn_free(&dbuf);
    if(*err)
      goto out;
  }

  stream->close_handled = TRUE;
  *err = CURLE_OK;
  rv = 0;

out:
  DEBUGF(LOG_CF(data, cf, "handle_stream_close -> %zd, %d", rv, *err));
  return rv;
}

static int sweight_wanted(const struct Curl_easy *data)
{
  /* 0 weight is not set by user and we take the nghttp2 default one */
  return data->set.priority.weight?
    data->set.priority.weight : NGHTTP2_DEFAULT_WEIGHT;
}

static int sweight_in_effect(const struct Curl_easy *data)
{
  /* 0 weight is not set by user and we take the nghttp2 default one */
  return data->state.priority.weight?
    data->state.priority.weight : NGHTTP2_DEFAULT_WEIGHT;
}

/*
 * h2_pri_spec() fills in the pri_spec struct, used by nghttp2 to send weight
 * and dependency to the peer. It also stores the updated values in the state
 * struct.
 */

static void h2_pri_spec(struct Curl_easy *data,
                        nghttp2_priority_spec *pri_spec)
{
  struct Curl_data_priority *prio = &data->set.priority;
  struct HTTP *depstream = (prio->parent?
                            prio->parent->req.p.http:NULL);
  int32_t depstream_id = depstream? depstream->stream_id:0;
  nghttp2_priority_spec_init(pri_spec, depstream_id,
                             sweight_wanted(data),
                             data->set.priority.exclusive);
  data->state.priority = *prio;
}

/*
 * Check if there's been an update in the priority /
 * dependency settings and if so it submits a PRIORITY frame with the updated
 * info.
 * Flush any out data pending in the network buffer.
 */
static CURLcode h2_progress_egress(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  int rv = 0;

  if((sweight_wanted(data) != sweight_in_effect(data)) ||
     (data->set.priority.exclusive != data->state.priority.exclusive) ||
     (data->set.priority.parent != data->state.priority.parent) ) {
    /* send new weight and/or dependency */
    nghttp2_priority_spec pri_spec;

    h2_pri_spec(data, &pri_spec);
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] Queuing PRIORITY",
                  stream->stream_id));
    DEBUGASSERT(stream->stream_id != -1);
    rv = nghttp2_submit_priority(ctx->h2, NGHTTP2_FLAG_NONE,
                                 stream->stream_id, &pri_spec);
    if(rv)
      goto out;
  }

  rv = nghttp2_session_send(ctx->h2);
out:
  if(nghttp2_is_fatal(rv)) {
    DEBUGF(LOG_CF(data, cf, "nghttp2_session_send error (%s)%d",
                  nghttp2_strerror(rv), rv));
    return CURLE_SEND_ERROR;
  }
  return nw_out_flush(cf, data);
}

static ssize_t stream_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           char *buf, size_t len, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  ssize_t nread = -1;

  *err = CURLE_AGAIN;
  if(!Curl_bufq_is_empty(&stream->h2_recvbuf)) {
    nread = Curl_bufq_read(&stream->h2_recvbuf,
                           (unsigned char *)buf, len, err);
    DEBUGF(LOG_CF(data, cf, "recvbuf read(len=%zu) -> %zd, %d",
                  len, nread, *err));
    if(nread < 0)
      goto out;
    DEBUGASSERT(nread > 0);
  }

  if(nread < 0) {
    if(stream->closed) {
      nread = http2_handle_stream_close(cf, data, stream, err);
    }
    else if(stream->reset ||
            (ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) ||
            (ctx->goaway && ctx->last_stream_id < stream->stream_id)) {
      *err = stream->bodystarted? CURLE_PARTIAL_FILE : CURLE_RECV_ERROR;
      nread = -1;
    }
  }
  else if(nread == 0) {
    *err = CURLE_AGAIN;
    nread = -1;
  }

out:
  DEBUGF(LOG_CF(data, cf, "stream_recv(len=%zu) -> %zd, %d",
                len, nread, *err));
  return nread;
}

static CURLcode h2_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  CURLcode result = CURLE_OK;
  ssize_t nread;
  bool keep_reading = TRUE;

  /* Process network input buffer fist */
  if(!Curl_bufq_is_empty(&ctx->inbufq)) {
    DEBUGF(LOG_CF(data, cf, "Process %zd bytes in connection buffer",
                  Curl_bufq_len(&ctx->inbufq)));
    if(h2_process_pending_input(cf, data, &result) < 0)
      return result;
  }

  /* Receive data from the "lower" filters, e.g. network until
   * it is time to stop or we have enough data for this stream */
  while(keep_reading &&
        !ctx->conn_closed &&               /* not closed the connection */
        !stream->closed &&                 /* nor the stream */
        Curl_bufq_is_empty(&ctx->inbufq) && /* and we consumed our input */
        !Curl_bufq_is_full(&stream->h2_recvbuf) && /* enough? */
        Curl_bufq_len(&stream->h2_recvbuf) < data->set.buffer_size) {

    nread = Curl_bufq_slurp(&ctx->inbufq, nw_in_reader, cf, &result);
    DEBUGF(LOG_CF(data, cf, "read %zd bytes nw data -> %zd, %d",
                  Curl_bufq_len(&ctx->inbufq), nread, result));
    if(nread < 0) {
      if(result != CURLE_AGAIN) {
        failf(data, "Failed receiving HTTP2 data");
        return result;
      }
      break;
    }
    else if(nread == 0) {
      ctx->conn_closed = TRUE;
      break;
    }

    keep_reading = Curl_bufq_is_full(&ctx->inbufq);
    if(h2_process_pending_input(cf, data, &result))
      return result;
  }

  if(ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) {
    connclose(cf->conn, "GOAWAY received");
  }

  return CURLE_OK;
}

static ssize_t cf_h2_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  ssize_t nread = -1;
  CURLcode result;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_recv: win %u/%u",
                stream->stream_id,
                nghttp2_session_get_local_window_size(ctx->h2),
                nghttp2_session_get_stream_local_window_size(ctx->h2,
                                                             stream->stream_id)
           ));
  nread = stream_recv(cf, data, buf, len, err);
  if(nread < 0 && *err != CURLE_AGAIN)
    goto out;

  if(nread < 0) {
    *err = h2_progress_ingress(cf, data);
    if(*err)
      goto out;

    nread = stream_recv(cf, data, buf, len, err);
    if(Curl_bufq_is_empty(&stream->h2_recvbuf)) {
      drained_transfer(cf, data);
    }
  }

  if(nread > 0) {
    size_t data_consumed = (size_t)nread;
    /* Now that we transferred this to the upper layer, we report
     * the actual amount of DATA consumed to the H2 session, so
     * that it adjusts stream flow control */
    if(stream->h2_recv_hds_len >= data_consumed) {
      stream->h2_recv_hds_len -= data_consumed;  /* no DATA */
    }
    else {
      if(stream->h2_recv_hds_len) {
        data_consumed -= stream->h2_recv_hds_len;
        stream->h2_recv_hds_len = 0;
      }
      if(data_consumed) {
        DEBUGF(LOG_CF(data, cf, "[h2sid=%u] increase window by %zu",
                      stream->stream_id, data_consumed));
        nghttp2_session_consume(ctx->h2, stream->stream_id, data_consumed);
      }
    }

    if(stream->closed) {
      DEBUGF(LOG_CF(data, cf, "[h2sid=%u] closed stream, set drain",
                    stream->stream_id));
      drain_this(cf, data);
    }
  }

out:
  result = h2_progress_egress(cf, data);
  if(result) {
    *err = result;
    nread = -1;
  }
  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_recv(len=%zu) -> %zd %d",
                stream->stream_id, len, nread, *err));
  CF_DATA_RESTORE(cf, save);
  return nread;
}

static ssize_t cf_h2_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err)
{
  /*
   * Currently, we send request in this function, but this function is also
   * used to send request body. It would be nice to add dedicated function for
   * request.
   */
  struct cf_h2_ctx *ctx = cf->ctx;
  int rv;
  struct HTTP *stream = data->req.p.http;
  nghttp2_nv *nva = NULL;
  size_t nheader;
  nghttp2_data_provider data_prd;
  int32_t stream_id;
  nghttp2_priority_spec pri_spec;
  CURLcode result;
  struct h2h3req *hreq;
  struct cf_call_data save;
  ssize_t nwritten;

  CF_DATA_SAVE(save, cf, data);

  if(stream->stream_id != -1) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_send: win %u/%u",
                stream->stream_id,
                nghttp2_session_get_remote_window_size(ctx->h2),
                nghttp2_session_get_stream_remote_window_size(
                  ctx->h2, stream->stream_id)
           ));

    if(stream->close_handled) {
      infof(data, "stream %u closed", stream->stream_id);
      *err = CURLE_HTTP2_STREAM;
      nwritten = -1;
      goto out;
    }
    else if(stream->closed) {
      nwritten = http2_handle_stream_close(cf, data, stream, err);
      goto out;
    }
    /* If stream_id != -1, we have dispatched request HEADERS, and now
       are going to send or sending request body in DATA frame */
    nwritten = Curl_bufq_write(&stream->h2_sendbuf, buf, len, err);
    if(nwritten < 0) {
      if(*err != CURLE_AGAIN)
        goto out;
      nwritten = 0;
    }

    if(!Curl_bufq_is_empty(&stream->h2_sendbuf)) {
      rv = nghttp2_session_resume_data(ctx->h2, stream->stream_id);
      if(nghttp2_is_fatal(rv)) {
        *err = CURLE_SEND_ERROR;
        nwritten = -1;
        goto out;
      }
    }

    result = h2_progress_ingress(cf, data);
    if(result) {
      *err = result;
      nwritten = -1;
      goto out;
    }

    result = h2_progress_egress(cf, data);
    if(result) {
      *err = result;
      nwritten = -1;
      goto out;
    }

    if(should_close_session(ctx)) {
      DEBUGF(LOG_CF(data, cf, "send: nothing to do in this session"));
      *err = CURLE_HTTP2;
      nwritten = -1;
      goto out;
    }

    if(!nwritten) {
      size_t rwin = nghttp2_session_get_stream_remote_window_size(ctx->h2,
                                                          stream->stream_id);
      DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_send: win %u/%zu",
             stream->stream_id,
             nghttp2_session_get_remote_window_size(ctx->h2), rwin));
        if(rwin == 0) {
          /* We cannot upload more as the stream's remote window size
           * is 0. We need to receive WIN_UPDATEs before we can continue.
           */
          data->req.keepon |= KEEP_SEND_HOLD;
          DEBUGF(LOG_CF(data, cf, "[h2sid=%u] holding send as remote flow "
                 "window is exhausted", stream->stream_id));
        }
    }
    /* handled writing BODY for open stream. */
    goto out;
  }

  DEBUGF(LOG_CF(data, cf, "cf_send, submit %s", data->state.url));
  if(!stream->h2_send_hds_len) {
    /* first invocation carries the HTTP/1.1 formatted request headers.
     * we remember that in case we EAGAIN this call, because the next
     * invocation may have added request body data into the buffer. */
    stream->h2_send_hds_len = len;
  }

  /* Stream has not been opened yet. `buf` is expected to contain
   * `stream->h2_send_hds_len` bytes of request headers. */
  DEBUGASSERT(stream->h2_send_hds_len <= len);
  result = Curl_pseudo_headers(data, buf, stream->h2_send_hds_len,
                               NULL, &hreq);
  if(result) {
    *err = result;
    nwritten = -1;
    goto out;
  }
  nheader = hreq->entries;

  nva = malloc(sizeof(nghttp2_nv) * nheader);
  if(!nva) {
    Curl_pseudo_free(hreq);
    *err = CURLE_OUT_OF_MEMORY;
    nwritten = -1;
    goto out;
  }
  else {
    unsigned int i;
    for(i = 0; i < nheader; i++) {
      nva[i].name = (unsigned char *)hreq->header[i].name;
      nva[i].namelen = hreq->header[i].namelen;
      nva[i].value = (unsigned char *)hreq->header[i].value;
      nva[i].valuelen = hreq->header[i].valuelen;
      nva[i].flags = NGHTTP2_NV_FLAG_NONE;
    }
    Curl_pseudo_free(hreq);
  }

  h2_pri_spec(data, &pri_spec);

  DEBUGF(LOG_CF(data, cf, "send request allowed %d (easy handle %p)",
                nghttp2_session_check_request_allowed(ctx->h2), (void *)data));

  switch(data->state.httpreq) {
  case HTTPREQ_POST:
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
  case HTTPREQ_PUT:
    if(data->state.infilesize != -1)
      stream->upload_left = data->state.infilesize;
    else
      /* data sending without specifying the data amount up front */
      stream->upload_left = -1; /* unknown, but not zero */

    data_prd.read_callback = req_body_read_callback;
    data_prd.source.ptr = NULL;
    stream_id = nghttp2_submit_request(ctx->h2, &pri_spec, nva, nheader,
                                       &data_prd, data);
    break;
  default:
    stream_id = nghttp2_submit_request(ctx->h2, &pri_spec, nva, nheader,
                                       NULL, data);
  }

  Curl_safefree(nva);

  if(stream_id < 0) {
    DEBUGF(LOG_CF(data, cf, "send: nghttp2_submit_request error (%s)%u",
                  nghttp2_strerror(stream_id), stream_id));
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_send(len=%zu) submit %s",
                stream_id, len, data->state.url));
  infof(data, "Using Stream ID: %u (easy handle %p)",
        stream_id, (void *)data);
  stream->stream_id = stream_id;
  nwritten = stream->h2_send_hds_len;

  result = h2_progress_ingress(cf, data);
  if(result) {
    *err = result;
    nwritten = -1;
    goto out;
  }

  result = h2_progress_egress(cf, data);
  if(result) {
    *err = result;
    nwritten = -1;
    goto out;
  }

  if(should_close_session(ctx)) {
    DEBUGF(LOG_CF(data, cf, "send: nothing to do in this session"));
    *err = CURLE_HTTP2;
    nwritten = -1;
    goto out;
  }

out:
  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_send -> %zd, %d",
         stream->stream_id, nwritten, *err));
  CF_DATA_RESTORE(cf, save);
  return nwritten;
}

static int cf_h2_get_select_socks(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  curl_socket_t *sock)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct SingleRequest *k = &data->req;
  struct HTTP *stream = data->req.p.http;
  int bitmap = GETSOCK_BLANK;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  sock[0] = Curl_conn_cf_get_socket(cf, data);

  if(!(k->keepon & (KEEP_RECV_PAUSE|KEEP_RECV_HOLD)))
    /* Unless paused - in an HTTP/2 connection we can basically always get a
       frame so we should always be ready for one */
    bitmap |= GETSOCK_READSOCK(0);

  /* we're (still uploading OR the HTTP/2 layer wants to send data) AND
     there's a window to send data in */
  if((((k->keepon & KEEP_SENDBITS) == KEEP_SEND) ||
      nghttp2_session_want_write(ctx->h2)) &&
     (nghttp2_session_get_remote_window_size(ctx->h2) &&
      nghttp2_session_get_stream_remote_window_size(ctx->h2,
                                                    stream->stream_id)))
    bitmap |= GETSOCK_WRITESOCK(0);

  CF_DATA_RESTORE(cf, save);
  return bitmap;
}


static CURLcode cf_h2_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool blocking, bool *done)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the lower filters first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, blocking, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;

  CF_DATA_SAVE(save, cf, data);
  if(!ctx->h2) {
    result = cf_h2_ctx_init(cf, data, FALSE);
    if(result)
      goto out;
  }

  result = h2_progress_ingress(cf, data);
  if(result)
    goto out;

  result = h2_progress_egress(cf, data);
  if(result)
    goto out;

  *done = TRUE;
  cf->connected = TRUE;
  result = CURLE_OK;

out:
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_h2_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;

  if(ctx) {
    struct cf_call_data save;

    CF_DATA_SAVE(save, cf, data);
    cf_h2_ctx_clear(ctx);
    CF_DATA_RESTORE(cf, save);
  }
}

static void cf_h2_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
    cf_h2_ctx_free(ctx);
    cf->ctx = NULL;
  }
}

static CURLcode http2_data_pause(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool pause)
{
  struct cf_h2_ctx *ctx = cf->ctx;

  DEBUGASSERT(data);
#ifdef NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE
  if(ctx && ctx->h2) {
    struct HTTP *stream = data->req.p.http;
    uint32_t window = !pause * H2_STREAM_WINDOW_SIZE;
    CURLcode result;

    int rv = nghttp2_session_set_local_window_size(ctx->h2,
                                                   NGHTTP2_FLAG_NONE,
                                                   stream->stream_id,
                                                   window);
    if(rv) {
      failf(data, "nghttp2_session_set_local_window_size() failed: %s(%d)",
            nghttp2_strerror(rv), rv);
      return CURLE_HTTP2;
    }

    /* make sure the window update gets sent */
    result = h2_progress_egress(cf, data);
    if(result)
      return result;

    DEBUGF(infof(data, "Set HTTP/2 window size to %u for stream %u",
                 window, stream->stream_id));

#ifdef DEBUGBUILD
    {
      /* read out the stream local window again */
      uint32_t window2 =
        nghttp2_session_get_stream_local_window_size(ctx->h2,
                                                     stream->stream_id);
      DEBUGF(infof(data, "HTTP/2 window size is now %u for stream %u",
                   window2, stream->stream_id));
    }
#endif
  }
#endif
  return CURLE_OK;
}

static CURLcode cf_h2_cntrl(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            int event, int arg1, void *arg2)
{
  CURLcode result = CURLE_OK;
  struct cf_call_data save;

  (void)arg2;

  CF_DATA_SAVE(save, cf, data);
  switch(event) {
  case CF_CTRL_DATA_SETUP: {
    result = http2_data_setup(cf, data);
    break;
  }
  case CF_CTRL_DATA_PAUSE:
    result = http2_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    result = http2_data_done_send(cf, data);
    break;
  }
  case CF_CTRL_DATA_DONE: {
    http2_data_done(cf, data, arg1 != 0);
    break;
  }
  default:
    break;
  }
  CF_DATA_RESTORE(cf, save);
  return result;
}

static bool cf_h2_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;

  if(ctx && (!Curl_bufq_is_empty(&ctx->inbufq)
            || (stream && !Curl_bufq_is_empty(&stream->h2_recvbuf))))
    return TRUE;
  return cf->next? cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

static bool cf_h2_is_alive(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           bool *input_pending)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  CURLcode result;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  result = (ctx && ctx->h2 && http2_connisalive(cf, data, input_pending));
  DEBUGF(LOG_CF(data, cf, "conn alive -> %d, input_pending=%d",
         result, *input_pending));
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode cf_h2_keep_alive(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  CURLcode result;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  result = http2_send_ping(cf, data);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode cf_h2_query(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            int query, int *pres1, void *pres2)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  size_t effective_max;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT:
    DEBUGASSERT(pres1);

    CF_DATA_SAVE(save, cf, data);
    if(nghttp2_session_check_request_allowed(ctx->h2) == 0) {
      /* the limit is what we have in use right now */
      effective_max = CONN_INUSE(cf->conn);
    }
    else {
      effective_max = ctx->max_concurrent_streams;
    }
    *pres1 = (effective_max > INT_MAX)? INT_MAX : (int)effective_max;
    CF_DATA_RESTORE(cf, save);
    return CURLE_OK;
  default:
    break;
  }
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

struct Curl_cftype Curl_cft_nghttp2 = {
  "HTTP/2",
  CF_TYPE_MULTIPLEX,
  CURL_LOG_DEFAULT,
  cf_h2_destroy,
  cf_h2_connect,
  cf_h2_close,
  Curl_cf_def_get_host,
  cf_h2_get_select_socks,
  cf_h2_data_pending,
  cf_h2_send,
  cf_h2_recv,
  cf_h2_cntrl,
  cf_h2_is_alive,
  cf_h2_keep_alive,
  cf_h2_query,
};

static CURLcode http2_cfilter_add(struct Curl_cfilter **pcf,
                                  struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_h2_ctx *ctx;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(data->conn);
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx)
    goto out;

  result = Curl_cf_create(&cf, &Curl_cft_nghttp2, ctx);
  if(result)
    goto out;

  Curl_conn_cf_add(data, conn, sockindex, cf);
  result = CURLE_OK;

out:
  if(result)
    cf_h2_ctx_free(ctx);
  *pcf = result? NULL : cf;
  return result;
}

static CURLcode http2_cfilter_insert_after(struct Curl_cfilter *cf,
                                           struct Curl_easy *data)
{
  struct Curl_cfilter *cf_h2 = NULL;
  struct cf_h2_ctx *ctx;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  (void)data;
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx)
    goto out;

  result = Curl_cf_create(&cf_h2, &Curl_cft_nghttp2, ctx);
  if(result)
    goto out;

  Curl_conn_cf_insert_after(cf, cf_h2);
  result = CURLE_OK;

out:
  if(result)
    cf_h2_ctx_free(ctx);
  return result;
}

bool Curl_cf_is_http2(struct Curl_cfilter *cf, const struct Curl_easy *data)
{
  (void)data;
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_nghttp2)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

bool Curl_conn_is_http2(const struct Curl_easy *data,
                        const struct connectdata *conn,
                        int sockindex)
{
  return conn? Curl_cf_is_http2(conn->cfilter[sockindex], data) : FALSE;
}

bool Curl_http2_may_switch(struct Curl_easy *data,
                           struct connectdata *conn,
                           int sockindex)
{
  (void)sockindex;
  if(!Curl_conn_is_http2(data, conn, sockindex) &&
     data->state.httpwant == CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE) {
#ifndef CURL_DISABLE_PROXY
    if(conn->bits.httpproxy && !conn->bits.tunnel_proxy) {
      /* We don't support HTTP/2 proxies yet. Also it's debatable
         whether or not this setting should apply to HTTP/2 proxies. */
      infof(data, "Ignoring HTTP/2 prior knowledge due to proxy");
      return FALSE;
    }
#endif
    return TRUE;
  }
  return FALSE;
}

CURLcode Curl_http2_switch(struct Curl_easy *data,
                           struct connectdata *conn, int sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  DEBUGASSERT(!Curl_conn_is_http2(data, conn, sockindex));
  DEBUGF(infof(data, DMSGI(data, sockindex, "switching to HTTP/2")));

  result = http2_cfilter_add(&cf, data, conn, sockindex);
  if(result)
    return result;

  result = cf_h2_ctx_init(cf, data, FALSE);
  if(result)
    return result;

  conn->httpversion = 20; /* we know we're on HTTP/2 now */
  conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  conn->bundle->multiuse = BUNDLE_MULTIPLEX;
  multi_connchanged(data->multi);

  if(cf->next) {
    bool done;
    return Curl_conn_cf_connect(cf, data, FALSE, &done);
  }
  return CURLE_OK;
}

CURLcode Curl_http2_switch_at(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct Curl_cfilter *cf_h2;
  CURLcode result;

  DEBUGASSERT(!Curl_cf_is_http2(cf, data));

  result = http2_cfilter_insert_after(cf, data);
  if(result)
    return result;

  cf_h2 = cf->next;
  result = cf_h2_ctx_init(cf_h2, data, FALSE);
  if(result)
    return result;

  cf->conn->httpversion = 20; /* we know we're on HTTP/2 now */
  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  cf->conn->bundle->multiuse = BUNDLE_MULTIPLEX;
  multi_connchanged(data->multi);

  if(cf_h2->next) {
    bool done;
    return Curl_conn_cf_connect(cf_h2, data, FALSE, &done);
  }
  return CURLE_OK;
}

CURLcode Curl_http2_upgrade(struct Curl_easy *data,
                            struct connectdata *conn, int sockindex,
                            const char *mem, size_t nread)
{
  struct Curl_cfilter *cf;
  struct cf_h2_ctx *ctx;
  CURLcode result;

  DEBUGASSERT(!Curl_conn_is_http2(data, conn, sockindex));
  DEBUGF(infof(data, DMSGI(data, sockindex, "upgrading to HTTP/2")));
  DEBUGASSERT(data->req.upgr101 == UPGR101_RECEIVED);

  result = http2_cfilter_add(&cf, data, conn, sockindex);
  if(result)
    return result;

  DEBUGASSERT(cf->cft == &Curl_cft_nghttp2);
  ctx = cf->ctx;

  result = cf_h2_ctx_init(cf, data, TRUE);
  if(result)
    return result;

  if(nread > 0) {
    /* Remaining data from the protocol switch reply is already using
     * the switched protocol, ie. HTTP/2. We add that to the network
     * inbufq. */
    ssize_t copied;

    copied = Curl_bufq_write(&ctx->inbufq,
                             (const unsigned char *)mem, nread, &result);
    if(copied < 0) {
      failf(data, "error on copying HTTP Upgrade response: %d", result);
      return CURLE_RECV_ERROR;
    }
    if((size_t)copied < nread) {
      failf(data, "connection buffer size could not take all data "
            "from HTTP Upgrade response header: copied=%zd, datalen=%zu",
            copied, nread);
      return CURLE_HTTP2;
    }
    infof(data, "Copied HTTP/2 data in stream buffer to connection buffer"
          " after upgrade: len=%zu", nread);
  }

  conn->httpversion = 20; /* we know we're on HTTP/2 now */
  conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  conn->bundle->multiuse = BUNDLE_MULTIPLEX;
  multi_connchanged(data->multi);

  if(cf->next) {
    bool done;
    return Curl_conn_cf_connect(cf, data, FALSE, &done);
  }
  return CURLE_OK;
}

/* Only call this function for a transfer that already got an HTTP/2
   CURLE_HTTP2_STREAM error! */
bool Curl_h2_http_1_1_error(struct Curl_easy *data)
{
  struct HTTP *stream = data->req.p.http;
  return (stream && stream->error == NGHTTP2_HTTP_1_1_REQUIRED);
}

#else /* !USE_NGHTTP2 */

/* Satisfy external references even if http2 is not compiled in. */
#include <curl/curl.h>

char *curl_pushheader_bynum(struct curl_pushheaders *h, size_t num)
{
  (void) h;
  (void) num;
  return NULL;
}

char *curl_pushheader_byname(struct curl_pushheaders *h, const char *header)
{
  (void) h;
  (void) header;
  return NULL;
}

#endif /* USE_NGHTTP2 */
