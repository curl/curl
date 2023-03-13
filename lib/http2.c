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

#define H2_BUFSIZE 32768

#if (NGHTTP2_VERSION_NUM < 0x010c00)
#error too old nghttp2 version, upgrade!
#endif

#ifdef CURL_DISABLE_VERBOSE_STRINGS
#define nghttp2_session_callbacks_set_error_callback(x,y)
#endif

#if (NGHTTP2_VERSION_NUM >= 0x010c00)
#define NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE 1
#endif

#define HTTP2_HUGE_WINDOW_SIZE (32 * 1024 * 1024) /* 32 MB */


#define H2_SETTINGS_IV_LEN  3
#define H2_BINSETTINGS_LEN 80

static int populate_settings(nghttp2_settings_entry *iv,
                             struct Curl_easy *data)
{
  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = Curl_multi_max_concurrent_streams(data->multi);

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = HTTP2_HUGE_WINDOW_SIZE;

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

  char *inbuf; /* buffer to receive data from underlying socket */
  size_t inbuflen; /* number of bytes filled in inbuf */
  size_t nread_inbuf; /* number of bytes read from in inbuf */

  struct dynbuf outbuf;

  /* We need separate buffer for transmission and reception because we
     may call nghttp2_session_send() after the
     nghttp2_session_mem_recv() but mem buffer is still not full. In
     this case, we wrongly sends the content of mem buffer if we share
     them for both cases. */
  int32_t pause_stream_id; /* stream ID which paused
                              nghttp2_session_mem_recv */
  size_t drain_total; /* sum of all stream's UrlState.drain */
  int32_t goaway_error;
  int32_t last_stream_id;
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
  free(ctx->inbuf);
  Curl_dyn_free(&ctx->outbuf);
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

#if NGHTTP2_VERSION_NUM < 0x013200
  /* before 1.50.0 */
  return nghttp2_session_client_new(&ctx->h2, cbs, cf);
#else
  nghttp2_option *o;
  int rc = nghttp2_option_new(&o);
  if(rc)
    return rc;
  /* turn off RFC 9113 leading and trailing white spaces validation against
     HTTP field value. */
  nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(o, 1);
  rc = nghttp2_session_client_new2(&ctx->h2, cbs, cf, o);
  nghttp2_option_del(o);
  return rc;
#endif
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
  struct HTTP *stream = data->req.p.http;

  (void)cf;
  DEBUGASSERT(stream);
  DEBUGASSERT(data->state.buffer);

  stream->stream_id = -1;

  Curl_dyn_init(&stream->header_recvbuf, DYN_H2_HEADERS);
  Curl_dyn_init(&stream->trailer_recvbuf, DYN_H2_TRAILERS);

  stream->bodystarted = FALSE;
  stream->status_code = -1;
  stream->pausedata = NULL;
  stream->pauselen = 0;
  stream->closed = FALSE;
  stream->close_handled = FALSE;
  stream->memlen = 0;
  stream->error = NGHTTP2_NO_ERROR;
  stream->upload_left = 0;
  stream->upload_mem = NULL;
  stream->upload_len = 0;
  stream->mem = data->state.buffer;
  stream->len = data->set.buffer_size;

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
  ctx->inbuf = malloc(H2_BUFSIZE);
  if(!ctx->inbuf)
      goto out;
  /* we want to aggregate small frames, SETTINGS, PRIO, UPDATES */
  Curl_dyn_init(&ctx->outbuf, 4*1024);

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

static CURLcode  h2_session_send(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);
static int h2_process_pending_input(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    CURLcode *err);

/*
 * http2_stream_free() free HTTP2 stream related data
 */
static void http2_stream_free(struct HTTP *stream)
{
  if(stream) {
    Curl_dyn_free(&stream->header_recvbuf);
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
    nread = Curl_conn_cf_recv(cf->next, data,
                              ctx->inbuf, H2_BUFSIZE, &result);
    if(nread != -1) {
      DEBUGF(LOG_CF(data, cf, "%d bytes stray data read before trying "
                    "h2 connection", (int)nread));
      ctx->nread_inbuf = 0;
      ctx->inbuflen = nread;
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

static CURLcode flush_output(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  size_t buflen = Curl_dyn_len(&ctx->outbuf);
  ssize_t written;
  CURLcode result;

  if(!buflen)
    return CURLE_OK;

  DEBUGF(LOG_CF(data, cf, "h2 conn flush %zu bytes", buflen));
  written = Curl_conn_cf_send(cf->next, data, Curl_dyn_ptr(&ctx->outbuf),
                              buflen, &result);
  if(written < 0) {
    return result;
  }
  if((size_t)written < buflen) {
    Curl_dyn_tail(&ctx->outbuf, buflen - (size_t)written);
    return CURLE_AGAIN;
  }
  else {
    Curl_dyn_reset(&ctx->outbuf);
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
  ssize_t written;
  CURLcode result = CURLE_OK;
  size_t buflen = Curl_dyn_len(&ctx->outbuf);

  (void)h2;
  (void)flags;
  DEBUGASSERT(data);

  if(blen < 1024 && (buflen + blen + 1 < ctx->outbuf.toobig)) {
    result = Curl_dyn_addn(&ctx->outbuf, buf, blen);
    if(result) {
      failf(data, "Failed to add data to output buffer");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return blen;
  }
  if(buflen) {
    /* not adding, flush buffer */
    result = flush_output(cf, data);
    if(result) {
      if(result == CURLE_AGAIN) {
        return NGHTTP2_ERR_WOULDBLOCK;
      }
      failf(data, "Failed sending HTTP2 data");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  DEBUGF(LOG_CF(data, cf, "h2 conn send %zu bytes", blen));
  written = Curl_conn_cf_send(cf->next, data, buf, blen, &result);
  if(result == CURLE_AGAIN) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  if(written == -1) {
    failf(data, "Failed sending HTTP2 data");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if(!written)
    return NGHTTP2_ERR_WOULDBLOCK;

  return written;
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
                                              frame->promised_stream_id,
                                              newhandle);
    if(rv) {
      infof(data, "failed to set user_data for stream %u",
            frame->promised_stream_id);
      DEBUGASSERT(0);
      rv = CURL_PUSH_DENY;
      goto fail;
    }
    Curl_dyn_init(&newstream->header_recvbuf, DYN_H2_HEADERS);
    Curl_dyn_init(&newstream->trailer_recvbuf, DYN_H2_TRAILERS);
  }
  else {
    DEBUGF(LOG_CF(data, cf, "Got PUSH_PROMISE, ignore it"));
    rv = CURL_PUSH_DENY;
  }
  fail:
  return rv;
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
  size_t left, ncopy;
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
      if(!data->state.drain && stream->memlen) {
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

    result = Curl_dyn_addn(&stream->header_recvbuf, STRCONST("\r\n"));
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    left = Curl_dyn_len(&stream->header_recvbuf) -
      stream->nread_header_recvbuf;
    ncopy = CURLMIN(stream->len, left);

    memcpy(&stream->mem[stream->memlen],
           Curl_dyn_ptr(&stream->header_recvbuf) +
           stream->nread_header_recvbuf,
           ncopy);
    stream->nread_header_recvbuf += ncopy;

    DEBUGASSERT(stream->mem);
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] %zu header bytes, at %p",
                  stream_id, ncopy, (void *)stream->mem));

    stream->len -= ncopy;
    stream->memlen += ncopy;

    drain_this(cf, data_s);
    Curl_expire(data_s, 0, EXPIRE_RUN_NOW);
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
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream;
  struct Curl_easy *data_s;
  size_t nread;
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
    return 0;
  }

  stream = data_s->req.p.http;
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  nread = CURLMIN(stream->len, len);
  memcpy(&stream->mem[stream->memlen], mem, nread);

  stream->len -= nread;
  stream->memlen += nread;

  /* if we receive data for another handle, wake that up */
  if(CF_DATA_CURRENT(cf) != data_s) {
    drain_this(cf, data_s);
    Curl_expire(data_s, 0, EXPIRE_RUN_NOW);
  }

  DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] %zu DATA recvd, "
                "(buffer now holds %zu, %zu still free in %p)",
                stream_id, nread,
                stream->memlen, stream->len, (void *)stream->mem));

  if(nread < len) {
    stream->pausedata = mem + nread;
    stream->pauselen = len - nread;
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] %zu not recvd -> NGHTTP2_ERR_PAUSE",
                  stream_id, len - nread));
    ctx->pause_stream_id = stream_id;
    drain_this(cf, data_s);
    return NGHTTP2_ERR_PAUSE;
  }

  return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
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
  if(stream_id == ctx->pause_stream_id) {
    DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] closed the pause stream",
                  stream_id));
    ctx->pause_stream_id = 0;
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

/* Decode HTTP status code.  Returns -1 if no valid status code was
   decoded. */
static int decode_status_code(const uint8_t *value, size_t len)
{
  int i;
  int res;

  if(len != 3) {
    return -1;
  }

  res = 0;

  for(i = 0; i < 3; ++i) {
    char c = value[i];

    if(c < '0' || c > '9') {
      return -1;
    }

    res *= 10;
    res += c - '0';
  }

  return res;
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
    result = Curl_dyn_addf(&stream->trailer_recvbuf,
                           "%.*s: %.*s\r\n", (int)namelen, name,
                           (int)valuelen, value);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
  }

  if(namelen == sizeof(H2H3_PSEUDO_STATUS) - 1 &&
     memcmp(H2H3_PSEUDO_STATUS, name, namelen) == 0) {
    /* nghttp2 guarantees :status is received first and only once, and
       value is 3 digits status code, and decode_status_code always
       succeeds. */
    char buffer[32];
    stream->status_code = decode_status_code(value, valuelen);
    DEBUGASSERT(stream->status_code != -1);
    msnprintf(buffer, sizeof(buffer), H2H3_PSEUDO_STATUS ":%u\r",
              stream->status_code);
    result = Curl_headers_push(data_s, buffer, CURLH_PSEUDO);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    result = Curl_dyn_addn(&stream->header_recvbuf, STRCONST("HTTP/2 "));
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    result = Curl_dyn_addn(&stream->header_recvbuf, value, valuelen);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    /* the space character after the status code is mandatory */
    result = Curl_dyn_addn(&stream->header_recvbuf, STRCONST(" \r\n"));
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
  result = Curl_dyn_addn(&stream->header_recvbuf, name, namelen);
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  result = Curl_dyn_addn(&stream->header_recvbuf, STRCONST(": "));
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  result = Curl_dyn_addn(&stream->header_recvbuf, value, valuelen);
  if(result)
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  result = Curl_dyn_addn(&stream->header_recvbuf, STRCONST("\r\n"));
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

static ssize_t data_source_read_callback(nghttp2_session *session,
                                         int32_t stream_id,
                                         uint8_t *buf, size_t length,
                                         uint32_t *data_flags,
                                         nghttp2_data_source *source,
                                         void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct Curl_easy *data_s;
  struct HTTP *stream = NULL;
  size_t nread;
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

  nread = CURLMIN(stream->upload_len, length);
  if(nread > 0) {
    memcpy(buf, stream->upload_mem, nread);
    stream->upload_mem += nread;
    stream->upload_len -= nread;
    if(data_s->state.infilesize != -1)
      stream->upload_left -= nread;
  }

  if(stream->upload_left == 0)
    *data_flags = NGHTTP2_DATA_FLAG_EOF;
  else if(nread == 0)
    return NGHTTP2_ERR_DEFERRED;

  DEBUGF(LOG_CF(data_s, cf, "[h2sid=%u] data_source_read_callback: "
                "returns %zu bytes", stream_id, nread));

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
  Curl_dyn_free(&stream->header_recvbuf);
  Curl_dyn_free(&stream->trailer_recvbuf);
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

  /* do this before the reset handling, as that might clear ->stream_id */
  if(stream->stream_id && stream->stream_id == ctx->pause_stream_id) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] DONE, the pause stream",
                  stream->stream_id));
    ctx->pause_stream_id = 0;
  }

  (void)premature;
  if(!stream->closed && stream->stream_id) {
    /* RST_STREAM */
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] RST", stream->stream_id));
    if(!nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                                  stream->stream_id, NGHTTP2_STREAM_CLOSED))
      (void)nghttp2_session_send(ctx->h2);
  }

  if(data->state.drain)
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

/*
 * h2_process_pending_input() processes pending input left in
 * httpc->inbuf.  Then, call h2_session_send() to send pending data.
 * This function returns 0 if it succeeds, or -1 and error code will
 * be assigned to *err.
 */
static int h2_process_pending_input(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  ssize_t nread;
  ssize_t rv;

  nread = ctx->inbuflen - ctx->nread_inbuf;
  if(nread) {
    char *inbuf = ctx->inbuf + ctx->nread_inbuf;

    rv = nghttp2_session_mem_recv(ctx->h2, (const uint8_t *)inbuf, nread);
    if(rv < 0) {
      failf(data,
            "h2_process_pending_input: nghttp2_session_mem_recv() returned "
            "%zd:%s", rv, nghttp2_strerror((int)rv));
      *err = CURLE_RECV_ERROR;
      return -1;
    }

    if(nread == rv) {
      DEBUGF(LOG_CF(data, cf, "all data in connection buffer processed"));
      ctx->inbuflen = 0;
      ctx->nread_inbuf = 0;
    }
    else {
      ctx->nread_inbuf += rv;
      DEBUGF(LOG_CF(data, cf, "h2_process_pending_input: %zu bytes left "
                    "in connection buffer",
                   ctx->inbuflen - ctx->nread_inbuf));
    }
  }

  rv = h2_session_send(cf, data);
  if(rv) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  if(nghttp2_session_check_request_allowed(ctx->h2) == 0) {
    /* No more requests are allowed in the current session, so
       the connection may not be reused. This is set when a
       GOAWAY frame has been received or when the limit of stream
       identifiers has been reached. */
    connclose(cf->conn, "http/2: No new requests allowed");
  }

  if(should_close_session(ctx)) {
    struct HTTP *stream = data->req.p.http;
    DEBUGF(LOG_CF(data, cf,
                 "h2_process_pending_input: nothing to do in this session"));
    if(stream->reset)
      *err = CURLE_PARTIAL_FILE;
    else if(stream->error)
      *err = CURLE_HTTP2;
    else {
      /* not an error per se, but should still close the connection */
      connclose(cf->conn, "GOAWAY received");
      *err = CURLE_OK;
    }
    return -1;
  }
  return 0;
}

static CURLcode http2_data_done_send(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct HTTP *stream = data->req.p.http;

  if(!ctx || !ctx->h2)
    goto out;

  if(stream->upload_left) {
    /* If the stream still thinks there's data left to upload. */
    stream->upload_left = 0; /* DONE! */

    /* resume sending here to trigger the callback to get called again so
       that it can signal EOF to nghttp2 */
    (void)nghttp2_session_resume_data(ctx->h2, stream->stream_id);
    (void)h2_process_pending_input(cf, data, &result);
  }

  /* If nghttp2 still has pending frames unsent */
  if(nghttp2_session_want_write(ctx->h2)) {
    struct SingleRequest *k = &data->req;
    int rv;

    DEBUGF(LOG_CF(data, cf, "HTTP/2 still wants to send data"));

    /* and attempt to send the pending frames */
    rv = h2_session_send(cf, data);
    if(rv)
      result = CURLE_SEND_ERROR;

    if(nghttp2_session_want_write(ctx->h2)) {
       /* re-set KEEP_SEND to make sure we are called again */
       k->keepon |= KEEP_SEND;
    }
  }

out:
  return result;
}

static ssize_t http2_handle_stream_close(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct HTTP *stream, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;

  if(ctx->pause_stream_id == stream->stream_id) {
    ctx->pause_stream_id = 0;
  }

  drained_transfer(cf, data);

  if(ctx->pause_stream_id == 0) {
    if(h2_process_pending_input(cf, data, err) != 0) {
      return -1;
    }
  }

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

  if(Curl_dyn_len(&stream->trailer_recvbuf)) {
    char *trailp = Curl_dyn_ptr(&stream->trailer_recvbuf);
    char *lf;

    do {
      size_t len = 0;
      CURLcode result;
      /* each trailer line ends with a newline */
      lf = strchr(trailp, '\n');
      if(!lf)
        break;
      len = lf + 1 - trailp;

      Curl_debug(data, CURLINFO_HEADER_IN, trailp, len);
      /* pass the trailers one by one to the callback */
      result = Curl_client_write(data, CLIENTWRITE_HEADER, trailp, len);
      if(result) {
        *err = result;
        return -1;
      }
      trailp = ++lf;
    } while(lf);
  }

  stream->close_handled = TRUE;

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] closed cleanly", stream->stream_id));
  return 0;
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
 * h2_session_send() checks if there's been an update in the priority /
 * dependency settings and if so it submits a PRIORITY frame with the updated
 * info.
 */
static CURLcode h2_session_send(struct Curl_cfilter *cf,
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
  return flush_output(cf, data);
}

static ssize_t cf_h2_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  ssize_t nread = -1;
  struct cf_call_data save;
  bool conn_is_closed = FALSE;

  CF_DATA_SAVE(save, cf, data);

  /* If the h2 session has told us to GOAWAY with an error AND
   * indicated the highest stream id it has processes AND
   * the stream we are trying to read has a higher id, this
   * means we will most likely not receive any more for it.
   * Treat this as if the server explicitly had RST the stream */
  if((ctx->goaway && ctx->goaway_error &&
      ctx->last_stream_id > 0 &&
      ctx->last_stream_id < stream->stream_id)) {
    stream->reset = TRUE;
  }

  /* If a stream is RST, it does not matter what state the h2 session
   * is in, our answer to receiving data is always the same. */
  if(stream->reset) {
    *err = stream->bodystarted? CURLE_PARTIAL_FILE : CURLE_RECV_ERROR;
    nread = -1;
    goto out;
  }

  if(should_close_session(ctx)) {
    DEBUGF(LOG_CF(data, cf, "http2_recv: nothing to do in this session"));
    if(cf->conn->bits.close) {
      /* already marked for closure, return OK and we're done */
      drained_transfer(cf, data);
      *err = CURLE_OK;
      nread = 0;
      goto out;
    }
    *err = CURLE_HTTP2;
    nread = -1;
    goto out;
  }

  /* Nullify here because we call nghttp2_session_send() and they
     might refer to the old buffer. */
  stream->upload_mem = NULL;
  stream->upload_len = 0;

  /*
   * At this point 'stream' is just in the Curl_easy the connection
   * identifies as its owner at this time.
   */

  if(stream->bodystarted &&
     stream->nread_header_recvbuf < Curl_dyn_len(&stream->header_recvbuf)) {
    /* If there is header data pending for this stream to return, do that */
    size_t left =
      Curl_dyn_len(&stream->header_recvbuf) - stream->nread_header_recvbuf;
    size_t ncopy = CURLMIN(len, left);
    memcpy(buf, Curl_dyn_ptr(&stream->header_recvbuf) +
           stream->nread_header_recvbuf, ncopy);
    stream->nread_header_recvbuf += ncopy;

    DEBUGF(LOG_CF(data, cf, "recv: Got %d bytes from header_recvbuf",
                  (int)ncopy));
    nread = ncopy;
    goto out;
  }

  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_recv: win %u/%u",
                stream->stream_id,
                nghttp2_session_get_local_window_size(ctx->h2),
                nghttp2_session_get_stream_local_window_size(ctx->h2,
                                                             stream->stream_id)
           ));

  if(stream->memlen) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv: DRAIN %zu bytes (%p => %p)",
                  stream->stream_id, stream->memlen,
                  (void *)stream->mem, (void *)buf));
    if(buf != stream->mem) {
      /* if we didn't get the same buffer this time, we must move the data to
         the beginning */
      memmove(buf, stream->mem, stream->memlen);
      stream->len = len - stream->memlen;
      stream->mem = buf;
    }

    if(ctx->pause_stream_id == stream->stream_id && !stream->pausedata) {
      /* We have paused nghttp2, but we have no pause data (see
         on_data_chunk_recv). */
      ctx->pause_stream_id = 0;
      if(h2_process_pending_input(cf, data, err) != 0) {
        nread = -1;
        goto out;
      }
    }
  }
  else if(stream->pausedata) {
    DEBUGASSERT(ctx->pause_stream_id == stream->stream_id);
    nread = CURLMIN(len, stream->pauselen);
    memcpy(buf, stream->pausedata, nread);

    stream->pausedata += nread;
    stream->pauselen -= nread;
    drain_this(cf, data);

    if(stream->pauselen == 0) {
      DEBUGF(LOG_CF(data, cf, "[h2sid=%u] Unpaused", stream->stream_id));
      DEBUGASSERT(ctx->pause_stream_id == stream->stream_id);
      ctx->pause_stream_id = 0;

      stream->pausedata = NULL;
      stream->pauselen = 0;
    }
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] recv: returns unpaused %zd bytes",
                  stream->stream_id, nread));
    goto out;
  }
  else if(ctx->pause_stream_id) {
    /* If a stream paused nghttp2_session_mem_recv previously, and has
       not processed all data, it still refers to the buffer in
       nghttp2_session.  If we call nghttp2_session_mem_recv(), we may
       overwrite that buffer.  To avoid that situation, just return
       here with CURLE_AGAIN.  This could be busy loop since data in
       socket is not read.  But it seems that usually streams are
       notified with its drain property, and socket is read again
       quickly. */
    if(stream->closed) {
      /* closed overrides paused */
      drained_transfer(cf, data);
      nread = 0;
      goto out;
    }
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] is paused, pause h2sid: %u",
                  stream->stream_id, ctx->pause_stream_id));
    *err = CURLE_AGAIN;
    nread = -1;
    goto out;
  }
  else {
    /* We have nothing buffered for `data` and no other stream paused
     * the processing of incoming data, we can therefore read new data
     * from the network.
     * If DATA is coming for this stream, we want to store it ad the
     * `buf` passed in right away - saving us a copy.
     */
    stream->mem = buf;
    stream->len = len;
    stream->memlen = 0;

    if(ctx->inbuflen > 0) {
      DEBUGF(LOG_CF(data, cf, "[h2sid=%u] %zd bytes in inbuf",
                    stream->stream_id, ctx->inbuflen - ctx->nread_inbuf));
      if(h2_process_pending_input(cf, data, err))
        return -1;
    }

    while(stream->memlen == 0 &&       /* have no data for this stream */
          !stream->closed &&           /* and it is not closed/reset */
          !ctx->pause_stream_id &&     /* we are not paused either */
          ctx->inbuflen == 0 &&       /* and out input buffer is empty */
          !conn_is_closed) {          /* and connection is not closed */
      /* Receive data from the "lower" filters */
      nread = Curl_conn_cf_recv(cf->next, data, ctx->inbuf, H2_BUFSIZE, err);
      if(nread < 0) {
        DEBUGASSERT(*err);
        if(*err == CURLE_AGAIN) {
          break;
        }
        failf(data, "Failed receiving HTTP2 data");
        conn_is_closed = TRUE;
      }
      else if(nread == 0) {
        DEBUGF(LOG_CF(data, cf, "[h2sid=%u] underlying connection is closed",
                      stream->stream_id));
        conn_is_closed = TRUE;
      }
      else {
        DEBUGF(LOG_CF(data, cf, "[h2sid=%u] read %zd from connection",
                      stream->stream_id, nread));
        ctx->inbuflen = nread;
        DEBUGASSERT(ctx->nread_inbuf == 0);
        if(h2_process_pending_input(cf, data, err))
          return -1;
      }
    }

  }

  if(stream->memlen) {
    ssize_t retlen = stream->memlen;

    /* TODO: all this buffer handling is very brittle */
    stream->len += stream->memlen;
    stream->memlen = 0;

    if(ctx->pause_stream_id == stream->stream_id) {
      /* data for this stream is returned now, but this stream caused a pause
         already so we need it called again asap */
      DEBUGF(LOG_CF(data, cf, "[h2sid=%u] Data returned for PAUSED stream",
                    stream->stream_id));
      drain_this(cf, data);
      Curl_expire(data, 0, EXPIRE_RUN_NOW);
    }
    else if(stream->closed) {
      if(stream->reset || stream->error) {
        nread = http2_handle_stream_close(cf, data, stream, err);
        goto out;
      }
      /* this stream is closed, trigger a another read ASAP to detect that */
      DEBUGF(LOG_CF(data, cf, "[h2sid=%u] is closed now, run again",
                    stream->stream_id));
      drain_this(cf, data);
      Curl_expire(data, 0, EXPIRE_RUN_NOW);
    }
    else {
      drained_transfer(cf, data);
    }

    *err = CURLE_OK;
    nread = retlen;
    goto out;
  }

  if(conn_is_closed && !stream->closed) {
    /* underlying connection is closed and we have nothing for the stream.
     * Treat this as a RST */
    stream->closed = stream->reset = TRUE;
      failf(data, "HTTP/2 stream %u was not closed cleanly before"
            " end of the underlying connection",
            stream->stream_id);
  }

  if(stream->closed) {
    nread = http2_handle_stream_close(cf, data, stream, err);
    goto out;
  }

  if(!data->state.drain && Curl_conn_cf_data_pending(cf->next, data)) {
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] pending data, set drain",
                  stream->stream_id));
    drain_this(cf, data);
  }
  *err = CURLE_AGAIN;
  nread = -1;
out:
  DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_recv -> %zd, %d",
                stream->stream_id, nread, *err));
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
  DEBUGF(LOG_CF(data, cf, "cf_send(len=%zu) start", len));

  if(stream->stream_id != -1) {
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
    stream->upload_mem = buf;
    stream->upload_len = len;
    rv = nghttp2_session_resume_data(ctx->h2, stream->stream_id);
    if(nghttp2_is_fatal(rv)) {
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
      goto out;
    }
    result = h2_session_send(cf, data);
    if(result) {
      *err = result;
      nwritten = -1;
      goto out;
    }

    nwritten = (ssize_t)len - (ssize_t)stream->upload_len;
    stream->upload_mem = NULL;
    stream->upload_len = 0;

    if(should_close_session(ctx)) {
      DEBUGF(LOG_CF(data, cf, "send: nothing to do in this session"));
      *err = CURLE_HTTP2;
      nwritten = -1;
      goto out;
    }

    if(stream->upload_left) {
      /* we are sure that we have more data to send here.  Calling the
         following API will make nghttp2_session_want_write() return
         nonzero if remote window allows it, which then libcurl checks
         socket is writable or not.  See http2_perform_getsock(). */
      nghttp2_session_resume_data(ctx->h2, stream->stream_id);
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
    DEBUGF(LOG_CF(data, cf, "[h2sid=%u] cf_send returns %zd ",
           stream->stream_id, nwritten));

    /* handled writing BODY for open stream. */
    goto out;
  }
  /* Stream has not been opened yet. `buf` is expected to contain
   * request headers. */
  /* TODO: this assumes that the `buf` and `len` we are called with
   * is *all* HEADERs and no body. We have no way to determine here
   * if that is indeed the case. */
  result = Curl_pseudo_headers(data, buf, len, NULL, &hreq);
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

    data_prd.read_callback = data_source_read_callback;
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

  infof(data, "Using Stream ID: %u (easy handle %p)",
        stream_id, (void *)data);
  stream->stream_id = stream_id;
  /* See TODO above. We assume that the whole buf was consumed by
   * generating the request headers. */
  nwritten = len;

  result = h2_session_send(cf, data);
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

  /* If whole HEADERS frame was sent off to the underlying socket, the nghttp2
     library calls data_source_read_callback. But only it found that no data
     available, so it deferred the DATA transmission. Which means that
     nghttp2_session_want_write() returns 0 on http2_perform_getsock(), which
     results that no writable socket check is performed. To workaround this,
     we issue nghttp2_session_resume_data() here to bring back DATA
     transmission from deferred state. */
  nghttp2_session_resume_data(ctx->h2, stream->stream_id);

out:
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

  if(!(k->keepon & KEEP_RECV_PAUSE))
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

  if(-1 == h2_process_pending_input(cf, data, &result)) {
    result = CURLE_HTTP2;
    goto out;
  }

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
    uint32_t window = !pause * HTTP2_HUGE_WINDOW_SIZE;
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
    result = h2_session_send(cf, data);
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
  case CF_CTRL_DATA_PAUSE: {
    result = http2_data_pause(cf, data, (arg1 != 0));
    break;
  }
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
  if(ctx && ctx->inbuflen > 0 && ctx->nread_inbuf > ctx->inbuflen)
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

  if(nread) {
    /* we are going to copy mem to httpc->inbuf.  This is required since
       mem is part of buffer pointed by stream->mem, and callbacks
       called by nghttp2_session_mem_recv() will write stream specific
       data into stream->mem, overwriting data already there. */
    if(H2_BUFSIZE < nread) {
      failf(data, "connection buffer size is too small to store data "
            "following HTTP Upgrade response header: buflen=%d, datalen=%zu",
            H2_BUFSIZE, nread);
      return CURLE_HTTP2;
    }

    infof(data, "Copying HTTP/2 data in stream buffer to connection buffer"
          " after upgrade: len=%zu", nread);
    DEBUGASSERT(ctx->nread_inbuf == 0);
    memcpy(ctx->inbuf, mem, nread);
    ctx->inbuflen = nread;
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
