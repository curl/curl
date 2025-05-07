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
#include <stdint.h>
#include <nghttp2/nghttp2.h>
#include "urldata.h"
#include "bufq.h"
#include "uint-hash.h"
#include "http1.h"
#include "http2.h"
#include "http.h"
#include "sendf.h"
#include "select.h"
#include "curlx/base64.h"
#include "strcase.h"
#include "multiif.h"
#include "url.h"
#include "urlapi-int.h"
#include "cfilters.h"
#include "connect.h"
#include "rand.h"
#include "strdup.h"
#include "curlx/strparse.h"
#include "transfer.h"
#include "curlx/dynbuf.h"
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
/* connection window size */
#define H2_CONN_WINDOW_SIZE     (10 * 1024 * 1024)
/* on receiving from TLS, we prep for holding a full stream window */
#define H2_NW_RECV_CHUNKS       (H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE)
/* on send into TLS, we just want to accumulate small frames */
#define H2_NW_SEND_CHUNKS       1
/* this is how much we want "in flight" for a stream, unthrottled  */
#define H2_STREAM_WINDOW_SIZE_MAX   (10 * 1024 * 1024)
/* this is how much we want "in flight" for a stream, initially, IFF
 * nghttp2 allows us to tweak the local window size. */
#if NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE
#define H2_STREAM_WINDOW_SIZE_INITIAL  (64 * 1024)
#else
#define H2_STREAM_WINDOW_SIZE_INITIAL H2_STREAM_WINDOW_SIZE_MAX
#endif
/* keep smaller stream upload buffer (default h2 window size) to have
 * our progress bars and "upload done" reporting closer to reality */
#define H2_STREAM_SEND_CHUNKS   ((64 * 1024) / H2_CHUNK_SIZE)
/* spare chunks we keep for a full window */
#define H2_STREAM_POOL_SPARES   (H2_CONN_WINDOW_SIZE / H2_CHUNK_SIZE)

/* We need to accommodate the max number of streams with their window sizes on
 * the overall connection. Streams might become PAUSED which will block their
 * received QUOTA in the connection window. If we run out of space, the server
 * is blocked from sending us any data. See #10988 for an issue with this. */
#define HTTP2_HUGE_WINDOW_SIZE (100 * H2_STREAM_WINDOW_SIZE_MAX)

#define H2_SETTINGS_IV_LEN  3
#define H2_BINSETTINGS_LEN 80

static size_t populate_settings(nghttp2_settings_entry *iv,
                                struct Curl_easy *data)
{
  iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
  iv[0].value = Curl_multi_max_concurrent_streams(data->multi);

  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = H2_STREAM_WINDOW_SIZE_INITIAL;

  iv[2].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
  iv[2].value = data->multi->push_cb != NULL;

  return 3;
}

static ssize_t populate_binsettings(uint8_t *binsettings,
                                    struct Curl_easy *data)
{
  nghttp2_settings_entry iv[H2_SETTINGS_IV_LEN];
  size_t ivlen;

  ivlen = populate_settings(iv, data);
  /* this returns number of bytes it wrote or a negative number on error. */
  return nghttp2_pack_settings_payload(binsettings, H2_BINSETTINGS_LEN,
                                       iv, ivlen);
}

struct cf_h2_ctx {
  nghttp2_session *h2;
  /* The easy handle used in the current filter call, cleared at return */
  struct cf_call_data call_data;

  struct bufq inbufq;           /* network input */
  struct bufq outbufq;          /* network output */
  struct bufc_pool stream_bufcp; /* spares for stream buffers */
  struct dynbuf scratch;        /* scratch buffer for temp use */

  struct uint_hash streams; /* hash of `data->mid` to `h2_stream_ctx` */
  size_t drain_total; /* sum of all stream's UrlState drain */
  uint32_t max_concurrent_streams;
  uint32_t goaway_error;        /* goaway error code from server */
  int32_t remote_max_sid;       /* max id processed by server */
  int32_t local_max_sid;        /* max id processed by us */
#ifdef DEBUGBUILD
  int32_t stream_win_max;       /* max h2 stream window size */
#endif
  BIT(initialized);
  BIT(via_h1_upgrade);
  BIT(conn_closed);
  BIT(rcvd_goaway);
  BIT(sent_goaway);
  BIT(enable_push);
  BIT(nw_out_blocked);
};

/* How to access `call_data` from a cf_h2 filter */
#undef CF_CTX_CALL_DATA
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_h2_ctx *)(cf)->ctx)->call_data

static void h2_stream_hash_free(unsigned int id, void *stream);

static void cf_h2_ctx_init(struct cf_h2_ctx *ctx, bool via_h1_upgrade)
{
  Curl_bufcp_init(&ctx->stream_bufcp, H2_CHUNK_SIZE, H2_STREAM_POOL_SPARES);
  Curl_bufq_initp(&ctx->inbufq, &ctx->stream_bufcp, H2_NW_RECV_CHUNKS, 0);
  Curl_bufq_initp(&ctx->outbufq, &ctx->stream_bufcp, H2_NW_SEND_CHUNKS, 0);
  curlx_dyn_init(&ctx->scratch, CURL_MAX_HTTP_HEADER);
  Curl_uint_hash_init(&ctx->streams, 63, h2_stream_hash_free);
  ctx->remote_max_sid = 2147483647;
  ctx->via_h1_upgrade = via_h1_upgrade;
#ifdef DEBUGBUILD
  {
    const char *p = getenv("CURL_H2_STREAM_WIN_MAX");

    ctx->stream_win_max = H2_STREAM_WINDOW_SIZE_MAX;
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, INT_MAX))
        ctx->stream_win_max = (int32_t)l;
    }
  }
#endif
  ctx->initialized = TRUE;
}

static void cf_h2_ctx_free(struct cf_h2_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_bufq_free(&ctx->inbufq);
    Curl_bufq_free(&ctx->outbufq);
    Curl_bufcp_free(&ctx->stream_bufcp);
    curlx_dyn_free(&ctx->scratch);
    Curl_uint_hash_destroy(&ctx->streams);
    memset(ctx, 0, sizeof(*ctx));
  }
  free(ctx);
}

static void cf_h2_ctx_close(struct cf_h2_ctx *ctx)
{
  if(ctx->h2) {
    nghttp2_session_del(ctx->h2);
  }
}

static CURLcode h2_progress_egress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data);

/**
 * All about the H2 internals of a stream
 */
struct h2_stream_ctx {
  struct bufq sendbuf; /* request buffer */
  struct h1_req_parser h1; /* parsing the request */
  struct dynhds resp_trailers; /* response trailer fields */
  size_t resp_hds_len; /* amount of response header bytes in recvbuf */
  curl_off_t nrcvd_data;  /* number of DATA bytes received */

  char **push_headers;       /* allocated array */
  size_t push_headers_used;  /* number of entries filled in */
  size_t push_headers_alloc; /* number of entries allocated */

  int status_code; /* HTTP response status code */
  uint32_t error; /* stream error code */
  CURLcode xfer_result; /* Result of writing out response */
  int32_t local_window_size; /* the local recv window size */
  int32_t id; /* HTTP/2 protocol identifier for stream */
  BIT(resp_hds_complete); /* we have a complete, final response */
  BIT(closed); /* TRUE on stream close */
  BIT(reset);  /* TRUE on stream reset */
  BIT(close_handled); /* TRUE if stream closure is handled by libcurl */
  BIT(bodystarted);
  BIT(body_eos);    /* the complete body has been added to `sendbuf` and
                     * is being/has been processed from there. */
  BIT(write_paused);  /* stream write is paused */
};

#define H2_STREAM_CTX(ctx,data)                                         \
  ((struct h2_stream_ctx *)(                                            \
    data? Curl_uint_hash_get(&(ctx)->streams, (data)->mid) : NULL))

static struct h2_stream_ctx *h2_stream_ctx_create(struct cf_h2_ctx *ctx)
{
  struct h2_stream_ctx *stream;

  (void)ctx;
  stream = calloc(1, sizeof(*stream));
  if(!stream)
    return NULL;

  stream->id = -1;
  Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                  H2_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);
  Curl_dynhds_init(&stream->resp_trailers, 0, DYN_HTTP_REQUEST);
  stream->bodystarted = FALSE;
  stream->status_code = -1;
  stream->closed = FALSE;
  stream->close_handled = FALSE;
  stream->error = NGHTTP2_NO_ERROR;
  stream->local_window_size = H2_STREAM_WINDOW_SIZE_INITIAL;
  stream->nrcvd_data = 0;
  return stream;
}

static void free_push_headers(struct h2_stream_ctx *stream)
{
  size_t i;
  for(i = 0; i < stream->push_headers_used; i++)
    free(stream->push_headers[i]);
  Curl_safefree(stream->push_headers);
  stream->push_headers_used = 0;
}

static void h2_stream_ctx_free(struct h2_stream_ctx *stream)
{
  Curl_bufq_free(&stream->sendbuf);
  Curl_h1_req_parse_free(&stream->h1);
  Curl_dynhds_free(&stream->resp_trailers);
  free_push_headers(stream);
  free(stream);
}

static void h2_stream_hash_free(unsigned int id, void *stream)
{
  (void)id;
  DEBUGASSERT(stream);
  h2_stream_ctx_free((struct h2_stream_ctx *)stream);
}

#ifdef NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE
static int32_t cf_h2_get_desired_local_win(struct Curl_cfilter *cf,
                                           struct Curl_easy *data)
{
  (void)cf;
  if(data->set.max_recv_speed && data->set.max_recv_speed < INT32_MAX) {
    /* The transfer should only receive `max_recv_speed` bytes per second.
     * We restrict the stream's local window size, so that the server cannot
     * send us "too much" at a time.
     * This gets less precise the higher the latency. */
    return (int32_t)data->set.max_recv_speed;
  }
#ifdef DEBUGBUILD
  else {
    struct cf_h2_ctx *ctx = cf->ctx;
    CURL_TRC_CF(data, cf, "stream_win_max=%d", ctx->stream_win_max);
    return ctx->stream_win_max;
  }
#else
  return H2_STREAM_WINDOW_SIZE_MAX;
#endif
}

static CURLcode cf_h2_update_local_win(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       struct h2_stream_ctx *stream)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  int32_t dwsize;
  int rv;

  dwsize = (stream->write_paused || stream->xfer_result) ?
           0 : cf_h2_get_desired_local_win(cf, data);
  if(dwsize != stream->local_window_size) {
    int32_t wsize = nghttp2_session_get_stream_effective_local_window_size(
                      ctx->h2, stream->id);
    if(dwsize > wsize) {
      rv = nghttp2_session_set_local_window_size(ctx->h2, NGHTTP2_FLAG_NONE,
                                                 stream->id, dwsize);
      if(rv) {
        failf(data, "[%d] nghttp2 set_local_window_size(%d) failed: "
              "%s(%d)", stream->id, dwsize, nghttp2_strerror(rv), rv);
        return CURLE_HTTP2;
      }
      rv = nghttp2_submit_window_update(ctx->h2, NGHTTP2_FLAG_NONE,
                                        stream->id, dwsize - wsize);
      if(rv) {
        failf(data, "[%d] nghttp2_submit_window_update() failed: "
              "%s(%d)", stream->id, nghttp2_strerror(rv), rv);
        return CURLE_HTTP2;
      }
      stream->local_window_size = dwsize;
      CURL_TRC_CF(data, cf, "[%d] local window update by %d",
                  stream->id, dwsize - wsize);
    }
    else {
      rv = nghttp2_session_set_local_window_size(ctx->h2, NGHTTP2_FLAG_NONE,
                                                 stream->id, dwsize);
      if(rv) {
        failf(data, "[%d] nghttp2_session_set_local_window_size() failed: "
              "%s(%d)", stream->id, nghttp2_strerror(rv), rv);
        return CURLE_HTTP2;
      }
      stream->local_window_size = dwsize;
      CURL_TRC_CF(data, cf, "[%d] local window size now %d",
                  stream->id, dwsize);
    }
  }
  return CURLE_OK;
}

#else /* NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE */

static CURLcode cf_h2_update_local_win(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       struct h2_stream_ctx *stream)
{
  (void)cf;
  (void)data;
  (void)stream;
  return CURLE_OK;
}
#endif /* !NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE */

/*
 * Mark this transfer to get "drained".
 */
static void drain_stream(struct Curl_cfilter *cf,
                         struct Curl_easy *data,
                         struct h2_stream_ctx *stream)
{
  unsigned char bits;

  (void)cf;
  bits = CURL_CSELECT_IN;
  if(!stream->closed &&
     (!stream->body_eos || !Curl_bufq_is_empty(&stream->sendbuf)))
    bits |= CURL_CSELECT_OUT;
  if(stream->closed || (data->state.select_bits != bits)) {
    CURL_TRC_CF(data, cf, "[%d] DRAIN select_bits=%x",
                stream->id, bits);
    data->state.select_bits = bits;
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
  }
}

static CURLcode http2_data_setup(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct h2_stream_ctx **pstream)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream;

  (void)cf;
  DEBUGASSERT(data);
  stream = H2_STREAM_CTX(ctx, data);
  if(stream) {
    *pstream = stream;
    return CURLE_OK;
  }

  stream = h2_stream_ctx_create(ctx);
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  if(!Curl_uint_hash_set(&ctx->streams, data->mid, stream)) {
    h2_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  *pstream = stream;
  return CURLE_OK;
}

static void http2_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);

  DEBUGASSERT(ctx);
  if(!stream || !ctx->initialized)
    return;

  if(ctx->h2) {
    bool flush_egress = FALSE;
    /* returns error if stream not known, which is fine here */
    (void)nghttp2_session_set_stream_user_data(ctx->h2, stream->id, NULL);

    if(!stream->closed && stream->id > 0) {
      /* RST_STREAM */
      CURL_TRC_CF(data, cf, "[%d] premature DATA_DONE, RST stream",
                  stream->id);
      stream->closed = TRUE;
      stream->reset = TRUE;
      nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                                stream->id, NGHTTP2_STREAM_CLOSED);
      flush_egress = TRUE;
    }

    if(flush_egress)
      nghttp2_session_send(ctx->h2);
  }

  Curl_uint_hash_remove(&ctx->streams, data->mid);
}

static int h2_client_new(struct Curl_cfilter *cf,
                         nghttp2_session_callbacks *cbs)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  nghttp2_option *o;
  nghttp2_mem mem = {NULL, Curl_nghttp2_malloc, Curl_nghttp2_free,
    Curl_nghttp2_calloc, Curl_nghttp2_realloc};

  int rc = nghttp2_option_new(&o);
  if(rc)
    return rc;
  /* We handle window updates ourself to enforce buffer limits */
  nghttp2_option_set_no_auto_window_update(o, 1);
#if NGHTTP2_VERSION_NUM >= 0x013200
  /* with 1.50.0 */
  /* turn off RFC 9113 leading and trailing white spaces validation against
     HTTP field value. */
  nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(o, 1);
#endif
  rc = nghttp2_session_client_new3(&ctx->h2, cbs, cf, o, &mem);
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

  if(data) {
    ssize_t nwritten = Curl_conn_cf_send(cf->next, data, (const char *)buf,
                                         buflen, FALSE, err);
    if(nwritten > 0)
      CURL_TRC_CF(data, cf, "[0] egress: wrote %zd bytes", nwritten);
    return nwritten;
  }
  return 0;
}

static ssize_t send_callback(nghttp2_session *h2,
                             const uint8_t *mem, size_t length, int flags,
                             void *userp);
static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp);
static int cf_h2_on_invalid_frame_recv(nghttp2_session *session,
                                       const nghttp2_frame *frame,
                                       int lib_error_code,
                                       void *user_data);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
static int on_frame_send(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp);
#endif
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
#if !defined(CURL_DISABLE_VERBOSE_STRINGS)
static int error_callback(nghttp2_session *session, const char *msg,
                          size_t len, void *userp);
#endif
static CURLcode cf_h2_ctx_open(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream;
  CURLcode result = CURLE_OUT_OF_MEMORY;
  int rc;
  nghttp2_session_callbacks *cbs = NULL;

  DEBUGASSERT(!ctx->h2);
  DEBUGASSERT(ctx->initialized);

  rc = nghttp2_session_callbacks_new(&cbs);
  if(rc) {
    failf(data, "Couldn't initialize nghttp2 callbacks");
    goto out;
  }

  nghttp2_session_callbacks_set_send_callback(cbs, send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv);
  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(cbs,
    cf_h2_on_invalid_frame_recv);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  nghttp2_session_callbacks_set_on_frame_send_callback(cbs, on_frame_send);
#endif
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    cbs, on_data_chunk_recv);
  nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close);
  nghttp2_session_callbacks_set_on_begin_headers_callback(
    cbs, on_begin_headers);
  nghttp2_session_callbacks_set_on_header_callback(cbs, on_header);
#if !defined(CURL_DISABLE_VERBOSE_STRINGS)
  nghttp2_session_callbacks_set_error_callback(cbs, error_callback);
#endif

  /* The nghttp2 session is not yet setup, do it */
  rc = h2_client_new(cf, cbs);
  if(rc) {
    failf(data, "Couldn't initialize nghttp2");
    goto out;
  }
  ctx->max_concurrent_streams = DEFAULT_MAX_CONCURRENT_STREAMS;

  if(ctx->via_h1_upgrade) {
    /* HTTP/1.1 Upgrade issued. H2 Settings have already been submitted
     * in the H1 request and we upgrade from there. This stream
     * is opened implicitly as #1. */
    uint8_t binsettings[H2_BINSETTINGS_LEN];
    ssize_t binlen; /* length of the binsettings data */

    binlen = populate_binsettings(binsettings, data);
    if(binlen <= 0) {
      failf(data, "nghttp2 unexpectedly failed on pack_settings_payload");
      result = CURLE_FAILED_INIT;
      goto out;
    }

    result = http2_data_setup(cf, data, &stream);
    if(result)
      goto out;
    DEBUGASSERT(stream);
    stream->id = 1;
    /* queue SETTINGS frame (again) */
    rc = nghttp2_session_upgrade2(ctx->h2, binsettings, (size_t)binlen,
                                  data->state.httpreq == HTTPREQ_HEAD,
                                  NULL);
    if(rc) {
      failf(data, "nghttp2_session_upgrade2() failed: %s(%d)",
            nghttp2_strerror(rc), rc);
      result = CURLE_HTTP2;
      goto out;
    }

    rc = nghttp2_session_set_stream_user_data(ctx->h2, stream->id,
                                              data);
    if(rc) {
      infof(data, "http/2: failed to set user_data for stream %u",
            stream->id);
      DEBUGASSERT(0);
    }
    CURL_TRC_CF(data, cf, "created session via Upgrade");
  }
  else {
    nghttp2_settings_entry iv[H2_SETTINGS_IV_LEN];
    size_t ivlen;

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
  CURL_TRC_CF(data, cf, "[0] created h2 session%s",
              ctx->via_h1_upgrade ? " (via h1 upgrade)" : "");

out:
  if(cbs)
    nghttp2_session_callbacks_del(cbs);
  return result;
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
    if(rv < 0) {
      failf(data, "nghttp2 recv error %zd: %s", rv, nghttp2_strerror((int)rv));
      *err = CURLE_HTTP2;
      return -1;
    }
    Curl_bufq_skip(&ctx->inbufq, (size_t)rv);
    if(Curl_bufq_is_empty(&ctx->inbufq)) {
      break;
    }
    else {
      CURL_TRC_CF(data, cf, "process_pending_input: %zu bytes left "
                  "in connection buffer", Curl_bufq_len(&ctx->inbufq));
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
    /* This happens before we have sent off a request and the connection is
       not in use by any other transfer, there should not be any data here,
       only "protocol frames" */
    CURLcode result;
    ssize_t nread = -1;

    *input_pending = FALSE;
    nread = Curl_bufq_slurp(&ctx->inbufq, nw_in_reader, cf, &result);
    if(nread != -1) {
      CURL_TRC_CF(data, cf, "%zd bytes stray data read before trying "
                  "h2 connection", nread);
      if(h2_process_pending_input(cf, data, &result) < 0)
        /* immediate error, considered dead */
        alive = FALSE;
      else {
        alive = !should_close_session(ctx);
      }
    }
    else if(result != CURLE_AGAIN) {
      /* the read failed so let's say this is dead anyway */
      alive = FALSE;
    }
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

  nwritten = Curl_bufq_pass(&ctx->outbufq, nw_out_writer, cf, &result);
  if(nwritten < 0) {
    if(result == CURLE_AGAIN) {
      CURL_TRC_CF(data, cf, "flush nw send buffer(%zu) -> EAGAIN",
                  Curl_bufq_len(&ctx->outbufq));
      ctx->nw_out_blocked = 1;
    }
    return result;
  }
  return Curl_bufq_is_empty(&ctx->outbufq) ? CURLE_OK : CURLE_AGAIN;
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

  if(!cf->connected)
    nwritten = Curl_bufq_write(&ctx->outbufq, buf, blen, &result);
  else
    nwritten = Curl_bufq_write_pass(&ctx->outbufq, buf, blen,
                                    nw_out_writer, cf, &result);
  if(nwritten < 0) {
    if(result == CURLE_AGAIN) {
      ctx->nw_out_blocked = 1;
      return NGHTTP2_ERR_WOULDBLOCK;
    }
    failf(data, "Failed sending HTTP2 data");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if(!nwritten) {
    ctx->nw_out_blocked = 1;
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  return nwritten;
}


/* We pass a pointer to this struct in the push callback, but the contents of
   the struct are hidden from the user. */
struct curl_pushheaders {
  struct Curl_easy *data;
  struct h2_stream_ctx *stream;
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
    if(h->stream && num < h->stream->push_headers_used)
      return h->stream->push_headers[num];
  }
  return NULL;
}

/*
 * push header access function. Only to be used from within the push callback
 */
char *curl_pushheader_byname(struct curl_pushheaders *h, const char *header)
{
  struct h2_stream_ctx *stream;
  size_t len;
  size_t i;
  /* Verify that we got a good easy handle in the push header struct,
     mostly to detect rubbish input fast(er). Also empty header name
     is just a rubbish too. We have to allow ":" at the beginning of
     the header, but header == ":" must be rejected. If we have ':' in
     the middle of header, it could be matched in middle of the value,
     this is because we do prefix match.*/
  if(!h || !GOOD_EASY_HANDLE(h->data) || !header || !header[0] ||
     !strcmp(header, ":") || strchr(header + 1, ':'))
    return NULL;

  stream = h->stream;
  if(!stream)
    return NULL;

  len = strlen(header);
  for(i = 0; i < stream->push_headers_used; i++) {
    if(!strncmp(header, stream->push_headers[i], len)) {
      /* sub-match, make sure that it is followed by a colon */
      if(stream->push_headers[i][len] != ':')
        continue;
      return &stream->push_headers[i][len + 1];
    }
  }
  return NULL;
}

static struct Curl_easy *h2_duphandle(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct Curl_easy *second = curl_easy_duphandle(data);
  if(second) {
    struct h2_stream_ctx *second_stream;
    http2_data_setup(cf, second, &second_stream);
    second->state.priority.weight = data->state.priority.weight;
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

  v = curl_pushheader_byname(hp, HTTP_PSEUDO_SCHEME);
  if(v) {
    uc = curl_url_set(u, CURLUPART_SCHEME, v, 0);
    if(uc) {
      rc = 1;
      goto fail;
    }
  }

  v = curl_pushheader_byname(hp, HTTP_PSEUDO_AUTHORITY);
  if(v) {
    uc = Curl_url_set_authority(u, v);
    if(uc) {
      rc = 2;
      goto fail;
    }
  }

  v = curl_pushheader_byname(hp, HTTP_PSEUDO_PATH);
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

static void discard_newhandle(struct Curl_cfilter *cf,
                              struct Curl_easy *newhandle)
{
  http2_data_done(cf, newhandle);
  (void)Curl_close(&newhandle);
}

static int push_promise(struct Curl_cfilter *cf,
                        struct Curl_easy *data,
                        const nghttp2_push_promise *frame)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  int rv; /* one of the CURL_PUSH_* defines */

  CURL_TRC_CF(data, cf, "[%d] PUSH_PROMISE received",
              frame->promised_stream_id);
  if(data->multi->push_cb) {
    struct h2_stream_ctx *stream;
    struct h2_stream_ctx *newstream;
    struct curl_pushheaders heads;
    CURLMcode rc;
    CURLcode result;
    /* clone the parent */
    struct Curl_easy *newhandle = h2_duphandle(cf, data);
    if(!newhandle) {
      infof(data, "failed to duplicate handle");
      rv = CURL_PUSH_DENY; /* FAIL HARD */
      goto fail;
    }

    stream = H2_STREAM_CTX(ctx, data);
    if(!stream) {
      failf(data, "Internal NULL stream");
      discard_newhandle(cf, newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    heads.data = data;
    heads.stream = stream;
    heads.frame = frame;

    rv = set_transfer_url(newhandle, &heads);
    if(rv) {
      CURL_TRC_CF(data, cf, "[%d] PUSH_PROMISE, failed to set url -> %d",
                  frame->promised_stream_id, rv);
      discard_newhandle(cf, newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    Curl_set_in_callback(data, TRUE);
    rv = data->multi->push_cb(data, newhandle,
                              stream->push_headers_used, &heads,
                              data->multi->push_userp);
    Curl_set_in_callback(data, FALSE);

    /* free the headers again */
    free_push_headers(stream);

    if(rv) {
      DEBUGASSERT((rv > CURL_PUSH_OK) && (rv <= CURL_PUSH_ERROROUT));
      /* denied, kill off the new handle again */
      CURL_TRC_CF(data, cf, "[%d] PUSH_PROMISE, denied by application -> %d",
                  frame->promised_stream_id, rv);
      discard_newhandle(cf, newhandle);
      goto fail;
    }

    /* approved, add to the multi handle for processing. This
     * assigns newhandle->mid. For the new `mid` we assign the
     * h2_stream instance and remember the stream_id already known. */
    rc = Curl_multi_add_perform(data->multi, newhandle, cf->conn);
    if(rc) {
      infof(data, "failed to add handle to multi");
      discard_newhandle(cf, newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    result = http2_data_setup(cf, newhandle, &newstream);
    if(result) {
      failf(data, "error setting up stream: %d", result);
      discard_newhandle(cf, newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    DEBUGASSERT(newstream);
    newstream->id = frame->promised_stream_id;
    newhandle->req.maxdownload = -1;
    newhandle->req.size = -1;

    CURL_TRC_CF(data, cf, "promise easy handle added to multi, mid=%u",
                newhandle->mid);
    rv = nghttp2_session_set_stream_user_data(ctx->h2,
                                              newstream->id,
                                              newhandle);
    if(rv) {
      infof(data, "failed to set user_data for stream %u",
            newstream->id);
      DEBUGASSERT(0);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    /* success, remember max stream id processed */
    if(newstream->id > ctx->local_max_sid)
      ctx->local_max_sid = newstream->id;
  }
  else {
    CURL_TRC_CF(data, cf, "Got PUSH_PROMISE, ignore it");
    rv = CURL_PUSH_DENY;
  }
fail:
  return rv;
}

static void h2_xfer_write_resp_hd(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h2_stream_ctx *stream,
                                  const char *buf, size_t blen, bool eos)
{

  /* If we already encountered an error, skip further writes */
  if(!stream->xfer_result) {
    stream->xfer_result = Curl_xfer_write_resp_hd(data, buf, blen, eos);
    if(!stream->xfer_result && !eos)
      stream->xfer_result = cf_h2_update_local_win(cf, data, stream);
    if(stream->xfer_result)
      CURL_TRC_CF(data, cf, "[%d] error %d writing %zu bytes of headers",
                  stream->id, stream->xfer_result, blen);
  }
}

static void h2_xfer_write_resp(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h2_stream_ctx *stream,
                               const char *buf, size_t blen, bool eos)
{

  /* If we already encountered an error, skip further writes */
  if(!stream->xfer_result)
    stream->xfer_result = Curl_xfer_write_resp(data, buf, blen, eos);
  /* If the transfer write is errored, we do not want any more data */
  if(stream->xfer_result) {
    struct cf_h2_ctx *ctx = cf->ctx;
    CURL_TRC_CF(data, cf, "[%d] error %d writing %zu bytes of data, "
                "RST-ing stream",
                stream->id, stream->xfer_result, blen);
    nghttp2_submit_rst_stream(ctx->h2, 0, stream->id,
                              (uint32_t)NGHTTP2_ERR_CALLBACK_FAILURE);
  }
  else if(!stream->write_paused && Curl_xfer_write_is_paused(data)) {
    CURL_TRC_CF(data, cf, "[%d] stream output paused", stream->id);
    stream->write_paused = TRUE;
  }
  else if(stream->write_paused && !Curl_xfer_write_is_paused(data)) {
    CURL_TRC_CF(data, cf, "[%d] stream output unpaused", stream->id);
    stream->write_paused = FALSE;
  }

  if(!stream->xfer_result && !eos)
    stream->xfer_result = cf_h2_update_local_win(cf, data, stream);
}

static CURLcode on_stream_frame(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const nghttp2_frame *frame)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
  int32_t stream_id = frame->hd.stream_id;
  int rv;

  if(!stream) {
    CURL_TRC_CF(data, cf, "[%d] No stream_ctx set", stream_id);
    return CURLE_FAILED_INIT;
  }

  switch(frame->hd.type) {
  case NGHTTP2_DATA:
    CURL_TRC_CF(data, cf, "[%d] DATA, window=%d/%d",
                stream_id,
                nghttp2_session_get_stream_effective_recv_data_length(
                  ctx->h2, stream->id),
                nghttp2_session_get_stream_effective_local_window_size(
                  ctx->h2, stream->id));
    /* If !body started on this stream, then receiving DATA is illegal. */
    if(!stream->bodystarted) {
      rv = nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                                     stream_id, NGHTTP2_PROTOCOL_ERROR);

      if(nghttp2_is_fatal(rv)) {
        return CURLE_RECV_ERROR;
      }
    }
    break;
  case NGHTTP2_HEADERS:
    if(stream->bodystarted) {
      /* Only valid HEADERS after body started is trailer HEADERS. We
         buffer them in on_header callback. */
      break;
    }

    /* nghttp2 guarantees that :status is received, and we store it to
       stream->status_code. Fuzzing has proven this can still be reached
       without status code having been set. */
    if(stream->status_code == -1)
      return CURLE_RECV_ERROR;

    /* Only final status code signals the end of header */
    if(stream->status_code / 100 != 1)
      stream->bodystarted = TRUE;
    else
      stream->status_code = -1;

    h2_xfer_write_resp_hd(cf, data, stream, STRCONST("\r\n"), stream->closed);

    if(stream->status_code / 100 != 1) {
      stream->resp_hds_complete = TRUE;
    }
    drain_stream(cf, data, stream);
    break;
  case NGHTTP2_PUSH_PROMISE:
    rv = push_promise(cf, data, &frame->push_promise);
    if(rv) { /* deny! */
      DEBUGASSERT((rv > CURL_PUSH_OK) && (rv <= CURL_PUSH_ERROROUT));
      rv = nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                                     frame->push_promise.promised_stream_id,
                                     NGHTTP2_CANCEL);
      if(nghttp2_is_fatal(rv))
        return CURLE_SEND_ERROR;
      else if(rv == CURL_PUSH_ERROROUT) {
        CURL_TRC_CF(data, cf, "[%d] fail in PUSH_PROMISE received",
                    stream_id);
        return CURLE_RECV_ERROR;
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    stream->closed = TRUE;
    if(frame->rst_stream.error_code) {
      stream->reset = TRUE;
    }
    drain_stream(cf, data, stream);
    break;
  case NGHTTP2_WINDOW_UPDATE:
    if(CURL_WANT_SEND(data) && Curl_bufq_is_empty(&stream->sendbuf)) {
      /* need more data, force processing of transfer */
      drain_stream(cf, data, stream);
    }
    else if(!Curl_bufq_is_empty(&stream->sendbuf)) {
      /* resume the potentially suspended stream */
      rv = nghttp2_session_resume_data(ctx->h2, stream->id);
      if(nghttp2_is_fatal(rv))
        return CURLE_SEND_ERROR;
    }
    break;
  default:
    break;
  }

  if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    if(!stream->closed && !stream->body_eos &&
       ((stream->status_code >= 400) || (stream->status_code < 200))) {
      /* The server did not give us a positive response and we are not
       * done uploading the request body. We need to stop doing that and
       * also inform the server that we aborted our side. */
      CURL_TRC_CF(data, cf, "[%d] EOS frame with unfinished upload and "
                  "HTTP status %d, abort upload by RST",
                  stream_id, stream->status_code);
      nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                                stream->id, NGHTTP2_STREAM_CLOSED);
      stream->closed = TRUE;
    }
    drain_stream(cf, data, stream);
  }
  return CURLE_OK;
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static int fr_print(const nghttp2_frame *frame, char *buffer, size_t blen)
{
  switch(frame->hd.type) {
    case NGHTTP2_DATA: {
      return msnprintf(buffer, blen,
                       "FRAME[DATA, len=%d, eos=%d, padlen=%d]",
                       (int)frame->hd.length,
                       !!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM),
                       (int)frame->data.padlen);
    }
    case NGHTTP2_HEADERS: {
      return msnprintf(buffer, blen,
                       "FRAME[HEADERS, len=%d, hend=%d, eos=%d]",
                       (int)frame->hd.length,
                       !!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS),
                       !!(frame->hd.flags & NGHTTP2_FLAG_END_STREAM));
    }
    case NGHTTP2_PRIORITY: {
      return msnprintf(buffer, blen,
                       "FRAME[PRIORITY, len=%d, flags=%d]",
                       (int)frame->hd.length, frame->hd.flags);
    }
    case NGHTTP2_RST_STREAM: {
      return msnprintf(buffer, blen,
                       "FRAME[RST_STREAM, len=%d, flags=%d, error=%u]",
                       (int)frame->hd.length, frame->hd.flags,
                       frame->rst_stream.error_code);
    }
    case NGHTTP2_SETTINGS: {
      if(frame->hd.flags & NGHTTP2_FLAG_ACK) {
        return msnprintf(buffer, blen, "FRAME[SETTINGS, ack=1]");
      }
      return msnprintf(buffer, blen,
                       "FRAME[SETTINGS, len=%d]", (int)frame->hd.length);
    }
    case NGHTTP2_PUSH_PROMISE: {
      return msnprintf(buffer, blen,
                       "FRAME[PUSH_PROMISE, len=%d, hend=%d]",
                       (int)frame->hd.length,
                       !!(frame->hd.flags & NGHTTP2_FLAG_END_HEADERS));
    }
    case NGHTTP2_PING: {
      return msnprintf(buffer, blen,
                       "FRAME[PING, len=%d, ack=%d]",
                       (int)frame->hd.length,
                       frame->hd.flags&NGHTTP2_FLAG_ACK);
    }
    case NGHTTP2_GOAWAY: {
      char scratch[128];
      size_t s_len = CURL_ARRAYSIZE(scratch);
      size_t len = (frame->goaway.opaque_data_len < s_len) ?
        frame->goaway.opaque_data_len : s_len-1;
      if(len)
        memcpy(scratch, frame->goaway.opaque_data, len);
      scratch[len] = '\0';
      return msnprintf(buffer, blen, "FRAME[GOAWAY, error=%d, reason='%s', "
                       "last_stream=%d]", frame->goaway.error_code,
                       scratch, frame->goaway.last_stream_id);
    }
    case NGHTTP2_WINDOW_UPDATE: {
      return msnprintf(buffer, blen,
                       "FRAME[WINDOW_UPDATE, incr=%d]",
                       frame->window_update.window_size_increment);
    }
    default:
      return msnprintf(buffer, blen, "FRAME[%d, len=%d, flags=%d]",
                       frame->hd.type, (int)frame->hd.length,
                       frame->hd.flags);
  }
}

static int on_frame_send(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  (void)session;
  DEBUGASSERT(data);
  if(data && Curl_trc_cf_is_verbose(cf, data)) {
    char buffer[256];
    int len;
    len = fr_print(frame, buffer, sizeof(buffer)-1);
    buffer[len] = 0;
    CURL_TRC_CF(data, cf, "[%d] -> %s", frame->hd.stream_id, buffer);
  }
  if((frame->hd.type == NGHTTP2_GOAWAY) && !ctx->sent_goaway) {
    /* A GOAWAY not initiated by us, but by nghttp2 itself on detecting
     * a protocol error on the connection */
    failf(data, "nghttp2 shuts down connection with error %d: %s",
          frame->goaway.error_code,
          nghttp2_http2_strerror(frame->goaway.error_code));
  }
  return 0;
}
#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf), *data_s;
  int32_t stream_id = frame->hd.stream_id;

  DEBUGASSERT(data);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(Curl_trc_cf_is_verbose(cf, data)) {
    char buffer[256];
    int len;
    len = fr_print(frame, buffer, sizeof(buffer)-1);
    buffer[len] = 0;
    CURL_TRC_CF(data, cf, "[%d] <- %s",frame->hd.stream_id, buffer);
  }
#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

  if(!stream_id) {
    /* stream ID zero is for connection-oriented stuff */
    DEBUGASSERT(data);
    switch(frame->hd.type) {
    case NGHTTP2_SETTINGS: {
      if(!(frame->hd.flags & NGHTTP2_FLAG_ACK)) {
        uint32_t max_conn = ctx->max_concurrent_streams;
        ctx->max_concurrent_streams = nghttp2_session_get_remote_settings(
            session, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
        ctx->enable_push = nghttp2_session_get_remote_settings(
            session, NGHTTP2_SETTINGS_ENABLE_PUSH) != 0;
        CURL_TRC_CF(data, cf, "[0] MAX_CONCURRENT_STREAMS: %d",
                    ctx->max_concurrent_streams);
        CURL_TRC_CF(data, cf, "[0] ENABLE_PUSH: %s",
                    ctx->enable_push ? "TRUE" : "false");
        if(data && max_conn != ctx->max_concurrent_streams) {
          /* only signal change if the value actually changed */
          CURL_TRC_CF(data, cf, "[0] notify MAX_CONCURRENT_STREAMS: %u",
                      ctx->max_concurrent_streams);
          Curl_multi_connchanged(data->multi);
        }
        /* Since the initial stream window is 64K, a request might be on HOLD,
         * due to exhaustion. The (initial) SETTINGS may announce a much larger
         * window and *assume* that we treat this like a WINDOW_UPDATE. Some
         * servers send an explicit WINDOW_UPDATE, but not all seem to do that.
         * To be safe, we UNHOLD a stream in order not to stall. */
        if(CURL_WANT_SEND(data)) {
          struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
          if(stream)
            drain_stream(cf, data, stream);
        }
      }
      break;
    }
    case NGHTTP2_GOAWAY:
      ctx->rcvd_goaway = TRUE;
      ctx->goaway_error = frame->goaway.error_code;
      ctx->remote_max_sid = frame->goaway.last_stream_id;
      if(data) {
        infof(data, "received GOAWAY, error=%u, last_stream=%u",
                    ctx->goaway_error, ctx->remote_max_sid);
        Curl_multi_connchanged(data->multi);
      }
      break;
    default:
      break;
    }
    return 0;
  }

  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!data_s) {
    CURL_TRC_CF(data, cf, "[%d] No Curl_easy associated", stream_id);
    return 0;
  }

  return on_stream_frame(cf, data_s, frame) ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

static int cf_h2_on_invalid_frame_recv(nghttp2_session *session,
                                       const nghttp2_frame *frame,
                                       int ngerr, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct Curl_easy *data;
  int32_t stream_id = frame->hd.stream_id;

  data = nghttp2_session_get_stream_user_data(session, stream_id);
  if(data) {
    struct h2_stream_ctx *stream;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
    char buffer[256];
    int len;
    len = fr_print(frame, buffer, sizeof(buffer)-1);
    buffer[len] = 0;
    failf(data, "[HTTP2] [%d] received invalid frame: %s, error %d: %s",
          stream_id, buffer, ngerr, nghttp2_strerror(ngerr));
#endif /* !CURL_DISABLE_VERBOSE_STRINGS */
    stream = H2_STREAM_CTX(ctx, data);
    if(stream) {
      nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                                stream->id, NGHTTP2_STREAM_CLOSED);
      stream->error = ngerr;
      stream->closed = TRUE;
      stream->reset = TRUE;
      return 0;  /* keep the connection alive */
    }
  }
  return NGHTTP2_ERR_CALLBACK_FAILURE;
}

static int on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              const uint8_t *mem, size_t len, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream;
  struct Curl_easy *data_s;
  (void)flags;

  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */
  DEBUGASSERT(CF_DATA_CURRENT(cf));

  /* get the stream from the hash based on Stream ID */
  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!data_s) {
    /* Receiving a Stream ID not in the hash should not happen - unless
       we have aborted a transfer artificially and there were more data
       in the pipeline. Silently ignore. */
    CURL_TRC_CF(CF_DATA_CURRENT(cf), cf, "[%d] Data for unknown",
                stream_id);
    /* consumed explicitly as no one will read it */
    nghttp2_session_consume(session, stream_id, len);
    return 0;
  }

  stream = H2_STREAM_CTX(ctx, data_s);
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  h2_xfer_write_resp(cf, data_s, stream, (const char *)mem, len, FALSE);

  nghttp2_session_consume(ctx->h2, stream_id, len);
  stream->nrcvd_data += (curl_off_t)len;
  return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct Curl_easy *data_s, *call_data = CF_DATA_CURRENT(cf);
  struct h2_stream_ctx *stream;
  int rv;
  (void)session;

  DEBUGASSERT(call_data);
  /* stream id 0 is the connection, do not look there for streams. */
  data_s = stream_id ?
    nghttp2_session_get_stream_user_data(session, stream_id) : NULL;
  if(!data_s) {
    CURL_TRC_CF(call_data, cf,
                "[%d] on_stream_close, no easy set on stream", stream_id);
    return 0;
  }
  if(!GOOD_EASY_HANDLE(data_s)) {
    /* nghttp2 still has an easy registered for the stream which has
     * been freed be libcurl. This points to a code path that does not
     * trigger DONE or DETACH events as it must. */
    CURL_TRC_CF(call_data, cf,
                "[%d] on_stream_close, not a GOOD easy on stream", stream_id);
    (void)nghttp2_session_set_stream_user_data(session, stream_id, 0);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  stream = H2_STREAM_CTX(ctx, data_s);
  if(!stream) {
    CURL_TRC_CF(data_s, cf,
                "[%d] on_stream_close, GOOD easy but no stream", stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  stream->closed = TRUE;
  stream->error = error_code;
  if(stream->error) {
    stream->reset = TRUE;
  }

  if(stream->error)
    CURL_TRC_CF(data_s, cf, "[%d] RESET: %s (err %d)",
              stream_id, nghttp2_http2_strerror(error_code), error_code);
  else
    CURL_TRC_CF(data_s, cf, "[%d] CLOSED", stream_id);
  drain_stream(cf, data_s, stream);

  /* remove `data_s` from the nghttp2 stream */
  rv = nghttp2_session_set_stream_user_data(session, stream_id, 0);
  if(rv) {
    infof(data_s, "http/2: failed to clear user_data for stream %u",
          stream_id);
    DEBUGASSERT(0);
  }
  return 0;
}

static int on_begin_headers(nghttp2_session *session,
                            const nghttp2_frame *frame, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream;
  struct Curl_easy *data_s = NULL;

  (void)cf;
  data_s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(!data_s) {
    return 0;
  }

  if(frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  stream = H2_STREAM_CTX(ctx, data_s);
  if(!stream || !stream->bodystarted) {
    return 0;
  }

  return 0;
}

static void cf_h2_header_error(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h2_stream_ctx *stream,
                               CURLcode result)
{
  struct cf_h2_ctx *ctx = cf->ctx;

  failf(data, "Error receiving HTTP2 header: %d(%s)", result,
        curl_easy_strerror(result));
  if(stream) {
    nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                              stream->id, NGHTTP2_STREAM_CLOSED);
    stream->closed = TRUE;
    stream->reset = TRUE;
  }
}

/* frame->hd.type is either NGHTTP2_HEADERS or NGHTTP2_PUSH_PROMISE */
static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags,
                     void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream;
  struct Curl_easy *data_s;
  int32_t stream_id = frame->hd.stream_id;
  CURLcode result;
  (void)flags;

  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */

  /* get the stream from the hash based on Stream ID */
  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!GOOD_EASY_HANDLE(data_s))
    /* Receiving a Stream ID not in the hash should not happen, this is an
       internal error more than anything else! */
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  stream = H2_STREAM_CTX(ctx, data_s);
  if(!stream) {
    failf(data_s, "Internal NULL stream");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  /* Store received PUSH_PROMISE headers to be used when the subsequent
     PUSH_PROMISE callback comes */
  if(frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    char *h;

    if(!strcmp(HTTP_PSEUDO_AUTHORITY, (const char *)name)) {
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
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      stream->push_headers_used = 0;
    }
    else if(stream->push_headers_used ==
            stream->push_headers_alloc) {
      char **headp;
      if(stream->push_headers_alloc > 1000) {
        /* this is beyond crazy many headers, bail out */
        failf(data_s, "Too many PUSH_PROMISE headers");
        free_push_headers(stream);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      stream->push_headers_alloc *= 2;
      headp = realloc(stream->push_headers,
                      stream->push_headers_alloc * sizeof(char *));
      if(!headp) {
        free_push_headers(stream);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
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
    CURL_TRC_CF(data_s, cf, "[%d] trailer: %.*s: %.*s",
                stream->id, (int)namelen, name, (int)valuelen, value);
    result = Curl_dynhds_add(&stream->resp_trailers,
                             (const char *)name, namelen,
                             (const char *)value, valuelen);
    if(result) {
      cf_h2_header_error(cf, data_s, stream, result);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }

  if(namelen == sizeof(HTTP_PSEUDO_STATUS) - 1 &&
     memcmp(HTTP_PSEUDO_STATUS, name, namelen) == 0) {
    /* nghttp2 guarantees :status is received first and only once. */
    char buffer[32];
    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)value, valuelen);
    if(result) {
      cf_h2_header_error(cf, data_s, stream, result);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    msnprintf(buffer, sizeof(buffer), HTTP_PSEUDO_STATUS ":%u\r",
              stream->status_code);
    result = Curl_headers_push(data_s, buffer, CURLH_PSEUDO);
    if(result) {
      cf_h2_header_error(cf, data_s, stream, result);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    curlx_dyn_reset(&ctx->scratch);
    result = curlx_dyn_addn(&ctx->scratch, STRCONST("HTTP/2 "));
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch, value, valuelen);
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch, STRCONST(" \r\n"));
    if(!result)
      h2_xfer_write_resp_hd(cf, data_s, stream, curlx_dyn_ptr(&ctx->scratch),
                            curlx_dyn_len(&ctx->scratch), FALSE);
    if(result) {
      cf_h2_header_error(cf, data_s, stream, result);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    /* if we receive data for another handle, wake that up */
    if(CF_DATA_CURRENT(cf) != data_s)
      Curl_expire(data_s, 0, EXPIRE_RUN_NOW);

    CURL_TRC_CF(data_s, cf, "[%d] status: HTTP/2 %03d",
                stream->id, stream->status_code);
    return 0;
  }

  /* nghttp2 guarantees that namelen > 0, and :status was already
     received, and this is not pseudo-header field . */
  /* convert to an HTTP1-style header */
  curlx_dyn_reset(&ctx->scratch);
  result = curlx_dyn_addn(&ctx->scratch, (const char *)name, namelen);
  if(!result)
    result = curlx_dyn_addn(&ctx->scratch, STRCONST(": "));
  if(!result)
    result = curlx_dyn_addn(&ctx->scratch, (const char *)value, valuelen);
  if(!result)
    result = curlx_dyn_addn(&ctx->scratch, STRCONST("\r\n"));
  if(!result)
    h2_xfer_write_resp_hd(cf, data_s, stream, curlx_dyn_ptr(&ctx->scratch),
                          curlx_dyn_len(&ctx->scratch), FALSE);
  if(result) {
    cf_h2_header_error(cf, data_s, stream, result);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  /* if we receive data for another handle, wake that up */
  if(CF_DATA_CURRENT(cf) != data_s)
    Curl_expire(data_s, 0, EXPIRE_RUN_NOW);

  CURL_TRC_CF(data_s, cf, "[%d] header: %.*s: %.*s",
              stream->id, (int)namelen, name, (int)valuelen, value);

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
  struct cf_h2_ctx *ctx = cf->ctx;
  struct Curl_easy *data_s;
  struct h2_stream_ctx *stream = NULL;
  CURLcode result;
  ssize_t nread;
  (void)source;

  (void)cf;
  if(!stream_id)
    return NGHTTP2_ERR_INVALID_ARGUMENT;

  /* get the stream from the hash based on Stream ID, stream ID zero is for
     connection-oriented stuff */
  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!data_s)
    /* Receiving a Stream ID not in the hash should not happen, this is an
       internal error more than anything else! */
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  stream = H2_STREAM_CTX(ctx, data_s);
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  nread = Curl_bufq_read(&stream->sendbuf, buf, length, &result);
  if(nread < 0) {
    if(result != CURLE_AGAIN)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    nread = 0;
  }

  CURL_TRC_CF(data_s, cf, "[%d] req_body_read(len=%zu) eos=%d -> %zd, %d",
              stream_id, length, stream->body_eos, nread, result);

  if(stream->body_eos && Curl_bufq_is_empty(&stream->sendbuf)) {
    *data_flags = NGHTTP2_DATA_FLAG_EOF;
    return nread;
  }
  return (nread == 0) ? NGHTTP2_ERR_DEFERRED : nread;
}

#if !defined(CURL_DISABLE_VERBOSE_STRINGS)
static int error_callback(nghttp2_session *session,
                          const char *msg,
                          size_t len,
                          void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  (void)session;
  failf(data, "%.*s", (int)len, msg);
  return 0;
}
#endif

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
  ssize_t binlen; /* length of the binsettings data */

  binlen = populate_binsettings(binsettings, data);
  if(binlen <= 0) {
    failf(data, "nghttp2 unexpectedly failed on pack_settings_payload");
    curlx_dyn_free(req);
    return CURLE_FAILED_INIT;
  }

  result = curlx_base64url_encode((const char *)binsettings, (size_t)binlen,
                                  &base64, &blen);
  if(result) {
    curlx_dyn_free(req);
    return result;
  }

  result = curlx_dyn_addf(req,
                          "Connection: Upgrade, HTTP2-Settings\r\n"
                          "Upgrade: %s\r\n"
                          "HTTP2-Settings: %s\r\n",
                          NGHTTP2_CLEARTEXT_PROTO_VERSION_ID, base64);
  free(base64);

  k->upgr101 = UPGR101_H2;
  data->conn->bits.asks_multiplex = TRUE;

  return result;
}

static ssize_t http2_handle_stream_close(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct h2_stream_ctx *stream,
                                         CURLcode *err)
{
  ssize_t rv = 0;

  if(stream->error == NGHTTP2_REFUSED_STREAM) {
    CURL_TRC_CF(data, cf, "[%d] REFUSED_STREAM, try again on a new "
                "connection", stream->id);
    connclose(cf->conn, "REFUSED_STREAM"); /* do not use this anymore */
    data->state.refused_stream = TRUE;
    *err = CURLE_RECV_ERROR; /* trigger Curl_retry_request() later */
    return -1;
  }
  else if(stream->error != NGHTTP2_NO_ERROR) {
    if(stream->resp_hds_complete && data->req.no_body) {
      CURL_TRC_CF(data, cf, "[%d] error after response headers, but we did "
                  "not want a body anyway, ignore: %s (err %u)",
                  stream->id, nghttp2_http2_strerror(stream->error),
                  stream->error);
      stream->close_handled = TRUE;
      *err = CURLE_OK;
      goto out;
    }
    failf(data, "HTTP/2 stream %u was not closed cleanly: %s (err %u)",
          stream->id, nghttp2_http2_strerror(stream->error),
          stream->error);
    *err = CURLE_HTTP2_STREAM;
    return -1;
  }
  else if(stream->reset) {
    failf(data, "HTTP/2 stream %u was reset", stream->id);
    *err = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP2;
    return -1;
  }

  if(!stream->bodystarted) {
    failf(data, "HTTP/2 stream %u was closed cleanly, but before getting "
          " all response header fields, treated as error",
          stream->id);
    *err = CURLE_HTTP2_STREAM;
    return -1;
  }

  if(Curl_dynhds_count(&stream->resp_trailers)) {
    struct dynhds_entry *e;
    struct dynbuf dbuf;
    size_t i;

    *err = CURLE_OK;
    curlx_dyn_init(&dbuf, DYN_TRAILERS);
    for(i = 0; i < Curl_dynhds_count(&stream->resp_trailers); ++i) {
      e = Curl_dynhds_getn(&stream->resp_trailers, i);
      if(!e)
        break;
      curlx_dyn_reset(&dbuf);
      *err = curlx_dyn_addf(&dbuf, "%.*s: %.*s\x0d\x0a",
                            (int)e->namelen, e->name,
                            (int)e->valuelen, e->value);
      if(*err)
        break;
      Curl_debug(data, CURLINFO_HEADER_IN, curlx_dyn_ptr(&dbuf),
                 curlx_dyn_len(&dbuf));
      *err = Curl_client_write(data, CLIENTWRITE_HEADER|CLIENTWRITE_TRAILER,
                               curlx_dyn_ptr(&dbuf), curlx_dyn_len(&dbuf));
      if(*err)
        break;
    }
    curlx_dyn_free(&dbuf);
    if(*err)
      goto out;
  }

  stream->close_handled = TRUE;
  *err = CURLE_OK;
  rv = 0;

out:
  CURL_TRC_CF(data, cf, "handle_stream_close -> %zd, %d", rv, *err);
  return rv;
}

static int sweight_wanted(const struct Curl_easy *data)
{
  /* 0 weight is not set by user and we take the nghttp2 default one */
  return data->set.priority.weight ?
    data->set.priority.weight : NGHTTP2_DEFAULT_WEIGHT;
}

static int sweight_in_effect(const struct Curl_easy *data)
{
  /* 0 weight is not set by user and we take the nghttp2 default one */
  return data->state.priority.weight ?
    data->state.priority.weight : NGHTTP2_DEFAULT_WEIGHT;
}

/*
 * h2_pri_spec() fills in the pri_spec struct, used by nghttp2 to send weight
 * and dependency to the peer. It also stores the updated values in the state
 * struct.
 */

static void h2_pri_spec(struct cf_h2_ctx *ctx,
                        struct Curl_easy *data,
                        nghttp2_priority_spec *pri_spec)
{
  struct Curl_data_priority *prio = &data->set.priority;
  struct h2_stream_ctx *depstream = H2_STREAM_CTX(ctx, prio->parent);
  int32_t depstream_id = depstream ? depstream->id : 0;
  nghttp2_priority_spec_init(pri_spec, depstream_id,
                             sweight_wanted(data),
                             data->set.priority.exclusive);
  data->state.priority = *prio;
}

/*
 * Check if there is been an update in the priority /
 * dependency settings and if so it submits a PRIORITY frame with the updated
 * info.
 * Flush any out data pending in the network buffer.
 */
static CURLcode h2_progress_egress(struct Curl_cfilter *cf,
                                  struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
  int rv = 0;

  if(stream && stream->id > 0 &&
     ((sweight_wanted(data) != sweight_in_effect(data)) ||
      (data->set.priority.exclusive != data->state.priority.exclusive) ||
      (data->set.priority.parent != data->state.priority.parent)) ) {
    /* send new weight and/or dependency */
    nghttp2_priority_spec pri_spec;

    h2_pri_spec(ctx, data, &pri_spec);
    CURL_TRC_CF(data, cf, "[%d] Queuing PRIORITY", stream->id);
    DEBUGASSERT(stream->id != -1);
    rv = nghttp2_submit_priority(ctx->h2, NGHTTP2_FLAG_NONE,
                                 stream->id, &pri_spec);
    if(rv)
      goto out;
  }

  ctx->nw_out_blocked = 0;
  while(!rv && !ctx->nw_out_blocked && nghttp2_session_want_write(ctx->h2))
    rv = nghttp2_session_send(ctx->h2);

out:
  if(nghttp2_is_fatal(rv)) {
    CURL_TRC_CF(data, cf, "nghttp2_session_send error (%s)%d",
                nghttp2_strerror(rv), rv);
    return CURLE_SEND_ERROR;
  }
  /* Defer flushing during the connect phase so that the SETTINGS and
   * other initial frames are sent together with the first request.
   * Unless we are 'connect_only' where the request will never come. */
  if(!cf->connected && !cf->conn->connect_only)
    return CURLE_OK;
  return nw_out_flush(cf, data);
}

static ssize_t stream_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           struct h2_stream_ctx *stream,
                           char *buf, size_t len, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  ssize_t nread = -1;

  (void)buf;
  *err = CURLE_AGAIN;
  if(stream->xfer_result) {
    CURL_TRC_CF(data, cf, "[%d] xfer write failed", stream->id);
    *err = stream->xfer_result;
    nread = -1;
  }
  else if(stream->closed) {
    CURL_TRC_CF(data, cf, "[%d] returning CLOSE", stream->id);
    nread = http2_handle_stream_close(cf, data, stream, err);
  }
  else if(stream->reset ||
          (ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) ||
          (ctx->rcvd_goaway && ctx->remote_max_sid < stream->id)) {
    CURL_TRC_CF(data, cf, "[%d] returning ERR", stream->id);
    *err = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP2;
    nread = -1;
  }

  if(nread < 0 && *err != CURLE_AGAIN)
    CURL_TRC_CF(data, cf, "[%d] stream_recv(len=%zu) -> %zd, %d",
                stream->id, len, nread, *err);
  return nread;
}

static CURLcode h2_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    size_t data_max_bytes)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream;
  CURLcode result = CURLE_OK;
  ssize_t nread;

  if(should_close_session(ctx)) {
    CURL_TRC_CF(data, cf, "progress ingress, session is closed");
    return CURLE_HTTP2;
  }

  /* Process network input buffer fist */
  if(!Curl_bufq_is_empty(&ctx->inbufq)) {
    CURL_TRC_CF(data, cf, "Process %zu bytes in connection buffer",
                Curl_bufq_len(&ctx->inbufq));
    if(h2_process_pending_input(cf, data, &result) < 0)
      return result;
  }

  /* Receive data from the "lower" filters, e.g. network until
   * it is time to stop due to connection close or us not processing
   * all network input */
  while(!ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) {
    stream = H2_STREAM_CTX(ctx, data);
    if(stream && (stream->closed || !data_max_bytes)) {
      /* We would like to abort here and stop processing, so that
       * the transfer loop can handle the data/close here. However,
       * this may leave data in underlying buffers that will not
       * be consumed. */
      if(!cf->next || !cf->next->cft->has_data_pending(cf->next, data))
        drain_stream(cf, data, stream);
      break;
    }

    nread = Curl_bufq_sipn(&ctx->inbufq, 0, nw_in_reader, cf, &result);
    if(nread < 0) {
      if(result != CURLE_AGAIN) {
        failf(data, "Failed receiving HTTP2 data: %d(%s)", result,
              curl_easy_strerror(result));
        return result;
      }
      break;
    }
    else if(nread == 0) {
      CURL_TRC_CF(data, cf, "[0] ingress: connection closed");
      ctx->conn_closed = TRUE;
      break;
    }
    else {
      CURL_TRC_CF(data, cf, "[0] ingress: read %zd bytes", nread);
      data_max_bytes = (data_max_bytes > (size_t)nread) ?
        (data_max_bytes - (size_t)nread) : 0;
    }

    if(h2_process_pending_input(cf, data, &result))
      return result;
    CURL_TRC_CF(data, cf, "[0] progress ingress: inbufg=%zu",
                Curl_bufq_len(&ctx->inbufq));
  }

  if(ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) {
    connclose(cf->conn, "GOAWAY received");
  }

  CURL_TRC_CF(data, cf, "[0] progress ingress: done");
  return CURLE_OK;
}

static ssize_t cf_h2_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
  ssize_t nread = -1;
  CURLcode result;
  struct cf_call_data save;

  if(!stream) {
    /* Abnormal call sequence: either this transfer has never opened a stream
     * (unlikely) or the transfer has been done, cleaned up its resources, but
     * a read() is called anyway. It is not clear what the calling sequence
     * is for such a case. */
    failf(data, "http/2 recv on a transfer never opened "
          "or already cleared, mid=%u", data->mid);
    *err = CURLE_HTTP2;
    return -1;
  }

  CF_DATA_SAVE(save, cf, data);

  nread = stream_recv(cf, data, stream, buf, len, err);
  if(nread < 0 && *err != CURLE_AGAIN)
    goto out;

  if(nread < 0) {
    *err = h2_progress_ingress(cf, data, len);
    if(*err)
      goto out;

    nread = stream_recv(cf, data, stream, buf, len, err);
  }

  if(nread > 0) {
    /* Now that we transferred this to the upper layer, we report
     * the actual amount of DATA consumed to the H2 session, so
     * that it adjusts stream flow control */
    nghttp2_session_consume(ctx->h2, stream->id, (size_t)nread);
    if(stream->closed) {
      CURL_TRC_CF(data, cf, "[%d] DRAIN closed stream", stream->id);
      drain_stream(cf, data, stream);
    }
  }

out:
  result = h2_progress_egress(cf, data);
  if(result == CURLE_AGAIN) {
    /* pending data to send, need to be called again. Ideally, we
     * monitor the socket for POLLOUT, but when not SENDING
     * any more, we force processing of the transfer. */
    if(!CURL_WANT_SEND(data))
      drain_stream(cf, data, stream);
  }
  else if(result) {
    *err = result;
    nread = -1;
  }
  CURL_TRC_CF(data, cf, "[%d] cf_recv(len=%zu) -> %zd %d, "
              "window=%d/%d, connection %d/%d",
              stream->id, len, nread, *err,
              nghttp2_session_get_stream_effective_recv_data_length(
                ctx->h2, stream->id),
              nghttp2_session_get_stream_effective_local_window_size(
                ctx->h2, stream->id),
              nghttp2_session_get_local_window_size(ctx->h2),
              HTTP2_HUGE_WINDOW_SIZE);

  CF_DATA_RESTORE(cf, save);
  return nread;
}

static ssize_t cf_h2_body_send(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h2_stream_ctx *stream,
                               const void *buf, size_t blen, bool eos,
                               CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  ssize_t nwritten;

  if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%d] discarding data"
                  "on closed stream with response", stream->id);
      if(eos)
        stream->body_eos = TRUE;
      *err = CURLE_OK;
      return (ssize_t)blen;
    }
    /* Server closed before we got a response, this is an error */
    infof(data, "stream %u closed", stream->id);
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  nwritten = Curl_bufq_write(&stream->sendbuf, buf, blen, err);
  if(nwritten < 0)
    return -1;

  if(eos && (blen == (size_t)nwritten))
    stream->body_eos = TRUE;

  if(eos || !Curl_bufq_is_empty(&stream->sendbuf)) {
    /* resume the potentially suspended stream */
    int rv = nghttp2_session_resume_data(ctx->h2, stream->id);
    if(nghttp2_is_fatal(rv)) {
      *err = CURLE_SEND_ERROR;
      return -1;
    }
  }
  return nwritten;
}

static ssize_t h2_submit(struct h2_stream_ctx **pstream,
                         struct Curl_cfilter *cf, struct Curl_easy *data,
                         const void *buf, size_t len,
                         bool eos, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream = NULL;
  struct dynhds h2_headers;
  nghttp2_nv *nva = NULL;
  const void *body = NULL;
  size_t nheader, bodylen, i;
  nghttp2_data_provider data_prd;
  int32_t stream_id;
  nghttp2_priority_spec pri_spec;
  ssize_t nwritten;

  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);

  *err = http2_data_setup(cf, data, &stream);
  if(*err) {
    nwritten = -1;
    goto out;
  }

  nwritten = Curl_h1_req_parse_read(&stream->h1, buf, len, NULL, 0, err);
  if(nwritten < 0)
    goto out;
  if(!stream->h1.done) {
    /* need more data */
    goto out;
  }
  DEBUGASSERT(stream->h1.req);

  *err = Curl_http_req_to_h2(&h2_headers, stream->h1.req, data);
  if(*err) {
    nwritten = -1;
    goto out;
  }
  /* no longer needed */
  Curl_h1_req_parse_free(&stream->h1);

  nva = Curl_dynhds_to_nva(&h2_headers, &nheader);
  if(!nva) {
    *err = CURLE_OUT_OF_MEMORY;
    nwritten = -1;
    goto out;
  }

  h2_pri_spec(ctx, data, &pri_spec);
  if(!nghttp2_session_check_request_allowed(ctx->h2))
    CURL_TRC_CF(data, cf, "send request NOT allowed (via nghttp2)");

  switch(data->state.httpreq) {
  case HTTPREQ_POST:
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
  case HTTPREQ_PUT:
    data_prd.read_callback = req_body_read_callback;
    data_prd.source.ptr = NULL;
    stream_id = nghttp2_submit_request(ctx->h2, &pri_spec, nva, nheader,
                                       &data_prd, data);
    break;
  default:
    stream_id = nghttp2_submit_request(ctx->h2, &pri_spec, nva, nheader,
                                       NULL, data);
  }

  if(stream_id < 0) {
    CURL_TRC_CF(data, cf, "send: nghttp2_submit_request error (%s)%u",
                nghttp2_strerror(stream_id), stream_id);
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }

#define MAX_ACC 60000  /* <64KB to account for some overhead */
  if(Curl_trc_is_verbose(data)) {
    size_t acc = 0;

    infof(data, "[HTTP/2] [%d] OPENED stream for %s",
          stream_id, data->state.url);
    for(i = 0; i < nheader; ++i) {
      acc += nva[i].namelen + nva[i].valuelen;

      infof(data, "[HTTP/2] [%d] [%.*s: %.*s]", stream_id,
            (int)nva[i].namelen, nva[i].name,
            (int)nva[i].valuelen, nva[i].value);
    }

    if(acc > MAX_ACC) {
      infof(data, "[HTTP/2] Warning: The cumulative length of all "
            "headers exceeds %d bytes and that could cause the "
            "stream to be rejected.", MAX_ACC);
    }
  }

  stream->id = stream_id;

  body = (const char *)buf + nwritten;
  bodylen = len - nwritten;

  if(bodylen || eos) {
    ssize_t n = cf_h2_body_send(cf, data, stream, body, bodylen, eos, err);
    if(n >= 0)
      nwritten += n;
    else if(*err == CURLE_AGAIN)
      *err = CURLE_OK;
    else if(*err != CURLE_AGAIN) {
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
      goto out;
    }
  }

out:
  CURL_TRC_CF(data, cf, "[%d] submit -> %zd, %d",
              stream ? stream->id : -1, nwritten, *err);
  Curl_safefree(nva);
  *pstream = stream;
  Curl_dynhds_free(&h2_headers);
  return nwritten;
}

static ssize_t cf_h2_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, bool eos,
                          CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  ssize_t nwritten;
  CURLcode result;

  CF_DATA_SAVE(save, cf, data);

  if(!stream || stream->id == -1) {
    nwritten = h2_submit(&stream, cf, data, buf, len, eos, err);
    if(nwritten < 0) {
      goto out;
    }
    DEBUGASSERT(stream);
  }
  else if(stream->body_eos) {
    /* We already wrote this, but CURLE_AGAINed the call due to not
     * being able to flush stream->sendbuf. Make a 0-length write
     * to trigger flushing again.
     * If this works, we report to have written `len` bytes. */
    DEBUGASSERT(eos);
    nwritten = cf_h2_body_send(cf, data, stream, buf, 0, eos, err);
    CURL_TRC_CF(data, cf, "[%d] cf_body_send last CHUNK -> %zd, %d, eos=%d",
                stream->id, nwritten, *err, eos);
    if(nwritten < 0) {
      goto out;
    }
    nwritten = len;
  }
  else {
    nwritten = cf_h2_body_send(cf, data, stream, buf, len, eos, err);
    CURL_TRC_CF(data, cf, "[%d] cf_body_send(len=%zu) -> %zd, %d, eos=%d",
                stream->id, len, nwritten, *err, eos);
  }

  /* Call the nghttp2 send loop and flush to write ALL buffered data,
   * headers and/or request body completely out to the network */
  result = h2_progress_egress(cf, data);

  /* if the stream has been closed in egress handling (nghttp2 does that
   * when it does not like the headers, for example */
  if(stream && stream->closed) {
    infof(data, "stream %u closed", stream->id);
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }
  else if(result && (result != CURLE_AGAIN)) {
    *err = result;
    nwritten = -1;
    goto out;
  }

  if(should_close_session(ctx)) {
    /* nghttp2 thinks this session is done. If the stream has not been
     * closed, this is an error state for out transfer */
    if(stream && stream->closed) {
      nwritten = http2_handle_stream_close(cf, data, stream, err);
    }
    else {
      CURL_TRC_CF(data, cf, "send: nothing to do in this session");
      *err = CURLE_HTTP2;
      nwritten = -1;
    }
  }

out:
  if(stream) {
    CURL_TRC_CF(data, cf, "[%d] cf_send(len=%zu) -> %zd, %d, "
                "eos=%d, h2 windows %d-%d (stream-conn), "
                "buffers %zu-%zu (stream-conn)",
                stream->id, len, nwritten, *err,
                stream->body_eos,
                nghttp2_session_get_stream_remote_window_size(
                  ctx->h2, stream->id),
                nghttp2_session_get_remote_window_size(ctx->h2),
                Curl_bufq_len(&stream->sendbuf),
                Curl_bufq_len(&ctx->outbufq));
  }
  else {
    CURL_TRC_CF(data, cf, "cf_send(len=%zu) -> %zd, %d, "
                "connection-window=%d, nw_send_buffer(%zu)",
                len, nwritten, *err,
                nghttp2_session_get_remote_window_size(ctx->h2),
                Curl_bufq_len(&ctx->outbufq));
  }
  CF_DATA_RESTORE(cf, save);
  return nwritten;
}

static CURLcode cf_h2_flush(struct Curl_cfilter *cf,
                            struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);
  if(stream && !Curl_bufq_is_empty(&stream->sendbuf)) {
    /* resume the potentially suspended stream */
    int rv = nghttp2_session_resume_data(ctx->h2, stream->id);
    if(nghttp2_is_fatal(rv)) {
      result = CURLE_SEND_ERROR;
      goto out;
    }
  }

  result = h2_progress_egress(cf, data);

out:
  if(stream) {
    CURL_TRC_CF(data, cf, "[%d] flush -> %d, "
                "h2 windows %d-%d (stream-conn), "
                "buffers %zu-%zu (stream-conn)",
                stream->id, result,
                nghttp2_session_get_stream_remote_window_size(
                  ctx->h2, stream->id),
                nghttp2_session_get_remote_window_size(ctx->h2),
                Curl_bufq_len(&stream->sendbuf),
                Curl_bufq_len(&ctx->outbufq));
  }
  else {
    CURL_TRC_CF(data, cf, "flush -> %d, "
                "connection-window=%d, nw_send_buffer(%zu)",
                result, nghttp2_session_get_remote_window_size(ctx->h2),
                Curl_bufq_len(&ctx->outbufq));
  }
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_h2_adjust_pollset(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct easy_pollset *ps)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  curl_socket_t sock;
  bool want_recv, want_send;

  if(!ctx->h2)
    return;

  sock = Curl_conn_cf_get_socket(cf, data);
  Curl_pollset_check(data, ps, sock, &want_recv, &want_send);
  if(want_recv || want_send) {
    struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
    bool c_exhaust, s_exhaust;

    CF_DATA_SAVE(save, cf, data);
    c_exhaust = want_send && !nghttp2_session_get_remote_window_size(ctx->h2);
    s_exhaust = want_send && stream && stream->id >= 0 &&
                !nghttp2_session_get_stream_remote_window_size(ctx->h2,
                                                               stream->id);
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                (!c_exhaust && nghttp2_session_want_write(ctx->h2)) ||
                !Curl_bufq_is_empty(&ctx->outbufq);

    Curl_pollset_set(data, ps, sock, want_recv, want_send);
    CF_DATA_RESTORE(cf, save);
  }
  else if(ctx->sent_goaway && !cf->shutdown) {
    /* shutdown in progress */
    CF_DATA_SAVE(save, cf, data);
    want_send = nghttp2_session_want_write(ctx->h2) ||
                !Curl_bufq_is_empty(&ctx->outbufq);
    want_recv = nghttp2_session_want_read(ctx->h2);
    Curl_pollset_set(data, ps, sock, want_recv, want_send);
    CF_DATA_RESTORE(cf, save);
  }
}

static CURLcode cf_h2_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool *done)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;
  bool first_time = FALSE;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the lower filters first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(ctx->initialized);
  if(!ctx->h2) {
    result = cf_h2_ctx_open(cf, data);
    if(result)
      goto out;
    first_time = TRUE;
  }

  if(!first_time) {
    result = h2_progress_ingress(cf, data, H2_CHUNK_SIZE);
    if(result)
      goto out;
  }

  /* Send out our SETTINGS and ACKs and such. If that blocks, we
   * have it buffered and  can count this filter as being connected */
  result = h2_progress_egress(cf, data);
  if(result && (result != CURLE_AGAIN))
    goto out;

  *done = TRUE;
  cf->connected = TRUE;
  result = CURLE_OK;

out:
  CURL_TRC_CF(data, cf, "cf_connect() -> %d, %d, ", result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_h2_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;

  if(ctx) {
    struct cf_call_data save;

    CF_DATA_SAVE(save, cf, data);
    cf_h2_ctx_close(ctx);
    CF_DATA_RESTORE(cf, save);
    cf->connected = FALSE;
  }
  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
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

static CURLcode cf_h2_shutdown(struct Curl_cfilter *cf,
                               struct Curl_easy *data, bool *done)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result;
  int rv;

  if(!cf->connected || !ctx->h2 || cf->shutdown || ctx->conn_closed) {
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);

  if(!ctx->sent_goaway) {
    ctx->sent_goaway = TRUE;
    rv = nghttp2_submit_goaway(ctx->h2, NGHTTP2_FLAG_NONE,
                               ctx->local_max_sid, 0,
                               (const uint8_t *)"shutdown",
                               sizeof("shutdown"));
    if(rv) {
      failf(data, "nghttp2_submit_goaway() failed: %s(%d)",
            nghttp2_strerror(rv), rv);
      result = CURLE_SEND_ERROR;
      goto out;
    }
  }
  /* GOAWAY submitted, process egress and ingress until nghttp2 is done. */
  result = CURLE_OK;
  if(nghttp2_session_want_write(ctx->h2) ||
     !Curl_bufq_is_empty(&ctx->outbufq))
    result = h2_progress_egress(cf, data);
  if(!result && nghttp2_session_want_read(ctx->h2))
    result = h2_progress_ingress(cf, data, 0);

  if(result == CURLE_AGAIN)
    result = CURLE_OK;

  *done = (ctx->conn_closed ||
           (!result && !nghttp2_session_want_write(ctx->h2) &&
            !nghttp2_session_want_read(ctx->h2) &&
            Curl_bufq_is_empty(&ctx->outbufq)));

out:
  CF_DATA_RESTORE(cf, save);
  cf->shutdown = (result || *done);
  return result;
}

static CURLcode http2_data_pause(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool pause)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);

  DEBUGASSERT(data);
  if(ctx && ctx->h2 && stream) {
    CURLcode result;

    stream->write_paused = pause;
    result = cf_h2_update_local_win(cf, data, stream);
    if(result)
      return result;

    /* attempt to send the window update */
    (void)h2_progress_egress(cf, data);

    if(!pause) {
      /* Unpausing a h2 transfer, requires it to be run again. The server
       * may send new DATA on us increasing the flow window, and it may
       * not. We may have already buffered and exhausted the new window
       * by operating on things in flight during the handling of other
       * transfers. */
      drain_stream(cf, data, stream);
      Curl_expire(data, 0, EXPIRE_RUN_NOW);
    }
    CURL_TRC_CF(data, cf, "[%d] stream now %spaused", stream->id,
                pause ? "" : "un");
  }
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
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = http2_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_FLUSH:
    result = cf_h2_flush(cf, data);
    break;
  case CF_CTRL_DATA_DONE:
    http2_data_done(cf, data);
    break;
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

  if(ctx && !Curl_bufq_is_empty(&ctx->inbufq))
    return TRUE;
  return cf->next ? cf->next->cft->has_data_pending(cf->next, data) : FALSE;
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
  CURL_TRC_CF(data, cf, "conn alive -> %d, input_pending=%d",
              result, *input_pending);
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
      effective_max = CONN_ATTACHED(cf->conn);
    }
    else {
      effective_max = ctx->max_concurrent_streams;
    }
    *pres1 = (effective_max > INT_MAX) ? INT_MAX : (int)effective_max;
    CF_DATA_RESTORE(cf, save);
    return CURLE_OK;
  case CF_QUERY_STREAM_ERROR: {
    struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
    *pres1 = stream ? (int)stream->error : 0;
    return CURLE_OK;
  }
  case CF_QUERY_NEED_FLUSH: {
    struct h2_stream_ctx *stream = H2_STREAM_CTX(ctx, data);
    if(!Curl_bufq_is_empty(&ctx->outbufq) ||
       (stream && !Curl_bufq_is_empty(&stream->sendbuf))) {
      *pres1 = TRUE;
      return CURLE_OK;
    }
    break;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 20;
    return CURLE_OK;
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

struct Curl_cftype Curl_cft_nghttp2 = {
  "HTTP/2",
  CF_TYPE_MULTIPLEX | CF_TYPE_HTTP,
  CURL_LOG_LVL_NONE,
  cf_h2_destroy,
  cf_h2_connect,
  cf_h2_close,
  cf_h2_shutdown,
  Curl_cf_def_get_host,
  cf_h2_adjust_pollset,
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
                                  int sockindex,
                                  bool via_h1_upgrade)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_h2_ctx *ctx;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(data->conn);
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx)
    goto out;
  cf_h2_ctx_init(ctx, via_h1_upgrade);

  result = Curl_cf_create(&cf, &Curl_cft_nghttp2, ctx);
  if(result)
    goto out;

  ctx = NULL;
  Curl_conn_cf_add(data, conn, sockindex, cf);

out:
  if(result)
    cf_h2_ctx_free(ctx);
  *pcf = result ? NULL : cf;
  return result;
}

static CURLcode http2_cfilter_insert_after(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           bool via_h1_upgrade)
{
  struct Curl_cfilter *cf_h2 = NULL;
  struct cf_h2_ctx *ctx;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx)
    goto out;
  cf_h2_ctx_init(ctx, via_h1_upgrade);

  result = Curl_cf_create(&cf_h2, &Curl_cft_nghttp2, ctx);
  if(result)
    goto out;

  ctx = NULL;
  Curl_conn_cf_insert_after(cf, cf_h2);

out:
  if(result)
    cf_h2_ctx_free(ctx);
  return result;
}

bool Curl_http2_may_switch(struct Curl_easy *data)
{
  if(Curl_conn_http_version(data, data->conn) < 20 &&
     (data->state.http_neg.wanted & CURL_HTTP_V2x) &&
     data->state.http_neg.h2_prior_knowledge) {
#ifndef CURL_DISABLE_PROXY
    if(data->conn->bits.httpproxy && !data->conn->bits.tunnel_proxy) {
      /* We do not support HTTP/2 proxies yet. Also it is debatable
         whether or not this setting should apply to HTTP/2 proxies. */
      infof(data, "Ignoring HTTP/2 prior knowledge due to proxy");
      return FALSE;
    }
#endif
    return TRUE;
  }
  return FALSE;
}

CURLcode Curl_http2_switch(struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  DEBUGASSERT(Curl_conn_http_version(data, data->conn) < 20);

  result = http2_cfilter_add(&cf, data, data->conn, FIRSTSOCKET, FALSE);
  if(result)
    return result;
  CURL_TRC_CF(data, cf, "switching connection to HTTP/2");

  data->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  Curl_multi_connchanged(data->multi);

  if(cf->next) {
    bool done;
    return Curl_conn_cf_connect(cf, data, &done);
  }
  return CURLE_OK;
}

CURLcode Curl_http2_switch_at(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct Curl_cfilter *cf_h2;
  CURLcode result;

  DEBUGASSERT(Curl_conn_http_version(data, data->conn) < 20);

  result = http2_cfilter_insert_after(cf, data, FALSE);
  if(result)
    return result;

  cf_h2 = cf->next;
  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  Curl_multi_connchanged(data->multi);

  if(cf_h2->next) {
    bool done;
    return Curl_conn_cf_connect(cf_h2, data, &done);
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

  DEBUGASSERT(Curl_conn_http_version(data, conn) <  20);
  DEBUGASSERT(data->req.upgr101 == UPGR101_RECEIVED);

  result = http2_cfilter_add(&cf, data, conn, sockindex, TRUE);
  if(result)
    return result;
  CURL_TRC_CF(data, cf, "upgrading connection to HTTP/2");

  DEBUGASSERT(cf->cft == &Curl_cft_nghttp2);
  ctx = cf->ctx;

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

  conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  Curl_multi_connchanged(data->multi);

  if(cf->next) {
    bool done;
    return Curl_conn_cf_connect(cf, data, &done);
  }
  return CURLE_OK;
}

/* Only call this function for a transfer that already got an HTTP/2
   CURLE_HTTP2_STREAM error! */
bool Curl_h2_http_1_1_error(struct Curl_easy *data)
{
  if(Curl_conn_http_version(data, data->conn) == 20) {
    int err = Curl_conn_get_stream_error(data, data->conn, FIRSTSOCKET);
    return err == NGHTTP2_HTTP_1_1_REQUIRED;
  }
  return FALSE;
}

void *Curl_nghttp2_malloc(size_t size, void *user_data)
{
  (void)user_data;
  return Curl_cmalloc(size);
}

void Curl_nghttp2_free(void *ptr, void *user_data)
{
  (void)user_data;
  Curl_cfree(ptr);
}

void *Curl_nghttp2_calloc(size_t nmemb, size_t size, void *user_data)
{
  (void)user_data;
  return Curl_ccalloc(nmemb, size);
}

void *Curl_nghttp2_realloc(void *ptr, size_t size, void *user_data)
{
  (void)user_data;
  return Curl_crealloc(ptr, size);
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
