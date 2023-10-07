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
#include "http1.h"
#include "http2.h"
#include "http.h"
#include "sendf.h"
#include "select.h"
#include "curl_base64.h"
#include "strcase.h"
#include "multiif.h"
#include "url.h"
#include "urlapi-int.h"
#include "cfilters.h"
#include "connect.h"
#include "rand.h"
#include "strtoofft.h"
#include "strdup.h"
#include "transfer.h"
#include "dynbuf.h"
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
#define H2_STREAM_WINDOW_SIZE   (10 * 1024 * 1024)
/* on receiving from TLS, we prep for holding a full stream window */
#define H2_NW_RECV_CHUNKS       (H2_STREAM_WINDOW_SIZE / H2_CHUNK_SIZE)
/* on send into TLS, we just want to accumulate small frames */
#define H2_NW_SEND_CHUNKS       1
/* stream recv/send chunks are a result of window / chunk sizes */
#define H2_STREAM_RECV_CHUNKS   (H2_STREAM_WINDOW_SIZE / H2_CHUNK_SIZE)
/* keep smaller stream upload buffer (default h2 window size) to have
 * our progress bars and "upload done" reporting closer to reality */
#define H2_STREAM_SEND_CHUNKS   ((64 * 1024) / H2_CHUNK_SIZE)
/* spare chunks we keep for a full window */
#define H2_STREAM_POOL_SPARES   (H2_STREAM_WINDOW_SIZE / H2_CHUNK_SIZE)

/* We need to accommodate the max number of streams with their window
 * sizes on the overall connection. Streams might become PAUSED which
 * will block their received QUOTA in the connection window. And if we
 * run out of space, the server is blocked from sending us any data.
 * See #10988 for an issue with this. */
#define HTTP2_HUGE_WINDOW_SIZE (100 * H2_STREAM_WINDOW_SIZE)

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

  size_t drain_total; /* sum of all stream's UrlState drain */
  int32_t goaway_error;
  int32_t last_stream_id;
  BIT(conn_closed);
  BIT(goaway);
  BIT(enable_push);
  BIT(nw_out_blocked);
};

/* How to access `call_data` from a cf_h2 filter */
#undef CF_CTX_CALL_DATA
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

static CURLcode h2_progress_egress(struct Curl_cfilter *cf,
                                  struct Curl_easy *data);

/**
 * All about the H3 internals of a stream
 */
struct stream_ctx {
  /*********** for HTTP/2 we store stream-local data here *************/
  int32_t id; /* HTTP/2 protocol identifier for stream */
  struct bufq recvbuf; /* response buffer */
  struct bufq sendbuf; /* request buffer */
  struct h1_req_parser h1; /* parsing the request */
  struct dynhds resp_trailers; /* response trailer fields */
  size_t resp_hds_len; /* amount of response header bytes in recvbuf */
  size_t upload_blocked_len;
  curl_off_t upload_left; /* number of request bytes left to upload */

  char **push_headers;       /* allocated array */
  size_t push_headers_used;  /* number of entries filled in */
  size_t push_headers_alloc; /* number of entries allocated */

  int status_code; /* HTTP response status code */
  uint32_t error; /* stream error code */
  uint32_t local_window_size; /* the local recv window size */
  bool resp_hds_complete; /* we have a complete, final response */
  bool closed; /* TRUE on stream close */
  bool reset;  /* TRUE on stream reset */
  bool close_handled; /* TRUE if stream closure is handled by libcurl */
  bool bodystarted;
  bool send_closed; /* transfer is done sending, we might have still
                        buffered data in stream->sendbuf to upload. */
};

#define H2_STREAM_CTX(d)    ((struct stream_ctx *)(((d) && (d)->req.p.http)? \
                             ((struct HTTP *)(d)->req.p.http)->h2_ctx \
                               : NULL))
#define H2_STREAM_LCTX(d)   ((struct HTTP *)(d)->req.p.http)->h2_ctx
#define H2_STREAM_ID(d)     (H2_STREAM_CTX(d)? \
                             H2_STREAM_CTX(d)->id : -2)

/*
 * Mark this transfer to get "drained".
 */
static void drain_stream(struct Curl_cfilter *cf,
                         struct Curl_easy *data,
                         struct stream_ctx *stream)
{
  unsigned char bits;

  (void)cf;
  bits = CURL_CSELECT_IN;
  if(!stream->send_closed &&
     (stream->upload_left || stream->upload_blocked_len))
    bits |= CURL_CSELECT_OUT;
  if(data->state.dselect_bits != bits) {
    CURL_TRC_CF(data, cf, "[%d] DRAIN dselect_bits=%x",
                stream->id, bits);
    data->state.dselect_bits = bits;
    Curl_expire(data, 0, EXPIRE_RUN_NOW);
  }
}

static CURLcode http2_data_setup(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct stream_ctx **pstream)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct stream_ctx *stream;

  (void)cf;
  DEBUGASSERT(data);
  if(!data->req.p.http) {
    failf(data, "initialization failure, transfer not http initialized");
    return CURLE_FAILED_INIT;
  }
  stream = H2_STREAM_CTX(data);
  if(stream) {
    *pstream = stream;
    return CURLE_OK;
  }

  stream = calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->id = -1;
  Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                  H2_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  Curl_bufq_initp(&stream->recvbuf, &ctx->stream_bufcp,
                  H2_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);
  Curl_dynhds_init(&stream->resp_trailers, 0, DYN_HTTP_REQUEST);
  stream->resp_hds_len = 0;
  stream->bodystarted = FALSE;
  stream->status_code = -1;
  stream->closed = FALSE;
  stream->close_handled = FALSE;
  stream->error = NGHTTP2_NO_ERROR;
  stream->local_window_size = H2_STREAM_WINDOW_SIZE;
  stream->upload_left = 0;

  H2_STREAM_LCTX(data) = stream;
  *pstream = stream;
  return CURLE_OK;
}

static void http2_data_done(struct Curl_cfilter *cf,
                            struct Curl_easy *data, bool premature)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H2_STREAM_CTX(data);

  DEBUGASSERT(ctx);
  (void)premature;
  if(!stream)
    return;

  if(ctx->h2) {
    if(!stream->closed && stream->id > 0) {
      /* RST_STREAM */
      CURL_TRC_CF(data, cf, "[%d] premature DATA_DONE, RST stream",
                  stream->id);
      if(!nghttp2_submit_rst_stream(ctx->h2, NGHTTP2_FLAG_NONE,
                                    stream->id, NGHTTP2_STREAM_CLOSED))
        (void)nghttp2_session_send(ctx->h2);
    }
    if(!Curl_bufq_is_empty(&stream->recvbuf)) {
      /* Anything in the recvbuf is still being counted
       * in stream and connection window flow control. Need
       * to free that space or the connection window might get
       * exhausted eventually. */
      nghttp2_session_consume(ctx->h2, stream->id,
                              Curl_bufq_len(&stream->recvbuf));
      /* give WINDOW_UPATE a chance to be sent, but ignore any error */
      (void)h2_progress_egress(cf, data);
    }

    /* -1 means unassigned and 0 means cleared */
    if(nghttp2_session_get_stream_user_data(ctx->h2, stream->id)) {
      int rv = nghttp2_session_set_stream_user_data(ctx->h2,
                                                    stream->id, 0);
      if(rv) {
        infof(data, "http/2: failed to clear user_data for stream %u",
              stream->id);
        DEBUGASSERT(0);
      }
    }
  }

  Curl_bufq_free(&stream->sendbuf);
  Curl_bufq_free(&stream->recvbuf);
  Curl_h1_req_parse_free(&stream->h1);
  Curl_dynhds_free(&stream->resp_trailers);
  if(stream->push_headers) {
    /* if they weren't used and then freed before */
    for(; stream->push_headers_used > 0; --stream->push_headers_used) {
      free(stream->push_headers[stream->push_headers_used - 1]);
    }
    free(stream->push_headers);
    stream->push_headers = NULL;
  }

  free(stream);
  H2_STREAM_LCTX(data) = NULL;
}

static int h2_client_new(struct Curl_cfilter *cf,
                         nghttp2_session_callbacks *cbs)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  nghttp2_option *o;

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
  ssize_t nwritten;

  nwritten = Curl_conn_cf_send(cf->next, data, (const char *)buf, buflen, err);
  if(nwritten > 0)
    CURL_TRC_CF(data, cf, "[0] egress: wrote %zd bytes", nwritten);
  return nwritten;
}

static ssize_t send_callback(nghttp2_session *h2,
                             const uint8_t *mem, size_t length, int flags,
                             void *userp);
static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp);
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
static int error_callback(nghttp2_session *session, const char *msg,
                          size_t len, void *userp);

/*
 * Initialize the cfilter context
 */
static CURLcode cf_h2_ctx_init(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool via_h1_upgrade)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct stream_ctx *stream;
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
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  nghttp2_session_callbacks_set_on_frame_send_callback(cbs, on_frame_send);
#endif
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

  if(via_h1_upgrade) {
    /* HTTP/1.1 Upgrade issued. H2 Settings have already been submitted
     * in the H1 request and we upgrade from there. This stream
     * is opened implicitly as #1. */
    uint8_t binsettings[H2_BINSETTINGS_LEN];
    size_t  binlen; /* length of the binsettings data */

    binlen = populate_binsettings(binsettings, data);

    result = http2_data_setup(cf, data, &stream);
    if(result)
      goto out;
    DEBUGASSERT(stream);
    stream->id = 1;
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
    int ivlen;

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
              via_h1_upgrade? " (via h1 upgrade)" : "");

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
      failf(data,
            "process_pending_input: nghttp2_session_mem_recv() returned "
            "%zd:%s", rv, nghttp2_strerror((int)rv));
      *err = CURLE_RECV_ERROR;
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
    /* This happens before we've sent off a request and the connection is
       not in use by any other transfer, there shouldn't be any data here,
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
  return Curl_bufq_is_empty(&ctx->outbufq)? CURLE_OK: CURLE_AGAIN;
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
    struct stream_ctx *stream = H2_STREAM_CTX(h->data);
    if(stream && num < stream->push_headers_used)
      return stream->push_headers[num];
  }
  return NULL;
}

/*
 * push header access function. Only to be used from within the push callback
 */
char *curl_pushheader_byname(struct curl_pushheaders *h, const char *header)
{
  struct stream_ctx *stream;
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

  stream = H2_STREAM_CTX(h->data);
  if(!stream)
    return NULL;

  len = strlen(header);
  for(i = 0; i<stream->push_headers_used; i++) {
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
    /* setup the request struct */
    struct HTTP *http = calloc(1, sizeof(struct HTTP));
    if(!http) {
      (void)Curl_close(&second);
    }
    else {
      struct stream_ctx *second_stream;

      second->req.p.http = http;
      http2_data_setup(cf, second, &second_stream);
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
    uc = Curl_url_set_authority(u, v, CURLU_DISALLOW_USER);
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
  if(!newhandle->req.p.http) {
    http2_data_done(cf, newhandle, TRUE);
    newhandle->req.p.http = NULL;
  }
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
    struct stream_ctx *stream;
    struct stream_ctx *newstream;
    struct curl_pushheaders heads;
    CURLMcode rc;
    CURLcode result;
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
    CURL_TRC_CF(data, cf, "Got PUSH_PROMISE, ask application");

    stream = H2_STREAM_CTX(data);
    if(!stream) {
      failf(data, "Internal NULL stream");
      discard_newhandle(cf, newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

    rv = set_transfer_url(newhandle, &heads);
    if(rv) {
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
    DEBUGASSERT(stream);

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
      discard_newhandle(cf, newhandle);
      goto fail;
    }

    newstream->id = frame->promised_stream_id;
    newhandle->req.maxdownload = -1;
    newhandle->req.size = -1;

    /* approved, add to the multi handle and immediately switch to PERFORM
       state with the given connection !*/
    rc = Curl_multi_add_perform(data->multi, newhandle, cf->conn);
    if(rc) {
      infof(data, "failed to add handle to multi");
      discard_newhandle(cf, newhandle);
      rv = CURL_PUSH_DENY;
      goto fail;
    }

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
  }
  else {
    CURL_TRC_CF(data, cf, "Got PUSH_PROMISE, ignore it");
    rv = CURL_PUSH_DENY;
  }
fail:
  return rv;
}

static CURLcode recvbuf_write_hds(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  const char *buf, size_t blen)
{
  struct stream_ctx *stream = H2_STREAM_CTX(data);
  ssize_t nwritten;
  CURLcode result;

  (void)cf;
  nwritten = Curl_bufq_write(&stream->recvbuf,
                             (const unsigned char *)buf, blen, &result);
  if(nwritten < 0)
    return result;
  stream->resp_hds_len += (size_t)nwritten;
  DEBUGASSERT((size_t)nwritten == blen);
  return CURLE_OK;
}

static CURLcode on_stream_frame(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const nghttp2_frame *frame)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H2_STREAM_CTX(data);
  int32_t stream_id = frame->hd.stream_id;
  CURLcode result;
  size_t rbuflen;
  int rv;

  if(!stream) {
    CURL_TRC_CF(data, cf, "[%d] No stream_ctx set", stream_id);
    return CURLE_FAILED_INIT;
  }

  switch(frame->hd.type) {
  case NGHTTP2_DATA:
    rbuflen = Curl_bufq_len(&stream->recvbuf);
    CURL_TRC_CF(data, cf, "[%d] DATA, buffered=%zu, window=%d/%d",
                stream_id, rbuflen,
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
    if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      drain_stream(cf, data, stream);
    }
    else if(rbuflen > stream->local_window_size) {
      int32_t wsize = nghttp2_session_get_stream_local_window_size(
                        ctx->h2, stream->id);
      if(wsize > 0 && (uint32_t)wsize != stream->local_window_size) {
        /* H2 flow control is not absolute, as the server might not have the
         * same view, yet. When we receive more than we want, we enforce
         * the local window size again to make nghttp2 send WINDOW_UPATEs
         * accordingly. */
        nghttp2_session_set_local_window_size(ctx->h2,
                                              NGHTTP2_FLAG_NONE,
                                              stream->id,
                                              stream->local_window_size);
      }
    }
    break;
  case NGHTTP2_HEADERS:
    if(stream->bodystarted) {
      /* Only valid HEADERS after body started is trailer HEADERS.  We
         buffer them in on_header callback. */
      break;
    }

    /* nghttp2 guarantees that :status is received, and we store it to
       stream->status_code. Fuzzing has proven this can still be reached
       without status code having been set. */
    if(stream->status_code == -1)
      return CURLE_RECV_ERROR;

    /* Only final status code signals the end of header */
    if(stream->status_code / 100 != 1) {
      stream->bodystarted = TRUE;
      stream->status_code = -1;
    }

    result = recvbuf_write_hds(cf, data, STRCONST("\r\n"));
    if(result)
      return result;

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
    stream->send_closed = TRUE;
    data->req.keepon &= ~KEEP_SEND_HOLD;
    drain_stream(cf, data, stream);
    break;
  case NGHTTP2_WINDOW_UPDATE:
    if((data->req.keepon & KEEP_SEND_HOLD) &&
       (data->req.keepon & KEEP_SEND)) {
      data->req.keepon &= ~KEEP_SEND_HOLD;
      drain_stream(cf, data, stream);
      CURL_TRC_CF(data, cf, "[%d] un-holding after win update",
                  stream_id);
    }
    break;
  default:
    break;
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
      size_t s_len = sizeof(scratch)/sizeof(scratch[0]);
        size_t len = (frame->goaway.opaque_data_len < s_len)?
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
        if((data->req.keepon & KEEP_SEND_HOLD) &&
           (data->req.keepon & KEEP_SEND)) {
          struct stream_ctx *stream = H2_STREAM_CTX(data);
          data->req.keepon &= ~KEEP_SEND_HOLD;
          if(stream) {
            drain_stream(cf, data, stream);
            CURL_TRC_CF(data, cf, "[%d] un-holding after SETTINGS",
                        stream_id);
          }
        }
      }
      break;
    }
    case NGHTTP2_GOAWAY:
      ctx->goaway = TRUE;
      ctx->goaway_error = frame->goaway.error_code;
      ctx->last_stream_id = frame->goaway.last_stream_id;
      if(data) {
        infof(data, "received GOAWAY, error=%d, last_stream=%u",
                    ctx->goaway_error, ctx->last_stream_id);
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

  return on_stream_frame(cf, data_s, frame)? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

static int on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              const uint8_t *mem, size_t len, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct stream_ctx *stream;
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
    CURL_TRC_CF(CF_DATA_CURRENT(cf), cf, "[%d] Data for unknown",
                stream_id);
    /* consumed explicitly as no one will read it */
    nghttp2_session_consume(session, stream_id, len);
    return 0;
  }

  stream = H2_STREAM_CTX(data_s);
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  nwritten = Curl_bufq_write(&stream->recvbuf, mem, len, &result);
  if(nwritten < 0) {
    if(result != CURLE_AGAIN)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    nwritten = 0;
  }

  /* if we receive data for another handle, wake that up */
  drain_stream(cf, data_s, stream);

  DEBUGASSERT((size_t)nwritten == len);
  return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp)
{
  struct Curl_cfilter *cf = userp;
  struct Curl_easy *data_s;
  struct stream_ctx *stream;
  int rv;
  (void)session;

  /* get the stream from the hash based on Stream ID, stream ID zero is for
     connection-oriented stuff */
  data_s = stream_id?
             nghttp2_session_get_stream_user_data(session, stream_id) : NULL;
  if(!data_s) {
    return 0;
  }
  stream = H2_STREAM_CTX(data_s);
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  stream->closed = TRUE;
  stream->error = error_code;
  if(stream->error)
    stream->reset = TRUE;
  data_s->req.keepon &= ~KEEP_SEND_HOLD;

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
  struct stream_ctx *stream;
  struct Curl_easy *data_s = NULL;

  (void)cf;
  data_s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(!data_s) {
    return 0;
  }

  if(frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  stream = H2_STREAM_CTX(data_s);
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
  struct stream_ctx *stream;
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

  stream = H2_STREAM_CTX(data_s);
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
    CURL_TRC_CF(data_s, cf, "[%d] trailer: %.*s: %.*s",
                stream->id, (int)namelen, name, (int)valuelen, value);
    result = Curl_dynhds_add(&stream->resp_trailers,
                             (const char *)name, namelen,
                             (const char *)value, valuelen);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    return 0;
  }

  if(namelen == sizeof(HTTP_PSEUDO_STATUS) - 1 &&
     memcmp(HTTP_PSEUDO_STATUS, name, namelen) == 0) {
    /* nghttp2 guarantees :status is received first and only once. */
    char buffer[32];
    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)value, valuelen);
    if(result)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    msnprintf(buffer, sizeof(buffer), HTTP_PSEUDO_STATUS ":%u\r",
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

    CURL_TRC_CF(data_s, cf, "[%d] status: HTTP/2 %03d",
                stream->id, stream->status_code);
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
  struct Curl_easy *data_s;
  struct stream_ctx *stream = NULL;
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

    stream = H2_STREAM_CTX(data_s);
    if(!stream)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  else
    return NGHTTP2_ERR_INVALID_ARGUMENT;

  nread = Curl_bufq_read(&stream->sendbuf, buf, length, &result);
  if(nread < 0) {
    if(result != CURLE_AGAIN)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    nread = 0;
  }

  if(nread > 0 && stream->upload_left != -1)
    stream->upload_left -= nread;

  CURL_TRC_CF(data_s, cf, "[%d] req_body_read(len=%zu) left=%"
              CURL_FORMAT_CURL_OFF_T " -> %zd, %d",
              stream_id, length, stream->upload_left, nread, result);

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
  struct stream_ctx *stream = H2_STREAM_CTX(data);

  if(!ctx || !ctx->h2 || !stream)
    goto out;

  CURL_TRC_CF(data, cf, "[%d] data done send", stream->id);
  if(!stream->send_closed) {
    stream->send_closed = TRUE;
    if(stream->upload_left) {
      /* we now know that everything that is buffered is all there is. */
      stream->upload_left = Curl_bufq_len(&stream->sendbuf);
      /* resume sending here to trigger the callback to get called again so
         that it can signal EOF to nghttp2 */
      (void)nghttp2_session_resume_data(ctx->h2, stream->id);
      drain_stream(cf, data, stream);
    }
  }

out:
  return result;
}

static ssize_t http2_handle_stream_close(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct stream_ctx *stream,
                                         CURLcode *err)
{
  ssize_t rv = 0;

  if(stream->error == NGHTTP2_REFUSED_STREAM) {
    CURL_TRC_CF(data, cf, "[%d] REFUSED_STREAM, try again on a new "
                "connection", stream->id);
    connclose(cf->conn, "REFUSED_STREAM"); /* don't use this anymore */
    data->state.refused_stream = TRUE;
    *err = CURLE_RECV_ERROR; /* trigger Curl_retry_request() later */
    return -1;
  }
  else if(stream->error != NGHTTP2_NO_ERROR) {
    failf(data, "HTTP/2 stream %u was not closed cleanly: %s (err %u)",
          stream->id, nghttp2_http2_strerror(stream->error),
          stream->error);
    *err = CURLE_HTTP2_STREAM;
    return -1;
  }
  else if(stream->reset) {
    failf(data, "HTTP/2 stream %u was reset", stream->id);
    *err = stream->bodystarted? CURLE_PARTIAL_FILE : CURLE_RECV_ERROR;
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
  CURL_TRC_CF(data, cf, "handle_stream_close -> %zd, %d", rv, *err);
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
  struct stream_ctx *depstream = H2_STREAM_CTX(prio->parent);
  int32_t depstream_id = depstream? depstream->id:0;
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
  struct stream_ctx *stream = H2_STREAM_CTX(data);
  int rv = 0;

  if(stream && stream->id > 0 &&
     ((sweight_wanted(data) != sweight_in_effect(data)) ||
      (data->set.priority.exclusive != data->state.priority.exclusive) ||
      (data->set.priority.parent != data->state.priority.parent)) ) {
    /* send new weight and/or dependency */
    nghttp2_priority_spec pri_spec;

    h2_pri_spec(data, &pri_spec);
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
  return nw_out_flush(cf, data);
}

static ssize_t stream_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           struct stream_ctx *stream,
                           char *buf, size_t len, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  ssize_t nread = -1;

  *err = CURLE_AGAIN;
  if(!Curl_bufq_is_empty(&stream->recvbuf)) {
    nread = Curl_bufq_read(&stream->recvbuf,
                           (unsigned char *)buf, len, err);
    if(nread < 0)
      goto out;
    DEBUGASSERT(nread > 0);
  }

  if(nread < 0) {
    if(stream->closed) {
      CURL_TRC_CF(data, cf, "[%d] returning CLOSE", stream->id);
      nread = http2_handle_stream_close(cf, data, stream, err);
    }
    else if(stream->reset ||
            (ctx->conn_closed && Curl_bufq_is_empty(&ctx->inbufq)) ||
            (ctx->goaway && ctx->last_stream_id < stream->id)) {
      CURL_TRC_CF(data, cf, "[%d] returning ERR", stream->id);
      *err = stream->bodystarted? CURLE_PARTIAL_FILE : CURLE_RECV_ERROR;
      nread = -1;
    }
  }
  else if(nread == 0) {
    *err = CURLE_AGAIN;
    nread = -1;
  }

out:
  if(nread < 0 && *err != CURLE_AGAIN)
    CURL_TRC_CF(data, cf, "[%d] stream_recv(len=%zu) -> %zd, %d",
                stream->id, len, nread, *err);
  return nread;
}

static CURLcode h2_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct stream_ctx *stream;
  CURLcode result = CURLE_OK;
  ssize_t nread;

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
    stream = H2_STREAM_CTX(data);
    if(stream && (stream->closed || Curl_bufq_is_full(&stream->recvbuf))) {
      /* We would like to abort here and stop processing, so that
       * the transfer loop can handle the data/close here. However,
       * this may leave data in underlying buffers that will not
       * be consumed. */
      if(!cf->next || !cf->next->cft->has_data_pending(cf->next, data))
        break;
    }

    nread = Curl_bufq_slurp(&ctx->inbufq, nw_in_reader, cf, &result);
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
      CURL_TRC_CF(data, cf, "[0] ingress: read %zd bytes",
                  nread);
    }

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
  struct stream_ctx *stream = H2_STREAM_CTX(data);
  ssize_t nread = -1;
  CURLcode result;
  struct cf_call_data save;

  if(!stream) {
    /* Abnormal call sequence: either this transfer has never opened a stream
     * (unlikely) or the transfer has been done, cleaned up its resources, but
     * a read() is called anyway. It is not clear what the calling sequence
     * is for such a case. */
    failf(data, "[%zd-%zd], http/2 recv on a transfer never opened "
          "or already cleared", (ssize_t)data->id,
          (ssize_t)cf->conn->connection_id);
    *err = CURLE_HTTP2;
    return -1;
  }

  CF_DATA_SAVE(save, cf, data);

  nread = stream_recv(cf, data, stream, buf, len, err);
  if(nread < 0 && *err != CURLE_AGAIN)
    goto out;

  if(nread < 0) {
    *err = h2_progress_ingress(cf, data);
    if(*err)
      goto out;

    nread = stream_recv(cf, data, stream, buf, len, err);
  }

  if(nread > 0) {
    size_t data_consumed = (size_t)nread;
    /* Now that we transferred this to the upper layer, we report
     * the actual amount of DATA consumed to the H2 session, so
     * that it adjusts stream flow control */
    if(stream->resp_hds_len >= data_consumed) {
      stream->resp_hds_len -= data_consumed;  /* no DATA */
    }
    else {
      if(stream->resp_hds_len) {
        data_consumed -= stream->resp_hds_len;
        stream->resp_hds_len = 0;
      }
      if(data_consumed) {
        nghttp2_session_consume(ctx->h2, stream->id, data_consumed);
      }
    }

    if(stream->closed) {
      CURL_TRC_CF(data, cf, "[%d] DRAIN closed stream", stream->id);
      drain_stream(cf, data, stream);
    }
  }

out:
  result = h2_progress_egress(cf, data);
  if(result == CURLE_AGAIN) {
    /* pending data to send, need to be called again. Ideally, we'd
     * monitor the socket for POLLOUT, but we might not be in SENDING
     * transfer state any longer and are unable to make this happen.
     */
    drain_stream(cf, data, stream);
  }
  else if(result) {
    *err = result;
    nread = -1;
  }
  CURL_TRC_CF(data, cf, "[%d] cf_recv(len=%zu) -> %zd %d, "
              "buffered=%zu, window=%d/%d, connection %d/%d",
              stream->id, len, nread, *err,
              Curl_bufq_len(&stream->recvbuf),
              nghttp2_session_get_stream_effective_recv_data_length(
                ctx->h2, stream->id),
              nghttp2_session_get_stream_effective_local_window_size(
                ctx->h2, stream->id),
              nghttp2_session_get_local_window_size(ctx->h2),
              HTTP2_HUGE_WINDOW_SIZE);

  CF_DATA_RESTORE(cf, save);
  return nread;
}

static ssize_t h2_submit(struct stream_ctx **pstream,
                         struct Curl_cfilter *cf, struct Curl_easy *data,
                         const void *buf, size_t len, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = NULL;
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

  nheader = Curl_dynhds_count(&h2_headers);
  nva = malloc(sizeof(nghttp2_nv) * nheader);
  if(!nva) {
    *err = CURLE_OUT_OF_MEMORY;
    nwritten = -1;
    goto out;
  }

  for(i = 0; i < nheader; ++i) {
    struct dynhds_entry *e = Curl_dynhds_getn(&h2_headers, i);
    nva[i].name = (unsigned char *)e->name;
    nva[i].namelen = e->namelen;
    nva[i].value = (unsigned char *)e->value;
    nva[i].valuelen = e->valuelen;
    nva[i].flags = NGHTTP2_NV_FLAG_NONE;
  }

  h2_pri_spec(data, &pri_spec);
  if(!nghttp2_session_check_request_allowed(ctx->h2))
    CURL_TRC_CF(data, cf, "send request NOT allowed (via nghttp2)");

  switch(data->state.httpreq) {
  case HTTPREQ_POST:
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
  case HTTPREQ_PUT:
    if(data->state.infilesize != -1)
      stream->upload_left = data->state.infilesize;
    else
      /* data sending without specifying the data amount up front */
      stream->upload_left = -1; /* unknown */

    data_prd.read_callback = req_body_read_callback;
    data_prd.source.ptr = NULL;
    stream_id = nghttp2_submit_request(ctx->h2, &pri_spec, nva, nheader,
                                       &data_prd, data);
    break;
  default:
    stream->upload_left = 0; /* no request body */
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
  stream->local_window_size = H2_STREAM_WINDOW_SIZE;
  if(data->set.max_recv_speed) {
    /* We are asked to only receive `max_recv_speed` bytes per second.
     * Let's limit our stream window size around that, otherwise the server
     * will send in large bursts only. We make the window 50% larger to
     * allow for data in flight and avoid stalling. */
    curl_off_t n = (((data->set.max_recv_speed - 1) / H2_CHUNK_SIZE) + 1);
    n += CURLMAX((n/2), 1);
    if(n < (H2_STREAM_WINDOW_SIZE / H2_CHUNK_SIZE) &&
       n < (UINT_MAX / H2_CHUNK_SIZE)) {
      stream->local_window_size = (uint32_t)n * H2_CHUNK_SIZE;
    }
  }

  body = (const char *)buf + nwritten;
  bodylen = len - nwritten;

  if(bodylen) {
    /* We have request body to send in DATA frame */
    ssize_t n = Curl_bufq_write(&stream->sendbuf, body, bodylen, err);
    if(n < 0) {
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
      goto out;
    }
    nwritten += n;
  }

out:
  CURL_TRC_CF(data, cf, "[%d] submit -> %zd, %d",
              stream? stream->id : -1, nwritten, *err);
  Curl_safefree(nva);
  *pstream = stream;
  Curl_dynhds_free(&h2_headers);
  return nwritten;
}

static ssize_t cf_h2_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H2_STREAM_CTX(data);
  struct cf_call_data save;
  int rv;
  ssize_t nwritten;
  CURLcode result;
  int blocked = 0, was_blocked = 0;

  CF_DATA_SAVE(save, cf, data);

  if(stream && stream->id != -1) {
    if(stream->upload_blocked_len) {
      /* the data in `buf` has already been submitted or added to the
       * buffers, but have been EAGAINed on the last invocation. */
      /* TODO: this assertion triggers in OSSFuzz runs and it is not
       * clear why. Disable for now to let OSSFuzz continue its tests. */
      DEBUGASSERT(len >= stream->upload_blocked_len);
      if(len < stream->upload_blocked_len) {
        /* Did we get called again with a smaller `len`? This should not
         * happen. We are not prepared to handle that. */
        failf(data, "HTTP/2 send again with decreased length (%zd vs %zd)",
              len, stream->upload_blocked_len);
        *err = CURLE_HTTP2;
        nwritten = -1;
        goto out;
      }
      nwritten = (ssize_t)stream->upload_blocked_len;
      stream->upload_blocked_len = 0;
      was_blocked = 1;
    }
    else if(stream->closed) {
      if(stream->resp_hds_complete) {
        /* Server decided to close the stream after having sent us a findl
         * response. This is valid if it is not interested in the request
         * body. This happens on 30x or 40x responses.
         * We silently discard the data sent, since this is not a transport
         * error situation. */
        CURL_TRC_CF(data, cf, "[%d] discarding data"
                    "on closed stream with response", stream->id);
        *err = CURLE_OK;
        nwritten = (ssize_t)len;
        goto out;
      }
      infof(data, "stream %u closed", stream->id);
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
      goto out;
    }
    else {
      /* If stream_id != -1, we have dispatched request HEADERS and
       * optionally request body, and now are going to send or sending
       * more request body in DATA frame */
      nwritten = Curl_bufq_write(&stream->sendbuf, buf, len, err);
      if(nwritten < 0 && *err != CURLE_AGAIN)
        goto out;
    }

    if(!Curl_bufq_is_empty(&stream->sendbuf)) {
      /* req body data is buffered, resume the potentially suspended stream */
      rv = nghttp2_session_resume_data(ctx->h2, stream->id);
      if(nghttp2_is_fatal(rv)) {
        *err = CURLE_SEND_ERROR;
        nwritten = -1;
        goto out;
      }
    }
  }
  else {
    nwritten = h2_submit(&stream, cf, data, buf, len, err);
    if(nwritten < 0) {
      goto out;
    }
    DEBUGASSERT(stream);
  }

  /* Call the nghttp2 send loop and flush to write ALL buffered data,
   * headers and/or request body completely out to the network */
  result = h2_progress_egress(cf, data);
  /* if the stream has been closed in egress handling (nghttp2 does that
   * when it does not like the headers, for example */
  if(stream && stream->closed && !was_blocked) {
    infof(data, "stream %u closed", stream->id);
    *err = CURLE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }
  else if(result == CURLE_AGAIN) {
    blocked = 1;
  }
  else if(result) {
    *err = result;
    nwritten = -1;
    goto out;
  }
  else if(stream && !Curl_bufq_is_empty(&stream->sendbuf)) {
    /* although we wrote everything that nghttp2 wants to send now,
     * there is data left in our stream send buffer unwritten. This may
     * be due to the stream's HTTP/2 flow window being exhausted. */
    blocked = 1;
  }

  if(stream && blocked && nwritten > 0) {
    /* Unable to send all data, due to connection blocked or H2 window
     * exhaustion. Data is left in our stream buffer, or nghttp2's internal
     * frame buffer or our network out buffer. */
    size_t rwin = nghttp2_session_get_stream_remote_window_size(ctx->h2,
                                                                stream->id);
    if(rwin == 0) {
      /* H2 flow window exhaustion. We need to HOLD upload until we get
       * a WINDOW_UPDATE from the server. */
      data->req.keepon |= KEEP_SEND_HOLD;
      CURL_TRC_CF(data, cf, "[%d] holding send as remote flow "
                  "window is exhausted", stream->id);
    }

    /* Whatever the cause, we need to return CURL_EAGAIN for this call.
     * We have unwritten state that needs us being invoked again and EAGAIN
     * is the only way to ensure that. */
    stream->upload_blocked_len = nwritten;
    CURL_TRC_CF(data, cf, "[%d] cf_send(len=%zu) BLOCK: win %u/%zu "
                "blocked_len=%zu",
                stream->id, len,
                nghttp2_session_get_remote_window_size(ctx->h2), rwin,
                nwritten);
    *err = CURLE_AGAIN;
    nwritten = -1;
    goto out;
  }
  else if(should_close_session(ctx)) {
    /* nghttp2 thinks this session is done. If the stream has not been
     * closed, this is an error state for out transfer */
    if(stream->closed) {
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
                "upload_left=%" CURL_FORMAT_CURL_OFF_T ", "
                "h2 windows %d-%d (stream-conn), "
                "buffers %zu-%zu (stream-conn)",
                stream->id, len, nwritten, *err,
                stream->upload_left,
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

static int cf_h2_get_select_socks(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  curl_socket_t *sock)
{
  struct cf_h2_ctx *ctx = cf->ctx;
  struct SingleRequest *k = &data->req;
  struct stream_ctx *stream = H2_STREAM_CTX(data);
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
                                                    stream->id)))
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

  /* Send out our SETTINGS and ACKs and such. If that blocks, we
   * have it buffered and  can count this filter as being connected */
  result = h2_progress_egress(cf, data);
  if(result == CURLE_AGAIN)
    result = CURLE_OK;
  else if(result)
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
    cf_h2_ctx_clear(ctx);
    CF_DATA_RESTORE(cf, save);
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

static CURLcode http2_data_pause(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool pause)
{
#ifdef NGHTTP2_HAS_SET_LOCAL_WINDOW_SIZE
  struct cf_h2_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H2_STREAM_CTX(data);

  DEBUGASSERT(data);
  if(ctx && ctx->h2 && stream) {
    uint32_t window = pause? 0 : stream->local_window_size;

    int rv = nghttp2_session_set_local_window_size(ctx->h2,
                                                   NGHTTP2_FLAG_NONE,
                                                   stream->id,
                                                   window);
    if(rv) {
      failf(data, "nghttp2_session_set_local_window_size() failed: %s(%d)",
            nghttp2_strerror(rv), rv);
      return CURLE_HTTP2;
    }

    if(!pause)
      drain_stream(cf, data, stream);

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
    DEBUGF(infof(data, "Set HTTP/2 window size to %u for stream %u",
                 window, stream->id));

#ifdef DEBUGBUILD
    {
      /* read out the stream local window again */
      uint32_t window2 =
        nghttp2_session_get_stream_local_window_size(ctx->h2,
                                                     stream->id);
      DEBUGF(infof(data, "HTTP/2 window size is now %u for stream %u",
                   window2, stream->id));
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
  case CF_CTRL_DATA_SETUP:
    break;
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
  struct stream_ctx *stream = H2_STREAM_CTX(data);

  if(ctx && (!Curl_bufq_is_empty(&ctx->inbufq)
            || (stream && !Curl_bufq_is_empty(&stream->sendbuf))
            || (stream && !Curl_bufq_is_empty(&stream->recvbuf))))
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
  CURL_LOG_LVL_NONE,
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

static bool Curl_cf_is_http2(struct Curl_cfilter *cf,
                             const struct Curl_easy *data)
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
  DEBUGF(infof(data, "switching to HTTP/2"));

  result = http2_cfilter_add(&cf, data, conn, sockindex);
  if(result)
    return result;

  result = cf_h2_ctx_init(cf, data, FALSE);
  if(result)
    return result;

  conn->httpversion = 20; /* we know we're on HTTP/2 now */
  conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  conn->bundle->multiuse = BUNDLE_MULTIPLEX;
  Curl_multi_connchanged(data->multi);

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
  Curl_multi_connchanged(data->multi);

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
  DEBUGF(infof(data, "upgrading to HTTP/2"));
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
  Curl_multi_connchanged(data->multi);

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
  struct stream_ctx *stream = H2_STREAM_CTX(data);
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
