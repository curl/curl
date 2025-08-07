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

#include "../curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_QUICHE)
#include <quiche.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "../bufq.h"
#include "../uint-hash.h"
#include "../urldata.h"
#include "../cfilters.h"
#include "../cf-socket.h"
#include "../sendf.h"
#include "../strdup.h"
#include "../rand.h"
#include "../multiif.h"
#include "../connect.h"
#include "../progress.h"
#include "../strerror.h"
#include "../select.h"
#include "../http1.h"
#include "vquic.h"
#include "vquic_int.h"
#include "vquic-tls.h"
#include "curl_quiche.h"
#include "../transfer.h"
#include "../url.h"
#include "../curlx/inet_pton.h"
#include "../vtls/openssl.h"
#include "../vtls/keylog.h"
#include "../vtls/vtls.h"

/* The last 3 #include files should be in this order */
#include "../curl_printf.h"
#include "../curl_memory.h"
#include "../memdebug.h"

/* HTTP/3 error values defined in RFC 9114, ch. 8.1 */
#define CURL_H3_NO_ERROR  (0x0100)

#define QUIC_MAX_STREAMS              (100)

#define H3_STREAM_WINDOW_SIZE  (128 * 1024)
#define H3_STREAM_CHUNK_SIZE    (16 * 1024)
/* The pool keeps spares around and half of a full stream windows seems good.
 * More does not seem to improve performance. The benefit of the pool is that
 * stream buffer to not keep spares. Memory consumption goes down when streams
 * run empty, have a large upload done, etc. */
#define H3_STREAM_POOL_SPARES \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE ) / 2
/* Receive and Send max number of chunks just follows from the
 * chunk size and window size */
#define H3_STREAM_RECV_CHUNKS \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)
#define H3_STREAM_SEND_CHUNKS \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)

/*
 * Store quiche version info in this buffer.
 */
void Curl_quiche_ver(char *p, size_t len)
{
  (void)msnprintf(p, len, "quiche/%s", quiche_version());
}

struct cf_quiche_ctx {
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
  quiche_conn *qconn;
  quiche_config *cfg;
  quiche_h3_conn *h3c;
  quiche_h3_config *h3config;
  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  struct curltime started_at;        /* time the current attempt started */
  struct curltime handshake_at;      /* time connect handshake finished */
  struct bufc_pool stream_bufcp;     /* chunk pool for streams */
  struct uint_hash streams;          /* hash `data->mid` to `stream_ctx` */
  curl_off_t data_recvd;
  BIT(initialized);
  BIT(goaway);                       /* got GOAWAY from server */
  BIT(x509_store_setup);             /* if x509 store has been set up */
  BIT(shutdown_started);             /* queued shutdown packets */
};

#ifdef DEBUG_QUICHE
/* initialize debug log callback only once */
static int debug_log_init = 0;
static void quiche_debug_log(const char *line, void *argp)
{
  (void)argp;
  fprintf(stderr, "%s\n", line);
}
#endif

static void h3_stream_hash_free(unsigned int id, void *stream);

static void cf_quiche_ctx_init(struct cf_quiche_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
#ifdef DEBUG_QUICHE
  if(!debug_log_init) {
    quiche_enable_debug_logging(quiche_debug_log, NULL);
    debug_log_init = 1;
  }
#endif
  Curl_bufcp_init(&ctx->stream_bufcp, H3_STREAM_CHUNK_SIZE,
                  H3_STREAM_POOL_SPARES);
  Curl_uint_hash_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->data_recvd = 0;
  ctx->initialized = TRUE;
}

static void cf_quiche_ctx_free(struct cf_quiche_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    /* quiche just freed it */
    ctx->tls.ossl.ssl = NULL;
    Curl_vquic_tls_cleanup(&ctx->tls);
    Curl_ssl_peer_cleanup(&ctx->peer);
    vquic_ctx_free(&ctx->q);
    Curl_bufcp_free(&ctx->stream_bufcp);
    Curl_uint_hash_destroy(&ctx->streams);
  }
  free(ctx);
}

static void cf_quiche_ctx_close(struct cf_quiche_ctx *ctx)
{
  if(ctx->h3c)
    quiche_h3_conn_free(ctx->h3c);
  if(ctx->h3config)
    quiche_h3_config_free(ctx->h3config);
  if(ctx->qconn)
    quiche_conn_free(ctx->qconn);
  if(ctx->cfg)
    quiche_config_free(ctx->cfg);
}

static CURLcode cf_flush_egress(struct Curl_cfilter *cf,
                                struct Curl_easy *data);

/**
 * All about the H3 internals of a stream
 */
struct h3_stream_ctx {
  curl_uint64_t id; /* HTTP/3 protocol stream identifier */
  struct bufq recvbuf; /* h3 response */
  struct h1_req_parser h1; /* h1 request parsing */
  curl_uint64_t error3; /* HTTP/3 stream error code */
  BIT(opened); /* TRUE after stream has been opened */
  BIT(closed); /* TRUE on stream close */
  BIT(reset);  /* TRUE on stream reset */
  BIT(send_closed); /* stream is locally closed */
  BIT(resp_hds_complete);  /* final response has been received */
  BIT(resp_got_header); /* TRUE when h3 stream has recvd some HEADER */
  BIT(quic_flow_blocked); /* stream is blocked by QUIC flow control */
};

static void h3_stream_ctx_free(struct h3_stream_ctx *stream)
{
  Curl_bufq_free(&stream->recvbuf);
  Curl_h1_req_parse_free(&stream->h1);
  free(stream);
}

static void h3_stream_hash_free(unsigned int id, void *stream)
{
  (void)id;
  DEBUGASSERT(stream);
  h3_stream_ctx_free((struct h3_stream_ctx *)stream);
}

typedef bool cf_quiche_svisit(struct Curl_cfilter *cf,
                              struct Curl_easy *sdata,
                              struct h3_stream_ctx *stream,
                              void *user_data);

struct cf_quiche_visit_ctx {
  struct Curl_cfilter *cf;
  struct Curl_multi *multi;
  cf_quiche_svisit *cb;
  void *user_data;
};

static bool cf_quiche_stream_do(unsigned int mid, void *val, void *user_data)
{
  struct cf_quiche_visit_ctx *vctx = user_data;
  struct h3_stream_ctx *stream = val;
  struct Curl_easy *sdata = Curl_multi_get_easy(vctx->multi, mid);
  if(sdata)
    return vctx->cb(vctx->cf, sdata, stream, vctx->user_data);
  return TRUE;
}

static void cf_quiche_for_all_streams(struct Curl_cfilter *cf,
                                      struct Curl_multi *multi,
                                      cf_quiche_svisit *do_cb,
                                      void *user_data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct cf_quiche_visit_ctx vctx;
  vctx.cf = cf;
  vctx.multi = multi;
  vctx.cb = do_cb;
  vctx.user_data = user_data;
  Curl_uint_hash_visit(&ctx->streams, cf_quiche_stream_do, &vctx);
}

static bool cf_quiche_do_resume(struct Curl_cfilter *cf,
                                struct Curl_easy *sdata,
                                struct h3_stream_ctx *stream,
                                void *user_data)
{
  (void)user_data;
  if(stream->quic_flow_blocked) {
    stream->quic_flow_blocked = FALSE;
    Curl_multi_mark_dirty(sdata);
    CURL_TRC_CF(sdata, cf, "[%"FMT_PRIu64"] unblock", stream->id);
  }
  return TRUE;
}

static bool cf_quiche_do_expire(struct Curl_cfilter *cf,
                                struct Curl_easy *sdata,
                                struct h3_stream_ctx *stream,
                                void *user_data)
{
  (void)stream;
  (void)user_data;
  CURL_TRC_CF(sdata, cf, "conn closed, mark as dirty");
  Curl_multi_mark_dirty(sdata);
  return TRUE;
}

static CURLcode h3_data_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  if(stream)
    return CURLE_OK;

  stream = calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->id = -1;
  Curl_bufq_initp(&stream->recvbuf, &ctx->stream_bufcp,
                  H3_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);

  if(!Curl_uint_hash_set(&ctx->streams, data->mid, stream)) {
    h3_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static void h3_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result;

  (void)cf;
  if(stream) {
    CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] easy handle is done", stream->id);
    if(ctx->qconn && !stream->closed) {
      quiche_conn_stream_shutdown(ctx->qconn, stream->id,
                                  QUICHE_SHUTDOWN_READ, CURL_H3_NO_ERROR);
      if(!stream->send_closed) {
        quiche_conn_stream_shutdown(ctx->qconn, stream->id,
                                    QUICHE_SHUTDOWN_WRITE, CURL_H3_NO_ERROR);
        stream->send_closed = TRUE;
      }
      stream->closed = TRUE;
      result = cf_flush_egress(cf, data);
      if(result)
        CURL_TRC_CF(data, cf, "data_done, flush egress -> %d", result);
    }
    Curl_uint_hash_remove(&ctx->streams, data->mid);
  }
}

static void cf_quiche_expire_conn_closed(struct Curl_cfilter *cf,
                                         struct Curl_easy *data)
{
  DEBUGASSERT(data->multi);
  CURL_TRC_CF(data, cf, "conn closed, expire all transfers");
  cf_quiche_for_all_streams(cf, data->multi, cf_quiche_do_expire, NULL);
}

/*
 * write_resp_raw() copies response data in raw format to the `data`'s
  * receive buffer. If not enough space is available, it appends to the
 * `data`'s overflow buffer.
 */
static CURLcode write_resp_raw(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const void *mem, size_t memlen)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;
  size_t nwritten;

  (void)cf;
  if(!stream)
    return CURLE_RECV_ERROR;
  result = Curl_bufq_write(&stream->recvbuf, mem, memlen, &nwritten);
  if(result)
    return result;

  if(nwritten < memlen) {
    /* This MUST not happen. Our recbuf is dimensioned to hold the
     * full max_stream_window and then some for this very reason. */
    DEBUGASSERT(0);
    return CURLE_RECV_ERROR;
  }
  return result;
}

struct cb_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
};

static int cb_each_header(uint8_t *name, size_t name_len,
                          uint8_t *value, size_t value_len,
                          void *argp)
{
  struct cb_ctx *x = argp;
  struct cf_quiche_ctx *ctx = x->cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, x->data);
  CURLcode result;

  if(!stream)
    return CURLE_OK;

  if((name_len == 7) && !strncmp(HTTP_PSEUDO_STATUS, (char *)name, 7)) {
    CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRIu64 "] status: %.*s",
                stream->id, (int)value_len, value);
    result = write_resp_raw(x->cf, x->data, "HTTP/3 ", sizeof("HTTP/3 ") - 1);
    if(!result)
      result = write_resp_raw(x->cf, x->data, value, value_len);
    if(!result)
      result = write_resp_raw(x->cf, x->data, " \r\n", 3);
  }
  else {
    CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRIu64 "] header: %.*s: %.*s",
                stream->id, (int)name_len, name,
                (int)value_len, value);
    result = write_resp_raw(x->cf, x->data, name, name_len);
    if(!result)
      result = write_resp_raw(x->cf, x->data, ": ", 2);
    if(!result)
      result = write_resp_raw(x->cf, x->data, value, value_len);
    if(!result)
      result = write_resp_raw(x->cf, x->data, "\r\n", 2);
  }
  if(result) {
    CURL_TRC_CF(x->data, x->cf, "[%"FMT_PRIu64"] on header error %d",
                stream->id, result);
  }
  return result;
}

static CURLcode stream_resp_read(void *reader_ctx,
                                 unsigned char *buf, size_t len,
                                 size_t *pnread)
{
  struct cb_ctx *x = reader_ctx;
  struct cf_quiche_ctx *ctx = x->cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, x->data);
  ssize_t nread;

  *pnread = 0;
  if(!stream)
    return CURLE_RECV_ERROR;

  nread = quiche_h3_recv_body(ctx->h3c, ctx->qconn, stream->id, buf, len);
  if(nread >= 0) {
    *pnread = (size_t)nread;
    return CURLE_OK;
  }
  else
    return CURLE_AGAIN;
}

static CURLcode cf_recv_body(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  size_t nread;
  struct cb_ctx cb_ctx;
  CURLcode result = CURLE_OK;

  if(!stream)
    return CURLE_RECV_ERROR;

  if(!stream->resp_hds_complete) {
    result = write_resp_raw(cf, data, "\r\n", 2);
    if(result)
      return result;
    stream->resp_hds_complete = TRUE;
  }

  cb_ctx.cf = cf;
  cb_ctx.data = data;
  result = Curl_bufq_slurp(&stream->recvbuf,
                           stream_resp_read, &cb_ctx, &nread);

  if(result && result != CURLE_AGAIN) {
    CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] recv_body error %zu",
                stream->id, nread);
    failf(data, "Error %d in HTTP/3 response body for stream[%"FMT_PRIu64"]",
          result, stream->id);
    stream->closed = TRUE;
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    streamclose(cf->conn, "Reset of stream");
    return result;
  }
  return CURLE_OK;
}

#ifdef DEBUGBUILD
static const char *cf_ev_name(quiche_h3_event *ev)
{
  switch(quiche_h3_event_type(ev)) {
  case QUICHE_H3_EVENT_HEADERS:
    return "HEADERS";
  case QUICHE_H3_EVENT_DATA:
    return "DATA";
  case QUICHE_H3_EVENT_RESET:
    return "RESET";
  case QUICHE_H3_EVENT_FINISHED:
    return "FINISHED";
  case QUICHE_H3_EVENT_GOAWAY:
    return "GOAWAY";
  default:
    return "Unknown";
  }
}
#else
#define cf_ev_name(x)   ""
#endif

static CURLcode h3_process_event(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct h3_stream_ctx *stream,
                                 quiche_h3_event *ev)
{
  struct cb_ctx cb_ctx;
  CURLcode result = CURLE_OK;
  int rc;

  if(!stream)
    return CURLE_OK;
  switch(quiche_h3_event_type(ev)) {
  case QUICHE_H3_EVENT_HEADERS:
    stream->resp_got_header = TRUE;
    cb_ctx.cf = cf;
    cb_ctx.data = data;
    rc = quiche_h3_event_for_each_header(ev, cb_each_header, &cb_ctx);
    if(rc) {
      failf(data, "Error %d in HTTP/3 response header for stream[%"
            FMT_PRIu64"]", rc, stream->id);
      return CURLE_RECV_ERROR;
    }
    CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] <- [HEADERS]", stream->id);
    break;

  case QUICHE_H3_EVENT_DATA:
    if(!stream->closed) {
      result = cf_recv_body(cf, data);
    }
    break;

  case QUICHE_H3_EVENT_RESET:
    CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] RESET", stream->id);
    stream->closed = TRUE;
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    streamclose(cf->conn, "Reset of stream");
    break;

  case QUICHE_H3_EVENT_FINISHED:
    CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] CLOSED", stream->id);
    if(!stream->resp_hds_complete) {
      result = write_resp_raw(cf, data, "\r\n", 2);
      if(result)
        return result;
      stream->resp_hds_complete = TRUE;
    }
    stream->closed = TRUE;
    streamclose(cf->conn, "End of stream");
    break;

  case QUICHE_H3_EVENT_GOAWAY:
    CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] <- [GOAWAY]", stream->id);
    break;

  default:
    CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] recv, unhandled event %d",
                stream->id, quiche_h3_event_type(ev));
    break;
  }
  return result;
}

static CURLcode cf_quiche_ev_process(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct h3_stream_ctx *stream,
                                     quiche_h3_event *ev)
{
  CURLcode result = h3_process_event(cf, data, stream, ev);
  Curl_multi_mark_dirty(data);
  if(result)
    CURL_TRC_CF(data, cf, "error processing event %s "
                "for [%"FMT_PRIu64"] -> %d", cf_ev_name(ev),
                stream->id, result);
  return result;
}

struct cf_quich_disp_ctx {
  curl_uint64_t stream_id;
  struct Curl_cfilter *cf;
  struct Curl_multi *multi;
  quiche_h3_event *ev;
  CURLcode result;
};

static bool cf_quiche_disp_event(unsigned int mid, void *val, void *user_data)
{
  struct cf_quich_disp_ctx *dctx = user_data;
  struct h3_stream_ctx *stream = val;

  if(stream->id == dctx->stream_id) {
    struct Curl_easy *sdata = Curl_multi_get_easy(dctx->multi, mid);
    if(sdata)
      dctx->result = cf_quiche_ev_process(dctx->cf, sdata, stream, dctx->ev);
    return FALSE; /* stop iterating */
  }
  return TRUE;
}

static CURLcode cf_poll_events(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = NULL;
  quiche_h3_event *ev;

  /* Take in the events and distribute them to the transfers. */
  while(ctx->h3c) {
    curl_int64_t stream3_id = quiche_h3_conn_poll(ctx->h3c, ctx->qconn, &ev);
    if(stream3_id == QUICHE_H3_ERR_DONE) {
      break;
    }
    else if(stream3_id < 0) {
      CURL_TRC_CF(data, cf, "error poll: %"FMT_PRId64, stream3_id);
      return CURLE_HTTP3;
    }
    else {
      struct cf_quich_disp_ctx dctx;
      dctx.stream_id = (curl_uint64_t)stream3_id;
      dctx.cf = cf;
      dctx.multi = data->multi;
      dctx.ev = ev;
      dctx.result = CURLE_OK;
      stream = H3_STREAM_CTX(ctx, data);
      if(stream && stream->id == dctx.stream_id) {
        /* event for calling transfer */
        CURLcode result = cf_quiche_ev_process(cf, data, stream, ev);
        quiche_h3_event_free(ev);
        if(result)
          return result;
      }
      else {
        /* another transfer, do not return errors, as they are not for
         * the calling transfer */
        Curl_uint_hash_visit(&ctx->streams, cf_quiche_disp_event, &dctx);
        quiche_h3_event_free(ev);
      }
    }
  }
  return CURLE_OK;
}

struct recv_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  int pkts;
};

static CURLcode recv_pkt(const unsigned char *pkt, size_t pktlen,
                         struct sockaddr_storage *remote_addr,
                         socklen_t remote_addrlen, int ecn,
                         void *userp)
{
  struct recv_ctx *r = userp;
  struct cf_quiche_ctx *ctx = r->cf->ctx;
  quiche_recv_info recv_info;
  ssize_t nread;

  (void)ecn;
  ++r->pkts;

  recv_info.to = (struct sockaddr *)&ctx->q.local_addr;
  recv_info.to_len = ctx->q.local_addrlen;
  recv_info.from = (struct sockaddr *)remote_addr;
  recv_info.from_len = remote_addrlen;

  nread = quiche_conn_recv(ctx->qconn,
                           (unsigned char *)CURL_UNCONST(pkt), pktlen,
                           &recv_info);
  if(nread < 0) {
    if(QUICHE_ERR_DONE == nread) {
      if(quiche_conn_is_draining(ctx->qconn)) {
        CURL_TRC_CF(r->data, r->cf, "ingress, connection is draining");
        return CURLE_RECV_ERROR;
      }
      if(quiche_conn_is_closed(ctx->qconn)) {
        CURL_TRC_CF(r->data, r->cf, "ingress, connection is closed");
        return CURLE_RECV_ERROR;
      }
      CURL_TRC_CF(r->data, r->cf, "ingress, quiche is DONE");
      return CURLE_OK;
    }
    else if(QUICHE_ERR_TLS_FAIL == nread) {
      long verify_ok = SSL_get_verify_result(ctx->tls.ossl.ssl);
      if(verify_ok != X509_V_OK) {
        failf(r->data, "SSL certificate problem: %s",
              X509_verify_cert_error_string(verify_ok));
        return CURLE_PEER_FAILED_VERIFICATION;
      }
    }
    else {
      failf(r->data, "quiche_conn_recv() == %zd", nread);
      return CURLE_RECV_ERROR;
    }
  }
  else if((size_t)nread < pktlen) {
    CURL_TRC_CF(r->data, r->cf, "ingress, quiche only read %zd/%zu bytes",
                nread, pktlen);
  }

  return CURLE_OK;
}

static CURLcode cf_process_ingress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct recv_ctx rctx;
  CURLcode result;

  DEBUGASSERT(ctx->qconn);
  result = Curl_vquic_tls_before_recv(&ctx->tls, cf, data);
  if(result)
    return result;

  rctx.cf = cf;
  rctx.data = data;
  rctx.pkts = 0;

  result = vquic_recv_packets(cf, data, &ctx->q, 1000, recv_pkt, &rctx);
  if(result)
    return result;

  if(rctx.pkts > 0) {
    /* quiche digested ingress packets. It might have opened flow control
     * windows again. */
    DEBUGASSERT(data->multi);
    cf_quiche_for_all_streams(cf, data->multi, cf_quiche_do_resume, NULL);
  }
  return cf_poll_events(cf, data);
}

struct read_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  quiche_send_info send_info;
};

static CURLcode read_pkt_to_send(void *userp,
                                 unsigned char *buf, size_t buflen,
                                 size_t *pnread)
{
  struct read_ctx *x = userp;
  struct cf_quiche_ctx *ctx = x->cf->ctx;
  ssize_t n;

  *pnread = 0;
  n = quiche_conn_send(ctx->qconn, buf, buflen, &x->send_info);
  if(n == QUICHE_ERR_DONE)
    return CURLE_AGAIN;

  if(n < 0) {
    failf(x->data, "quiche_conn_send returned %zd", n);
    return CURLE_SEND_ERROR;
  }
  *pnread = (size_t)n;
  return CURLE_OK;
}

/*
 * flush_egress drains the buffers and sends off data.
 * Calls failf() on errors.
 */
static CURLcode cf_flush_egress(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  size_t nread;
  CURLcode result;
  curl_int64_t expiry_ns;
  curl_int64_t timeout_ns;
  struct read_ctx readx;
  size_t pkt_count, gsolen;

  expiry_ns = quiche_conn_timeout_as_nanos(ctx->qconn);
  if(!expiry_ns) {
    quiche_conn_on_timeout(ctx->qconn);
    if(quiche_conn_is_closed(ctx->qconn)) {
      if(quiche_conn_is_timed_out(ctx->qconn))
        failf(data, "connection closed by idle timeout");
      else
        failf(data, "connection closed by server");
      /* Connection timed out, expire all transfers belonging to it
       * as will not get any more POLL events here. */
      cf_quiche_expire_conn_closed(cf, data);
      return CURLE_SEND_ERROR;
    }
  }

  result = vquic_flush(cf, data, &ctx->q);
  if(result) {
    if(result == CURLE_AGAIN) {
      Curl_expire(data, 1, EXPIRE_QUIC);
      return CURLE_OK;
    }
    return result;
  }

  readx.cf = cf;
  readx.data = data;
  memset(&readx.send_info, 0, sizeof(readx.send_info));
  pkt_count = 0;
  gsolen = quiche_conn_max_send_udp_payload_size(ctx->qconn);
  for(;;) {
    /* add the next packet to send, if any, to our buffer */
    result = Curl_bufq_sipn(&ctx->q.sendbuf, 0,
                            read_pkt_to_send, &readx, &nread);
    if(result) {
      if(result != CURLE_AGAIN)
        return result;
      /* Nothing more to add, flush and leave */
      result = vquic_send(cf, data, &ctx->q, gsolen);
      if(result) {
        if(result == CURLE_AGAIN) {
          Curl_expire(data, 1, EXPIRE_QUIC);
          return CURLE_OK;
        }
        return result;
      }
      goto out;
    }

    ++pkt_count;
    if(nread < gsolen || pkt_count >= MAX_PKT_BURST) {
      result = vquic_send(cf, data, &ctx->q, gsolen);
      if(result) {
        if(result == CURLE_AGAIN) {
          Curl_expire(data, 1, EXPIRE_QUIC);
          return CURLE_OK;
        }
        goto out;
      }
      pkt_count = 0;
    }
  }

out:
  timeout_ns = quiche_conn_timeout_as_nanos(ctx->qconn);
  if(timeout_ns % 1000000)
    timeout_ns += 1000000;
    /* expire resolution is milliseconds */
  Curl_expire(data, (timeout_ns / 1000000), EXPIRE_QUIC);
  return result;
}

static CURLcode recv_closed_stream(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   size_t *pnread)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;

  DEBUGASSERT(stream);
  *pnread = 0;
  if(stream->reset) {
    failf(data,
          "HTTP/3 stream %" FMT_PRIu64 " reset by server", stream->id);
    result = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
    CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] cf_recv, was reset -> %d",
                stream->id, result);
  }
  else if(!stream->resp_got_header) {
    failf(data,
          "HTTP/3 stream %" FMT_PRIu64 " was closed cleanly, but before "
          "getting all response header fields, treated as error",
          stream->id);
    result = CURLE_HTTP3;
  }
  return result;
}

static CURLcode cf_quiche_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                               char *buf, size_t len, size_t *pnread)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;

  *pnread = 0;
  vquic_ctx_update_time(&ctx->q);

  if(!stream)
    return CURLE_RECV_ERROR;


  if(!Curl_bufq_is_empty(&stream->recvbuf)) {
    result = Curl_bufq_cread(&stream->recvbuf, buf, len, pnread);
    CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] read recvbuf(len=%zu) "
                "-> %d, %zu", stream->id, len, result, *pnread);
    if(result)
      goto out;
  }

  if(cf_process_ingress(cf, data)) {
    CURL_TRC_CF(data, cf, "cf_recv, error on ingress");
    result = CURLE_RECV_ERROR;
    goto out;
  }

  /* recvbuf had nothing before, maybe after progressing ingress? */
  if(!*pnread && !Curl_bufq_is_empty(&stream->recvbuf)) {
    result = Curl_bufq_cread(&stream->recvbuf, buf, len, pnread);
    CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] read recvbuf(len=%zu) "
                "-> %d, %zu", stream->id, len, result, *pnread);
    if(result)
      goto out;
  }

  if(*pnread) {
    if(stream->closed)
      Curl_multi_mark_dirty(data);
  }
  else {
    if(stream->closed)
      result = recv_closed_stream(cf, data, pnread);
    else if(quiche_conn_is_draining(ctx->qconn)) {
      failf(data, "QUIC connection is draining");
      result = CURLE_HTTP3;
    }
    else
      result = CURLE_AGAIN;
  }

out:
  result = Curl_1st_err(result, cf_flush_egress(cf, data));
  if(*pnread > 0)
    ctx->data_recvd += *pnread;
  CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] cf_recv(total=%"
              FMT_OFF_T ") -> %d, %zu",
              stream->id, ctx->data_recvd, result, *pnread);
  return result;
}

static CURLcode cf_quiche_send_body(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct h3_stream_ctx *stream,
                                    const void *buf, size_t len, bool eos,
                                    size_t *pnwritten)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  ssize_t nwritten;

  *pnwritten = 0;
  nwritten = quiche_h3_send_body(ctx->h3c, ctx->qconn, stream->id,
                                 (uint8_t *)CURL_UNCONST(buf), len, eos);
  if(nwritten == QUICHE_H3_ERR_DONE || (nwritten == 0 && len > 0)) {
    /* Blocked on flow control and should HOLD sending. But when do we open
     * again? */
    if(!quiche_conn_stream_writable(ctx->qconn, stream->id, len)) {
      CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                  "-> window exhausted", stream->id, len);
      stream->quic_flow_blocked = TRUE;
    }
    return CURLE_AGAIN;
  }
  else if(nwritten == QUICHE_H3_TRANSPORT_ERR_INVALID_STREAM_STATE) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                "-> invalid stream state", stream->id, len);
    return CURLE_HTTP3;
  }
  else if(nwritten == QUICHE_H3_TRANSPORT_ERR_FINAL_SIZE) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                "-> exceeds size", stream->id, len);
    return CURLE_SEND_ERROR;
  }
  else if(nwritten < 0) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                "-> quiche err %zd", stream->id, len, nwritten);
    return CURLE_SEND_ERROR;
  }
  else {
    if(eos && (len == (size_t)nwritten))
      stream->send_closed = TRUE;
    CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send body(len=%zu, "
                "eos=%d) -> %zd",
                stream->id, len, stream->send_closed, nwritten);
    *pnwritten = (size_t)nwritten;
    return CURLE_OK;
  }
}

/* Index where :authority header field will appear in request header
   field list. */
#define AUTHORITY_DST_IDX 3

static CURLcode h3_open_stream(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const char *buf, size_t blen, bool eos,
                               size_t *pnwritten)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  size_t nheader, i;
  curl_int64_t stream3_id;
  struct dynhds h2_headers;
  quiche_h3_header *nva = NULL;
  CURLcode result = CURLE_OK;
  ssize_t nwritten;

  *pnwritten = 0;
  if(!stream) {
    result = h3_data_setup(cf, data);
    if(result)
      return result;
    stream = H3_STREAM_CTX(ctx, data);
    DEBUGASSERT(stream);
  }

  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);

  DEBUGASSERT(stream);
  nwritten = Curl_h1_req_parse_read(&stream->h1, buf, blen, NULL, 0, &result);
  if(nwritten < 0)
    goto out;
  if(!stream->h1.done) {
    /* need more data */
    goto out;
  }
  DEBUGASSERT(stream->h1.req);

  result = Curl_http_req_to_h2(&h2_headers, stream->h1.req, data);
  if(result)
    goto out;

  /* no longer needed */
  Curl_h1_req_parse_free(&stream->h1);

  nheader = Curl_dynhds_count(&h2_headers);
  nva = malloc(sizeof(quiche_h3_header) * nheader);
  if(!nva) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  for(i = 0; i < nheader; ++i) {
    struct dynhds_entry *e = Curl_dynhds_getn(&h2_headers, i);
    nva[i].name = (unsigned char *)e->name;
    nva[i].name_len = e->namelen;
    nva[i].value = (unsigned char *)e->value;
    nva[i].value_len = e->valuelen;
  }

  *pnwritten = (size_t)nwritten;
  buf += *pnwritten;
  blen -= *pnwritten;

  if(eos && !blen)
    stream->send_closed = TRUE;

  stream3_id = quiche_h3_send_request(ctx->h3c, ctx->qconn, nva, nheader,
                                      stream->send_closed);
  CURL_TRC_CF(data, cf, "quiche_send_request() -> %" FMT_PRIu64, stream3_id);
  if(stream3_id < 0) {
    if(QUICHE_H3_ERR_STREAM_BLOCKED == stream3_id) {
      /* quiche seems to report this error if the connection window is
       * exhausted. Which happens frequently and intermittent. */
      CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] blocked", stream->id);
      stream->quic_flow_blocked = TRUE;
      result = CURLE_AGAIN;
      goto out;
    }
    else {
      CURL_TRC_CF(data, cf, "send_request(%s) -> %" FMT_PRIu64,
                  data->state.url, stream3_id);
    }
    result = CURLE_SEND_ERROR;
    goto out;
  }

  DEBUGASSERT(!stream->opened);
  stream->id = stream3_id;
  stream->opened = TRUE;
  stream->closed = FALSE;
  stream->reset = FALSE;

  if(Curl_trc_is_verbose(data)) {
    infof(data, "[HTTP/3] [%" FMT_PRIu64 "] OPENED stream for %s",
          stream->id, data->state.url);
    for(i = 0; i < nheader; ++i) {
      infof(data, "[HTTP/3] [%" FMT_PRIu64 "] [%.*s: %.*s]", stream->id,
            (int)nva[i].name_len, nva[i].name,
            (int)nva[i].value_len, nva[i].value);
    }
  }

  if(blen) {  /* after the headers, there was request BODY data */
    size_t bwritten;
    CURLcode r2 = CURLE_OK;

    r2 = cf_quiche_send_body(cf, data, stream, buf, blen, eos, &bwritten);
    if(r2 && (CURLE_AGAIN != r2)) {  /* real error, fail */
      result = r2;
    }
    else if(bwritten > 0) {
      *pnwritten += (size_t)bwritten;
    }
  }

out:
  free(nva);
  Curl_dynhds_free(&h2_headers);
  return result;
}

static CURLcode cf_quiche_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                               const void *buf, size_t len, bool eos,
                               size_t *pnwritten)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result;

  *pnwritten = 0;
  vquic_ctx_update_time(&ctx->q);

  result = cf_process_ingress(cf, data);
  if(result)
    goto out;

  if(!stream || !stream->opened) {
    result = h3_open_stream(cf, data, buf, len, eos, pnwritten);
    if(result)
      goto out;
    stream = H3_STREAM_CTX(ctx, data);
  }
  else if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* sending request body on a stream that has been closed by the
       * server. If the server has send us a final response, we should
       * silently discard the send data.
       * This happens for example on redirects where the server, instead
       * of reading the full request body just closed the stream after
       * sending the 30x response.
       * This is sort of a race: had the transfer loop called recv first,
       * it would see the response and stop/discard sending on its own- */
      CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] discarding data"
                  "on closed stream with response", stream->id);
      result = CURLE_OK;
      *pnwritten = len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                "-> stream closed", stream->id, len);
    result = CURLE_HTTP3;
    goto out;
  }
  else {
    result = cf_quiche_send_body(cf, data, stream, buf, len, eos, pnwritten);
  }

out:
  result = Curl_1st_err(result, cf_flush_egress(cf, data));

  CURL_TRC_CF(data, cf, "[%" FMT_PRIu64 "] cf_send(len=%zu) -> %d, %zu",
              stream ? stream->id : (curl_uint64_t)~0, len,
              result, *pnwritten);
  return result;
}

static bool stream_is_writeable(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  return stream && (quiche_conn_stream_writable(
    ctx->qconn, (curl_uint64_t)stream->id, 1) > 0);
}

static CURLcode cf_quiche_adjust_pollset(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct easy_pollset *ps)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  bool want_recv, want_send;
  CURLcode result = CURLE_OK;

  if(!ctx->qconn)
    return CURLE_OK;

  Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
  if(want_recv || want_send) {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    bool c_exhaust, s_exhaust;

    c_exhaust = FALSE; /* Have not found any call in quiche that tells
                          us if the connection itself is blocked */
    s_exhaust = want_send && stream && stream->opened &&
                (stream->quic_flow_blocked || !stream_is_writeable(cf, data));
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                 !Curl_bufq_is_empty(&ctx->q.sendbuf);

    result = Curl_pollset_set(data, ps, ctx->q.sockfd, want_recv, want_send);
  }
  return result;
}

/*
 * Called from transfer.c:data_pending to know if we should keep looping
 * to receive more data from the connection.
 */
static bool cf_quiche_data_pending(struct Curl_cfilter *cf,
                                   const struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  const struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)cf;
  return stream && !Curl_bufq_is_empty(&stream->recvbuf);
}

static CURLcode h3_data_pause(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool pause)
{
  /* There seems to exist no API in quiche to shrink/enlarge the streams
   * windows. As we do in HTTP/2. */
  (void)cf;
  if(!pause) {
    Curl_multi_mark_dirty(data);
  }
  return CURLE_OK;
}

static CURLcode cf_quiche_cntrl(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int event, int arg1, void *arg2)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = h3_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE:
    h3_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if(stream && !stream->send_closed) {
      unsigned char body[1];
      size_t sent;

      stream->send_closed = TRUE;
      body[0] = 'X';
      result = cf_quiche_send(cf, data, body, 0, TRUE, &sent);
      CURL_TRC_CF(data, cf, "[%"FMT_PRIu64"] DONE_SEND -> %d, %zu",
                  stream->id, result, sent);
    }
    break;
  }
  case CF_CTRL_DATA_IDLE: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if(stream && !stream->closed) {
      result = cf_flush_egress(cf, data);
      if(result)
        CURL_TRC_CF(data, cf, "data idle, flush egress -> %d", result);
    }
    break;
  }
  case CF_CTRL_CONN_INFO_UPDATE:
    if(!cf->sockindex && cf->connected)
      cf->conn->httpversion_seen = 30;
    break;
  default:
    break;
  }
  return result;
}

static CURLcode cf_quiche_ctx_open(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  int rv;
  CURLcode result;
  const struct Curl_sockaddr_ex *sockaddr;
static const struct alpn_spec ALPN_SPEC_H3 = {
  { "h3" }, 1
};

  DEBUGASSERT(ctx->q.sockfd != CURL_SOCKET_BAD);
  DEBUGASSERT(ctx->initialized);

  result = vquic_ctx_init(&ctx->q);
  if(result)
    return result;

  ctx->cfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if(!ctx->cfg) {
    failf(data, "cannot create quiche config");
    return CURLE_FAILED_INIT;
  }
  quiche_config_enable_pacing(ctx->cfg, FALSE);
  quiche_config_set_initial_max_data(ctx->cfg, (1 * 1024 * 1024)
    /* (QUIC_MAX_STREAMS/2) * H3_STREAM_WINDOW_SIZE */);
  quiche_config_set_initial_max_streams_bidi(ctx->cfg, QUIC_MAX_STREAMS);
  quiche_config_set_initial_max_streams_uni(ctx->cfg, QUIC_MAX_STREAMS);
  quiche_config_set_initial_max_stream_data_bidi_local(ctx->cfg,
    H3_STREAM_WINDOW_SIZE);
  quiche_config_set_initial_max_stream_data_bidi_remote(ctx->cfg,
    H3_STREAM_WINDOW_SIZE);
  quiche_config_set_initial_max_stream_data_uni(ctx->cfg,
    H3_STREAM_WINDOW_SIZE);
  quiche_config_set_disable_active_migration(ctx->cfg, TRUE);

  quiche_config_set_max_connection_window(ctx->cfg,
    10 * QUIC_MAX_STREAMS * H3_STREAM_WINDOW_SIZE);
  quiche_config_set_max_stream_window(ctx->cfg, 10 * H3_STREAM_WINDOW_SIZE);
  quiche_config_set_application_protos(ctx->cfg,
                       (uint8_t *)CURL_UNCONST(QUICHE_H3_APPLICATION_PROTOCOL),
                                       sizeof(QUICHE_H3_APPLICATION_PROTOCOL)
                                       - 1);

  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer,
                               &ALPN_SPEC_H3, NULL, NULL, cf, NULL);
  if(result)
    return result;

  result = Curl_rand(data, ctx->scid, sizeof(ctx->scid));
  if(result)
    return result;

  Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &sockaddr, NULL);
  ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
  rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                   &ctx->q.local_addrlen);
  if(rv == -1)
    return CURLE_QUIC_CONNECT_ERROR;

  ctx->qconn = quiche_conn_new_with_tls((const uint8_t *)ctx->scid,
                                        sizeof(ctx->scid), NULL, 0,
                                        (struct sockaddr *)&ctx->q.local_addr,
                                        ctx->q.local_addrlen,
                                        &sockaddr->curl_sa_addr,
                                        sockaddr->addrlen,
                                        ctx->cfg, ctx->tls.ossl.ssl, FALSE);
  if(!ctx->qconn) {
    failf(data, "cannot create quiche connection");
    return CURLE_OUT_OF_MEMORY;
  }

  /* Known to not work on Windows */
#if !defined(_WIN32) && defined(HAVE_QUICHE_CONN_SET_QLOG_FD)
  {
    int qfd;
    (void)Curl_qlogdir(data, ctx->scid, sizeof(ctx->scid), &qfd);
    if(qfd != -1)
      quiche_conn_set_qlog_fd(ctx->qconn, qfd,
                              "qlog title", "curl qlog");
  }
#endif

  result = cf_flush_egress(cf, data);
  if(result)
    return result;

  {
    unsigned char alpn_protocols[] = QUICHE_H3_APPLICATION_PROTOCOL;
    unsigned alpn_len, offset = 0;

    /* Replace each ALPN length prefix by a comma. */
    while(offset < sizeof(alpn_protocols) - 1) {
      alpn_len = alpn_protocols[offset];
      alpn_protocols[offset] = ',';
      offset += 1 + alpn_len;
    }

    CURL_TRC_CF(data, cf, "Sent QUIC client Initial, ALPN: %s",
                alpn_protocols + 1);
  }

  return CURLE_OK;
}

static CURLcode cf_quiche_verify_peer(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;

  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */

  return Curl_vquic_tls_verify_peer(&ctx->tls, cf, data, &ctx->peer);
}

static CURLcode cf_quiche_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *done)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the UDP filter first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;
  vquic_ctx_update_time(&ctx->q);

  if(!ctx->qconn) {
    result = cf_quiche_ctx_open(cf, data);
    if(result)
      goto out;
    ctx->started_at = ctx->q.last_op;
    result = cf_flush_egress(cf, data);
    /* we do not expect to be able to recv anything yet */
    goto out;
  }

  result = cf_process_ingress(cf, data);
  if(result)
    goto out;

  result = cf_flush_egress(cf, data);
  if(result)
    goto out;

  if(quiche_conn_is_established(ctx->qconn)) {
    ctx->handshake_at = ctx->q.last_op;
    CURL_TRC_CF(data, cf, "handshake complete after %dms",
                (int)curlx_timediff(ctx->handshake_at, ctx->started_at));
    result = cf_quiche_verify_peer(cf, data);
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      ctx->h3config = quiche_h3_config_new();
      if(!ctx->h3config) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }

      /* Create a new HTTP/3 connection on the QUIC connection. */
      ctx->h3c = quiche_h3_conn_new_with_transport(ctx->qconn, ctx->h3config);
      if(!ctx->h3c) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      cf->connected = TRUE;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }
  else if(quiche_conn_is_draining(ctx->qconn)) {
    /* When a QUIC server instance is shutting down, it may send us a
     * CONNECTION_CLOSE right away. Our connection then enters the DRAINING
     * state. The CONNECT may work in the near future again. Indicate
     * that as a "weird" reply. */
    result = CURLE_WEIRD_SERVER_REPLY;
  }

out:
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(result && result != CURLE_AGAIN) {
    struct ip_quadruple ip;

    Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip);
    infof(data, "connect to %s port %u failed: %s",
          ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
  }
#endif
  return result;
}

static CURLcode cf_quiche_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data, bool *done)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(cf->shutdown || !ctx || !ctx->qconn) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  if(!ctx->shutdown_started) {
    int err;

    ctx->shutdown_started = TRUE;
    vquic_ctx_update_time(&ctx->q);
    err = quiche_conn_close(ctx->qconn, TRUE, 0, NULL, 0);
    if(err) {
      CURL_TRC_CF(data, cf, "error %d adding shutdown packet, "
                  "aborting shutdown", err);
      result = CURLE_SEND_ERROR;
      goto out;
    }
  }

  if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    CURL_TRC_CF(data, cf, "shutdown, flushing sendbuf");
    result = cf_flush_egress(cf, data);
    if(result)
      goto out;
  }

  if(Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    /* sent everything, quiche does not seem to support a graceful
     * shutdown waiting for a reply, so ware done. */
    CURL_TRC_CF(data, cf, "shutdown completely sent off, done");
    *done = TRUE;
  }
  else {
    CURL_TRC_CF(data, cf, "shutdown sending blocked");
  }

out:
  return result;
}

static void cf_quiche_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  if(cf->ctx) {
    bool done;
    (void)cf_quiche_shutdown(cf, data, &done);
    cf_quiche_ctx_close(cf->ctx);
  }
}

static void cf_quiche_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  (void)data;
  if(cf->ctx) {
    cf_quiche_ctx_free(cf->ctx);
    cf->ctx = NULL;
  }
}

static CURLcode cf_quiche_query(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int query, int *pres1, void *pres2)
{
  struct cf_quiche_ctx *ctx = cf->ctx;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT: {
    curl_uint64_t max_streams = CONN_ATTACHED(cf->conn);
    if(!ctx->goaway && ctx->qconn) {
      max_streams += quiche_conn_peer_streams_left_bidi(ctx->qconn);
    }
    *pres1 = (max_streams > INT_MAX) ? INT_MAX : (int)max_streams;
    CURL_TRC_CF(data, cf, "query conn[%" FMT_OFF_T "]: "
                "MAX_CONCURRENT -> %d (%u in use)",
                cf->conn->connection_id, *pres1, CONN_ATTACHED(cf->conn));
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->q.got_first_byte) {
      timediff_t ms = curlx_timediff(ctx->q.first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT: {
    struct curltime *when = pres2;
    if(ctx->q.got_first_byte)
      *when = ctx->q.first_byte_at;
    return CURLE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT: {
    struct curltime *when = pres2;
    if(cf->connected)
      *when = ctx->handshake_at;
    return CURLE_OK;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 30;
    return CURLE_OK;
  case CF_QUERY_SSL_INFO:
  case CF_QUERY_SSL_CTX_INFO: {
    struct curl_tlssessioninfo *info = pres2;
    if(Curl_vquic_tls_get_ssl_info(&ctx->tls,
                                   (query == CF_QUERY_SSL_CTX_INFO), info))
      return CURLE_OK;
    break;
  }
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = cf->connected ? "h3" : NULL;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_quiche_conn_is_alive(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *input_pending)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  bool alive = TRUE;

  *input_pending = FALSE;
  if(!ctx->qconn)
    return FALSE;

  if(quiche_conn_is_closed(ctx->qconn)) {
    if(quiche_conn_is_timed_out(ctx->qconn))
      CURL_TRC_CF(data, cf, "connection was closed due to idle timeout");
    else
      CURL_TRC_CF(data, cf, "connection is closed");
    return FALSE;
  }

  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    return FALSE;

  if(*input_pending) {
    /* This happens before we have sent off a request and the connection is
       not in use by any other transfer, there should not be any data here,
       only "protocol frames" */
    *input_pending = FALSE;
    if(cf_process_ingress(cf, data))
      alive = FALSE;
    else {
      alive = TRUE;
    }
  }

  return alive;
}

struct Curl_cftype Curl_cft_http3 = {
  "HTTP/3",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX | CF_TYPE_HTTP,
  0,
  cf_quiche_destroy,
  cf_quiche_connect,
  cf_quiche_close,
  cf_quiche_shutdown,
  cf_quiche_adjust_pollset,
  cf_quiche_data_pending,
  cf_quiche_send,
  cf_quiche_recv,
  cf_quiche_cntrl,
  cf_quiche_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_quiche_query,
};

CURLcode Curl_cf_quiche_create(struct Curl_cfilter **pcf,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               const struct Curl_addrinfo *ai)
{
  struct cf_quiche_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL, *udp_cf = NULL;
  CURLcode result;

  (void)data;
  (void)conn;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_quiche_ctx_init(ctx);

  result = Curl_cf_create(&cf, &Curl_cft_http3, ctx);
  if(result)
    goto out;

  result = Curl_cf_udp_create(&udp_cf, data, conn, ai, TRNSPRT_QUIC);
  if(result)
    goto out;

  udp_cf->conn = cf->conn;
  udp_cf->sockindex = cf->sockindex;
  cf->next = udp_cf;

out:
  *pcf = (!result) ? cf : NULL;
  if(result) {
    if(udp_cf)
      Curl_conn_cf_discard_sub(cf, udp_cf, data, TRUE);
    Curl_safefree(cf);
    cf_quiche_ctx_free(ctx);
  }

  return result;
}

#endif
