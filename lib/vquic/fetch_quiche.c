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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifdef USE_QUICHE
#include <quiche.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "bufq.h"
#include "hash.h"
#include "urldata.h"
#include "cfilters.h"
#include "cf-socket.h"
#include "sendf.h"
#include "strdup.h"
#include "rand.h"
#include "strcase.h"
#include "multiif.h"
#include "connect.h"
#include "progress.h"
#include "strerror.h"
#include "http1.h"
#include "vquic.h"
#include "vquic_int.h"
#include "vquic-tls.h"
#include "fetch_quiche.h"
#include "transfer.h"
#include "inet_pton.h"
#include "vtls/openssl.h"
#include "vtls/keylog.h"
#include "vtls/vtls.h"

/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

/* HTTP/3 error values defined in RFC 9114, ch. 8.1 */
#define FETCH_H3_NO_ERROR (0x0100)

#define QUIC_MAX_STREAMS (100)

#define H3_STREAM_WINDOW_SIZE (128 * 1024)
#define H3_STREAM_CHUNK_SIZE (16 * 1024)
/* The pool keeps spares around and half of a full stream windows seems good.
 * More does not seem to improve performance. The benefit of the pool is that
 * stream buffer to not keep spares. Memory consumption goes down when streams
 * run empty, have a large upload done, etc. */
#define H3_STREAM_POOL_SPARES \
  (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE) / 2
/* Receive and Send max number of chunks just follows from the
 * chunk size and window size */
#define H3_STREAM_RECV_CHUNKS \
  (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)
#define H3_STREAM_SEND_CHUNKS \
  (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)

/*
 * Store quiche version info in this buffer.
 */
void Fetch_quiche_ver(char *p, size_t len)
{
  (void)msnprintf(p, len, "quiche/%s", quiche_version());
}

struct cf_quiche_ctx
{
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct fetch_tls_ctx tls;
  quiche_conn *qconn;
  quiche_config *cfg;
  quiche_h3_conn *h3c;
  quiche_h3_config *h3config;
  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  struct fetchtime started_at;   /* time the current attempt started */
  struct fetchtime handshake_at; /* time connect handshake finished */
  struct bufc_pool stream_bufcp; /* chunk pool for streams */
  struct Fetch_hash streams;      /* hash `data->mid` to `stream_ctx` */
  fetch_off_t data_recvd;
  BIT(initialized);
  BIT(goaway);           /* got GOAWAY from server */
  BIT(x509_store_setup); /* if x509 store has been set up */
  BIT(shutdown_started); /* queued shutdown packets */
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

static void h3_stream_hash_free(void *stream);

static void cf_quiche_ctx_init(struct cf_quiche_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
#ifdef DEBUG_QUICHE
  if (!debug_log_init)
  {
    quiche_enable_debug_logging(quiche_debug_log, NULL);
    debug_log_init = 1;
  }
#endif
  Fetch_bufcp_init(&ctx->stream_bufcp, H3_STREAM_CHUNK_SIZE,
                  H3_STREAM_POOL_SPARES);
  Fetch_hash_offt_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->data_recvd = 0;
  ctx->initialized = TRUE;
}

static void cf_quiche_ctx_free(struct cf_quiche_ctx *ctx)
{
  if (ctx && ctx->initialized)
  {
    /* quiche just freed it */
    ctx->tls.ossl.ssl = NULL;
    Fetch_vquic_tls_cleanup(&ctx->tls);
    Fetch_ssl_peer_cleanup(&ctx->peer);
    vquic_ctx_free(&ctx->q);
    Fetch_bufcp_free(&ctx->stream_bufcp);
    Fetch_hash_clean(&ctx->streams);
    Fetch_hash_destroy(&ctx->streams);
  }
  free(ctx);
}

static void cf_quiche_ctx_close(struct cf_quiche_ctx *ctx)
{
  if (ctx->h3c)
    quiche_h3_conn_free(ctx->h3c);
  if (ctx->h3config)
    quiche_h3_config_free(ctx->h3config);
  if (ctx->qconn)
    quiche_conn_free(ctx->qconn);
  if (ctx->cfg)
    quiche_config_free(ctx->cfg);
}

static FETCHcode cf_flush_egress(struct Fetch_cfilter *cf,
                                 struct Fetch_easy *data);

/**
 * All about the H3 internals of a stream
 */
struct stream_ctx
{
  fetch_uint64_t id;       /* HTTP/3 protocol stream identifier */
  struct bufq recvbuf;     /* h3 response */
  struct h1_req_parser h1; /* h1 request parsing */
  fetch_uint64_t error3;   /* HTTP/3 stream error code */
  BIT(opened);             /* TRUE after stream has been opened */
  BIT(closed);             /* TRUE on stream close */
  BIT(reset);              /* TRUE on stream reset */
  BIT(send_closed);        /* stream is locally closed */
  BIT(resp_hds_complete);  /* final response has been received */
  BIT(resp_got_header);    /* TRUE when h3 stream has recvd some HEADER */
  BIT(quic_flow_blocked);  /* stream is blocked by QUIC flow control */
};

#define H3_STREAM_CTX(ctx, data) ((struct stream_ctx *)(data ? Fetch_hash_offt_get(&(ctx)->streams, (data)->mid) : NULL))

static void h3_stream_ctx_free(struct stream_ctx *stream)
{
  Fetch_bufq_free(&stream->recvbuf);
  Fetch_h1_req_parse_free(&stream->h1);
  free(stream);
}

static void h3_stream_hash_free(void *stream)
{
  DEBUGASSERT(stream);
  h3_stream_ctx_free((struct stream_ctx *)stream);
}

static void check_resumes(struct Fetch_cfilter *cf,
                          struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct Fetch_llist_node *e;

  DEBUGASSERT(data->multi);
  for (e = Fetch_llist_head(&data->multi->process); e; e = Fetch_node_next(e))
  {
    struct Fetch_easy *sdata = Fetch_node_elem(e);
    if (sdata->conn == data->conn)
    {
      struct stream_ctx *stream = H3_STREAM_CTX(ctx, sdata);
      if (stream && stream->quic_flow_blocked)
      {
        stream->quic_flow_blocked = FALSE;
        Fetch_expire(data, 0, EXPIRE_RUN_NOW);
        FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] unblock", stream->id);
      }
    }
  }
}

static FETCHcode h3_data_setup(struct Fetch_cfilter *cf,
                               struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  if (stream)
    return FETCHE_OK;

  stream = calloc(1, sizeof(*stream));
  if (!stream)
    return FETCHE_OUT_OF_MEMORY;

  stream->id = -1;
  Fetch_bufq_initp(&stream->recvbuf, &ctx->stream_bufcp,
                  H3_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);
  Fetch_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);

  if (!Fetch_hash_offt_set(&ctx->streams, data->mid, stream))
  {
    h3_stream_ctx_free(stream);
    return FETCHE_OUT_OF_MEMORY;
  }

  return FETCHE_OK;
}

static void h3_data_done(struct Fetch_cfilter *cf, struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  FETCHcode result;

  (void)cf;
  if (stream)
  {
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] easy handle is done", stream->id);
    if (ctx->qconn && !stream->closed)
    {
      quiche_conn_stream_shutdown(ctx->qconn, stream->id,
                                  QUICHE_SHUTDOWN_READ, FETCH_H3_NO_ERROR);
      if (!stream->send_closed)
      {
        quiche_conn_stream_shutdown(ctx->qconn, stream->id,
                                    QUICHE_SHUTDOWN_WRITE, FETCH_H3_NO_ERROR);
        stream->send_closed = TRUE;
      }
      stream->closed = TRUE;
      result = cf_flush_egress(cf, data);
      if (result)
        FETCH_TRC_CF(data, cf, "data_done, flush egress -> %d", result);
    }
    Fetch_hash_offt_remove(&ctx->streams, data->mid);
  }
}

static void h3_drain_stream(struct Fetch_cfilter *cf,
                            struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  unsigned char bits;

  (void)cf;
  bits = FETCH_CSELECT_IN;
  if (stream && !stream->send_closed)
    bits |= FETCH_CSELECT_OUT;
  if (data->state.select_bits != bits)
  {
    data->state.select_bits = bits;
    Fetch_expire(data, 0, EXPIRE_RUN_NOW);
  }
}

static struct Fetch_easy *get_stream_easy(struct Fetch_cfilter *cf,
                                         struct Fetch_easy *data,
                                         fetch_uint64_t stream_id,
                                         struct stream_ctx **pstream)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream;

  (void)cf;
  stream = H3_STREAM_CTX(ctx, data);
  if (stream && stream->id == stream_id)
  {
    *pstream = stream;
    return data;
  }
  else
  {
    struct Fetch_llist_node *e;
    DEBUGASSERT(data->multi);
    for (e = Fetch_llist_head(&data->multi->process); e; e = Fetch_node_next(e))
    {
      struct Fetch_easy *sdata = Fetch_node_elem(e);
      if (sdata->conn != data->conn)
        continue;
      stream = H3_STREAM_CTX(ctx, sdata);
      if (stream && stream->id == stream_id)
      {
        *pstream = stream;
        return sdata;
      }
    }
  }
  *pstream = NULL;
  return NULL;
}

static void cf_quiche_expire_conn_closed(struct Fetch_cfilter *cf,
                                         struct Fetch_easy *data)
{
  struct Fetch_llist_node *e;

  DEBUGASSERT(data->multi);
  FETCH_TRC_CF(data, cf, "conn closed, expire all transfers");
  for (e = Fetch_llist_head(&data->multi->process); e; e = Fetch_node_next(e))
  {
    struct Fetch_easy *sdata = Fetch_node_elem(e);
    if (sdata == data || sdata->conn != data->conn)
      continue;
    FETCH_TRC_CF(sdata, cf, "conn closed, expire transfer");
    Fetch_expire(sdata, 0, EXPIRE_RUN_NOW);
  }
}

/*
 * write_resp_raw() copies response data in raw format to the `data`'s
 * receive buffer. If not enough space is available, it appends to the
 * `data`'s overflow buffer.
 */
static FETCHcode write_resp_raw(struct Fetch_cfilter *cf,
                                struct Fetch_easy *data,
                                const void *mem, size_t memlen)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  FETCHcode result = FETCHE_OK;
  ssize_t nwritten;

  (void)cf;
  if (!stream)
    return FETCHE_RECV_ERROR;
  nwritten = Fetch_bufq_write(&stream->recvbuf, mem, memlen, &result);
  if (nwritten < 0)
    return result;

  if ((size_t)nwritten < memlen)
  {
    /* This MUST not happen. Our recbuf is dimensioned to hold the
     * full max_stream_window and then some for this very reason. */
    DEBUGASSERT(0);
    return FETCHE_RECV_ERROR;
  }
  return result;
}

struct cb_ctx
{
  struct Fetch_cfilter *cf;
  struct Fetch_easy *data;
};

static int cb_each_header(uint8_t *name, size_t name_len,
                          uint8_t *value, size_t value_len,
                          void *argp)
{
  struct cb_ctx *x = argp;
  struct cf_quiche_ctx *ctx = x->cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, x->data);
  FETCHcode result;

  if (!stream)
    return FETCHE_OK;

  if ((name_len == 7) && !strncmp(HTTP_PSEUDO_STATUS, (char *)name, 7))
  {
    FETCH_TRC_CF(x->data, x->cf, "[%" FMT_PRIu64 "] status: %.*s",
                 stream->id, (int)value_len, value);
    result = write_resp_raw(x->cf, x->data, "HTTP/3 ", sizeof("HTTP/3 ") - 1);
    if (!result)
      result = write_resp_raw(x->cf, x->data, value, value_len);
    if (!result)
      result = write_resp_raw(x->cf, x->data, " \r\n", 3);
  }
  else
  {
    FETCH_TRC_CF(x->data, x->cf, "[%" FMT_PRIu64 "] header: %.*s: %.*s",
                 stream->id, (int)name_len, name,
                 (int)value_len, value);
    result = write_resp_raw(x->cf, x->data, name, name_len);
    if (!result)
      result = write_resp_raw(x->cf, x->data, ": ", 2);
    if (!result)
      result = write_resp_raw(x->cf, x->data, value, value_len);
    if (!result)
      result = write_resp_raw(x->cf, x->data, "\r\n", 2);
  }
  if (result)
  {
    FETCH_TRC_CF(x->data, x->cf, "[%" FMT_PRIu64 "] on header error %d",
                 stream->id, result);
  }
  return result;
}

static ssize_t stream_resp_read(void *reader_ctx,
                                unsigned char *buf, size_t len,
                                FETCHcode *err)
{
  struct cb_ctx *x = reader_ctx;
  struct cf_quiche_ctx *ctx = x->cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, x->data);
  ssize_t nread;

  if (!stream)
  {
    *err = FETCHE_RECV_ERROR;
    return -1;
  }

  nread = quiche_h3_recv_body(ctx->h3c, ctx->qconn, stream->id,
                              buf, len);
  if (nread >= 0)
  {
    *err = FETCHE_OK;
    return nread;
  }
  else
  {
    *err = FETCHE_AGAIN;
    return -1;
  }
}

static FETCHcode cf_recv_body(struct Fetch_cfilter *cf,
                              struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t nwritten;
  struct cb_ctx cb_ctx;
  FETCHcode result = FETCHE_OK;

  if (!stream)
    return FETCHE_RECV_ERROR;

  if (!stream->resp_hds_complete)
  {
    result = write_resp_raw(cf, data, "\r\n", 2);
    if (result)
      return result;
    stream->resp_hds_complete = TRUE;
  }

  cb_ctx.cf = cf;
  cb_ctx.data = data;
  nwritten = Fetch_bufq_slurp(&stream->recvbuf,
                             stream_resp_read, &cb_ctx, &result);

  if (nwritten < 0 && result != FETCHE_AGAIN)
  {
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] recv_body error %zd",
                 stream->id, nwritten);
    failf(data, "Error %d in HTTP/3 response body for stream[%" FMT_PRIu64 "]",
          result, stream->id);
    stream->closed = TRUE;
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    streamclose(cf->conn, "Reset of stream");
    return result;
  }
  return FETCHE_OK;
}

#ifdef DEBUGBUILD
static const char *cf_ev_name(quiche_h3_event *ev)
{
  switch (quiche_h3_event_type(ev))
  {
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
#define cf_ev_name(x) ""
#endif

static FETCHcode h3_process_event(struct Fetch_cfilter *cf,
                                  struct Fetch_easy *data,
                                  struct stream_ctx *stream,
                                  quiche_h3_event *ev)
{
  struct cb_ctx cb_ctx;
  FETCHcode result = FETCHE_OK;
  int rc;

  if (!stream)
    return FETCHE_OK;
  switch (quiche_h3_event_type(ev))
  {
  case QUICHE_H3_EVENT_HEADERS:
    stream->resp_got_header = TRUE;
    cb_ctx.cf = cf;
    cb_ctx.data = data;
    rc = quiche_h3_event_for_each_header(ev, cb_each_header, &cb_ctx);
    if (rc)
    {
      failf(data, "Error %d in HTTP/3 response header for stream[%" FMT_PRIu64 "]", rc, stream->id);
      return FETCHE_RECV_ERROR;
    }
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] <- [HEADERS]", stream->id);
    break;

  case QUICHE_H3_EVENT_DATA:
    if (!stream->closed)
    {
      result = cf_recv_body(cf, data);
    }
    break;

  case QUICHE_H3_EVENT_RESET:
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] RESET", stream->id);
    stream->closed = TRUE;
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    streamclose(cf->conn, "Reset of stream");
    break;

  case QUICHE_H3_EVENT_FINISHED:
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] CLOSED", stream->id);
    if (!stream->resp_hds_complete)
    {
      result = write_resp_raw(cf, data, "\r\n", 2);
      if (result)
        return result;
      stream->resp_hds_complete = TRUE;
    }
    stream->closed = TRUE;
    streamclose(cf->conn, "End of stream");
    break;

  case QUICHE_H3_EVENT_GOAWAY:
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] <- [GOAWAY]", stream->id);
    break;

  default:
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] recv, unhandled event %d",
                 stream->id, quiche_h3_event_type(ev));
    break;
  }
  return result;
}

static FETCHcode cf_poll_events(struct Fetch_cfilter *cf,
                                struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = NULL;
  struct Fetch_easy *sdata;
  quiche_h3_event *ev;
  FETCHcode result;

  /* Take in the events and distribute them to the transfers. */
  while (ctx->h3c)
  {
    fetch_int64_t stream3_id = quiche_h3_conn_poll(ctx->h3c, ctx->qconn, &ev);
    if (stream3_id == QUICHE_H3_ERR_DONE)
    {
      break;
    }
    else if (stream3_id < 0)
    {
      FETCH_TRC_CF(data, cf, "error poll: %" FMT_PRId64, stream3_id);
      return FETCHE_HTTP3;
    }

    sdata = get_stream_easy(cf, data, stream3_id, &stream);
    if (!sdata || !stream)
    {
      FETCH_TRC_CF(data, cf, "discard event %s for unknown [%" FMT_PRId64 "]",
                   cf_ev_name(ev), stream3_id);
    }
    else
    {
      result = h3_process_event(cf, sdata, stream, ev);
      h3_drain_stream(cf, sdata);
      if (result)
      {
        FETCH_TRC_CF(data, cf, "error processing event %s "
                               "for [%" FMT_PRIu64 "] -> %d",
                     cf_ev_name(ev),
                     stream3_id, result);
        if (data == sdata)
        {
          /* Only report this error to the caller if it is about the
           * transfer we were called with. Otherwise we fail a transfer
           * due to a problem in another one. */
          quiche_h3_event_free(ev);
          return result;
        }
      }
      quiche_h3_event_free(ev);
    }
  }
  return FETCHE_OK;
}

struct recv_ctx
{
  struct Fetch_cfilter *cf;
  struct Fetch_easy *data;
  int pkts;
};

static FETCHcode recv_pkt(const unsigned char *pkt, size_t pktlen,
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

  nread = quiche_conn_recv(ctx->qconn, (unsigned char *)pkt, pktlen,
                           &recv_info);
  if (nread < 0)
  {
    if (QUICHE_ERR_DONE == nread)
    {
      if (quiche_conn_is_draining(ctx->qconn))
      {
        FETCH_TRC_CF(r->data, r->cf, "ingress, connection is draining");
        return FETCHE_RECV_ERROR;
      }
      if (quiche_conn_is_closed(ctx->qconn))
      {
        FETCH_TRC_CF(r->data, r->cf, "ingress, connection is closed");
        return FETCHE_RECV_ERROR;
      }
      FETCH_TRC_CF(r->data, r->cf, "ingress, quiche is DONE");
      return FETCHE_OK;
    }
    else if (QUICHE_ERR_TLS_FAIL == nread)
    {
      long verify_ok = SSL_get_verify_result(ctx->tls.ossl.ssl);
      if (verify_ok != X509_V_OK)
      {
        failf(r->data, "SSL certificate problem: %s",
              X509_verify_cert_error_string(verify_ok));
        return FETCHE_PEER_FAILED_VERIFICATION;
      }
    }
    else
    {
      failf(r->data, "quiche_conn_recv() == %zd", nread);
      return FETCHE_RECV_ERROR;
    }
  }
  else if ((size_t)nread < pktlen)
  {
    FETCH_TRC_CF(r->data, r->cf, "ingress, quiche only read %zd/%zu bytes",
                 nread, pktlen);
  }

  return FETCHE_OK;
}

static FETCHcode cf_process_ingress(struct Fetch_cfilter *cf,
                                    struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct recv_ctx rctx;
  FETCHcode result;

  DEBUGASSERT(ctx->qconn);
  result = Fetch_vquic_tls_before_recv(&ctx->tls, cf, data);
  if (result)
    return result;

  rctx.cf = cf;
  rctx.data = data;
  rctx.pkts = 0;

  result = vquic_recv_packets(cf, data, &ctx->q, 1000, recv_pkt, &rctx);
  if (result)
    return result;

  if (rctx.pkts > 0)
  {
    /* quiche digested ingress packets. It might have opened flow control
     * windows again. */
    check_resumes(cf, data);
  }
  return cf_poll_events(cf, data);
}

struct read_ctx
{
  struct Fetch_cfilter *cf;
  struct Fetch_easy *data;
  quiche_send_info send_info;
};

static ssize_t read_pkt_to_send(void *userp,
                                unsigned char *buf, size_t buflen,
                                FETCHcode *err)
{
  struct read_ctx *x = userp;
  struct cf_quiche_ctx *ctx = x->cf->ctx;
  ssize_t nwritten;

  nwritten = quiche_conn_send(ctx->qconn, buf, buflen, &x->send_info);
  if (nwritten == QUICHE_ERR_DONE)
  {
    *err = FETCHE_AGAIN;
    return -1;
  }

  if (nwritten < 0)
  {
    failf(x->data, "quiche_conn_send returned %zd", nwritten);
    *err = FETCHE_SEND_ERROR;
    return -1;
  }
  *err = FETCHE_OK;
  return nwritten;
}

/*
 * flush_egress drains the buffers and sends off data.
 * Calls failf() on errors.
 */
static FETCHcode cf_flush_egress(struct Fetch_cfilter *cf,
                                 struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  ssize_t nread;
  FETCHcode result;
  fetch_int64_t expiry_ns;
  fetch_int64_t timeout_ns;
  struct read_ctx readx;
  size_t pkt_count, gsolen;

  expiry_ns = quiche_conn_timeout_as_nanos(ctx->qconn);
  if (!expiry_ns)
  {
    quiche_conn_on_timeout(ctx->qconn);
    if (quiche_conn_is_closed(ctx->qconn))
    {
      if (quiche_conn_is_timed_out(ctx->qconn))
        failf(data, "connection closed by idle timeout");
      else
        failf(data, "connection closed by server");
      /* Connection timed out, expire all transfers belonging to it
       * as will not get any more POLL events here. */
      cf_quiche_expire_conn_closed(cf, data);
      return FETCHE_SEND_ERROR;
    }
  }

  result = vquic_flush(cf, data, &ctx->q);
  if (result)
  {
    if (result == FETCHE_AGAIN)
    {
      Fetch_expire(data, 1, EXPIRE_QUIC);
      return FETCHE_OK;
    }
    return result;
  }

  readx.cf = cf;
  readx.data = data;
  memset(&readx.send_info, 0, sizeof(readx.send_info));
  pkt_count = 0;
  gsolen = quiche_conn_max_send_udp_payload_size(ctx->qconn);
  for (;;)
  {
    /* add the next packet to send, if any, to our buffer */
    nread = Fetch_bufq_sipn(&ctx->q.sendbuf, 0,
                           read_pkt_to_send, &readx, &result);
    if (nread < 0)
    {
      if (result != FETCHE_AGAIN)
        return result;
      /* Nothing more to add, flush and leave */
      result = vquic_send(cf, data, &ctx->q, gsolen);
      if (result)
      {
        if (result == FETCHE_AGAIN)
        {
          Fetch_expire(data, 1, EXPIRE_QUIC);
          return FETCHE_OK;
        }
        return result;
      }
      goto out;
    }

    ++pkt_count;
    if ((size_t)nread < gsolen || pkt_count >= MAX_PKT_BURST)
    {
      result = vquic_send(cf, data, &ctx->q, gsolen);
      if (result)
      {
        if (result == FETCHE_AGAIN)
        {
          Fetch_expire(data, 1, EXPIRE_QUIC);
          return FETCHE_OK;
        }
        goto out;
      }
      pkt_count = 0;
    }
  }

out:
  timeout_ns = quiche_conn_timeout_as_nanos(ctx->qconn);
  if (timeout_ns % 1000000)
    timeout_ns += 1000000;
  /* expire resolution is milliseconds */
  Fetch_expire(data, (timeout_ns / 1000000), EXPIRE_QUIC);
  return result;
}

static ssize_t recv_closed_stream(struct Fetch_cfilter *cf,
                                  struct Fetch_easy *data,
                                  FETCHcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t nread = -1;

  DEBUGASSERT(stream);
  if (stream->reset)
  {
    failf(data,
          "HTTP/3 stream %" FMT_PRIu64 " reset by server", stream->id);
    *err = data->req.bytecount ? FETCHE_PARTIAL_FILE : FETCHE_HTTP3;
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] cf_recv, was reset -> %d",
                 stream->id, *err);
  }
  else if (!stream->resp_got_header)
  {
    failf(data,
          "HTTP/3 stream %" FMT_PRIu64 " was closed cleanly, but before "
          "getting all response header fields, treated as error",
          stream->id);
    /* *err = FETCHE_PARTIAL_FILE; */
    *err = FETCHE_HTTP3;
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] cf_recv, closed incomplete"
                           " -> %d",
                 stream->id, *err);
  }
  else
  {
    *err = FETCHE_OK;
    nread = 0;
  }
  return nread;
}

static ssize_t cf_quiche_recv(struct Fetch_cfilter *cf, struct Fetch_easy *data,
                              char *buf, size_t len, FETCHcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t nread = -1;
  FETCHcode result;

  vquic_ctx_update_time(&ctx->q);

  if (!stream)
  {
    *err = FETCHE_RECV_ERROR;
    return -1;
  }

  if (!Fetch_bufq_is_empty(&stream->recvbuf))
  {
    nread = Fetch_bufq_read(&stream->recvbuf,
                           (unsigned char *)buf, len, err);
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] read recvbuf(len=%zu) "
                           "-> %zd, %d",
                 stream->id, len, nread, *err);
    if (nread < 0)
      goto out;
  }

  if (cf_process_ingress(cf, data))
  {
    FETCH_TRC_CF(data, cf, "cf_recv, error on ingress");
    *err = FETCHE_RECV_ERROR;
    nread = -1;
    goto out;
  }

  /* recvbuf had nothing before, maybe after progressing ingress? */
  if (nread < 0 && !Fetch_bufq_is_empty(&stream->recvbuf))
  {
    nread = Fetch_bufq_read(&stream->recvbuf,
                           (unsigned char *)buf, len, err);
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] read recvbuf(len=%zu) "
                           "-> %zd, %d",
                 stream->id, len, nread, *err);
    if (nread < 0)
      goto out;
  }

  if (nread > 0)
  {
    if (stream->closed)
      h3_drain_stream(cf, data);
  }
  else
  {
    if (stream->closed)
    {
      nread = recv_closed_stream(cf, data, err);
      goto out;
    }
    else if (quiche_conn_is_draining(ctx->qconn))
    {
      failf(data, "QUIC connection is draining");
      *err = FETCHE_HTTP3;
      nread = -1;
      goto out;
    }
    *err = FETCHE_AGAIN;
    nread = -1;
  }

out:
  result = cf_flush_egress(cf, data);
  if (result)
  {
    FETCH_TRC_CF(data, cf, "cf_recv, flush egress failed");
    *err = result;
    nread = -1;
  }
  if (nread > 0)
    ctx->data_recvd += nread;
  FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] cf_recv(total=%" FMT_OFF_T ") -> %zd, %d",
               stream->id, ctx->data_recvd, nread, *err);
  return nread;
}

static ssize_t cf_quiche_send_body(struct Fetch_cfilter *cf,
                                   struct Fetch_easy *data,
                                   struct stream_ctx *stream,
                                   const void *buf, size_t len, bool eos,
                                   FETCHcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  ssize_t nwritten;

  nwritten = quiche_h3_send_body(ctx->h3c, ctx->qconn, stream->id,
                                 (uint8_t *)buf, len, eos);
  if (nwritten == QUICHE_H3_ERR_DONE || (nwritten == 0 && len > 0))
  {
    /* TODO: we seem to be blocked on flow control and should HOLD
     * sending. But when do we open again? */
    if (!quiche_conn_stream_writable(ctx->qconn, stream->id, len))
    {
      FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                             "-> window exhausted",
                   stream->id, len);
      stream->quic_flow_blocked = TRUE;
    }
    *err = FETCHE_AGAIN;
    return -1;
  }
  else if (nwritten == QUICHE_H3_TRANSPORT_ERR_INVALID_STREAM_STATE)
  {
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                           "-> invalid stream state",
                 stream->id, len);
    *err = FETCHE_HTTP3;
    return -1;
  }
  else if (nwritten == QUICHE_H3_TRANSPORT_ERR_FINAL_SIZE)
  {
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                           "-> exceeds size",
                 stream->id, len);
    *err = FETCHE_SEND_ERROR;
    return -1;
  }
  else if (nwritten < 0)
  {
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                           "-> quiche err %zd",
                 stream->id, len, nwritten);
    *err = FETCHE_SEND_ERROR;
    return -1;
  }
  else
  {
    if (eos && (len == (size_t)nwritten))
      stream->send_closed = TRUE;
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send body(len=%zu, "
                           "eos=%d) -> %zd",
                 stream->id, len, stream->send_closed, nwritten);
    *err = FETCHE_OK;
    return nwritten;
  }
}

/* Index where :authority header field will appear in request header
   field list. */
#define AUTHORITY_DST_IDX 3

static ssize_t h3_open_stream(struct Fetch_cfilter *cf,
                              struct Fetch_easy *data,
                              const char *buf, size_t len, bool eos,
                              FETCHcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  size_t nheader, i;
  fetch_int64_t stream3_id;
  struct dynhds h2_headers;
  quiche_h3_header *nva = NULL;
  ssize_t nwritten;

  if (!stream)
  {
    *err = h3_data_setup(cf, data);
    if (*err)
    {
      return -1;
    }
    stream = H3_STREAM_CTX(ctx, data);
    DEBUGASSERT(stream);
  }

  Fetch_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);

  DEBUGASSERT(stream);
  nwritten = Fetch_h1_req_parse_read(&stream->h1, buf, len, NULL, 0, err);
  if (nwritten < 0)
    goto out;
  if (!stream->h1.done)
  {
    /* need more data */
    goto out;
  }
  DEBUGASSERT(stream->h1.req);

  *err = Fetch_http_req_to_h2(&h2_headers, stream->h1.req, data);
  if (*err)
  {
    nwritten = -1;
    goto out;
  }
  /* no longer needed */
  Fetch_h1_req_parse_free(&stream->h1);

  nheader = Fetch_dynhds_count(&h2_headers);
  nva = malloc(sizeof(quiche_h3_header) * nheader);
  if (!nva)
  {
    *err = FETCHE_OUT_OF_MEMORY;
    nwritten = -1;
    goto out;
  }

  for (i = 0; i < nheader; ++i)
  {
    struct dynhds_entry *e = Fetch_dynhds_getn(&h2_headers, i);
    nva[i].name = (unsigned char *)e->name;
    nva[i].name_len = e->namelen;
    nva[i].value = (unsigned char *)e->value;
    nva[i].value_len = e->valuelen;
  }

  if (eos && ((size_t)nwritten == len))
    stream->send_closed = TRUE;

  stream3_id = quiche_h3_send_request(ctx->h3c, ctx->qconn, nva, nheader,
                                      stream->send_closed);
  if (stream3_id < 0)
  {
    if (QUICHE_H3_ERR_STREAM_BLOCKED == stream3_id)
    {
      /* quiche seems to report this error if the connection window is
       * exhausted. Which happens frequently and intermittent. */
      FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] blocked", stream->id);
      stream->quic_flow_blocked = TRUE;
      *err = FETCHE_AGAIN;
      nwritten = -1;
      goto out;
    }
    else
    {
      FETCH_TRC_CF(data, cf, "send_request(%s) -> %" FMT_PRIu64,
                   data->state.url, stream3_id);
    }
    *err = FETCHE_SEND_ERROR;
    nwritten = -1;
    goto out;
  }

  DEBUGASSERT(!stream->opened);
  *err = FETCHE_OK;
  stream->id = stream3_id;
  stream->opened = TRUE;
  stream->closed = FALSE;
  stream->reset = FALSE;

  if (Fetch_trc_is_verbose(data))
  {
    infof(data, "[HTTP/3] [%" FMT_PRIu64 "] OPENED stream for %s",
          stream->id, data->state.url);
    for (i = 0; i < nheader; ++i)
    {
      infof(data, "[HTTP/3] [%" FMT_PRIu64 "] [%.*s: %.*s]", stream->id,
            (int)nva[i].name_len, nva[i].name,
            (int)nva[i].value_len, nva[i].value);
    }
  }

  if (nwritten > 0 && ((size_t)nwritten < len))
  {
    /* after the headers, there was request BODY data */
    size_t hds_len = (size_t)nwritten;
    ssize_t bwritten;

    bwritten = cf_quiche_send_body(cf, data, stream,
                                   buf + hds_len, len - hds_len, eos, err);
    if ((bwritten < 0) && (FETCHE_AGAIN != *err))
    {
      /* real error, fail */
      nwritten = -1;
    }
    else if (bwritten > 0)
    {
      nwritten += bwritten;
    }
  }

out:
  free(nva);
  Fetch_dynhds_free(&h2_headers);
  return nwritten;
}

static ssize_t cf_quiche_send(struct Fetch_cfilter *cf, struct Fetch_easy *data,
                              const void *buf, size_t len, bool eos,
                              FETCHcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  FETCHcode result;
  ssize_t nwritten;

  vquic_ctx_update_time(&ctx->q);

  *err = cf_process_ingress(cf, data);
  if (*err)
  {
    nwritten = -1;
    goto out;
  }

  if (!stream || !stream->opened)
  {
    nwritten = h3_open_stream(cf, data, buf, len, eos, err);
    if (nwritten < 0)
      goto out;
    stream = H3_STREAM_CTX(ctx, data);
  }
  else if (stream->closed)
  {
    if (stream->resp_hds_complete)
    {
      /* sending request body on a stream that has been closed by the
       * server. If the server has send us a final response, we should
       * silently discard the send data.
       * This happens for example on redirects where the server, instead
       * of reading the full request body just closed the stream after
       * sending the 30x response.
       * This is sort of a race: had the transfer loop called recv first,
       * it would see the response and stop/discard sending on its own- */
      FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] discarding data"
                             "on closed stream with response",
                   stream->id);
      *err = FETCHE_OK;
      nwritten = (ssize_t)len;
      goto out;
    }
    FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] send_body(len=%zu) "
                           "-> stream closed",
                 stream->id, len);
    *err = FETCHE_HTTP3;
    nwritten = -1;
    goto out;
  }
  else
  {
    nwritten = cf_quiche_send_body(cf, data, stream, buf, len, eos, err);
  }

out:
  result = cf_flush_egress(cf, data);
  if (result)
  {
    *err = result;
    nwritten = -1;
  }
  FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] cf_send(len=%zu) -> %zd, %d",
               stream ? stream->id : (fetch_uint64_t)~0, len, nwritten, *err);
  return nwritten;
}

static bool stream_is_writeable(struct Fetch_cfilter *cf,
                                struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  return stream && (quiche_conn_stream_writable(
                        ctx->qconn, (fetch_uint64_t)stream->id, 1) > 0);
}

static void cf_quiche_adjust_pollset(struct Fetch_cfilter *cf,
                                     struct Fetch_easy *data,
                                     struct easy_pollset *ps)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  bool want_recv, want_send;

  if (!ctx->qconn)
    return;

  Fetch_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
  if (want_recv || want_send)
  {
    struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    bool c_exhaust, s_exhaust;

    c_exhaust = FALSE; /* Have not found any call in quiche that tells
                          us if the connection itself is blocked */
    s_exhaust = want_send && stream && stream->opened &&
                (stream->quic_flow_blocked || !stream_is_writeable(cf, data));
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                !Fetch_bufq_is_empty(&ctx->q.sendbuf);

    Fetch_pollset_set(data, ps, ctx->q.sockfd, want_recv, want_send);
  }
}

/*
 * Called from transfer.c:data_pending to know if we should keep looping
 * to receive more data from the connection.
 */
static bool cf_quiche_data_pending(struct Fetch_cfilter *cf,
                                   const struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  const struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)cf;
  return stream && !Fetch_bufq_is_empty(&stream->recvbuf);
}

static FETCHcode h3_data_pause(struct Fetch_cfilter *cf,
                               struct Fetch_easy *data,
                               bool pause)
{
  /* TODO: there seems right now no API in quiche to shrink/enlarge
   * the streams windows. As we do in HTTP/2. */
  if (!pause)
  {
    h3_drain_stream(cf, data);
    Fetch_expire(data, 0, EXPIRE_RUN_NOW);
  }
  return FETCHE_OK;
}

static FETCHcode cf_quiche_data_event(struct Fetch_cfilter *cf,
                                      struct Fetch_easy *data,
                                      int event, int arg1, void *arg2)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  FETCHcode result = FETCHE_OK;

  (void)arg1;
  (void)arg2;
  switch (event)
  {
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = h3_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE:
    h3_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND:
  {
    struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if (stream && !stream->send_closed)
    {
      unsigned char body[1];
      ssize_t sent;

      stream->send_closed = TRUE;
      body[0] = 'X';
      sent = cf_quiche_send(cf, data, body, 0, TRUE, &result);
      FETCH_TRC_CF(data, cf, "[%" FMT_PRIu64 "] DONE_SEND -> %zd, %d",
                   stream->id, sent, result);
    }
    break;
  }
  case CF_CTRL_DATA_IDLE:
  {
    struct stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if (stream && !stream->closed)
    {
      result = cf_flush_egress(cf, data);
      if (result)
        FETCH_TRC_CF(data, cf, "data idle, flush egress -> %d", result);
    }
    break;
  }
  default:
    break;
  }
  return result;
}

static FETCHcode cf_quiche_ctx_open(struct Fetch_cfilter *cf,
                                    struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  int rv;
  FETCHcode result;
  const struct Fetch_sockaddr_ex *sockaddr;

  DEBUGASSERT(ctx->q.sockfd != FETCH_SOCKET_BAD);
  DEBUGASSERT(ctx->initialized);

  result = vquic_ctx_init(&ctx->q);
  if (result)
    return result;

  ctx->cfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if (!ctx->cfg)
  {
    failf(data, "cannot create quiche config");
    return FETCHE_FAILED_INIT;
  }
  quiche_config_enable_pacing(ctx->cfg, FALSE);
  quiche_config_set_max_idle_timeout(ctx->cfg, FETCH_QUIC_MAX_IDLE_MS);
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
                                       (uint8_t *)
                                           QUICHE_H3_APPLICATION_PROTOCOL,
                                       sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1);

  result = Fetch_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer,
                               QUICHE_H3_APPLICATION_PROTOCOL,
                               sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1,
                               NULL, NULL, cf, NULL);
  if (result)
    return result;

  result = Fetch_rand(data, ctx->scid, sizeof(ctx->scid));
  if (result)
    return result;

  Fetch_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &sockaddr, NULL);
  ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
  rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                   &ctx->q.local_addrlen);
  if (rv == -1)
    return FETCHE_QUIC_CONNECT_ERROR;

  ctx->qconn = quiche_conn_new_with_tls((const uint8_t *)ctx->scid,
                                        sizeof(ctx->scid), NULL, 0,
                                        (struct sockaddr *)&ctx->q.local_addr,
                                        ctx->q.local_addrlen,
                                        &sockaddr->fetch_sa_addr,
                                        sockaddr->addrlen,
                                        ctx->cfg, ctx->tls.ossl.ssl, FALSE);
  if (!ctx->qconn)
  {
    failf(data, "cannot create quiche connection");
    return FETCHE_OUT_OF_MEMORY;
  }

  /* Known to not work on Windows */
#if !defined(_WIN32) && defined(HAVE_QUICHE_CONN_SET_QLOG_FD)
  {
    int qfd;
    (void)Fetch_qlogdir(data, ctx->scid, sizeof(ctx->scid), &qfd);
    if (qfd != -1)
      quiche_conn_set_qlog_fd(ctx->qconn, qfd,
                              "qlog title", "fetch qlog");
  }
#endif

  result = cf_flush_egress(cf, data);
  if (result)
    return result;

  {
    unsigned char alpn_protocols[] = QUICHE_H3_APPLICATION_PROTOCOL;
    unsigned alpn_len, offset = 0;

    /* Replace each ALPN length prefix by a comma. */
    while (offset < sizeof(alpn_protocols) - 1)
    {
      alpn_len = alpn_protocols[offset];
      alpn_protocols[offset] = ',';
      offset += 1 + alpn_len;
    }

    FETCH_TRC_CF(data, cf, "Sent QUIC client Initial, ALPN: %s",
                 alpn_protocols + 1);
  }

  return FETCHE_OK;
}

static FETCHcode cf_quiche_verify_peer(struct Fetch_cfilter *cf,
                                       struct Fetch_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;

  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */

  return Fetch_vquic_tls_verify_peer(&ctx->tls, cf, data, &ctx->peer);
}

static FETCHcode cf_quiche_connect(struct Fetch_cfilter *cf,
                                   struct Fetch_easy *data,
                                   bool blocking, bool *done)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  FETCHcode result = FETCHE_OK;

  if (cf->connected)
  {
    *done = TRUE;
    return FETCHE_OK;
  }

  /* Connect the UDP filter first */
  if (!cf->next->connected)
  {
    result = Fetch_conn_cf_connect(cf->next, data, blocking, done);
    if (result || !*done)
      return result;
  }

  *done = FALSE;
  vquic_ctx_update_time(&ctx->q);

  if (!ctx->qconn)
  {
    result = cf_quiche_ctx_open(cf, data);
    if (result)
      goto out;
    ctx->started_at = ctx->q.last_op;
    result = cf_flush_egress(cf, data);
    /* we do not expect to be able to recv anything yet */
    goto out;
  }

  result = cf_process_ingress(cf, data);
  if (result)
    goto out;

  result = cf_flush_egress(cf, data);
  if (result)
    goto out;

  if (quiche_conn_is_established(ctx->qconn))
  {
    ctx->handshake_at = ctx->q.last_op;
    FETCH_TRC_CF(data, cf, "handshake complete after %dms",
                 (int)Fetch_timediff(ctx->handshake_at, ctx->started_at));
    result = cf_quiche_verify_peer(cf, data);
    if (!result)
    {
      FETCH_TRC_CF(data, cf, "peer verified");
      ctx->h3config = quiche_h3_config_new();
      if (!ctx->h3config)
      {
        result = FETCHE_OUT_OF_MEMORY;
        goto out;
      }

      /* Create a new HTTP/3 connection on the QUIC connection. */
      ctx->h3c = quiche_h3_conn_new_with_transport(ctx->qconn, ctx->h3config);
      if (!ctx->h3c)
      {
        result = FETCHE_OUT_OF_MEMORY;
        goto out;
      }
      cf->connected = TRUE;
      cf->conn->alpn = FETCH_HTTP_VERSION_3;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }
  else if (quiche_conn_is_draining(ctx->qconn))
  {
    /* When a QUIC server instance is shutting down, it may send us a
     * CONNECTION_CLOSE right away. Our connection then enters the DRAINING
     * state. The CONNECT may work in the near future again. Indicate
     * that as a "weird" reply. */
    result = FETCHE_WEIRD_SERVER_REPLY;
  }

out:
#ifndef FETCH_DISABLE_VERBOSE_STRINGS
  if (result && result != FETCHE_AGAIN)
  {
    struct ip_quadruple ip;

    Fetch_cf_socket_peek(cf->next, data, NULL, NULL, &ip);
    infof(data, "connect to %s port %u failed: %s",
          ip.remote_ip, ip.remote_port, fetch_easy_strerror(result));
  }
#endif
  return result;
}

static FETCHcode cf_quiche_shutdown(struct Fetch_cfilter *cf,
                                    struct Fetch_easy *data, bool *done)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  FETCHcode result = FETCHE_OK;

  if (cf->shutdown || !ctx || !ctx->qconn)
  {
    *done = TRUE;
    return FETCHE_OK;
  }

  *done = FALSE;
  if (!ctx->shutdown_started)
  {
    int err;

    ctx->shutdown_started = TRUE;
    vquic_ctx_update_time(&ctx->q);
    err = quiche_conn_close(ctx->qconn, TRUE, 0, NULL, 0);
    if (err)
    {
      FETCH_TRC_CF(data, cf, "error %d adding shutdown packet, "
                             "aborting shutdown",
                   err);
      result = FETCHE_SEND_ERROR;
      goto out;
    }
  }

  if (!Fetch_bufq_is_empty(&ctx->q.sendbuf))
  {
    FETCH_TRC_CF(data, cf, "shutdown, flushing sendbuf");
    result = cf_flush_egress(cf, data);
    if (result)
      goto out;
  }

  if (Fetch_bufq_is_empty(&ctx->q.sendbuf))
  {
    /* sent everything, quiche does not seem to support a graceful
     * shutdown waiting for a reply, so ware done. */
    FETCH_TRC_CF(data, cf, "shutdown completely sent off, done");
    *done = TRUE;
  }
  else
  {
    FETCH_TRC_CF(data, cf, "shutdown sending blocked");
  }

out:
  return result;
}

static void cf_quiche_close(struct Fetch_cfilter *cf, struct Fetch_easy *data)
{
  if (cf->ctx)
  {
    bool done;
    (void)cf_quiche_shutdown(cf, data, &done);
    cf_quiche_ctx_close(cf->ctx);
  }
}

static void cf_quiche_destroy(struct Fetch_cfilter *cf, struct Fetch_easy *data)
{
  (void)data;
  if (cf->ctx)
  {
    cf_quiche_ctx_free(cf->ctx);
    cf->ctx = NULL;
  }
}

static FETCHcode cf_quiche_query(struct Fetch_cfilter *cf,
                                 struct Fetch_easy *data,
                                 int query, int *pres1, void *pres2)
{
  struct cf_quiche_ctx *ctx = cf->ctx;

  switch (query)
  {
  case CF_QUERY_MAX_CONCURRENT:
  {
    fetch_uint64_t max_streams = CONN_INUSE(cf->conn);
    if (!ctx->goaway)
    {
      max_streams += quiche_conn_peer_streams_left_bidi(ctx->qconn);
    }
    *pres1 = (max_streams > INT_MAX) ? INT_MAX : (int)max_streams;
    FETCH_TRC_CF(data, cf, "query conn[%" FMT_OFF_T "]: "
                           "MAX_CONCURRENT -> %d (%zu in use)",
                 cf->conn->connection_id, *pres1, CONN_INUSE(cf->conn));
    return FETCHE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if (ctx->q.got_first_byte)
    {
      timediff_t ms = Fetch_timediff(ctx->q.first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return FETCHE_OK;
  case CF_QUERY_TIMER_CONNECT:
  {
    struct fetchtime *when = pres2;
    if (ctx->q.got_first_byte)
      *when = ctx->q.first_byte_at;
    return FETCHE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT:
  {
    struct fetchtime *when = pres2;
    if (cf->connected)
      *when = ctx->handshake_at;
    return FETCHE_OK;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 30;
    return FETCHE_OK;
  default:
    break;
  }
  return cf->next ? cf->next->cft->query(cf->next, data, query, pres1, pres2) : FETCHE_UNKNOWN_OPTION;
}

static bool cf_quiche_conn_is_alive(struct Fetch_cfilter *cf,
                                    struct Fetch_easy *data,
                                    bool *input_pending)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  bool alive = TRUE;

  *input_pending = FALSE;
  if (!ctx->qconn)
    return FALSE;

  if (quiche_conn_is_closed(ctx->qconn))
  {
    if (quiche_conn_is_timed_out(ctx->qconn))
      FETCH_TRC_CF(data, cf, "connection was closed due to idle timeout");
    else
      FETCH_TRC_CF(data, cf, "connection is closed");
    return FALSE;
  }

  if (!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    return FALSE;

  if (*input_pending)
  {
    /* This happens before we have sent off a request and the connection is
       not in use by any other transfer, there should not be any data here,
       only "protocol frames" */
    *input_pending = FALSE;
    if (cf_process_ingress(cf, data))
      alive = FALSE;
    else
    {
      alive = TRUE;
    }
  }

  return alive;
}

struct Fetch_cftype Fetch_cft_http3 = {
    "HTTP/3",
    CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX | CF_TYPE_HTTP,
    0,
    cf_quiche_destroy,
    cf_quiche_connect,
    cf_quiche_close,
    cf_quiche_shutdown,
    Fetch_cf_def_get_host,
    cf_quiche_adjust_pollset,
    cf_quiche_data_pending,
    cf_quiche_send,
    cf_quiche_recv,
    cf_quiche_data_event,
    cf_quiche_conn_is_alive,
    Fetch_cf_def_conn_keep_alive,
    cf_quiche_query,
};

FETCHcode Fetch_cf_quiche_create(struct Fetch_cfilter **pcf,
                                struct Fetch_easy *data,
                                struct connectdata *conn,
                                const struct Fetch_addrinfo *ai)
{
  struct cf_quiche_ctx *ctx = NULL;
  struct Fetch_cfilter *cf = NULL, *udp_cf = NULL;
  FETCHcode result;

  (void)data;
  (void)conn;
  ctx = calloc(1, sizeof(*ctx));
  if (!ctx)
  {
    result = FETCHE_OUT_OF_MEMORY;
    goto out;
  }
  cf_quiche_ctx_init(ctx);

  result = Fetch_cf_create(&cf, &Fetch_cft_http3, ctx);
  if (result)
    goto out;

  result = Fetch_cf_udp_create(&udp_cf, data, conn, ai, TRNSPRT_QUIC);
  if (result)
    goto out;

  udp_cf->conn = cf->conn;
  udp_cf->sockindex = cf->sockindex;
  cf->next = udp_cf;

out:
  *pcf = (!result) ? cf : NULL;
  if (result)
  {
    if (udp_cf)
      Fetch_conn_cf_discard_sub(cf, udp_cf, data, TRUE);
    Fetch_safefree(cf);
    cf_quiche_ctx_free(ctx);
  }

  return result;
}

bool Fetch_conn_is_quiche(const struct Fetch_easy *data,
                         const struct connectdata *conn,
                         int sockindex)
{
  struct Fetch_cfilter *cf = conn ? conn->cfilter[sockindex] : NULL;

  (void)data;
  for (; cf; cf = cf->next)
  {
    if (cf->cft == &Fetch_cft_http3)
      return TRUE;
    if (cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

#endif
