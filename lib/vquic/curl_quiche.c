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

#ifdef USE_QUICHE
#include <quiche.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
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
#include "vquic.h"
#include "vquic_int.h"
#include "curl_quiche.h"
#include "transfer.h"
#include "h2h3.h"
#include "vtls/openssl.h"
#include "vtls/keylog.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_MAX_DATA (1*1024*1024)
#define QUIC_IDLE_TIMEOUT (60 * 1000) /* milliseconds */

/* how many UDP packets to send max in one call */
#define MAX_PKT_BURST 10
#define MAX_UDP_PAYLOAD_SIZE  1452

/*
 * Store quiche version info in this buffer.
 */
void Curl_quiche_ver(char *p, size_t len)
{
  (void)msnprintf(p, len, "quiche/%s", quiche_version());
}

static void keylog_callback(const SSL *ssl, const char *line)
{
  (void)ssl;
  Curl_tls_keylog_write_line(line);
}

static SSL_CTX *quic_ssl_ctx(struct Curl_easy *data)
{
  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

  SSL_CTX_set_alpn_protos(ssl_ctx,
                          (const uint8_t *)QUICHE_H3_APPLICATION_PROTOCOL,
                          sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  /* Open the file if a TLS or QUIC backend has not done this before. */
  Curl_tls_keylog_open();
  if(Curl_tls_keylog_enabled()) {
    SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
  }

  {
    struct connectdata *conn = data->conn;
    if(conn->ssl_config.verifypeer) {
      const char * const ssl_cafile = conn->ssl_config.CAfile;
      const char * const ssl_capath = conn->ssl_config.CApath;
      if(ssl_cafile || ssl_capath) {
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        /* tell OpenSSL where to find CA certificates that are used to verify
           the server's certificate. */
        if(!SSL_CTX_load_verify_locations(ssl_ctx, ssl_cafile, ssl_capath)) {
          /* Fail if we insist on successfully verifying the server. */
          failf(data, "error setting certificate verify locations:"
                "  CAfile: %s CApath: %s",
                ssl_cafile ? ssl_cafile : "none",
                ssl_capath ? ssl_capath : "none");
          return NULL;
        }
        infof(data, " CAfile: %s", ssl_cafile ? ssl_cafile : "none");
        infof(data, " CApath: %s", ssl_capath ? ssl_capath : "none");
      }
#ifdef CURL_CA_FALLBACK
      else {
        /* verifying the peer without any CA certificates won't work so
           use openssl's built-in default as fallback */
        SSL_CTX_set_default_verify_paths(ssl_ctx);
      }
#endif
    }
  }
  return ssl_ctx;
}

struct quic_handshake {
  char *buf;       /* pointer to the buffer */
  size_t alloclen; /* size of allocation */
  size_t len;      /* size of content in buffer */
  size_t nread;    /* how many bytes have been read */
};

struct h3_event_node {
  struct h3_event_node *next;
  quiche_h3_event *ev;
};

struct cf_quiche_ctx {
  struct cf_quic_ctx q;
  quiche_conn *qconn;
  quiche_config *cfg;
  quiche_h3_conn *h3c;
  quiche_h3_config *h3config;
  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  SSL_CTX *sslctx;
  SSL *ssl;
  struct curltime started_at;        /* time the current attempt started */
  struct curltime handshake_at;      /* time connect handshake finished */
  struct curltime first_byte_at;     /* when first byte was recvd */
  struct curltime reconnect_at;      /* time the next attempt should start */
  BIT(goaway);                       /* got GOAWAY from server */
  BIT(got_first_byte);               /* if first byte was received */
};


#ifdef DEBUG_QUICHE
static void quiche_debug_log(const char *line, void *argp)
{
  (void)argp;
  fprintf(stderr, "%s\n", line);
}
#endif

static void h3_clear_pending(struct Curl_easy *data)
{
  struct HTTP *stream = data->req.p.http;

  if(stream->pending) {
    struct h3_event_node *node, *next;
    for(node = stream->pending; node; node = next) {
      next = node->next;
      quiche_h3_event_free(node->ev);
      free(node);
    }
    stream->pending = NULL;
  }
}

static void cf_quiche_ctx_clear(struct cf_quiche_ctx *ctx)
{
  if(ctx) {
    vquic_ctx_free(&ctx->q);
    if(ctx->qconn)
      quiche_conn_free(ctx->qconn);
    if(ctx->h3config)
      quiche_h3_config_free(ctx->h3config);
    if(ctx->h3c)
      quiche_h3_conn_free(ctx->h3c);
    if(ctx->cfg)
      quiche_config_free(ctx->cfg);
    memset(ctx, 0, sizeof(*ctx));
  }
}

static void notify_drain(struct Curl_cfilter *cf,
                         struct Curl_easy *data)
{
  (void)cf;
  data->state.drain = 1;
  Curl_expire(data, 0, EXPIRE_RUN_NOW);
}

static CURLcode h3_add_event(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             int64_t stream3_id, quiche_h3_event *ev)
{
  struct Curl_easy *mdata;
  struct h3_event_node *node, **pnext;

  DEBUGASSERT(data->multi);
  for(mdata = data->multi->easyp; mdata; mdata = mdata->next) {
    if(mdata->req.p.http && mdata->req.p.http->stream3_id == stream3_id) {
      break;
    }
  }

  if(!mdata) {
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"] event discarded, easy handle "
                  "not found", stream3_id));
    quiche_h3_event_free(ev);
    return CURLE_OK;
  }

  node = calloc(sizeof(*node), 1);
  if(!node) {
    quiche_h3_event_free(ev);
    return CURLE_OUT_OF_MEMORY;
  }
  node->ev = ev;
  /* append to process them in order of arrival */
  pnext = &mdata->req.p.http->pending;
  while(*pnext) {
    pnext = &((*pnext)->next);
  }
  *pnext = node;
  notify_drain(cf, mdata);
  return CURLE_OK;
}

struct h3h1header {
  char *dest;
  size_t destlen; /* left to use */
  size_t nlen; /* used */
};

static int cb_each_header(uint8_t *name, size_t name_len,
                          uint8_t *value, size_t value_len,
                          void *argp)
{
  struct h3h1header *headers = (struct h3h1header *)argp;
  size_t olen = 0;

  if((name_len == 7) && !strncmp(H2H3_PSEUDO_STATUS, (char *)name, 7)) {
    msnprintf(headers->dest,
              headers->destlen, "HTTP/3 %.*s \r\n",
              (int) value_len, value);
  }
  else if(!headers->nlen) {
    return CURLE_HTTP3;
  }
  else {
    msnprintf(headers->dest,
              headers->destlen, "%.*s: %.*s\r\n",
              (int)name_len, name, (int) value_len, value);
  }
  olen = strlen(headers->dest);
  headers->destlen -= olen;
  headers->nlen += olen;
  headers->dest += olen;
  return 0;
}

static ssize_t cf_recv_body(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                char *buf, size_t len,
                                CURLcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  ssize_t nread;
  size_t offset = 0;

  if(!stream->firstbody) {
    /* add a header-body separator CRLF */
    offset = 2;
  }
  nread = quiche_h3_recv_body(ctx->h3c, ctx->qconn, stream->stream3_id,
                              (unsigned char *)buf + offset, len - offset);
  if(nread >= 0) {
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"][DATA] len=%zd",
                  stream->stream3_id, nread));
    if(!stream->firstbody) {
      stream->firstbody = TRUE;
      buf[0] = '\r';
      buf[1] = '\n';
      nread += offset;
    }
  }
  else if(nread == -1) {
    *err = CURLE_AGAIN;
    stream->h3_recving_data = FALSE;
  }
  else {
    failf(data, "Error %zd in HTTP/3 response body for stream[%"PRId64"]",
          nread, stream->stream3_id);
    stream->closed = TRUE;
    stream->reset = TRUE;
    streamclose(cf->conn, "Reset of stream");
    stream->h3_recving_data = FALSE;
    nread = -1;
    *err = stream->h3_got_header? CURLE_PARTIAL_FILE : CURLE_RECV_ERROR;
  }
  return nread;
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

static ssize_t h3_process_event(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                char *buf, size_t len,
                                int64_t stream3_id,
                                quiche_h3_event *ev,
                                CURLcode *err)
{
  struct HTTP *stream = data->req.p.http;
  ssize_t recvd = 0;
  int rc;
  struct h3h1header headers;

  DEBUGASSERT(stream3_id == stream->stream3_id);

  *err = CURLE_OK;
  switch(quiche_h3_event_type(ev)) {
  case QUICHE_H3_EVENT_HEADERS:
    stream->h3_got_header = TRUE;
    headers.dest = buf;
    headers.destlen = len;
    headers.nlen = 0;
    rc = quiche_h3_event_for_each_header(ev, cb_each_header, &headers);
    if(rc) {
      failf(data, "Error %d in HTTP/3 response header for stream[%"PRId64"]",
            rc, stream3_id);
      *err = CURLE_RECV_ERROR;
      recvd = -1;
      break;
    }
    recvd = headers.nlen;
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"][HEADERS] len=%zd",
                  stream3_id, recvd));
    break;

  case QUICHE_H3_EVENT_DATA:
    DEBUGASSERT(!stream->closed);
    stream->h3_recving_data = TRUE;
    recvd = cf_recv_body(cf, data, buf, len, err);
    if(recvd < 0) {
      if(*err != CURLE_AGAIN)
        return -1;
      recvd = 0;
    }
    break;

  case QUICHE_H3_EVENT_RESET:
      DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"][RESET]", stream3_id));
    stream->closed = TRUE;
    stream->reset = TRUE;
    /* streamclose(cf->conn, "Reset of stream");*/
    stream->h3_recving_data = FALSE;
    break;

  case QUICHE_H3_EVENT_FINISHED:
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"][FINISHED]", stream3_id));
    stream->closed = TRUE;
    /* streamclose(cf->conn, "End of stream");*/
    stream->h3_recving_data = FALSE;
    break;

  case QUICHE_H3_EVENT_GOAWAY:
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"][GOAWAY]", stream3_id));
    break;

  default:
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"] recv, unhandled event %d",
                  stream3_id, quiche_h3_event_type(ev)));
    break;
  }
  return recvd;
}

static ssize_t h3_process_pending(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  char *buf, size_t len,
                                  CURLcode *err)
{
  struct HTTP *stream = data->req.p.http;
  struct h3_event_node *node = stream->pending, **pnext = &stream->pending;
  ssize_t recvd = 0, erecvd;

  *err = CURLE_OK;
  DEBUGASSERT(stream);
  while(node && len) {
    erecvd = h3_process_event(cf, data, buf, len,
                              stream->stream3_id, node->ev, err);
    quiche_h3_event_free(node->ev);
    *pnext = node->next;
    free(node);
    node = *pnext;
    if(erecvd < 0) {
      DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"] process event -> %d",
                    stream->stream3_id, *err));
      return erecvd;
    }
    recvd += erecvd;
    *err = CURLE_OK;
    buf += erecvd;
    len -= erecvd;
  }
  return recvd;
}

static CURLcode cf_process_ingress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  int64_t stream3_id = data->req.p.http? data->req.p.http->stream3_id : -1;
  uint8_t buf[65536];
  int bufsize = (int)sizeof(buf);
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen;
  quiche_recv_info recv_info;
  ssize_t recvd, nread;
  ssize_t total = 0, pkts = 0;

  DEBUGASSERT(ctx->qconn);

  /* in case the timeout expired */
  quiche_conn_on_timeout(ctx->qconn);

  do {
    remote_addrlen = sizeof(remote_addr);
    while((recvd = recvfrom(ctx->q.sockfd, (char *)buf, bufsize, 0,
                            (struct sockaddr *)&remote_addr,
                            &remote_addrlen)) == -1 &&
          SOCKERRNO == EINTR)
      ;
    if(recvd < 0) {
      if((SOCKERRNO == EAGAIN) || (SOCKERRNO == EWOULDBLOCK)) {
        break;
      }
      if(SOCKERRNO == ECONNREFUSED) {
        const char *r_ip;
        int r_port;
        Curl_cf_socket_peek(cf->next, data, NULL, NULL,
                            &r_ip, &r_port, NULL, NULL);
        failf(data, "quiche: connection to %s:%u refused",
              r_ip, r_port);
        return CURLE_COULDNT_CONNECT;
      }
      failf(data, "quiche: recvfrom() unexpectedly returned %zd "
            "(errno: %d, socket %d)", recvd, SOCKERRNO, ctx->q.sockfd);
      return CURLE_RECV_ERROR;
    }

    total += recvd;
    ++pkts;
    if(recvd > 0 && !ctx->got_first_byte) {
      ctx->first_byte_at = Curl_now();
      ctx->got_first_byte = TRUE;
    }
    recv_info.from = (struct sockaddr *) &remote_addr;
    recv_info.from_len = remote_addrlen;
    recv_info.to = (struct sockaddr *) &ctx->q.local_addr;
    recv_info.to_len = ctx->q.local_addrlen;

    nread = quiche_conn_recv(ctx->qconn, buf, recvd, &recv_info);
    if(nread < 0) {
      if(QUICHE_ERR_DONE == nread) {
        DEBUGF(LOG_CF(data, cf, "ingress, quiche is DONE"));
        return CURLE_OK;
      }
      else if(QUICHE_ERR_TLS_FAIL == nread) {
        long verify_ok = SSL_get_verify_result(ctx->ssl);
        if(verify_ok != X509_V_OK) {
          failf(data, "SSL certificate problem: %s",
                X509_verify_cert_error_string(verify_ok));
          return CURLE_PEER_FAILED_VERIFICATION;
        }
      }
      else {
        failf(data, "quiche_conn_recv() == %zd", nread);
        return CURLE_RECV_ERROR;
      }
    }
    else if(nread < recvd) {
      DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] ingress, quiche only "
                    "accepted %zd/%zd bytes",
                    stream3_id, nread, recvd));
    }

  } while(pkts < 1000); /* arbitrary */

  DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] ingress, recvd %zd bytes "
                "in %zd packets", stream3_id, total, pkts));
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
  int64_t stream3_id = data->req.p.http? data->req.p.http->stream3_id : -1;
  quiche_send_info send_info;
  ssize_t outlen, total_len = 0;
  size_t max_udp_payload_size =
    quiche_conn_max_send_udp_payload_size(ctx->qconn);
  size_t gsolen = max_udp_payload_size;
  size_t sent, pktcnt = 0;
  CURLcode result;
  int64_t timeout_ns;

  ctx->q.no_gso = TRUE;
  if(ctx->q.num_blocked_pkt) {
    result = vquic_send_blocked_pkt(cf, data, &ctx->q);
    if(result) {
      if(result == CURLE_AGAIN) {
        DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] egress, still not "
                      "able to send blocked packet", stream3_id));
        Curl_expire(data, 1, EXPIRE_QUIC);
        return CURLE_OK;
      }
      goto out;
    }
  }

  for(;;) {
    outlen = quiche_conn_send(ctx->qconn, ctx->q.pktbuf, max_udp_payload_size,
                              &send_info);
    if(outlen == QUICHE_ERR_DONE) {
      result = CURLE_OK;
      goto out;
    }

    if(outlen < 0) {
      failf(data, "quiche_conn_send returned %zd", outlen);
      result = CURLE_SEND_ERROR;
      goto out;
    }

    /* send the pktbuf *before* the last addition */
    result = vquic_send_packet(cf, data, &ctx->q, ctx->q.pktbuf,
                               outlen, gsolen, &sent);
    ++pktcnt;
    total_len += outlen;
    if(result) {
      if(result == CURLE_AGAIN) {
        /* blocked, add the pktbuf *before* and *at* the last addition
         * separately to the blocked packages */
        DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] egress, pushing blocked "
                      "packet with %zd bytes", stream3_id, outlen));
        vquic_push_blocked_pkt(cf, &ctx->q, ctx->q.pktbuf, outlen, gsolen);
        Curl_expire(data, 1, EXPIRE_QUIC);
        return CURLE_OK;
      }
      goto out;
    }
  }

out:
  timeout_ns = quiche_conn_timeout_as_nanos(ctx->qconn);
  if(timeout_ns % 1000000)
    timeout_ns += 1000000;
    /* expire resolution is milliseconds */
  Curl_expire(data, (timeout_ns / 1000000), EXPIRE_QUIC);
  if(pktcnt)
    DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] egress, sent %zd packets "
                  "with %zd bytes", stream3_id, pktcnt, total_len));
  return result;
}

static ssize_t recv_closed_stream(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  CURLcode *err)
{
  struct HTTP *stream = data->req.p.http;
  ssize_t nread = -1;

  if(stream->reset) {
    failf(data,
          "HTTP/3 stream %" PRId64 " reset by server", stream->stream3_id);
    *err = stream->h3_got_header? CURLE_PARTIAL_FILE : CURLE_RECV_ERROR;
    DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] cf_recv, was reset -> %d",
                  stream->stream3_id, *err));
    goto out;
  }

  if(!stream->h3_got_header) {
    failf(data,
          "HTTP/3 stream %" PRId64 " was closed cleanly, but before getting"
          " all response header fields, treated as error",
          stream->stream3_id);
    /* *err = CURLE_PARTIAL_FILE; */
    *err = CURLE_RECV_ERROR;
    DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] cf_recv, closed incomplete"
                  " -> %d", stream->stream3_id, *err));
    goto out;
  }
  else {
    DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] cf_recv, closed ok"
                  " -> %d", stream->stream3_id, *err));
  }
  *err = CURLE_OK;
  nread = 0;

out:
  return nread;
}

static CURLcode cf_poll_events(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  quiche_h3_event *ev;

  /* Take in the events and distribute them to the transfers. */
  while(1) {
    int64_t stream3_id = quiche_h3_conn_poll(ctx->h3c, ctx->qconn, &ev);
    if(stream3_id < 0) {
      /* nothing more to do */
      break;
    }
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"] recv, queue event %s "
                  "for [h3sid=%"PRId64"]",
                  stream? stream->stream3_id : -1, cf_ev_name(ev),
                  stream3_id));
    if(h3_add_event(cf, data, stream3_id, ev) != CURLE_OK) {
      return CURLE_OUT_OF_MEMORY;
    }
  }
  return CURLE_OK;
}

static ssize_t cf_recv_transfer_data(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                      char *buf, size_t len,
                                      CURLcode *err)
{
  struct HTTP *stream = data->req.p.http;
  ssize_t recvd = -1;
  size_t offset = 0;

  if(stream->h3_recving_data) {
    /* try receiving body first */
    recvd = cf_recv_body(cf, data, buf, len, err);
    if(recvd < 0) {
      if(*err != CURLE_AGAIN)
        return -1;
      recvd = 0;
    }
    if(recvd > 0) {
      offset = recvd;
    }
  }

  if(offset < len && stream->pending) {
    /* process any pending events for `data` first. if there are,
     * return so the transfer can handle those. We do not want to
     * progress ingress while events are pending here. */
    recvd = h3_process_pending(cf, data, buf + offset, len - offset, err);
    if(recvd < 0) {
      if(*err != CURLE_AGAIN)
        return -1;
      recvd = 0;
    }
    if(recvd > 0) {
      offset += recvd;
    }
  }

  if(offset) {
    *err = CURLE_OK;
    return offset;
  }
  *err = CURLE_AGAIN;
  return 0;
}

static ssize_t cf_quiche_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                              char *buf, size_t len, CURLcode *err)
{
  struct HTTP *stream = data->req.p.http;
  ssize_t recvd = -1;

  *err = CURLE_AGAIN;

  recvd = cf_recv_transfer_data(cf, data, buf, len, err);
  if(recvd)
    goto out;
  if(stream->closed) {
    recvd = recv_closed_stream(cf, data, err);
    goto out;
  }

  /* we did get nothing from the quiche buffers or pending events.
   * Take in more data from the connection, any error is fatal */
  if(cf_process_ingress(cf, data)) {
    DEBUGF(LOG_CF(data, cf, "h3_stream_recv returns on ingress"));
    *err = CURLE_RECV_ERROR;
    recvd = -1;
    goto out;
  }
  /* poll quiche and distribute the events to the transfers */
  *err = cf_poll_events(cf, data);
  if(*err) {
    recvd = -1;
    goto out;
  }

  /* try to receive again for this transfer */
  recvd = cf_recv_transfer_data(cf, data, buf, len, err);
  if(recvd)
    goto out;
  if(stream->closed) {
    recvd = recv_closed_stream(cf, data, err);
    goto out;
  }
  recvd = -1;
  *err = CURLE_AGAIN;
  data->state.drain = 0;

out:
  if(cf_flush_egress(cf, data)) {
    DEBUGF(LOG_CF(data, cf, "cf_recv, flush egress failed"));
    *err = CURLE_SEND_ERROR;
    return -1;
  }
  DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"] cf_recv -> %zd, err=%d",
                stream->stream3_id, recvd, *err));
  if(recvd > 0)
    notify_drain(cf, data);
  return recvd;
}

/* Index where :authority header field will appear in request header
   field list. */
#define AUTHORITY_DST_IDX 3

static CURLcode cf_http_request(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const void *mem,
                                size_t len)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  size_t nheader;
  int64_t stream3_id;
  quiche_h3_header *nva = NULL;
  CURLcode result = CURLE_OK;
  struct h2h3req *hreq = NULL;

  stream->h3req = TRUE; /* send off! */
  stream->closed = FALSE;
  stream->reset = FALSE;

  result = Curl_pseudo_headers(data, mem, len, NULL, &hreq);
  if(result)
    goto fail;
  nheader = hreq->entries;

  nva = malloc(sizeof(quiche_h3_header) * nheader);
  if(!nva) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }
  else {
    unsigned int i;
    for(i = 0; i < nheader; i++) {
      nva[i].name = (unsigned char *)hreq->header[i].name;
      nva[i].name_len = hreq->header[i].namelen;
      nva[i].value = (unsigned char *)hreq->header[i].value;
      nva[i].value_len = hreq->header[i].valuelen;
    }
  }

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

    stream->upload_done = !stream->upload_left;
    stream3_id = quiche_h3_send_request(ctx->h3c, ctx->qconn, nva, nheader,
                                        stream->upload_done);
    break;
  default:
    stream->upload_left = 0;
    stream->upload_done = TRUE;
    stream3_id = quiche_h3_send_request(ctx->h3c, ctx->qconn, nva, nheader,
                                        TRUE);
    break;
  }

  Curl_safefree(nva);

  if(stream3_id < 0) {
    if(QUICHE_H3_ERR_STREAM_BLOCKED == stream3_id) {
      DEBUGF(LOG_CF(data, cf, "send_request(%s, body_len=%ld) rejected "
                    "with H3_ERR_STREAM_BLOCKED",
                    data->state.url, (long)stream->upload_left));
      result = CURLE_AGAIN;
      goto fail;
    }
    else {
      DEBUGF(LOG_CF(data, cf, "send_request(%s, body_len=%ld) -> %" PRId64,
                    data->state.url, (long)stream->upload_left, stream3_id));
    }
    result = CURLE_SEND_ERROR;
    goto fail;
  }

  stream->stream3_id = stream3_id;
  infof(data, "Using HTTP/3 Stream ID: %" PRId64 " (easy handle %p)",
        stream3_id, (void *)data);
  DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] opened for %s",
                stream3_id, data->state.url));

  Curl_pseudo_free(hreq);
  return CURLE_OK;

fail:
  free(nva);
  Curl_pseudo_free(hreq);
  return result;
}

static ssize_t cf_quiche_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                              const void *buf, size_t len, CURLcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  ssize_t nwritten;

  DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] cf_send(len=%zu) start",
                stream->h3req? stream->stream3_id : -1, len));
  *err = cf_process_ingress(cf, data);
  if(*err)
    return -1;

  if(!stream->h3req) {
    CURLcode result = cf_http_request(cf, data, buf, len);
    if(result) {
      *err = result;
      return -1;
    }
    nwritten = len;
  }
  else {
    nwritten = quiche_h3_send_body(ctx->h3c, ctx->qconn, stream->stream3_id,
                                   (uint8_t *)buf, len, FALSE);
    DEBUGF(LOG_CF(data, cf, "[h3sid=%" PRId64 "] send body(len=%zu) -> %zd",
                  stream->stream3_id, len, nwritten));
    if(nwritten == QUICHE_H3_ERR_DONE) {
      /* no error, nothing to do (flow control?) */
      *err = CURLE_AGAIN;
      nwritten = -1;
    }
    else if(nwritten == QUICHE_H3_TRANSPORT_ERR_FINAL_SIZE) {
      DEBUGF(LOG_CF(data, cf, "send_body(len=%zu) -> exceeds size", len));
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
    }
    else if(nwritten < 0) {
      DEBUGF(LOG_CF(data, cf, "send_body(len=%zu) -> SEND_ERROR", len));
      *err = CURLE_SEND_ERROR;
      nwritten = -1;
    }
    else {
      *err = CURLE_OK;
    }
  }

  if(cf_flush_egress(cf, data)) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  return nwritten;
}

static bool stream_is_writeable(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;

  /* surely, there must be a better way */
  quiche_stream_iter *qiter = quiche_conn_writable(ctx->qconn);
  if(qiter) {
    uint64_t stream_id;
    while(quiche_stream_iter_next(qiter, &stream_id)) {
      if(stream_id == (uint64_t)stream->stream3_id)
        return TRUE;
    }
    quiche_stream_iter_free(qiter);
  }
  return FALSE;
}

static int cf_quiche_get_select_socks(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      curl_socket_t *socks)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct SingleRequest *k = &data->req;
  int rv = GETSOCK_BLANK;

  socks[0] = ctx->q.sockfd;

  /* in an HTTP/3 connection we can basically always get a frame so we should
     always be ready for one */
  rv |= GETSOCK_READSOCK(0);

  /* we're still uploading or the HTTP/3 layer wants to send data */
  if(((k->keepon & KEEP_SENDBITS) == KEEP_SEND)
     && stream_is_writeable(cf, data))
    rv |= GETSOCK_WRITESOCK(0);

  return rv;
}

/*
 * Called from transfer.c:data_pending to know if we should keep looping
 * to receive more data from the connection.
 */
static bool cf_quiche_data_pending(struct Curl_cfilter *cf,
                                   const struct Curl_easy *data)
{
  struct HTTP *stream = data->req.p.http;

  if(stream->pending) {
    DEBUGF(LOG_CF((struct Curl_easy *)data, cf,
                   "[h3sid=%"PRId64"] has event pending", stream->stream3_id));
    return TRUE;
  }
  if(stream->h3_recving_data) {
    DEBUGF(LOG_CF((struct Curl_easy *)data, cf,
                   "[h3sid=%"PRId64"] is receiving DATA", stream->stream3_id));
    return TRUE;
  }
  if(data->state.drain) {
    DEBUGF(LOG_CF((struct Curl_easy *)data, cf,
                   "[h3sid=%"PRId64"] is draining", stream->stream3_id));
    return TRUE;
  }
  return FALSE;
}

static CURLcode cf_quiche_data_event(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     int event, int arg1, void *arg2)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_DONE: {
    struct HTTP *stream = data->req.p.http;
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"] easy handle is %s",
                  stream->stream3_id, arg1? "cancelled" : "done"));
    h3_clear_pending(data);
    break;
  }
  case CF_CTRL_DATA_DONE_SEND: {
    struct HTTP *stream = data->req.p.http;
    ssize_t sent;
    stream->upload_done = TRUE;
    sent = quiche_h3_send_body(ctx->h3c, ctx->qconn, stream->stream3_id,
                               NULL, 0, TRUE);
    DEBUGF(LOG_CF(data, cf, "[h3sid=%"PRId64"] send_body FINISHED",
                  stream->stream3_id));
    if(sent < 0)
      return CURLE_SEND_ERROR;
    break;
  }
  case CF_CTRL_DATA_IDLE:
    /* anything to do? */
    break;
  default:
    break;
  }
  return result;
}

static CURLcode cf_verify_peer(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  cf->conn->httpversion = 30;
  cf->conn->bundle->multiuse = BUNDLE_MULTIPLEX;

  if(cf->conn->ssl_config.verifyhost) {
    X509 *server_cert;
    server_cert = SSL_get_peer_certificate(ctx->ssl);
    if(!server_cert) {
      result = CURLE_PEER_FAILED_VERIFICATION;
      goto out;
    }
    result = Curl_ossl_verifyhost(data, cf->conn, server_cert);
    X509_free(server_cert);
    if(result)
      goto out;
  }
  else
    DEBUGF(LOG_CF(data, cf, "Skipped certificate verification"));

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
  if(data->set.ssl.certinfo)
    /* asked to gather certificate info */
    (void)Curl_ossl_certchain(data, ctx->ssl);

out:
  if(result) {
    if(ctx->h3config) {
      quiche_h3_config_free(ctx->h3config);
      ctx->h3config = NULL;
    }
    if(ctx->h3c) {
      quiche_h3_conn_free(ctx->h3c);
      ctx->h3c = NULL;
    }
  }
  return result;
}

static CURLcode cf_connect_start(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  int rv;
  CURLcode result;
  const struct Curl_sockaddr_ex *sockaddr;

  DEBUGASSERT(ctx->q.sockfd != CURL_SOCKET_BAD);

#ifdef DEBUG_QUICHE
  /* initialize debug log callback only once */
  static int debug_log_init = 0;
  if(!debug_log_init) {
    quiche_enable_debug_logging(quiche_debug_log, NULL);
    debug_log_init = 1;
  }
#endif

  result = vquic_ctx_init(&ctx->q, MAX_UDP_PAYLOAD_SIZE * MAX_PKT_BURST);
  if(result)
    return result;

  ctx->cfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if(!ctx->cfg) {
    failf(data, "can't create quiche config");
    return CURLE_FAILED_INIT;
  }
  quiche_config_set_max_idle_timeout(ctx->cfg, QUIC_IDLE_TIMEOUT);
  quiche_config_set_initial_max_data(ctx->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_bidi_local(
    ctx->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_bidi_remote(
    ctx->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_uni(ctx->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_streams_bidi(ctx->cfg, QUIC_MAX_STREAMS);
  quiche_config_set_initial_max_streams_uni(ctx->cfg, QUIC_MAX_STREAMS);
  quiche_config_set_application_protos(ctx->cfg,
                                       (uint8_t *)
                                       QUICHE_H3_APPLICATION_PROTOCOL,
                                       sizeof(QUICHE_H3_APPLICATION_PROTOCOL)
                                       - 1);

  DEBUGASSERT(!ctx->ssl);
  DEBUGASSERT(!ctx->sslctx);
  ctx->sslctx = quic_ssl_ctx(data);
  if(!ctx->sslctx)
    return CURLE_QUIC_CONNECT_ERROR;
  ctx->ssl = SSL_new(ctx->sslctx);
  if(!ctx->ssl)
    return CURLE_QUIC_CONNECT_ERROR;

  SSL_set_app_data(ctx->ssl, cf);
  SSL_set_tlsext_host_name(ctx->ssl, cf->conn->host.name);

  result = Curl_rand(data, ctx->scid, sizeof(ctx->scid));
  if(result)
    return result;

  Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd,
                      &sockaddr, NULL, NULL, NULL, NULL);
  ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
  rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                   &ctx->q.local_addrlen);
  if(rv == -1)
    return CURLE_QUIC_CONNECT_ERROR;

  ctx->qconn = quiche_conn_new_with_tls((const uint8_t *)ctx->scid,
                                      sizeof(ctx->scid), NULL, 0,
                                      (struct sockaddr *)&ctx->q.local_addr,
                                      ctx->q.local_addrlen,
                                      &sockaddr->sa_addr, sockaddr->addrlen,
                                      ctx->cfg, ctx->ssl, false);
  if(!ctx->qconn) {
    failf(data, "can't create quiche connection");
    return CURLE_OUT_OF_MEMORY;
  }

  /* Known to not work on Windows */
#if !defined(WIN32) && defined(HAVE_QUICHE_CONN_SET_QLOG_FD)
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

    DEBUGF(LOG_CF(data, cf, "Sent QUIC client Initial, ALPN: %s",
                   alpn_protocols + 1));
  }

  return CURLE_OK;
}

static CURLcode cf_quiche_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool blocking, bool *done)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct curltime now;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the UDP filter first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, blocking, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;
  now = Curl_now();

  if(ctx->reconnect_at.tv_sec && Curl_timediff(now, ctx->reconnect_at) < 0) {
    /* Not time yet to attempt the next connect */
    DEBUGF(LOG_CF(data, cf, "waiting for reconnect time"));
    goto out;
  }

  if(!ctx->qconn) {
    result = cf_connect_start(cf, data);
    if(result)
      goto out;
    ctx->started_at = now;
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
    DEBUGF(LOG_CF(data, cf, "handshake complete after %dms",
           (int)Curl_timediff(now, ctx->started_at)));
    ctx->handshake_at = now;
    result = cf_verify_peer(cf, data);
    if(!result) {
      DEBUGF(LOG_CF(data, cf, "peer verified"));
      cf->connected = TRUE;
      cf->conn->alpn = CURL_HTTP_VERSION_3;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }
  else if(quiche_conn_is_draining(ctx->qconn)) {
    /* When a QUIC server instance is shutting down, it may send us a
     * CONNECTION_CLOSE right away. Our connection then enters the DRAINING
     * state.
     * This may be a stopping of the service or it may be that the server
     * is reloading and a new instance will start serving soon.
     * In any case, we tear down our socket and start over with a new one.
     * We re-open the underlying UDP cf right now, but do not start
     * connecting until called again.
     */
    int reconn_delay_ms = 200;

    DEBUGF(LOG_CF(data, cf, "connect, remote closed, reconnect after %dms",
                  reconn_delay_ms));
    Curl_conn_cf_close(cf->next, data);
    cf_quiche_ctx_clear(ctx);
    result = Curl_conn_cf_connect(cf->next, data, FALSE, done);
    if(!result && *done) {
      *done = FALSE;
      ctx->reconnect_at = Curl_now();
      ctx->reconnect_at.tv_usec += reconn_delay_ms * 1000;
      Curl_expire(data, reconn_delay_ms, EXPIRE_QUIC);
      result = CURLE_OK;
    }
  }

out:
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(result && result != CURLE_AGAIN) {
    const char *r_ip;
    int r_port;

    Curl_cf_socket_peek(cf->next, data, NULL, NULL,
                        &r_ip, &r_port, NULL, NULL);
    infof(data, "connect to %s port %u failed: %s",
          r_ip, r_port, curl_easy_strerror(result));
  }
#endif
  return result;
}

static void cf_quiche_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
    if(ctx->qconn) {
      (void)quiche_conn_close(ctx->qconn, TRUE, 0, NULL, 0);
      /* flushing the egress is not a failsafe way to deliver all the
         outstanding packets, but we also don't want to get stuck here... */
      (void)cf_flush_egress(cf, data);
    }
    cf_quiche_ctx_clear(ctx);
  }
}

static void cf_quiche_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;

  (void)data;
  cf_quiche_ctx_clear(ctx);
  free(ctx);
  cf->ctx = NULL;
}

static CURLcode cf_quiche_query(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int query, int *pres1, void *pres2)
{
  struct cf_quiche_ctx *ctx = cf->ctx;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT: {
    uint64_t max_streams = CONN_INUSE(cf->conn);
    if(!ctx->goaway) {
      max_streams += quiche_conn_peer_streams_left_bidi(ctx->qconn);
    }
    *pres1 = (max_streams > INT_MAX)? INT_MAX : (int)max_streams;
    DEBUGF(LOG_CF(data, cf, "query: MAX_CONCURRENT -> %d", *pres1));
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->got_first_byte) {
      timediff_t ms = Curl_timediff(ctx->first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX)? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT: {
    struct curltime *when = pres2;
    if(ctx->got_first_byte)
      *when = ctx->first_byte_at;
    return CURLE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT: {
    struct curltime *when = pres2;
    if(cf->connected)
      *when = ctx->handshake_at;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_quiche_conn_is_alive(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *input_pending)
{
  bool alive = TRUE;

  *input_pending = FALSE;
  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    return FALSE;

  if(*input_pending) {
    /* This happens before we've sent off a request and the connection is
       not in use by any other transfer, there shouldn't be any data here,
       only "protocol frames" */
    *input_pending = FALSE;
    Curl_attach_connection(data, cf->conn);
    if(cf_process_ingress(cf, data))
      alive = FALSE;
    else {
      alive = TRUE;
    }
    Curl_detach_connection(data);
  }

  return alive;
}

struct Curl_cftype Curl_cft_http3 = {
  "HTTP/3",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX,
  0,
  cf_quiche_destroy,
  cf_quiche_connect,
  cf_quiche_close,
  Curl_cf_def_get_host,
  cf_quiche_get_select_socks,
  cf_quiche_data_pending,
  cf_quiche_send,
  cf_quiche_recv,
  cf_quiche_data_event,
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
  ctx = calloc(sizeof(*ctx), 1);
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

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
  *pcf = (!result)? cf : NULL;
  if(result) {
    if(udp_cf)
      Curl_conn_cf_discard(udp_cf, data);
    Curl_safefree(cf);
    Curl_safefree(ctx);
  }

  return result;
}

bool Curl_conn_is_quiche(const struct Curl_easy *data,
                         const struct connectdata *conn,
                         int sockindex)
{
  struct Curl_cfilter *cf = conn? conn->cfilter[sockindex] : NULL;

  (void)data;
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_http3)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

#endif
