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
  int64_t stream3_id;
  quiche_h3_event *ev;
};

struct cf_quiche_ctx {
  curl_socket_t sockfd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  quiche_conn *qconn;
  quiche_config *cfg;
  quiche_h3_conn *h3c;
  quiche_h3_config *h3config;
  uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
  SSL_CTX *sslctx;
  SSL *ssl;
  struct h3_event_node *pending;
  struct curltime connect_started; /* time the current attempt started */
  struct curltime handshake_done;    /* time connect handshake finished */
  int first_reply_ms;              /* ms since first data arrived */
  struct curltime reconnect_at;    /* time the next attempt should start */
  bool goaway;
};


#ifdef DEBUG_QUICHE
static void quiche_debug_log(const char *line, void *argp)
{
  (void)argp;
  fprintf(stderr, "%s\n", line);
}
#endif

static void h3_clear_pending(struct cf_quiche_ctx *ctx)
{
  if(ctx->pending) {
    struct h3_event_node *node, *next;
    for(node = ctx->pending; node; node = next) {
      next = node->next;
      quiche_h3_event_free(node->ev);
      free(node);
    }
    ctx->pending = NULL;
  }
}

static void cf_quiche_ctx_clear(struct cf_quiche_ctx *ctx)
{
  if(ctx) {
    if(ctx->pending)
      h3_clear_pending(ctx);
    if(ctx->qconn)
      quiche_conn_free(ctx->qconn);
    if(ctx->h3config)
      quiche_h3_config_free(ctx->h3config);
    if(ctx->h3c)
      quiche_h3_conn_free(ctx->h3c);
    if(ctx->cfg)
      quiche_config_free(ctx->cfg);
    memset(ctx, 0, sizeof(*ctx));
    ctx->first_reply_ms = -1;
  }
}

static CURLcode h3_add_event(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             int64_t stream3_id, quiche_h3_event *ev,
                             size_t *pqlen)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct Curl_easy *mdata;
  struct h3_event_node *node, **pnext = &ctx->pending;
  size_t qlen;

  DEBUGASSERT(data->multi);
  for(mdata = data->multi->easyp; mdata; mdata = mdata->next) {
    if(mdata->req.p.http && mdata->req.p.http->stream3_id == stream3_id) {
      break;
    }
  }

  if(!mdata) {
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] event discarded, easy handle "
                  "not found", stream3_id));
    quiche_h3_event_free(ev);
    *pqlen = 0;
    return CURLE_OK;
  }

  node = calloc(sizeof(*node), 1);
  if(!node)
    return CURLE_OUT_OF_MEMORY;
  node->stream3_id = stream3_id;
  node->ev = ev;
  /* append to process them in order of arrival */
  qlen = 0;
  while(*pnext) {
    pnext = &((*pnext)->next);
    ++qlen;
  }
  *pnext = node;
  *pqlen = qlen + 1;
  if(!mdata->state.drain) {
    /* tell the multi handle that this data needs processing */
    mdata->state.drain = 1;
    Curl_expire(mdata, 0, EXPIRE_RUN_NOW);
  }
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

static ssize_t h3_process_event(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                char *buf, size_t len,
                                int64_t stream3_id,
                                quiche_h3_event *ev,
                                CURLcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  ssize_t recvd = -1;
  ssize_t rcode;
  int rc;
  struct h3h1header headers;

  DEBUGASSERT(stream3_id == stream->stream3_id);

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
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] recv, HEADERS len=%zd",
                  stream3_id, recvd));
    break;

  case QUICHE_H3_EVENT_DATA:
    if(!stream->firstbody) {
      /* add a header-body separator CRLF */
      buf[0] = '\r';
      buf[1] = '\n';
      buf += 2;
      len -= 2;
      stream->firstbody = TRUE;
      recvd = 2; /* two bytes already */
    }
    else
      recvd = 0;
    rcode = quiche_h3_recv_body(ctx->h3c, ctx->qconn, stream3_id,
                               (unsigned char *)buf, len);
    if(rcode <= 0) {
      failf(data, "Error %zd in HTTP/3 response body for stream[%"PRId64"]",
            rcode, stream3_id);
      recvd = -1;
      *err = CURLE_AGAIN;
      break;
    }
    stream->h3_recving_data = TRUE;
    recvd += rcode;
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] recv, DATA len=%zd",
                  stream3_id, rcode));
    break;

  case QUICHE_H3_EVENT_RESET:
    if(quiche_conn_is_draining(ctx->qconn) && !stream->h3_got_header) {
      DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] stream RESET without response, "
                    "connection is draining", stream3_id));
    }
    else {
      DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] recv, RESET", stream3_id));
    }
    streamclose(cf->conn, "Stream reset");
    *err = stream->h3_got_header? CURLE_PARTIAL_FILE : CURLE_RECV_ERROR;
    recvd = -1;
    break;

  case QUICHE_H3_EVENT_FINISHED:
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] recv, FINISHED", stream3_id));
    stream->closed = TRUE;
    streamclose(cf->conn, "End of stream");
    *err = CURLE_OK;
    recvd = 0; /* end of stream */
    break;

  case QUICHE_H3_EVENT_GOAWAY:
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] recv, GOAWAY", stream3_id));
    recvd = -1;
    *err = CURLE_AGAIN;
    ctx->goaway = TRUE;
    break;

  default:
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] recv, unhandled event %d",
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
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  struct h3_event_node *node = ctx->pending, **pnext = &ctx->pending;
  ssize_t recvd = 0, erecvd;

  DEBUGASSERT(stream);
  while(node) {
    if(node->stream3_id == stream->stream3_id) {
      erecvd = h3_process_event(cf, data, buf, len,
                                node->stream3_id, node->ev, err);
      quiche_h3_event_free(node->ev);
      *pnext = node->next;
      free(node);
      node = *pnext;
      if(erecvd < 0) {
        recvd = erecvd;
        break;
      }
      recvd += erecvd;
      if(erecvd > INT_MAX || (size_t)erecvd >= len)
        break;
      buf += erecvd;
      len -= erecvd;
    }
    else {
      pnext = &node->next;
      node = node->next;
    }
  }
  return recvd;
}

static CURLcode cf_process_ingress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  ssize_t recvd;
  uint8_t *buf = (uint8_t *)data->state.buffer;
  size_t bufsize = data->set.buffer_size;
  struct sockaddr_storage from;
  socklen_t from_len;
  quiche_recv_info recv_info;

  DEBUGASSERT(ctx->qconn);

  /* in case the timeout expired */
  quiche_conn_on_timeout(ctx->qconn);

  do {
    from_len = sizeof(from);

    recvd = recvfrom(ctx->sockfd, buf, bufsize, 0,
                     (struct sockaddr *)&from, &from_len);

    if(recvd < 0) {
      if((SOCKERRNO == EAGAIN) || (SOCKERRNO == EWOULDBLOCK))
        goto out;
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
            "(errno: %d, socket %d)", recvd, SOCKERRNO, ctx->sockfd);
      return CURLE_RECV_ERROR;
    }

    DEBUGF(LOG_CF(data, cf, "ingress, recvd %zd bytes", recvd));
    recv_info.from = (struct sockaddr *) &from;
    recv_info.from_len = from_len;
    recv_info.to = (struct sockaddr *) &ctx->local_addr;
    recv_info.to_len = ctx->local_addrlen;

    recvd = quiche_conn_recv(ctx->qconn, buf, recvd, &recv_info);
    if(recvd == QUICHE_ERR_DONE)
      goto out;

    if(recvd < 0) {
      if(QUICHE_ERR_TLS_FAIL == recvd) {
        long verify_ok = SSL_get_verify_result(ctx->ssl);
        if(verify_ok != X509_V_OK) {
          failf(data, "SSL certificate problem: %s",
                X509_verify_cert_error_string(verify_ok));

          return CURLE_PEER_FAILED_VERIFICATION;
        }
      }

      failf(data, "quiche_conn_recv() == %zd", recvd);

      return CURLE_RECV_ERROR;
    }
    if(ctx->first_reply_ms < 0) {
      timediff_t ms = Curl_timediff(Curl_now(), ctx->connect_started);
      ctx->first_reply_ms = (ms < INT_MAX)? (int)ms : INT_MAX;
    }
  } while(1);

out:
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
  ssize_t sent;
  uint8_t out[1200];
  int64_t timeout_ns;
  quiche_send_info send_info;

  do {
    sent = quiche_conn_send(ctx->qconn, out, sizeof(out), &send_info);
    if(sent == QUICHE_ERR_DONE)
      break;

    if(sent < 0) {
      failf(data, "quiche_conn_send returned %zd", sent);
      return CURLE_SEND_ERROR;
    }

    DEBUGF(LOG_CF(data, cf, "egress, send %zu bytes", sent));
    sent = send(ctx->sockfd, out, sent, 0);
    if(sent < 0) {
      failf(data, "send() returned %zd", sent);
      return CURLE_SEND_ERROR;
    }
  } while(1);

  /* time until the next timeout event, as nanoseconds. */
  timeout_ns = quiche_conn_timeout_as_nanos(ctx->qconn);
  if(timeout_ns)
    /* expire uses milliseconds */
    Curl_expire(data, (timeout_ns + 999999) / 1000000, EXPIRE_QUIC);

  return CURLE_OK;
}

static ssize_t cf_quiche_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                              char *buf, size_t len, CURLcode *err)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  ssize_t recvd = -1;
  ssize_t rcode;
  quiche_h3_event *ev;
  struct HTTP *stream = data->req.p.http;

  *err = CURLE_AGAIN;
  /* process any pending events for `data` first. if there are,
   * return so the transfer can handle those. We do not want to
   * progress ingress while events are pending here. */
  recvd = h3_process_pending(cf, data, buf, len, err);
  if(recvd < 0) {
    goto out;
  }
  else if(recvd > 0) {
    *err = CURLE_OK;
    goto out;
  }
  recvd = -1;

  if(cf_process_ingress(cf, data)) {
    DEBUGF(LOG_CF(data, cf, "h3_stream_recv returns on ingress"));
    *err = CURLE_RECV_ERROR;
    goto out;
  }

  if(stream->h3_recving_data) {
    /* body receiving state */
    rcode = quiche_h3_recv_body(ctx->h3c, ctx->qconn, stream->stream3_id,
                                (unsigned char *)buf, len);
    if(rcode <= 0) {
      stream->h3_recving_data = FALSE;
      /* fall through into the while loop below */
    }
    else {
      *err = CURLE_OK;
      recvd = rcode;
      goto out;
    }
  }

  while(recvd < 0) {
    int64_t stream3_id = quiche_h3_conn_poll(ctx->h3c, ctx->qconn, &ev);
    if(stream3_id < 0)
      /* nothing more to do */
      break;

    if(stream3_id == stream->stream3_id) {
      recvd = h3_process_event(cf, data, buf, len, stream3_id, ev, err);
      quiche_h3_event_free(ev);
    }
    else {
      size_t qlen;
      /* event for another transfer, preserver for later */
      DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] recv, queue event "
                    "for h3[%"PRId64"]", stream->stream3_id, stream3_id));
      if(h3_add_event(cf, data, stream3_id, ev, &qlen) != CURLE_OK) {
        *err = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      if(qlen > 20) {
        Curl_expire(data, 0, EXPIRE_QUIC);
        break;
      }
    }
  }

  if(cf_flush_egress(cf, data)) {
    DEBUGF(LOG_CF(data, cf, "recv(), flush egress failed"));
    *err = CURLE_SEND_ERROR;
    recvd = -1;
    goto out;
  }

  if(recvd >= 0) {
    /* Get this called again to drain the event queue */
    Curl_expire(data, 0, EXPIRE_QUIC);
    *err = CURLE_OK;
  }
  else if(stream->closed) {
    *err = CURLE_OK;
    recvd = -1;
  }

out:
  data->state.drain = (recvd >= 0) ? 1 : 0;
  DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] recv -> %ld, err=%d",
                stream->stream3_id, (long)recvd, *err));
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

  DEBUGF(LOG_CF(data, cf, "cf_http_request %s", data->state.url));
  stream->h3req = TRUE; /* send off! */

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

    stream3_id = quiche_h3_send_request(ctx->h3c, ctx->qconn, nva, nheader,
                                        stream->upload_left ? FALSE: TRUE);
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] send request %s, upload=%zu",
                  stream3_id, data->state.url, stream->upload_left));
    break;
  default:
    stream3_id = quiche_h3_send_request(ctx->h3c, ctx->qconn, nva, nheader,
                                        TRUE);
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] send request %s",
                  stream3_id, data->state.url));
    break;
  }

  Curl_safefree(nva);

  if(stream3_id < 0) {
    DEBUGF(LOG_CF(data, cf, "quiche_h3_send_request returned %ld",
                  (long)stream3_id));
    result = CURLE_SEND_ERROR;
    goto fail;
  }

  DEBUGF(LOG_CF(data, cf, "Using HTTP/3 Stream ID: %"PRId64, stream3_id));
  stream->stream3_id = stream3_id;

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
  ssize_t sent;

  DEBUGF(LOG_CF(data, cf, "cf_quiche_send(len=%zu) %s", len, data->state.url));
  if(!stream->h3req) {
    CURLcode result = cf_http_request(cf, data, buf, len);
    if(result) {
      *err = CURLE_SEND_ERROR;
      return -1;
    }
    sent = len;
  }
  else {
    sent = quiche_h3_send_body(ctx->h3c, ctx->qconn, stream->stream3_id,
                               (uint8_t *)buf, len, FALSE);
    if(sent == QUICHE_H3_ERR_DONE) {
      sent = 0;
    }
    else if(sent == QUICHE_H3_TRANSPORT_ERR_FINAL_SIZE) {
      DEBUGF(LOG_CF(data, cf, "send_body(len=%zu) -> exceeds size", len));
      *err = CURLE_SEND_ERROR;
      return -1;
    }
    else if(sent < 0) {
      DEBUGF(LOG_CF(data, cf, "send_body(len=%zu) -> %zd", len, sent));
      *err = CURLE_SEND_ERROR;
      return -1;
    }
  }

  if(cf_flush_egress(cf, data)) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  *err = CURLE_OK;
  return sent;
}

static int cf_quiche_get_select_socks(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      curl_socket_t *socks)
{
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct SingleRequest *k = &data->req;
  int rv = GETSOCK_BLANK;

  socks[0] = ctx->sockfd;

  /* in an HTTP/3 connection we can basically always get a frame so we should
     always be ready for one */
  rv |= GETSOCK_READSOCK(0);

  /* we're still uploading or the HTTP/3 layer wants to send data */
  if((k->keepon & (KEEP_SEND|KEEP_SEND_PAUSE)) == KEEP_SEND)
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
  struct cf_quiche_ctx *ctx = cf->ctx;
  struct HTTP *stream = data->req.p.http;
  struct h3_event_node *node;

  for(node = ctx->pending; node; node = node->next) {
    if(node->stream3_id == stream->stream3_id) {
      DEBUGF(LOG_CF((struct Curl_easy *)data, cf,
                     "h3[%"PRId64"] has data pending", stream->stream3_id));
      return TRUE;
    }
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
  case CF_CTRL_DATA_DONE_SEND: {
    struct HTTP *stream = data->req.p.http;
    ssize_t sent;
    stream->upload_done = TRUE;
    sent = quiche_h3_send_body(ctx->h3c, ctx->qconn, stream->stream3_id,
                               NULL, 0, TRUE);
    if(sent < 0)
      return CURLE_SEND_ERROR;
    break;
  }
  case CF_CTRL_DATA_DONE: {
    struct HTTP *stream = data->req.p.http;
    DEBUGF(LOG_CF(data, cf, "h3[%"PRId64"] easy handle is %s",
                  stream->stream3_id, arg1? "cancelled" : "done"));
    break;
  }
  case CF_CTRL_CONN_REPORT_STATS:
    if(cf->sockindex == FIRSTSOCKET)
      Curl_pgrsTimeWas(data, TIMER_APPCONNECT, ctx->handshake_done);
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

  result = Curl_cf_socket_peek(cf->next, data, &ctx->sockfd,
                               &sockaddr, NULL, NULL, NULL, NULL);
  if(result)
    return result;
  DEBUGASSERT(ctx->sockfd != CURL_SOCKET_BAD);

#ifdef DEBUG_QUICHE
  /* initialize debug log callback only once */
  static int debug_log_init = 0;
  if(!debug_log_init) {
    quiche_enable_debug_logging(quiche_debug_log, NULL);
    debug_log_init = 1;
  }
#endif

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

  ctx->local_addrlen = sizeof(ctx->local_addr);
  rv = getsockname(ctx->sockfd, (struct sockaddr *)&ctx->local_addr,
                   &ctx->local_addrlen);
  if(rv == -1)
    return CURLE_QUIC_CONNECT_ERROR;

  ctx->qconn = quiche_conn_new_with_tls((const uint8_t *)ctx->scid,
                                      sizeof(ctx->scid), NULL, 0,
                                      (struct sockaddr *)&ctx->local_addr,
                                      ctx->local_addrlen,
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
    ctx->connect_started = now;
  }

  result = cf_process_ingress(cf, data);
  if(result)
    goto out;

  result = cf_flush_egress(cf, data);
  if(result)
    goto out;

  if(quiche_conn_is_established(ctx->qconn)) {
    DEBUGF(LOG_CF(data, cf, "handshake complete after %dms",
           (int)Curl_timediff(now, ctx->connect_started)));
    ctx->handshake_done = now;
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
    *pres1 = ctx->first_reply_ms;
    DEBUGF(LOG_CF(data, cf, "query connect reply: %dms", *pres1));
    return CURLE_OK;

  default:
    break;
  }
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
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
  Curl_cf_def_conn_is_alive,
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
