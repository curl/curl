/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "sendf.h"
#include "strdup.h"
#include "rand.h"
#include "quic.h"
#include "strcase.h"
#include "multiif.h"
#include "connect.h"
#include "strerror.h"
#include "vquic.h"
#include "transfer.h"
#include "h2h3.h"
#include "vtls/openssl.h"
#include "vtls/keylog.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define DEBUG_HTTP3
/* #define DEBUG_QUICHE */
#ifdef DEBUG_HTTP3
#define H3BUGF(x) x
#else
#define H3BUGF(x) do { } while(0)
#endif

#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_MAX_DATA (1*1024*1024)
#define QUIC_IDLE_TIMEOUT (60 * 1000) /* milliseconds */

static CURLcode process_ingress(struct Curl_easy *data,
                                curl_socket_t sockfd,
                                struct quicsocket *qs);

static CURLcode flush_egress(struct Curl_easy *data, curl_socket_t sockfd,
                             struct quicsocket *qs);

static CURLcode http_request(struct Curl_easy *data, const void *mem,
                             size_t len);
static Curl_recv h3_stream_recv;
static Curl_send h3_stream_send;

static int quiche_getsock(struct Curl_easy *data,
                          struct connectdata *conn, curl_socket_t *socks)
{
  struct SingleRequest *k = &data->req;
  int bitmap = GETSOCK_BLANK;

  socks[0] = conn->sock[FIRSTSOCKET];

  /* in a HTTP/2 connection we can basically always get a frame so we should
     always be ready for one */
  bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);

  /* we're still uploading or the HTTP/2 layer wants to send data */
  if((k->keepon & (KEEP_SEND|KEEP_SEND_PAUSE)) == KEEP_SEND)
    bitmap |= GETSOCK_WRITESOCK(FIRSTSOCKET);

  return bitmap;
}

static CURLcode qs_disconnect(struct Curl_easy *data,
                              struct quicsocket *qs)
{
  DEBUGASSERT(qs);
  if(qs->conn) {
    (void)quiche_conn_close(qs->conn, TRUE, 0, NULL, 0);
    /* flushing the egress is not a failsafe way to deliver all the
       outstanding packets, but we also don't want to get stuck here... */
    (void)flush_egress(data, qs->sockfd, qs);
    quiche_conn_free(qs->conn);
    qs->conn = NULL;
  }
  if(qs->h3config)
    quiche_h3_config_free(qs->h3config);
  if(qs->h3c)
    quiche_h3_conn_free(qs->h3c);
  if(qs->cfg) {
    quiche_config_free(qs->cfg);
    qs->cfg = NULL;
  }
  return CURLE_OK;
}

static CURLcode quiche_disconnect(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  bool dead_connection)
{
  struct quicsocket *qs = conn->quic;
  (void)dead_connection;
  return qs_disconnect(data, qs);
}

void Curl_quic_disconnect(struct Curl_easy *data,
                          struct connectdata *conn,
                          int tempindex)
{
  if(conn->transport == TRNSPRT_QUIC)
    qs_disconnect(data, &conn->hequic[tempindex]);
}

static unsigned int quiche_conncheck(struct Curl_easy *data,
                                     struct connectdata *conn,
                                     unsigned int checks_to_perform)
{
  (void)data;
  (void)conn;
  (void)checks_to_perform;
  return CONNRESULT_NONE;
}

static CURLcode quiche_do(struct Curl_easy *data, bool *done)
{
  struct HTTP *stream = data->req.p.http;
  stream->h3req = FALSE; /* not sent */
  return Curl_http(data, done);
}

static const struct Curl_handler Curl_handler_http3 = {
  "HTTPS",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  quiche_do,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  quiche_getsock,                       /* proto_getsock */
  quiche_getsock,                       /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  quiche_getsock,                       /* perform_getsock */
  quiche_disconnect,                    /* disconnect */
  ZERO_NULL,                            /* readwrite */
  quiche_conncheck,                     /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTPS,                      /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_STREAM          /* flags */
};

#ifdef DEBUG_QUICHE
static void quiche_debug_log(const char *line, void *argp)
{
  (void)argp;
  fprintf(stderr, "%s\n", line);
}
#endif

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

static int quic_init_ssl(struct quicsocket *qs, struct connectdata *conn)
{
  /* this will need some attention when HTTPS proxy over QUIC get fixed */
  const char * const hostname = conn->host.name;

  DEBUGASSERT(!qs->ssl);
  qs->ssl = SSL_new(qs->sslctx);

  SSL_set_app_data(qs->ssl, qs);

  /* set SNI */
  SSL_set_tlsext_host_name(qs->ssl, hostname);
  return 0;
}


CURLcode Curl_quic_connect(struct Curl_easy *data,
                           struct connectdata *conn, curl_socket_t sockfd,
                           int sockindex,
                           const struct sockaddr *addr, socklen_t addrlen)
{
  CURLcode result;
  struct quicsocket *qs = &conn->hequic[sockindex];
  char ipbuf[40];
  int port;

#ifdef DEBUG_QUICHE
  /* initialize debug log callback only once */
  static int debug_log_init = 0;
  if(!debug_log_init) {
    quiche_enable_debug_logging(quiche_debug_log, NULL);
    debug_log_init = 1;
  }
#endif

  (void)addr;
  (void)addrlen;

  qs->sockfd = sockfd;
  qs->cfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if(!qs->cfg) {
    failf(data, "can't create quiche config");
    return CURLE_FAILED_INIT;
  }

  quiche_config_set_max_idle_timeout(qs->cfg, QUIC_IDLE_TIMEOUT);
  quiche_config_set_initial_max_data(qs->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_bidi_local(qs->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_bidi_remote(qs->cfg,
                                                        QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_uni(qs->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_streams_bidi(qs->cfg, QUIC_MAX_STREAMS);
  quiche_config_set_initial_max_streams_uni(qs->cfg, QUIC_MAX_STREAMS);
  quiche_config_set_application_protos(qs->cfg,
                                       (uint8_t *)
                                       QUICHE_H3_APPLICATION_PROTOCOL,
                                       sizeof(QUICHE_H3_APPLICATION_PROTOCOL)
                                       - 1);

  qs->sslctx = quic_ssl_ctx(data);
  if(!qs->sslctx)
    return CURLE_QUIC_CONNECT_ERROR;

  if(quic_init_ssl(qs, conn))
    return CURLE_QUIC_CONNECT_ERROR;

  result = Curl_rand(data, qs->scid, sizeof(qs->scid));
  if(result)
    return result;

  qs->conn = quiche_conn_new_with_tls((const uint8_t *) qs->scid,
                                      sizeof(qs->scid), NULL, 0, addr, addrlen,
                                      qs->cfg, qs->ssl, false);
  if(!qs->conn) {
    failf(data, "can't create quiche connection");
    return CURLE_OUT_OF_MEMORY;
  }

  /* Known to not work on Windows */
#if !defined(WIN32) && defined(HAVE_QUICHE_CONN_SET_QLOG_FD)
  {
    int qfd;
    (void)Curl_qlogdir(data, qs->scid, sizeof(qs->scid), &qfd);
    if(qfd != -1)
      quiche_conn_set_qlog_fd(qs->conn, qfd,
                              "qlog title", "curl qlog");
  }
#endif

  result = flush_egress(data, sockfd, qs);
  if(result)
    return result;

  /* extract the used address as a string */
  if(!Curl_addr2string((struct sockaddr*)addr, addrlen, ipbuf, &port)) {
    char buffer[STRERROR_LEN];
    failf(data, "ssrem inet_ntop() failed with errno %d: %s",
          SOCKERRNO, Curl_strerror(SOCKERRNO, buffer, sizeof(buffer)));
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  infof(data, "Connect socket %d over QUIC to %s:%ld",
        sockfd, ipbuf, port);

  Curl_persistconninfo(data, conn, NULL, -1);

  /* for connection reuse purposes: */
  conn->ssl[FIRSTSOCKET].state = ssl_connection_complete;

  {
    unsigned char alpn_protocols[] = QUICHE_H3_APPLICATION_PROTOCOL;
    unsigned alpn_len, offset = 0;

    /* Replace each ALPN length prefix by a comma. */
    while(offset < sizeof(alpn_protocols) - 1) {
      alpn_len = alpn_protocols[offset];
      alpn_protocols[offset] = ',';
      offset += 1 + alpn_len;
    }

    infof(data, "Sent QUIC client Initial, ALPN: %s",
          alpn_protocols + 1);
  }

  return CURLE_OK;
}

static CURLcode quiche_has_connected(struct Curl_easy *data,
                                     struct connectdata *conn,
                                     int sockindex,
                                     int tempindex)
{
  CURLcode result;
  struct quicsocket *qs = conn->quic = &conn->hequic[tempindex];

  conn->recv[sockindex] = h3_stream_recv;
  conn->send[sockindex] = h3_stream_send;
  conn->handler = &Curl_handler_http3;
  conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  conn->httpversion = 30;
  conn->bundle->multiuse = BUNDLE_MULTIPLEX;

  if(conn->ssl_config.verifyhost) {
    X509 *server_cert;
    server_cert = SSL_get_peer_certificate(qs->ssl);
    if(!server_cert) {
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    result = Curl_ossl_verifyhost(data, conn, server_cert);
    X509_free(server_cert);
    if(result)
      return result;
    infof(data, "Verified certificate just fine");
  }
  else
    infof(data, "Skipped certificate verification");

  qs->h3config = quiche_h3_config_new();
  if(!qs->h3config)
    return CURLE_OUT_OF_MEMORY;

  /* Create a new HTTP/3 connection on the QUIC connection. */
  qs->h3c = quiche_h3_conn_new_with_transport(qs->conn, qs->h3config);
  if(!qs->h3c) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }
  if(conn->hequic[1-tempindex].cfg) {
    qs = &conn->hequic[1-tempindex];
    quiche_config_free(qs->cfg);
    quiche_conn_free(qs->conn);
    qs->cfg = NULL;
    qs->conn = NULL;
  }
  return CURLE_OK;
  fail:
  quiche_h3_config_free(qs->h3config);
  quiche_h3_conn_free(qs->h3c);
  return result;
}

/*
 * This function gets polled to check if this QUIC connection has connected.
 */
CURLcode Curl_quic_is_connected(struct Curl_easy *data,
                                struct connectdata *conn,
                                int sockindex,
                                bool *done)
{
  CURLcode result;
  struct quicsocket *qs = &conn->hequic[sockindex];
  curl_socket_t sockfd = conn->tempsock[sockindex];

  result = process_ingress(data, sockfd, qs);
  if(result)
    goto error;

  result = flush_egress(data, sockfd, qs);
  if(result)
    goto error;

  if(quiche_conn_is_established(qs->conn)) {
    *done = TRUE;
    result = quiche_has_connected(data, conn, 0, sockindex);
    DEBUGF(infof(data, "quiche established connection"));
  }

  return result;
  error:
  qs_disconnect(data, qs);
  return result;
}

static CURLcode process_ingress(struct Curl_easy *data, int sockfd,
                                struct quicsocket *qs)
{
  ssize_t recvd;
  uint8_t *buf = (uint8_t *)data->state.buffer;
  size_t bufsize = data->set.buffer_size;
  struct sockaddr_storage from;
  socklen_t from_len;
  quiche_recv_info recv_info;

  DEBUGASSERT(qs->conn);

  /* in case the timeout expired */
  quiche_conn_on_timeout(qs->conn);

  do {
    from_len = sizeof(from);

    recvd = recvfrom(sockfd, buf, bufsize, 0,
                     (struct sockaddr *)&from, &from_len);

    if((recvd < 0) && ((SOCKERRNO == EAGAIN) || (SOCKERRNO == EWOULDBLOCK)))
      break;

    if(recvd < 0) {
      failf(data, "quiche: recvfrom() unexpectedly returned %zd "
            "(errno: %d, socket %d)", recvd, SOCKERRNO, sockfd);
      return CURLE_RECV_ERROR;
    }

    recv_info.from = (struct sockaddr *) &from;
    recv_info.from_len = from_len;

    recvd = quiche_conn_recv(qs->conn, buf, recvd, &recv_info);
    if(recvd == QUICHE_ERR_DONE)
      break;

    if(recvd < 0) {
      if(QUICHE_ERR_TLS_FAIL == recvd) {
        long verify_ok = SSL_get_verify_result(qs->ssl);
        if(verify_ok != X509_V_OK) {
          failf(data, "SSL certificate problem: %s",
                X509_verify_cert_error_string(verify_ok));

          return CURLE_PEER_FAILED_VERIFICATION;
        }
      }

      failf(data, "quiche_conn_recv() == %zd", recvd);

      return CURLE_RECV_ERROR;
    }
  } while(1);

  return CURLE_OK;
}

/*
 * flush_egress drains the buffers and sends off data.
 * Calls failf() on errors.
 */
static CURLcode flush_egress(struct Curl_easy *data, int sockfd,
                             struct quicsocket *qs)
{
  ssize_t sent;
  uint8_t out[1200];
  int64_t timeout_ns;
  quiche_send_info send_info;

  do {
    sent = quiche_conn_send(qs->conn, out, sizeof(out), &send_info);
    if(sent == QUICHE_ERR_DONE)
      break;

    if(sent < 0) {
      failf(data, "quiche_conn_send returned %zd", sent);
      return CURLE_SEND_ERROR;
    }

    sent = send(sockfd, out, sent, 0);
    if(sent < 0) {
      failf(data, "send() returned %zd", sent);
      return CURLE_SEND_ERROR;
    }
  } while(1);

  /* time until the next timeout event, as nanoseconds. */
  timeout_ns = quiche_conn_timeout_as_nanos(qs->conn);
  if(timeout_ns)
    /* expire uses milliseconds */
    Curl_expire(data, (timeout_ns + 999999) / 1000000, EXPIRE_QUIC);

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
              headers->destlen, "HTTP/3 %.*s\n",
              (int) value_len, value);
  }
  else if(!headers->nlen) {
    return CURLE_HTTP3;
  }
  else {
    msnprintf(headers->dest,
              headers->destlen, "%.*s: %.*s\n",
              (int)name_len, name, (int) value_len, value);
  }
  olen = strlen(headers->dest);
  headers->destlen -= olen;
  headers->nlen += olen;
  headers->dest += olen;
  return 0;
}

static ssize_t h3_stream_recv(struct Curl_easy *data,
                              int sockindex,
                              char *buf,
                              size_t buffersize,
                              CURLcode *curlcode)
{
  ssize_t recvd = -1;
  ssize_t rcode;
  struct connectdata *conn = data->conn;
  struct quicsocket *qs = conn->quic;
  curl_socket_t sockfd = conn->sock[sockindex];
  quiche_h3_event *ev;
  int rc;
  struct h3h1header headers;
  struct HTTP *stream = data->req.p.http;
  headers.dest = buf;
  headers.destlen = buffersize;
  headers.nlen = 0;

  if(process_ingress(data, sockfd, qs)) {
    infof(data, "h3_stream_recv returns on ingress");
    *curlcode = CURLE_RECV_ERROR;
    return -1;
  }

  if(qs->h3_recving) {
    /* body receiving state */
    rcode = quiche_h3_recv_body(qs->h3c, qs->conn, stream->stream3_id,
                                (unsigned char *)buf, buffersize);
    if(rcode <= 0) {
      recvd = -1;
      qs->h3_recving = FALSE;
      /* fall through into the while loop below */
    }
    else
      recvd = rcode;
  }

  while(recvd < 0) {
    int64_t s = quiche_h3_conn_poll(qs->h3c, qs->conn, &ev);
    if(s < 0)
      /* nothing more to do */
      break;

    if(s != stream->stream3_id) {
      /* another transfer, ignore for now */
      infof(data, "Got h3 for stream %u, expects %u",
            s, stream->stream3_id);
      continue;
    }

    switch(quiche_h3_event_type(ev)) {
    case QUICHE_H3_EVENT_HEADERS:
      rc = quiche_h3_event_for_each_header(ev, cb_each_header, &headers);
      if(rc) {
        *curlcode = rc;
        failf(data, "Error in HTTP/3 response header");
        break;
      }
      recvd = headers.nlen;
      break;
    case QUICHE_H3_EVENT_DATA:
      if(!stream->firstbody) {
        /* add a header-body separator CRLF */
        buf[0] = '\r';
        buf[1] = '\n';
        buf += 2;
        buffersize -= 2;
        stream->firstbody = TRUE;
        recvd = 2; /* two bytes already */
      }
      else
        recvd = 0;
      rcode = quiche_h3_recv_body(qs->h3c, qs->conn, s, (unsigned char *)buf,
                                  buffersize);
      if(rcode <= 0) {
        recvd = -1;
        break;
      }
      qs->h3_recving = TRUE;
      recvd += rcode;
      break;

    case QUICHE_H3_EVENT_RESET:
      streamclose(conn, "Stream reset");
      *curlcode = CURLE_PARTIAL_FILE;
      return -1;

    case QUICHE_H3_EVENT_FINISHED:
      streamclose(conn, "End of stream");
      recvd = 0; /* end of stream */
      break;
    default:
      break;
    }

    quiche_h3_event_free(ev);
  }
  if(flush_egress(data, sockfd, qs)) {
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }

  *curlcode = (-1 == recvd)? CURLE_AGAIN : CURLE_OK;
  if(recvd >= 0)
    /* Get this called again to drain the event queue */
    Curl_expire(data, 0, EXPIRE_QUIC);

  data->state.drain = (recvd >= 0) ? 1 : 0;
  return recvd;
}

static ssize_t h3_stream_send(struct Curl_easy *data,
                              int sockindex,
                              const void *mem,
                              size_t len,
                              CURLcode *curlcode)
{
  ssize_t sent;
  struct connectdata *conn = data->conn;
  struct quicsocket *qs = conn->quic;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct HTTP *stream = data->req.p.http;

  if(!stream->h3req) {
    CURLcode result = http_request(data, mem, len);
    if(result) {
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
    sent = len;
  }
  else {
    sent = quiche_h3_send_body(qs->h3c, qs->conn, stream->stream3_id,
                               (uint8_t *)mem, len, FALSE);
    if(sent == QUICHE_H3_ERR_DONE) {
      sent = 0;
    }
    else if(sent < 0) {
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
  }

  if(flush_egress(data, sockfd, qs)) {
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }

  *curlcode = CURLE_OK;
  return sent;
}

/*
 * Store quiche version info in this buffer.
 */
void Curl_quic_ver(char *p, size_t len)
{
  (void)msnprintf(p, len, "quiche/%s", quiche_version());
}

/* Index where :authority header field will appear in request header
   field list. */
#define AUTHORITY_DST_IDX 3

static CURLcode http_request(struct Curl_easy *data, const void *mem,
                             size_t len)
{
  struct connectdata *conn = data->conn;
  struct HTTP *stream = data->req.p.http;
  size_t nheader;
  int64_t stream3_id;
  quiche_h3_header *nva = NULL;
  struct quicsocket *qs = conn->quic;
  CURLcode result = CURLE_OK;
  struct h2h3req *hreq = NULL;

  stream->h3req = TRUE; /* senf off! */

  result = Curl_pseudo_headers(data, mem, len, &hreq);
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

    stream3_id = quiche_h3_send_request(qs->h3c, qs->conn, nva, nheader,
                                        stream->upload_left ? FALSE: TRUE);
    if((stream3_id >= 0) && data->set.postfields) {
      ssize_t sent = quiche_h3_send_body(qs->h3c, qs->conn, stream3_id,
                                         (uint8_t *)data->set.postfields,
                                         stream->upload_left, TRUE);
      if(sent <= 0) {
        failf(data, "quiche_h3_send_body failed");
        result = CURLE_SEND_ERROR;
      }
      stream->upload_left = 0; /* nothing left to send */
    }
    break;
  default:
    stream3_id = quiche_h3_send_request(qs->h3c, qs->conn, nva, nheader,
                                        TRUE);
    break;
  }

  Curl_safefree(nva);

  if(stream3_id < 0) {
    H3BUGF(infof(data, "quiche_h3_send_request returned %d",
                 stream3_id));
    result = CURLE_SEND_ERROR;
    goto fail;
  }

  infof(data, "Using HTTP/3 Stream ID: %x (easy handle %p)",
        stream3_id, (void *)data);
  stream->stream3_id = stream3_id;

  Curl_pseudo_free(hreq);
  return CURLE_OK;

fail:
  free(nva);
  Curl_pseudo_free(hreq);
  return result;
}

/*
 * Called from transfer.c:done_sending when we stop HTTP/3 uploading.
 */
CURLcode Curl_quic_done_sending(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  DEBUGASSERT(conn);
  if(conn->handler == &Curl_handler_http3) {
    /* only for HTTP/3 transfers */
    ssize_t sent;
    struct HTTP *stream = data->req.p.http;
    struct quicsocket *qs = conn->quic;
    stream->upload_done = TRUE;
    sent = quiche_h3_send_body(qs->h3c, qs->conn, stream->stream3_id,
                               NULL, 0, TRUE);
    if(sent < 0)
      return CURLE_SEND_ERROR;
  }

  return CURLE_OK;
}

/*
 * Called from http.c:Curl_http_done when a request completes.
 */
void Curl_quic_done(struct Curl_easy *data, bool premature)
{
  (void)data;
  (void)premature;
}

/*
 * Called from transfer.c:data_pending to know if we should keep looping
 * to receive more data from the connection.
 */
bool Curl_quic_data_pending(const struct Curl_easy *data)
{
  (void)data;
  return FALSE;
}

/*
 * Called from transfer.c:Curl_readwrite when neither HTTP level read
 * nor write is performed. It is a good place to handle timer expiry
 * for QUIC transport.
 */
CURLcode Curl_quic_idle(struct Curl_easy *data)
{
  (void)data;
  return CURLE_OK;
}

#endif
