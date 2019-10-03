/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_NGTCP2
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>
#include <openssl/err.h>
#include "urldata.h"
#include "sendf.h"
#include "strdup.h"
#include "rand.h"
#include "ngtcp2.h"
#include "multiif.h"
#include "strcase.h"
#include "connect.h"
#include "strerror.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* #define DEBUG_NGTCP2 */
#ifdef CURLDEBUG
#define DEBUG_HTTP3
#endif
#ifdef DEBUG_HTTP3
#define H3BUGF(x) x
#else
#define H3BUGF(x) do { } WHILE_FALSE
#endif

/*
 * This holds outgoing HTTP/3 stream data that is used by nghttp3 until acked.
 * It is used as a circular buffer. Add new bytes at the end until it reaches
 * the far end, then start over at index 0 again.
 */

#define H3_SEND_SIZE (20*1024)
struct h3out {
  uint8_t buf[H3_SEND_SIZE];
  size_t used;   /* number of bytes used in the buffer */
  size_t windex; /* index in the buffer where to start writing the next
                    data block */
};

#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_MAX_DATA (1*1024*1024)
#define QUIC_IDLE_TIMEOUT 60000 /* milliseconds */
#define QUIC_CIPHERS                                                          \
  "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"               \
  "POLY1305_SHA256:TLS_AES_128_CCM_SHA256"
#define QUIC_GROUPS "P-256:X25519:P-384:P-521"

static CURLcode ng_process_ingress(struct connectdata *conn,
                                   curl_socket_t sockfd,
                                   struct quicsocket *qs);
static CURLcode ng_flush_egress(struct connectdata *conn, int sockfd,
                                struct quicsocket *qs);
static int cb_h3_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                                   size_t datalen, void *user_data,
                                   void *stream_user_data);

static ngtcp2_tstamp timestamp(void)
{
  struct curltime ct = Curl_now();
  return ct.tv_sec * NGTCP2_SECONDS + ct.tv_usec * NGTCP2_MICROSECONDS;
}

#ifdef DEBUG_NGTCP2
static void quic_printf(void *user_data, const char *fmt, ...)
{
  va_list ap;
  (void)user_data; /* TODO, use this to do infof() instead long-term */
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
}
#endif

static ngtcp2_crypto_level
quic_from_ossl_level(OSSL_ENCRYPTION_LEVEL ossl_level)
{
  switch(ossl_level) {
  case ssl_encryption_initial:
    return NGTCP2_CRYPTO_LEVEL_INITIAL;
  case ssl_encryption_early_data:
    return NGTCP2_CRYPTO_LEVEL_EARLY;
  case ssl_encryption_handshake:
    return NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
  case ssl_encryption_application:
    return NGTCP2_CRYPTO_LEVEL_APP;
  default:
    assert(0);
  }
}

static int setup_initial_crypto_context(struct quicsocket *qs)
{
  const ngtcp2_cid *dcid = ngtcp2_conn_get_dcid(qs->qconn);

  if(ngtcp2_crypto_derive_and_install_initial_key(
         qs->qconn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, dcid,
         NGTCP2_CRYPTO_SIDE_CLIENT) != 0)
    return -1;

  return 0;
}

static void quic_settings(ngtcp2_settings *s,
                          uint64_t stream_buffer_size)
{
  ngtcp2_settings_default(s);
#ifdef DEBUG_NGTCP2
  s->log_printf = quic_printf;
#else
  s->log_printf = NULL;
#endif
  s->initial_ts = timestamp();
  s->transport_params.initial_max_stream_data_bidi_local = stream_buffer_size;
  s->transport_params.initial_max_stream_data_bidi_remote = QUIC_MAX_STREAMS;
  s->transport_params.initial_max_stream_data_uni = QUIC_MAX_STREAMS;
  s->transport_params.initial_max_data = QUIC_MAX_DATA;
  s->transport_params.initial_max_streams_bidi = 1;
  s->transport_params.initial_max_streams_uni = 3;
  s->transport_params.idle_timeout = QUIC_IDLE_TIMEOUT;
}

static FILE *keylog_file; /* not thread-safe */
static void keylog_callback(const SSL *ssl, const char *line)
{
  (void)ssl;
  fputs(line, keylog_file);
  fputc('\n', keylog_file);
  fflush(keylog_file);
}

static int init_ngh3_conn(struct quicsocket *qs);

static int quic_set_encryption_secrets(SSL *ssl,
                                       OSSL_ENCRYPTION_LEVEL ossl_level,
                                       const uint8_t *rx_secret,
                                       const uint8_t *tx_secret,
                                       size_t secretlen)
{
  struct quicsocket *qs = (struct quicsocket *)SSL_get_app_data(ssl);
  int level = quic_from_ossl_level(ossl_level);

  if(ngtcp2_crypto_derive_and_install_key(
         qs->qconn, ssl, NULL, NULL, NULL, NULL, NULL, NULL, level, rx_secret,
         tx_secret, secretlen, NGTCP2_CRYPTO_SIDE_CLIENT) != 0)
    return 0;

  if(level == NGTCP2_CRYPTO_LEVEL_APP && init_ngh3_conn(qs) != CURLE_OK)
    return 0;

  return 1;
}

static int quic_add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level,
                                   const uint8_t *data, size_t len)
{
  struct quicsocket *qs = (struct quicsocket *)SSL_get_app_data(ssl);
  struct quic_handshake *crypto_data;
  ngtcp2_crypto_level level = quic_from_ossl_level(ossl_level);
  int rv;

  crypto_data = &qs->client_crypto_data[level];
  if(crypto_data->buf == NULL) {
    crypto_data->buf = malloc(4096);
    crypto_data->alloclen = 4096;
    /* TODO Explode if malloc failed */
  }

  /* TODO Just pretend that handshake does not grow more than 4KiB for
     now */
  assert(crypto_data->len + len <= crypto_data->alloclen);

  memcpy(&crypto_data->buf[crypto_data->len], data, len);
  crypto_data->len += len;

  rv = ngtcp2_conn_submit_crypto_data(
      qs->qconn, level, (uint8_t *)(&crypto_data->buf[crypto_data->len] - len),
      len);
  if(rv) {
    H3BUGF(fprintf(stderr, "write_client_handshake failed\n"));
  }
  assert(0 == rv);

  return 1;
}

static int quic_flush_flight(SSL *ssl)
{
  (void)ssl;
  return 1;
}

static int quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level,
                           uint8_t alert)
{
  struct quicsocket *qs = (struct quicsocket *)SSL_get_app_data(ssl);
  (void)level;

  qs->tls_alert = alert;
  return 1;
}

static SSL_QUIC_METHOD quic_method = {quic_set_encryption_secrets,
                                      quic_add_handshake_data,
                                      quic_flush_flight, quic_send_alert};

static SSL_CTX *quic_ssl_ctx(struct Curl_easy *data)
{
  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
  const char *keylog_filename;

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  if(SSL_CTX_set_ciphersuites(ssl_ctx, QUIC_CIPHERS) != 1) {
    failf(data, "SSL_CTX_set_ciphersuites: %s",
          ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  if(SSL_CTX_set1_groups_list(ssl_ctx, QUIC_GROUPS) != 1) {
    failf(data, "SSL_CTX_set1_groups_list failed");
    return NULL;
  }

  SSL_CTX_set_quic_method(ssl_ctx, &quic_method);

  keylog_filename = getenv("SSLKEYLOGFILE");
  if(keylog_filename) {
    keylog_file = fopen(keylog_filename, "wb");
    if(keylog_file) {
      SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);
    }
  }

  return ssl_ctx;
}

/** SSL callbacks ***/

static int quic_init_ssl(struct quicsocket *qs)
{
  const uint8_t *alpn = NULL;
  size_t alpnlen = 0;
  /* this will need some attention when HTTPS proxy over QUIC get fixed */
  const char * const hostname = qs->conn->host.name;

  if(qs->ssl)
    SSL_free(qs->ssl);

  qs->ssl = SSL_new(qs->sslctx);

  SSL_set_app_data(qs->ssl, qs);
  SSL_set_connect_state(qs->ssl);

  switch(qs->version) {
#ifdef NGTCP2_PROTO_VER
  case NGTCP2_PROTO_VER:
    alpn = (const uint8_t *)NGTCP2_ALPN_H3;
    alpnlen = sizeof(NGTCP2_ALPN_H3) - 1;
    break;
#endif
  }
  if(alpn)
    SSL_set_alpn_protos(qs->ssl, alpn, (int)alpnlen);

  /* set SNI */
  SSL_set_tlsext_host_name(qs->ssl, hostname);
  return 0;
}

static int cb_initial(ngtcp2_conn *quic, void *user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;

  if(ngtcp2_crypto_read_write_crypto_data(
         quic, qs->ssl, NGTCP2_CRYPTO_LEVEL_INITIAL, NULL, 0) != 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}

static int
cb_recv_crypto_data(ngtcp2_conn *tconn, ngtcp2_crypto_level crypto_level,
                    uint64_t offset,
                    const uint8_t *data, size_t datalen,
                    void *user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;
  (void)offset;

  if(ngtcp2_crypto_read_write_crypto_data(tconn, qs->ssl, crypto_level, data,
                                          datalen) != 0)
    return NGTCP2_ERR_CRYPTO;

  return 0;
}

static int cb_handshake_completed(ngtcp2_conn *tconn, void *user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;
  (void)tconn;
  infof(qs->conn->data, "QUIC handshake is completed\n");

  return 0;
}

static int cb_recv_stream_data(ngtcp2_conn *tconn, int64_t stream_id,
                               int fin, uint64_t offset,
                               const uint8_t *buf, size_t buflen,
                               void *user_data, void *stream_user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;
  ssize_t nconsumed;
  (void)offset;
  (void)stream_user_data;

  infof(qs->conn->data, "Received %ld bytes data on stream %u\n",
        buflen, stream_id);

  nconsumed =
    nghttp3_conn_read_stream(qs->h3conn, stream_id, buf, buflen, fin);
  if(nconsumed < 0) {
    failf(qs->conn->data, "nghttp3_conn_read_stream returned error: %s\n",
          nghttp3_strerror((int)nconsumed));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  ngtcp2_conn_extend_max_stream_offset(tconn, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(tconn, nconsumed);

  return 0;
}

static int
cb_acked_stream_data_offset(ngtcp2_conn *tconn, int64_t stream_id,
                            uint64_t offset, size_t datalen, void *user_data,
                            void *stream_user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;
  int rv;
  (void)stream_id;
  (void)tconn;
  (void)offset;
  (void)datalen;
  (void)stream_user_data;

  rv = nghttp3_conn_add_ack_offset(qs->h3conn, stream_id, datalen);
  if(rv != 0) {
    failf(qs->conn->data, "nghttp3_conn_add_ack_offset returned error: %s\n",
          nghttp3_strerror(rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_close(ngtcp2_conn *tconn, int64_t stream_id,
                           uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;
  int rv;
  (void)tconn;
  (void)stream_user_data;
  /* stream is closed... */

  rv = nghttp3_conn_close_stream(qs->h3conn, stream_id,
                                 app_error_code);
  if(rv != 0) {
    failf(qs->conn->data, "nghttp3_conn_close_stream returned error: %s\n",
          nghttp3_strerror(rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_reset(ngtcp2_conn *tconn, int64_t stream_id,
                           uint64_t final_size, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;
  int rv;
  (void)tconn;
  (void)final_size;
  (void)app_error_code;
  (void)stream_user_data;

  rv = nghttp3_conn_reset_stream(qs->h3conn, stream_id);
  if(rv != 0) {
    failf(qs->conn->data, "nghttp3_conn_reset_stream returned error: %s\n",
          nghttp3_strerror(rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_recv_retry(ngtcp2_conn *tconn, const ngtcp2_pkt_hd *hd,
                         const ngtcp2_pkt_retry *retry, void *user_data)
{
  /* Re-generate handshake secrets here because connection ID might change. */
  struct quicsocket *qs = (struct quicsocket *)user_data;
  (void)tconn;
  (void)hd;
  (void)retry;

  setup_initial_crypto_context(qs);

  return 0;
}

static int cb_extend_max_local_streams_bidi(ngtcp2_conn *tconn,
                                            uint64_t max_streams,
                                            void *user_data)
{
  (void)tconn;
  (void)max_streams;
  (void)user_data;

  return 0;
}

static int cb_extend_max_stream_data(ngtcp2_conn *tconn, int64_t stream_id,
                                     uint64_t max_data, void *user_data,
                                     void *stream_user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;
  int rv;
  (void)tconn;
  (void)max_data;
  (void)stream_user_data;

  rv = nghttp3_conn_unblock_stream(qs->h3conn, stream_id);
  if(rv != 0) {
    failf(qs->conn->data, "nghttp3_conn_unblock_stream returned error: %s\n",
          nghttp3_strerror(rv));
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_get_new_connection_id(ngtcp2_conn *tconn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data)
{
  struct quicsocket *qs = (struct quicsocket *)user_data;
  CURLcode result;
  (void)tconn;

  result = Curl_rand(qs->conn->data, cid->data, cidlen);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;

  result = Curl_rand(qs->conn->data, token, NGTCP2_STATELESS_RESET_TOKENLEN);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}

static ngtcp2_conn_callbacks ng_callbacks = {
  cb_initial,
  NULL, /* recv_client_initial */
  cb_recv_crypto_data,
  cb_handshake_completed,
  NULL, /* recv_version_negotiation */
  ngtcp2_crypto_encrypt_cb,
  ngtcp2_crypto_decrypt_cb,
  ngtcp2_crypto_hp_mask_cb,
  cb_recv_stream_data,
  NULL, /* acked_crypto_offset */
  cb_acked_stream_data_offset,
  NULL, /* stream_open */
  cb_stream_close,
  NULL, /* recv_stateless_reset */
  cb_recv_retry,
  cb_extend_max_local_streams_bidi,
  NULL, /* extend_max_local_streams_uni */
  NULL, /* rand  */
  cb_get_new_connection_id,
  NULL, /* remove_connection_id */
  NULL, /* update_key */
  NULL, /* path_validation */
  NULL, /* select_preferred_addr */
  cb_stream_reset,
  NULL, /* extend_max_remote_streams_bidi */
  NULL, /* extend_max_remote_streams_uni */
  cb_extend_max_stream_data,
};

/*
 * Might be called twice for happy eyeballs.
 */
CURLcode Curl_quic_connect(struct connectdata *conn,
                           curl_socket_t sockfd,
                           int sockindex,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  int rc;
  int rv;
  CURLcode result;
  ngtcp2_path path; /* TODO: this must be initialized properly */
  struct Curl_easy *data = conn->data;
  struct quicsocket *qs = &conn->hequic[sockindex];
  char ipbuf[40];
  long port;
  uint8_t paramsbuf[64];
  ngtcp2_transport_params params;
  ssize_t nwrite;

  qs->conn = conn;

  /* extract the used address as a string */
  if(!Curl_addr2string((struct sockaddr*)addr, addrlen, ipbuf, &port)) {
    char buffer[STRERROR_LEN];
    failf(data, "ssrem inet_ntop() failed with errno %d: %s",
          errno, Curl_strerror(errno, buffer, sizeof(buffer)));
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  infof(data, "Connect socket %d over QUIC to %s:%ld\n",
        sockfd, ipbuf, port);

  qs->version = NGTCP2_PROTO_VER;
  qs->sslctx = quic_ssl_ctx(data);
  if(!qs->sslctx)
    return CURLE_FAILED_INIT; /* TODO: better return code */

  if(quic_init_ssl(qs))
    return CURLE_FAILED_INIT; /* TODO: better return code */

  qs->dcid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, qs->dcid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  qs->scid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, qs->scid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  quic_settings(&qs->settings, data->set.buffer_size);

  qs->local_addrlen = sizeof(qs->local_addr);
  rv = getsockname(sockfd, (struct sockaddr *)&qs->local_addr,
                   &qs->local_addrlen);
  if(rv == -1)
    return CURLE_FAILED_INIT;

  ngtcp2_addr_init(&path.local, (uint8_t *)&qs->local_addr, qs->local_addrlen,
                   NULL);
  ngtcp2_addr_init(&path.remote, (uint8_t*)addr, addrlen, NULL);

#ifdef NGTCP2_PROTO_VER
#define QUICVER NGTCP2_PROTO_VER
#else
#error "unsupported ngtcp2 version"
#endif
  rc = ngtcp2_conn_client_new(&qs->qconn, &qs->dcid, &qs->scid, &path, QUICVER,
                              &ng_callbacks, &qs->settings, NULL, qs);
  if(rc)
    return CURLE_FAILED_INIT; /* TODO: create a QUIC error code */

  ngtcp2_conn_get_local_transport_params(qs->qconn, &params);
  nwrite = ngtcp2_encode_transport_params(
    paramsbuf, sizeof(paramsbuf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO,
    &params);
  if(nwrite < 0) {
    failf(data, "ngtcp2_encode_transport_params: %s\n",
          ngtcp2_strerror((int)nwrite));
    return CURLE_FAILED_INIT;
  }

  if(!SSL_set_quic_transport_params(qs->ssl, paramsbuf, nwrite))
    return CURLE_FAILED_INIT;

  rc = setup_initial_crypto_context(qs);
  if(rc)
    return CURLE_FAILED_INIT; /* TODO: better return code */

  return CURLE_OK;
}

/*
 * Store ngtp2 version info in this buffer, Prefix with a space.  Return total
 * length written.
 */
int Curl_quic_ver(char *p, size_t len)
{
  ngtcp2_info *ng2 = ngtcp2_version(0);
  nghttp3_info *ht3 = nghttp3_version(0);
  return msnprintf(p, len, " ngtcp2/%s nghttp3/%s",
                   ng2->version_str, ht3->version_str);
}

static int ng_getsock(struct connectdata *conn, curl_socket_t *socks)
{
  struct SingleRequest *k = &conn->data->req;
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

static int ng_perform_getsock(const struct connectdata *conn,
                              curl_socket_t *socks)
{
  return ng_getsock((struct connectdata *)conn, socks);
}

static CURLcode ng_disconnect(struct connectdata *conn,
                              bool dead_connection)
{
  (void)conn;
  (void)dead_connection;
  return CURLE_OK;
}

static unsigned int ng_conncheck(struct connectdata *conn,
                                 unsigned int checks_to_perform)
{
  (void)conn;
  (void)checks_to_perform;
  return CONNRESULT_NONE;
}

static const struct Curl_handler Curl_handler_http3 = {
  "HTTPS",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ng_getsock,                           /* proto_getsock */
  ng_getsock,                           /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ng_perform_getsock,                   /* perform_getsock */
  ng_disconnect,                        /* disconnect */
  ZERO_NULL,                            /* readwrite */
  ng_conncheck,                         /* connection_check */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTPS,                      /* protocol */
  PROTOPT_SSL | PROTOPT_STREAM          /* flags */
};

static int cb_h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_easy *data = stream_user_data;
  struct HTTP *stream = data->req.protop;
  (void)conn;
  (void)stream_id;
  (void)app_error_code;
  (void)user_data;
  H3BUGF(infof(data, "cb_h3_stream_close CALLED\n"));

  stream->closed = TRUE;
  Curl_expire(data, 0, EXPIRE_QUIC);
  return 0;
}

static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream_id,
                           const uint8_t *buf, size_t buflen,
                           void *user_data, void *stream_user_data)
{
  struct quicsocket *qs = user_data;
  size_t ncopy;
  struct Curl_easy *data = stream_user_data;
  struct HTTP *stream = data->req.protop;
  (void)conn;
  H3BUGF(infof(data, "cb_h3_recv_data CALLED with %d bytes\n", buflen));

  /* TODO: this needs to be handled properly */
  DEBUGASSERT(buflen <= stream->len);

  ncopy = CURLMIN(stream->len, buflen);
  memcpy(stream->mem, buf, ncopy);
  stream->len -= ncopy;
  stream->memlen += ncopy;
#if 0 /* extra debugging of incoming h3 data */
  fprintf(stderr, "!! Copies %zd bytes to %p (total %zd)\n",
          ncopy, stream->mem, stream->memlen);
  {
    size_t i;
    for(i = 0; i < ncopy; i++) {
      fprintf(stderr, "!! data[%d]: %02x '%c'\n", i, buf[i], buf[i]);
    }
  }
#endif
  stream->mem += ncopy;

  ngtcp2_conn_extend_max_stream_offset(qs->qconn, stream_id, buflen);
  ngtcp2_conn_extend_max_offset(qs->qconn, buflen);

  return 0;
}

static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
  struct quicsocket *qs = user_data;
  (void)conn;
  (void)stream_user_data;

  ngtcp2_conn_extend_max_stream_offset(qs->qconn, stream_id, consumed);
  ngtcp2_conn_extend_max_offset(qs->qconn, consumed);

  return 0;
}

/* Decode HTTP status code.  Returns -1 if no valid status code was
   decoded. (duplicate from http2.c) */
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

static int cb_h3_end_headers(nghttp3_conn *conn, int64_t stream_id,
                             void *user_data, void *stream_user_data)
{
  struct Curl_easy *data = stream_user_data;
  struct HTTP *stream = data->req.protop;
  (void)conn;
  (void)stream_id;
  (void)user_data;

  if(stream->memlen >= 2) {
    memcpy(stream->mem, "\r\n", 2);
    stream->len -= 2;
    stream->memlen += 2;
    stream->mem += 2;
  }
  return 0;
}

static int cb_h3_recv_header(nghttp3_conn *conn, int64_t stream_id,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
  nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);
  struct Curl_easy *data = stream_user_data;
  struct HTTP *stream = data->req.protop;
  size_t ncopy;
  (void)conn;
  (void)stream_id;
  (void)token;
  (void)flags;
  (void)user_data;

  if(h3name.len == sizeof(":status") - 1 &&
     !memcmp(":status", h3name.base, h3name.len)) {
    int status = decode_status_code(h3val.base, h3val.len);
    DEBUGASSERT(status != -1);
    msnprintf(stream->mem, stream->len, "HTTP/3 %03d \r\n", status);
  }
  else {
    /* store as a HTTP1-style header */
    msnprintf(stream->mem, stream->len, "%.*s: %.*s\n",
              h3name.len, h3name.base, h3val.len, h3val.base);
  }

  ncopy = strlen(stream->mem);
  stream->len -= ncopy;
  stream->memlen += ncopy;
  stream->mem += ncopy;
  return 0;
}

static int cb_h3_send_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                                   uint64_t app_error_code,
                                   void *user_data,
                                   void *stream_user_data)
{
  (void)conn;
  (void)stream_id;
  (void)app_error_code;
  (void)user_data;
  (void)stream_user_data;
  return 0;
}

static nghttp3_conn_callbacks ngh3_callbacks = {
  cb_h3_acked_stream_data, /* acked_stream_data */
  cb_h3_stream_close,
  cb_h3_recv_data,
  cb_h3_deferred_consume,
  NULL, /* begin_headers */
  cb_h3_recv_header,
  cb_h3_end_headers,
  NULL, /* begin_trailers */
  cb_h3_recv_header,
  NULL, /* end_trailers */
  NULL, /* http_begin_push_promise */
  NULL, /* http_recv_push_promise */
  NULL, /* http_end_push_promise */
  NULL, /* http_cancel_push */
  cb_h3_send_stop_sending,
  NULL, /* push_stream */
  NULL, /* end_stream */
};

static int init_ngh3_conn(struct quicsocket *qs)
{
  CURLcode result;
  int rc;
  int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;

  if(ngtcp2_conn_get_max_local_streams_uni(qs->qconn) < 3) {
    failf(qs->conn->data, "too few available QUIC streams");
    return CURLE_FAILED_INIT;
  }

  nghttp3_conn_settings_default(&qs->h3settings);

  rc = nghttp3_conn_client_new(&qs->h3conn,
                               &ngh3_callbacks,
                               &qs->h3settings,
                               nghttp3_mem_default(),
                               qs);
  if(rc) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  rc = ngtcp2_conn_open_uni_stream(qs->qconn, &ctrl_stream_id, NULL);
  if(rc) {
    result = CURLE_FAILED_INIT;
    goto fail;
  }

  rc = nghttp3_conn_bind_control_stream(qs->h3conn, ctrl_stream_id);
  if(rc) {
    result = CURLE_FAILED_INIT;
    goto fail;
  }

  rc = ngtcp2_conn_open_uni_stream(qs->qconn, &qpack_enc_stream_id, NULL);
  if(rc) {
    result = CURLE_FAILED_INIT;
    goto fail;
  }

  rc = ngtcp2_conn_open_uni_stream(qs->qconn, &qpack_dec_stream_id, NULL);
  if(rc) {
    result = CURLE_FAILED_INIT;
    goto fail;
  }

  rc = nghttp3_conn_bind_qpack_streams(qs->h3conn, qpack_enc_stream_id,
                                       qpack_dec_stream_id);
  if(rc) {
    result = CURLE_FAILED_INIT;
    goto fail;
  }

  return CURLE_OK;
  fail:

  return result;
}

static Curl_recv ngh3_stream_recv;
static Curl_send ngh3_stream_send;

/* incoming data frames on the h3 stream */
static ssize_t ngh3_stream_recv(struct connectdata *conn,
                                int sockindex,
                                char *buf,
                                size_t buffersize,
                                CURLcode *curlcode)
{
  curl_socket_t sockfd = conn->sock[sockindex];
  struct HTTP *stream = conn->data->req.protop;
  struct quicsocket *qs = conn->quic;

  if(!stream->memlen) {
    /* remember where to store incoming data for this stream and how big the
       buffer is */
    stream->mem = buf;
    stream->len = buffersize;
  }
  /* else, there's data in the buffer already */

  if(ng_process_ingress(conn, sockfd, qs)) {
    *curlcode = CURLE_RECV_ERROR;
    return -1;
  }
  if(ng_flush_egress(conn, sockfd, qs)) {
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }

  if(stream->memlen) {
    ssize_t memlen = stream->memlen;
    /* data arrived */
    *curlcode = CURLE_OK;
    /* reset to allow more data to come */
    stream->memlen = 0;
    stream->mem = buf;
    stream->len = buffersize;
    H3BUGF(infof(conn->data, "!! ngh3_stream_recv returns %zd bytes at %p\n",
                 memlen, buf));
    return memlen;
  }

  if(stream->closed) {
    *curlcode = CURLE_OK;
    return 0;
  }

  infof(conn->data, "ngh3_stream_recv returns 0 bytes and EAGAIN\n");
  *curlcode = CURLE_AGAIN;
  return -1;
}

/* this amount of data has now been acked on this stream */
static int cb_h3_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                                   size_t datalen, void *user_data,
                                   void *stream_user_data)
{
  struct Curl_easy *data = stream_user_data;
  struct HTTP *stream = data->req.protop;
  (void)conn;
  (void)stream_id;
  (void)user_data;

  if(!data->set.postfields) {
    stream->h3out->used -= datalen;
    H3BUGF(infof(data,
                 "cb_h3_acked_stream_data, %zd bytes, %zd left unacked\n",
                 datalen, stream->h3out->used));
    DEBUGASSERT(stream->h3out->used < H3_SEND_SIZE);
  }
  return 0;
}

static ssize_t cb_h3_readfunction(nghttp3_conn *conn, int64_t stream_id,
                                  nghttp3_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_easy *data = stream_user_data;
  size_t nread;
  struct HTTP *stream = data->req.protop;
  (void)conn;
  (void)stream_id;
  (void)user_data;
  (void)veccnt;

  if(data->set.postfields) {
    vec[0].base = data->set.postfields;
    vec[0].len = data->state.infilesize;
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 1;
  }

  nread = CURLMIN(stream->upload_len, H3_SEND_SIZE - stream->h3out->used);
  if(nread > 0) {
    /* nghttp3 wants us to hold on to the data until it tells us it is okay to
       delete it. Append the data at the end of the h3out buffer. Since we can
       only return consecutive data, copy the amount that fits and the next
       part comes in next invoke. */
    struct h3out *out = stream->h3out;
    if(nread + out->windex > H3_SEND_SIZE)
      nread = H3_SEND_SIZE - out->windex;

    memcpy(&out->buf[out->windex], stream->upload_mem, nread);
    out->windex += nread;
    out->used += nread;

    /* that's the chunk we return to nghttp3 */
    vec[0].base = &out->buf[out->windex];
    vec[0].len = nread;

    if(out->windex == H3_SEND_SIZE)
      out->windex = 0; /* wrap */
    stream->upload_mem += nread;
    stream->upload_len -= nread;
    if(data->state.infilesize != -1) {
      stream->upload_left -= nread;
      if(!stream->upload_left)
        *pflags = NGHTTP3_DATA_FLAG_EOF;
    }
    H3BUGF(infof(data, "cb_h3_readfunction %zd bytes%s (at %zd unacked)\n",
                 nread, *pflags == NGHTTP3_DATA_FLAG_EOF?" EOF":"",
                 out->used));
  }
  if(stream->upload_done && !stream->upload_len &&
     (stream->upload_left <= 0)) {
    H3BUGF(infof(data, "!!!!!!!!! cb_h3_readfunction sets EOF\n"));
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 0;
  }
  else if(!nread) {
    return NGHTTP3_ERR_WOULDBLOCK;
  }
  return 1;
}

/* Index where :authority header field will appear in request header
   field list. */
#define AUTHORITY_DST_IDX 3

static CURLcode http_request(struct connectdata *conn, const void *mem,
                             size_t len)
{
  struct HTTP *stream = conn->data->req.protop;
  size_t nheader;
  size_t i;
  size_t authority_idx;
  char *hdbuf = (char *)mem;
  char *end, *line_end;
  struct quicsocket *qs = conn->quic;
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = conn->data;
  nghttp3_nv *nva = NULL;
  int64_t stream3_id;
  int rc;
  struct h3out *h3out = NULL;

  rc = ngtcp2_conn_open_bidi_stream(qs->qconn, &stream3_id, NULL);
  if(rc) {
    failf(conn->data, "can get bidi streams");
    result = CURLE_SEND_ERROR;
    goto fail;
  }

  stream->stream3_id = stream3_id;
  stream->h3req = TRUE; /* senf off! */

  /* Calculate number of headers contained in [mem, mem + len). Assumes a
     correctly generated HTTP header field block. */
  nheader = 0;
  for(i = 1; i < len; ++i) {
    if(hdbuf[i] == '\n' && hdbuf[i - 1] == '\r') {
      ++nheader;
      ++i;
    }
  }
  if(nheader < 2)
    goto fail;

  /* We counted additional 2 \r\n in the first and last line. We need 3
     new headers: :method, :path and :scheme. Therefore we need one
     more space. */
  nheader += 1;
  nva = malloc(sizeof(nghttp3_nv) * nheader);
  if(!nva) {
    result = CURLE_OUT_OF_MEMORY;
    goto fail;
  }

  /* Extract :method, :path from request line
     We do line endings with CRLF so checking for CR is enough */
  line_end = memchr(hdbuf, '\r', len);
  if(!line_end) {
    result = CURLE_BAD_FUNCTION_ARGUMENT; /* internal error */
    goto fail;
  }

  /* Method does not contain spaces */
  end = memchr(hdbuf, ' ', line_end - hdbuf);
  if(!end || end == hdbuf)
    goto fail;
  nva[0].name = (unsigned char *)":method";
  nva[0].namelen = strlen((char *)nva[0].name);
  nva[0].value = (unsigned char *)hdbuf;
  nva[0].valuelen = (size_t)(end - hdbuf);
  nva[0].flags = NGHTTP3_NV_FLAG_NONE;

  hdbuf = end + 1;

  /* Path may contain spaces so scan backwards */
  end = NULL;
  for(i = (size_t)(line_end - hdbuf); i; --i) {
    if(hdbuf[i - 1] == ' ') {
      end = &hdbuf[i - 1];
      break;
    }
  }
  if(!end || end == hdbuf)
    goto fail;
  nva[1].name = (unsigned char *)":path";
  nva[1].namelen = strlen((char *)nva[1].name);
  nva[1].value = (unsigned char *)hdbuf;
  nva[1].valuelen = (size_t)(end - hdbuf);
  nva[1].flags = NGHTTP3_NV_FLAG_NONE;

  nva[2].name = (unsigned char *)":scheme";
  nva[2].namelen = strlen((char *)nva[2].name);
  if(conn->handler->flags & PROTOPT_SSL)
    nva[2].value = (unsigned char *)"https";
  else
    nva[2].value = (unsigned char *)"http";
  nva[2].valuelen = strlen((char *)nva[2].value);
  nva[2].flags = NGHTTP3_NV_FLAG_NONE;


  authority_idx = 0;
  i = 3;
  while(i < nheader) {
    size_t hlen;

    hdbuf = line_end + 2;

    /* check for next CR, but only within the piece of data left in the given
       buffer */
    line_end = memchr(hdbuf, '\r', len - (hdbuf - (char *)mem));
    if(!line_end || (line_end == hdbuf))
      goto fail;

    /* header continuation lines are not supported */
    if(*hdbuf == ' ' || *hdbuf == '\t')
      goto fail;

    for(end = hdbuf; end < line_end && *end != ':'; ++end)
      ;
    if(end == hdbuf || end == line_end)
      goto fail;
    hlen = end - hdbuf;

    if(hlen == 4 && strncasecompare("host", hdbuf, 4)) {
      authority_idx = i;
      nva[i].name = (unsigned char *)":authority";
      nva[i].namelen = strlen((char *)nva[i].name);
    }
    else {
      nva[i].namelen = (size_t)(end - hdbuf);
      /* Lower case the header name for HTTP/3 */
      Curl_strntolower((char *)hdbuf, hdbuf, nva[i].namelen);
      nva[i].name = (unsigned char *)hdbuf;
    }
    nva[i].flags = NGHTTP3_NV_FLAG_NONE;
    hdbuf = end + 1;
    while(*hdbuf == ' ' || *hdbuf == '\t')
      ++hdbuf;
    end = line_end;

#if 0 /* This should probably go in more or less like this */
    switch(inspect_header((const char *)nva[i].name, nva[i].namelen, hdbuf,
                          end - hdbuf)) {
    case HEADERINST_IGNORE:
      /* skip header fields prohibited by HTTP/2 specification. */
      --nheader;
      continue;
    case HEADERINST_TE_TRAILERS:
      nva[i].value = (uint8_t*)"trailers";
      nva[i].value_len = sizeof("trailers") - 1;
      break;
    default:
      nva[i].value = (unsigned char *)hdbuf;
      nva[i].value_len = (size_t)(end - hdbuf);
    }
#endif
    nva[i].value = (unsigned char *)hdbuf;
    nva[i].valuelen = (size_t)(end - hdbuf);
    nva[i].flags = NGHTTP3_NV_FLAG_NONE;

    ++i;
  }

  /* :authority must come before non-pseudo header fields */
  if(authority_idx != 0 && authority_idx != AUTHORITY_DST_IDX) {
    nghttp3_nv authority = nva[authority_idx];
    for(i = authority_idx; i > AUTHORITY_DST_IDX; --i) {
      nva[i] = nva[i - 1];
    }
    nva[i] = authority;
  }

  /* Warn stream may be rejected if cumulative length of headers is too
     large. */
#define MAX_ACC 60000  /* <64KB to account for some overhead */
  {
    size_t acc = 0;
    for(i = 0; i < nheader; ++i)
      acc += nva[i].namelen + nva[i].valuelen;

    if(acc > MAX_ACC) {
      infof(data, "http_request: Warning: The cumulative length of all "
            "headers exceeds %zu bytes and that could cause the "
            "stream to be rejected.\n", MAX_ACC);
    }
  }

  switch(data->set.httpreq) {
  case HTTPREQ_POST:
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
  case HTTPREQ_PUT: {
    nghttp3_data_reader data_reader;
    if(data->state.infilesize != -1)
      stream->upload_left = data->state.infilesize;
    else
      /* data sending without specifying the data amount up front */
      stream->upload_left = -1; /* unknown, but not zero */

    data_reader.read_data = cb_h3_readfunction;

    h3out = calloc(sizeof(struct h3out), 1);
    if(!h3out) {
      result = CURLE_OUT_OF_MEMORY;
      goto fail;
    }
    stream->h3out = h3out;

    rc = nghttp3_conn_submit_request(qs->h3conn, stream->stream3_id,
                                     nva, nheader, &data_reader,
                                     conn->data);
    if(rc) {
      result = CURLE_SEND_ERROR;
      goto fail;
    }
    break;
  }
  default:
    stream->upload_left = 0; /* nothing left to send */
    rc = nghttp3_conn_submit_request(qs->h3conn, stream->stream3_id,
                                     nva, nheader,
                                     NULL, /* no body! */
                                     conn->data);
    if(rc) {
      result = CURLE_SEND_ERROR;
      goto fail;
    }
    break;
  }

  Curl_safefree(nva);

  infof(data, "Using HTTP/3 Stream ID: %x (easy handle %p)\n",
        stream3_id, (void *)data);

  return CURLE_OK;

fail:
  free(nva);
  return result;
}
static ssize_t ngh3_stream_send(struct connectdata *conn,
                                int sockindex,
                                const void *mem,
                                size_t len,
                                CURLcode *curlcode)
{
  ssize_t sent;
  struct quicsocket *qs = conn->quic;
  curl_socket_t sockfd = conn->sock[sockindex];
  struct HTTP *stream = conn->data->req.protop;

  if(!stream->h3req) {
    CURLcode result = http_request(conn, mem, len);
    if(result) {
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
    sent = len;
  }
  else {
    H3BUGF(infof(conn->data, "ngh3_stream_send() wants to send %zd bytes\n",
                 len));
    if(!stream->upload_len) {
      stream->upload_mem = mem;
      stream->upload_len = len;
      (void)nghttp3_conn_resume_stream(qs->h3conn, stream->stream3_id);
      sent = len;
    }
    else {
      *curlcode = CURLE_AGAIN;
      return -1;
    }
  }

  if(ng_flush_egress(conn, sockfd, qs)) {
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }

  *curlcode = CURLE_OK;
  return sent;
}

static void ng_has_connected(struct connectdata *conn, int tempindex)
{
  conn->recv[FIRSTSOCKET] = ngh3_stream_recv;
  conn->send[FIRSTSOCKET] = ngh3_stream_send;
  conn->handler = &Curl_handler_http3;
  conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  conn->httpversion = 30;
  conn->bundle->multiuse = BUNDLE_MULTIPLEX;
  conn->quic = &conn->hequic[tempindex];
  DEBUGF(infof(conn->data, "ngtcp2 established connection!\n"));
}

/*
 * There can be multiple connection attempts going on in parallel.
 */
CURLcode Curl_quic_is_connected(struct connectdata *conn,
                                int sockindex,
                                bool *done)
{
  CURLcode result;
  struct quicsocket *qs = &conn->hequic[sockindex];
  curl_socket_t sockfd = conn->tempsock[sockindex];

  result = ng_process_ingress(conn, sockfd, qs);
  if(result)
    return result;

  result = ng_flush_egress(conn, sockfd, qs);
  if(result)
    return result;

  if(ngtcp2_conn_get_handshake_completed(qs->qconn)) {
    *done = TRUE;
    ng_has_connected(conn, sockindex);
  }

  return result;
}

static CURLcode ng_process_ingress(struct connectdata *conn, int sockfd,
                                   struct quicsocket *qs)
{
  ssize_t recvd;
  int rv;
  uint8_t buf[65536];
  size_t bufsize = sizeof(buf);
  struct sockaddr_storage remote_addr;
  socklen_t remote_addrlen;
  ngtcp2_path path;
  ngtcp2_tstamp ts = timestamp();

  for(;;) {
    remote_addrlen = sizeof(remote_addr);
    while((recvd = recvfrom(sockfd, buf, bufsize, MSG_DONTWAIT,
                            (struct sockaddr *)&remote_addr,
                            &remote_addrlen)) == -1 &&
          errno == EINTR)
      ;
    if(recvd == -1) {
      if(errno == EAGAIN || errno == EWOULDBLOCK)
        break;

      failf(conn->data, "ngtcp2: recvfrom() unexpectedly returned %d", recvd);
      return CURLE_RECV_ERROR;
    }

    ngtcp2_addr_init(&path.local, (uint8_t *)&qs->local_addr,
                     qs->local_addrlen, NULL);
    ngtcp2_addr_init(&path.remote, (uint8_t *)&remote_addr, remote_addrlen,
                     NULL);

    rv = ngtcp2_conn_read_pkt(qs->qconn, &path, buf, recvd, ts);
    if(rv != 0) {
      /* TODO Send CONNECTION_CLOSE if possible */
      return CURLE_RECV_ERROR;
    }
  }

  return CURLE_OK;
}

static CURLcode ng_flush_egress(struct connectdata *conn, int sockfd,
                                struct quicsocket *qs)
{
  int rv;
  ssize_t sent;
  ssize_t outlen;
  uint8_t out[NGTCP2_MAX_PKTLEN_IPV4];
  size_t pktlen;
  ngtcp2_path_storage ps;
  ngtcp2_tstamp ts = timestamp();
  struct sockaddr_storage remote_addr;
  ngtcp2_tstamp expiry;
  ngtcp2_duration timeout;
  int64_t stream_id;
  ssize_t veccnt;
  int fin;
  nghttp3_vec vec[16];
  ssize_t ndatalen;

  switch(qs->local_addr.ss_family) {
  case AF_INET:
    pktlen = NGTCP2_MAX_PKTLEN_IPV4;
    break;
  case AF_INET6:
    pktlen = NGTCP2_MAX_PKTLEN_IPV6;
    break;
  default:
    assert(0);
  }

  rv = ngtcp2_conn_handle_expiry(qs->qconn, ts);
  if(rv != 0) {
    failf(conn->data, "ngtcp2_conn_handle_expiry returned error: %s\n",
          ngtcp2_strerror(rv));
    return CURLE_SEND_ERROR;
  }

  ngtcp2_path_storage_zero(&ps);

  for(;;) {
    outlen = -1;
    if(qs->h3conn && ngtcp2_conn_get_max_data_left(qs->qconn)) {
      veccnt = nghttp3_conn_writev_stream(qs->h3conn, &stream_id, &fin, vec,
                                          sizeof(vec) / sizeof(vec[0]));
      if(veccnt < 0) {
        failf(conn->data, "nghttp3_conn_writev_stream returned error: %s\n",
              nghttp3_strerror((int)veccnt));
        return CURLE_SEND_ERROR;
      }
      else if(veccnt > 0) {
        outlen =
          ngtcp2_conn_writev_stream(qs->qconn, &ps.path,
                                    out, pktlen, &ndatalen,
                                    NGTCP2_WRITE_STREAM_FLAG_MORE,
                                    stream_id, fin,
                                    (const ngtcp2_vec *)vec, veccnt, ts);
        if(outlen == 0) {
          break;
        }
        if(outlen < 0) {
          if(outlen == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
             outlen == NGTCP2_ERR_STREAM_SHUT_WR) {
            rv = nghttp3_conn_block_stream(qs->h3conn, stream_id);
            if(rv != 0) {
              failf(conn->data,
                    "nghttp3_conn_block_stream returned error: %s\n",
                    nghttp3_strerror(rv));
              return CURLE_SEND_ERROR;
            }
            continue;
          }
          else if(outlen == NGTCP2_ERR_WRITE_STREAM_MORE) {
            assert(ndatalen > 0);
            rv = nghttp3_conn_add_write_offset(qs->h3conn, stream_id,
                                               ndatalen);
            if(rv != 0) {
              failf(conn->data,
                    "nghttp3_conn_add_write_offset returned error: %s\n",
                    nghttp3_strerror(rv));
              return CURLE_SEND_ERROR;
            }
            continue;
          }
          else {
            failf(conn->data, "ngtcp2_conn_writev_stream returned error: %s\n",
                  ngtcp2_strerror((int)outlen));
            return CURLE_SEND_ERROR;
          }
        }
        else if(ndatalen >= 0) {
          rv = nghttp3_conn_add_write_offset(qs->h3conn, stream_id, ndatalen);
          if(rv != 0) {
            failf(conn->data,
                  "nghttp3_conn_add_write_offset returned error: %s\n",
                  nghttp3_strerror(rv));
            return CURLE_SEND_ERROR;
          }
        }
      }
    }
    if(outlen < 0) {
      outlen = ngtcp2_conn_write_pkt(qs->qconn, &ps.path, out, pktlen, ts);
      if(outlen < 0) {
        failf(conn->data, "ngtcp2_conn_write_pkt returned error: %s\n",
              ngtcp2_strerror((int)outlen));
        return CURLE_SEND_ERROR;
      }
      if(outlen == 0)
        break;
    }

    memcpy(&remote_addr, ps.path.remote.addr, ps.path.remote.addrlen);
    while((sent = sendto(sockfd, out, outlen, MSG_DONTWAIT,
                         (struct sockaddr *)&remote_addr,
                         (socklen_t)ps.path.remote.addrlen)) == -1 &&
          errno == EINTR)
      ;

    if(sent == -1) {
      if(errno == EAGAIN || errno == EWOULDBLOCK) {
        /* TODO Cache packet */
        break;
      }
      else {
        failf(conn->data, "sendto() returned %zd (errno %d)\n", sent,
              SOCKERRNO);
        return CURLE_SEND_ERROR;
      }
    }
  }

  expiry = ngtcp2_conn_get_expiry(qs->qconn);
  if(expiry != UINT64_MAX) {
    if(expiry <= ts) {
      timeout = NGTCP2_MILLISECONDS;
    }
    else {
      timeout = expiry - ts;
    }
    Curl_expire(conn->data, timeout / NGTCP2_MILLISECONDS, EXPIRE_QUIC);
  }

  return CURLE_OK;
}

/*
 * Called from transfer.c:done_sending when we stop HTTP/3 uploading.
 */
CURLcode Curl_quic_done_sending(struct connectdata *conn)
{
  if(conn->handler == &Curl_handler_http3) {
    /* only for HTTP/3 transfers */
    struct HTTP *stream = conn->data->req.protop;
    struct quicsocket *qs = conn->quic;
    stream->upload_done = TRUE;
    (void)nghttp3_conn_resume_stream(qs->h3conn, stream->stream3_id);
  }

  return CURLE_OK;
}
#endif
