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
#include <openssl/err.h>
#include "urldata.h"
#include "sendf.h"
#include "strdup.h"
#include "rand.h"
#include "ngtcp2.h"
#include "ngtcp2-crypto.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_MAX_DATA (1*1024*1024)
#define QUIC_IDLE_TIMEOUT 60 /* seconds? */
#define QUIC_CIPHERS "TLS13-AES-128-GCM-SHA256:"                \
  "TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256"
#define QUIC_GROUPS "P-256:X25519:P-384:P-521"

static void quic_printf(void *user_data, const char *fmt, ...)
{
  va_list ap;
  (void)user_data; /* TODO, use this to do infof() instead long-term */
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}

static int setup_initial_crypto_context(struct connectdata *conn)
{
  int rv;
  uint8_t initial_secret[32];
  uint8_t secret[32];
  const ngtcp2_cid *dcid;
  uint8_t key[16];
  ssize_t keylen;
  uint8_t iv[16];
  ssize_t ivlen;
  uint8_t hp[16];
  ssize_t hplen;

  dcid = ngtcp2_conn_get_dcid(conn->quic.conn);
  rv = Curl_qc_derive_initial_secret(initial_secret, sizeof(initial_secret),
                                     dcid, (uint8_t *)NGTCP2_INITIAL_SALT,
                                     strlen(NGTCP2_INITIAL_SALT));
  if(rv) {
    return -1;
  }

  Curl_qc_prf_sha256(&conn->quic.hs_crypto_ctx);
  Curl_qc_aead_aes_128_gcm(&conn->quic.hs_crypto_ctx);

  rv = Curl_qc_derive_client_initial_secret(secret, sizeof(secret),
                                            initial_secret,
                                            sizeof(initial_secret));
  if(rv) {
    return -1;
  }

  keylen = Curl_qc_derive_packet_protection_key(key, sizeof(key),
                                                secret, sizeof(secret),
                                                &conn->quic.hs_crypto_ctx);
  if(keylen < 0) {
    return -1;
  }

  ivlen = Curl_qc_derive_packet_protection_iv(iv, sizeof(iv),
                                              secret, sizeof(secret),
                                              &conn->quic.hs_crypto_ctx);
  if(ivlen < 0) {
    return -1;
  }

  hplen = Curl_qc_derive_header_protection_key(hp, sizeof(hp),
                                               secret, sizeof(secret),
                                               &conn->quic.hs_crypto_ctx);
  if(hplen < 0) {
    return -1;
  }

  ngtcp2_conn_install_initial_tx_keys(conn->quic.conn, key, keylen, iv, ivlen,
                                      hp, hplen);

  rv = Curl_qc_derive_server_initial_secret(secret, sizeof(secret),
                                            initial_secret,
                                            sizeof(initial_secret));
  if(rv) {
    return -1;
  }

  keylen = Curl_qc_derive_packet_protection_key(key, sizeof(key),
                                                secret, sizeof(secret),
                                                &conn->quic.hs_crypto_ctx);
  if(keylen < 0) {
    return -1;
  }

  ivlen = Curl_qc_derive_packet_protection_iv(iv, sizeof(iv),
                                              secret, sizeof(secret),
                                              &conn->quic.hs_crypto_ctx);
  if(ivlen < 0) {
    return -1;
  }

  hplen = Curl_qc_derive_header_protection_key(hp, sizeof(hp),
                                               secret, sizeof(secret),
                                               &conn->quic.hs_crypto_ctx);
  if(hplen < 0) {
    return -1;
  }

  ngtcp2_conn_install_initial_rx_keys(conn->quic.conn,
                                      key, keylen, iv, ivlen, hp, hplen);

  return 0;
}

static void quic_settings(ngtcp2_settings *s)
{
  s->log_printf = quic_printf;
  s->initial_ts = 0;
  s->max_stream_data_bidi_local = QUIC_MAX_STREAMS;
  s->max_stream_data_bidi_remote = QUIC_MAX_STREAMS;
  s->max_stream_data_uni = QUIC_MAX_STREAMS;
  s->max_data = QUIC_MAX_DATA;
  s->max_streams_bidi = 1;
  s->max_streams_uni = 1;
  s->idle_timeout = QUIC_IDLE_TIMEOUT;
  s->max_packet_size = NGTCP2_MAX_PKT_SIZE;
  s->ack_delay_exponent = NGTCP2_DEFAULT_ACK_DELAY_EXPONENT;
  s->max_ack_delay = NGTCP2_DEFAULT_MAX_ACK_DELAY;
}

/* SSL extension functions */
static int transport_params_add_cb(SSL *ssl, unsigned int ext_type,
                                   unsigned int content,
                                   const unsigned char **out,
                                   size_t *outlen, X509 *x,
                                   size_t chainidx, int *al, void *add_arg)
{
  int rv;
  struct connectdata *conn = (struct connectdata *)SSL_get_app_data(ssl);
  ngtcp2_transport_params params;
  uint8_t buf[64];
  ssize_t nwrite;
  (void)ext_type;
  (void)content;
  (void)x;
  (void)chainidx;
  (void)add_arg;

  rv = ngtcp2_conn_get_local_transport_params(
    conn->quic.conn, &params, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO);
  if(rv) {
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  nwrite = ngtcp2_encode_transport_params(
    buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
  if(nwrite < 0) {
    fprintf(stderr, "ngtcp2_encode_transport_params: %s\n",
            ngtcp2_strerror((int)nwrite));
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
  }

  *out = Curl_memdup(buf, nwrite);
  *outlen = nwrite;

  return 1;
}

static void transport_params_free_cb(SSL *ssl, unsigned int ext_type,
                                     unsigned int context,
                                     const unsigned char *out,
                                     void *add_arg)
{
  (void)ssl;
  (void)ext_type;
  (void)context;
  (void)add_arg;
  free((char *)out);
}

static int transport_params_parse_cb(SSL *ssl, unsigned int ext_type,
                                     unsigned int context,
                                     const unsigned char *in,
                                     size_t inlen, X509 *x, size_t chainidx,
                                     int *al, void *parse_arg)
{
  struct connectdata *conn = (struct connectdata *)SSL_get_app_data(ssl);
  int rv;
  ngtcp2_transport_params params;
  (void)ext_type;
  (void)context;
  (void)x;
  (void)chainidx;
  (void)parse_arg;

  rv = ngtcp2_decode_transport_params(
    &params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, in, inlen);
  if(rv) {
    fprintf(stderr, "ngtcp2_decode_transport_params: %s\n",
            ngtcp2_strerror(rv));
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return -1;
  }

  rv = ngtcp2_conn_set_remote_transport_params(
    conn->quic.conn, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS,
    &params);
  if(rv) {
    *al = SSL_AD_ILLEGAL_PARAMETER;
    return -1;
  }

  return 1;
}

static SSL_CTX *quic_ssl_ctx(struct Curl_easy *data)
{
  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

  /* This makes OpenSSL client not send CCS after an initial ClientHello. */
  SSL_CTX_clear_options(ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  if(SSL_CTX_set_cipher_list(ssl_ctx, QUIC_CIPHERS) != 1) {
    failf(data, "SSL_CTX_set_cipher_list: %s",
          ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  if(SSL_CTX_set1_groups_list(ssl_ctx, QUIC_GROUPS) != 1) {
    failf(data, "SSL_CTX_set1_groups_list failed");
    return NULL;
  }

  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_QUIC_HACK);

  if(SSL_CTX_add_custom_ext(ssl_ctx,
                            NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
                            SSL_EXT_CLIENT_HELLO |
                            SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                            transport_params_add_cb,
                            transport_params_free_cb, NULL,
                            transport_params_parse_cb, NULL) != 1) {
    failf(data, "SSL_CTX_add_custom_ext(NGTCP2_TLSEXT_QUIC_TRANSPORT_"
          "PARAMETERS) failed: %s\n",
          ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  return ssl_ctx;
}

/** SSL callbacks ***/

static void set_tls_alert(struct connectdata *conn,
                          uint8_t alert)
{
  struct quicsocket *qs = &conn->quic;
  qs->tls_alert = alert;
}

static int ssl_on_key(struct connectdata *conn,
                      int name, const uint8_t *secret, size_t secretlen)
{
  int rv;
  uint8_t hp[64];
  ssize_t hplen;
  uint8_t key[64];
  ssize_t keylen;
  uint8_t iv[64];
  ssize_t ivlen;
  struct Context *crypto_ctx = &conn->quic.crypto_ctx;

  switch(name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    break;
  default:
    return 0;
  }

  /* TODO We don't have to call this everytime we get key generated. */
  rv = Curl_qc_negotiated_prf(crypto_ctx, conn->quic.ssl);
  if(rv != 0) {
    return -1;
  }
  rv = Curl_qc_negotiated_aead(crypto_ctx, conn->quic.ssl);
  if(rv != 0) {
    return -1;
  }

  keylen = Curl_qc_derive_packet_protection_key(key, sizeof(key),
                                                secret, sizeof(secret),
                                                crypto_ctx);
  if(keylen < 0) {
    return -1;
  }

  ivlen = Curl_qc_derive_packet_protection_iv(iv, sizeof(iv),
                                              secret, sizeof(secret),
                                              crypto_ctx);
  if(ivlen < 0) {
    return -1;
  }

  hplen =
    Curl_qc_derive_header_protection_key(hp, sizeof(hp),
                                         secret, secretlen, crypto_ctx);
  if(hplen < 0)
    return -1;

  /* TODO Just call this once. */
  ngtcp2_conn_set_aead_overhead(conn->quic.conn,
                                Curl_qc_aead_max_overhead(crypto_ctx));

  switch(name) {
  case SSL_KEY_CLIENT_EARLY_TRAFFIC:
    ngtcp2_conn_install_early_keys(conn->quic.conn, key, keylen, iv, ivlen,
                                   hp, hplen);
    break;
  case SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC:
    ngtcp2_conn_install_handshake_tx_keys(conn->quic.conn, key, keylen,
                                          iv, ivlen, hp, hplen);
    break;
  case SSL_KEY_CLIENT_APPLICATION_TRAFFIC:
    ngtcp2_conn_install_tx_keys(conn->quic.conn, key, keylen, iv, ivlen,
                                hp, hplen);
    break;
  case SSL_KEY_SERVER_HANDSHAKE_TRAFFIC:
    ngtcp2_conn_install_handshake_rx_keys(conn->quic.conn, key, keylen,
                                          iv, ivlen,
                                          hp, hplen);
    break;
  case SSL_KEY_SERVER_APPLICATION_TRAFFIC:
    ngtcp2_conn_install_rx_keys(conn->quic.conn, key, keylen, iv, ivlen,
                                hp, hplen);
    break;
  }
  return 0;
}

static void ssl_msg_cb(int write_p, int version, int content_type,
                       const void *buf, size_t len, SSL *ssl, void *user_data)
{
  int rv;
  struct connectdata *conn = (struct connectdata *)user_data;
  uint8_t *msg = (uint8_t *)buf;
  (void)version;
  (void)ssl;

  if(!write_p)
    return;

  switch(content_type) {
  case SSL3_RT_HANDSHAKE:
    break;
  case SSL3_RT_ALERT:
    assert(len == 2);
    if(msg[0] != 2 /* FATAL */) {
      return;
    }
    set_tls_alert(conn, msg[1]);
    return;
  default:
    return;
  }

  rv = ngtcp2_conn_submit_crypto_data(conn->quic.conn, buf, len);
  if(rv) {
    fprintf(stderr, "write_client_handshake failed\n");
  }
  assert(0 == rv);
}

static int ssl_key_cb(SSL *ssl, int name,
                      const unsigned char *secret,
                      size_t secretlen,
                      void *arg)
{
  struct connectdata *conn = (struct connectdata *)arg;
  (void)ssl;

  if(ssl_on_key(conn, name, secret, secretlen) != 0)
    return 0;

  /* log_secret(ssl, name, secret, secretlen); */

  return 1;
}

static int read_server_handshake(struct connectdata *conn,
                                 char *buf, int buflen)
{
  struct quic_handshake *hs = &conn->quic.handshake;
  int avail = (int)(hs->len - hs->nread);
  int n = CURLMIN(buflen, avail);
  memcpy(buf, &hs->buf[hs->nread], n);
  infof(conn->data, "read %d bytes of handshake data\n", n);
  hs->nread += n;
  return n;
}

static void write_server_handshake(struct connectdata *conn,
                                   const uint8_t *ptr, size_t datalen)
{
  char *p;
  struct quic_handshake *hs = &conn->quic.handshake;
  size_t alloclen = datalen + hs->alloclen;
  infof(conn->data, "store %zd bytes of handshake data\n", datalen);
  if(alloclen > hs->alloclen) {
    alloclen *= 2;
    p = realloc(conn->quic.handshake.buf, alloclen);
    if(!p)
      return; /* BAAAAAD */
    hs->buf = p;
    hs->alloclen = alloclen;
  }
  memcpy(&hs->buf[hs->len], ptr, datalen);
  hs->len += datalen;
}

/** BIO functions ***/

static int bio_write(BIO *b, const char *buf, int len)
{
  (void)b;
  (void)buf;
  (void)len;
  assert(0);
  return -1;
}

static int bio_read(BIO *b, char *buf, int len)
{
  struct connectdata *conn;
  BIO_clear_retry_flags(b);

  conn = (struct connectdata *)BIO_get_data(b);

  len = read_server_handshake(conn, buf, len);
  if(len == 0) {
    BIO_set_retry_read(b);
    return -1;
  }

  return len;
}

static int bio_puts(BIO *b, const char *str)
{
  return bio_write(b, str, (int)strlen(str));
}

static int bio_gets(BIO *b, char *buf, int len)
{
  (void)b;
  (void)buf;
  (void)len;
  return -1;
}

static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  (void)b;
  (void)cmd;
  (void)num;
  (void)ptr;
  switch(cmd) {
  case BIO_CTRL_FLUSH:
    return 1;
  }

  return 0;
}

static int bio_create(BIO *b)
{
  BIO_set_init(b, 1);
  return 1;
}

static int bio_destroy(BIO *b)
{
  if(!b)
    return 0;

  return 1;
}

static BIO_METHOD *create_bio_method(void)
{
  BIO_METHOD *meth = BIO_meth_new(BIO_TYPE_FD, "bio");
  BIO_meth_set_write(meth, bio_write);
  BIO_meth_set_read(meth, bio_read);
  BIO_meth_set_puts(meth, bio_puts);
  BIO_meth_set_gets(meth, bio_gets);
  BIO_meth_set_ctrl(meth, bio_ctrl);
  BIO_meth_set_create(meth, bio_create);
  BIO_meth_set_destroy(meth, bio_destroy);
  return meth;
}


static int quic_init_ssl(struct connectdata *conn)
{
  struct quicsocket *qs = &conn->quic;
  BIO *bio;
  const uint8_t *alpn = NULL;
  size_t alpnlen = 0;
  /* this will need some attention when HTTPS proxy over QUIC get fixed */
  const char * const hostname = conn->host.name;

  if(qs->ssl)
    SSL_free(qs->ssl);

  qs->ssl = SSL_new(qs->sslctx);
  bio = BIO_new(create_bio_method());
  /* supposedly this can fail too? */

  BIO_set_data(bio, conn);
  SSL_set_bio(qs->ssl, bio, bio);
  SSL_set_app_data(qs->ssl, conn);
  SSL_set_connect_state(qs->ssl);
  SSL_set_msg_callback(qs->ssl, ssl_msg_cb);
  SSL_set_msg_callback_arg(qs->ssl, conn);
  SSL_set_key_callback(qs->ssl, ssl_key_cb, conn);

  switch(qs->version) {
#ifdef NGTCP2_PROTO_VER_D17
  case NGTCP2_PROTO_VER_D17:
    alpn = (const uint8_t *)NGTCP2_ALPN_D17;
    alpnlen = strlen(NGTCP2_ALPN_D17);
    break;
#endif
  }
  if(alpn)
    SSL_set_alpn_protos(qs->ssl, alpn, (int)alpnlen);

  /* set SNI */
  SSL_set_tlsext_host_name(qs->ssl, hostname);
  return 0;
}

static int quic_tls_handshake(struct connectdata *conn,
                              bool resumption,
                              bool initial)
{
  int rv;
  struct quicsocket *qs = &conn->quic;
  ERR_clear_error();

  /* Note that SSL_SESSION_get_max_early_data() and
     SSL_get_max_early_data() return completely different value. */
  if(initial && resumption &&
     SSL_SESSION_get_max_early_data(SSL_get_session(qs->ssl))) {
    size_t nwrite;
    /* OpenSSL returns error if SSL_write_early_data is called when resumption
       is not attempted.  Sending empty string is a trick to just early_data
       extension. */
    rv = SSL_write_early_data(qs->ssl, "", 0, &nwrite);
    if(rv == 0) {
      int err = SSL_get_error(qs->ssl, rv);
      switch(err) {
      case SSL_ERROR_SSL:
        fprintf(stderr, "TLS handshake error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
      default:
        fprintf(stderr, "TLS handshake error: %d\n", err);
        return -1;
      }
    }
  }

  rv = SSL_do_handshake(qs->ssl);
  if(rv <= 0) {
    int err = SSL_get_error(qs->ssl, rv);
    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
        fprintf(stderr, "TLS handshake error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
      return -1;
    default:
      fprintf(stderr, "TLS handshake error: %d\n", err);
      return -1;
    }
  }

  /* SSL_get_early_data_status works after handshake completes. */
  if(resumption &&
     SSL_get_early_data_status(qs->ssl) != SSL_EARLY_DATA_ACCEPTED) {
    fprintf(stderr, "Early data was rejected by server\n");
    ngtcp2_conn_early_data_rejected(conn->quic.conn);
  }

  ngtcp2_conn_handshake_completed(conn->quic.conn);
  return 0;
}

static int cb_initial(ngtcp2_conn *quic, void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)quic;
  if(quic_tls_handshake(conn, false, true) != 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  return 0;
}

static int quic_read_tls(struct connectdata *conn)
{
  uint8_t buf[4096];
  size_t nread;

  ERR_clear_error();
  for(;;) {
    int err;
    int rv = SSL_read_ex(conn->quic.ssl, buf, sizeof(buf), &nread);
    if(rv == 1) {
      infof(conn->data,  "Read %zd bytes from TLS crypto stream",
            nread);
      continue;
    }
    err = SSL_get_error(conn->quic.ssl, 0);
    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;
    case SSL_ERROR_SSL:
    case SSL_ERROR_ZERO_RETURN:
      infof(conn->data, "TLS read error: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
      return NGTCP2_ERR_CRYPTO;
    default:
      infof(conn->data, "TLS read error: %d\n", err);
      return NGTCP2_ERR_CRYPTO;
    }
  }
  /* NEVER-REACHED */
}

static int
cb_recv_crypto_data(ngtcp2_conn *tconn, ngtcp2_crypto_level crypto_level,
                    uint64_t offset,
                    const uint8_t *data, size_t datalen,
                    void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)offset;
  (void)crypto_level;

  write_server_handshake(conn, data, datalen);

  if(!ngtcp2_conn_get_handshake_completed(tconn) &&
     quic_tls_handshake(conn, false, false)) {
    return NGTCP2_ERR_CRYPTO;
  }

  /* SSL_do_handshake() might not consume all data (e.g.,
     NewSessionTicket). */
  return quic_read_tls(conn);
}

static int cb_handshake_completed(ngtcp2_conn *tconn, void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)tconn;
  infof(conn->data, "QUIC handshake is completed\n");
  return 0;
}

static ssize_t cb_in_encrypt(ngtcp2_conn *tconn,
                             uint8_t *dest, size_t destlen,
                             const uint8_t *plaintext,
                             size_t plaintextlen,
                             const uint8_t *key, size_t keylen,
                             const uint8_t *nonce, size_t noncelen,
                             const uint8_t *ad, size_t adlen,
                             void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  ssize_t nwrite = Curl_qc_encrypt(dest, destlen, plaintext, plaintextlen,
                                   &conn->quic.hs_crypto_ctx,
                                   key, keylen, nonce, noncelen, ad, adlen);
  if(nwrite < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  (void)tconn;

  return nwrite;
}

static ssize_t cb_in_decrypt(ngtcp2_conn *tconn,
                             uint8_t *dest, size_t destlen,
                             const uint8_t *ciphertext, size_t ciphertextlen,
                             const uint8_t *key, size_t keylen,
                             const uint8_t *nonce, size_t noncelen,
                             const uint8_t *ad, size_t adlen,
                             void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)tconn;
  return Curl_qc_decrypt(dest, destlen, ciphertext, ciphertextlen,
                         &conn->quic.hs_crypto_ctx, key, keylen,
                         nonce, noncelen, ad, adlen);
}


static ssize_t cb_encrypt_data(ngtcp2_conn *tconn,
                               uint8_t *dest, size_t destlen,
                               const uint8_t *plaintext, size_t plaintextlen,
                               const uint8_t *key, size_t keylen,
                               const uint8_t *nonce, size_t noncelen,
                               const uint8_t *ad, size_t adlen,
                               void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  ssize_t rc;
  (void)tconn;
  rc = Curl_qc_encrypt(dest, destlen, plaintext, plaintextlen,
                       &conn->quic.crypto_ctx,
                       key, keylen, nonce, noncelen, ad, adlen);
  if(rc < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  return rc;
}

static ssize_t
cb_decrypt_data(ngtcp2_conn *tconn,
                uint8_t *dest, size_t destlen,
                const uint8_t *ciphertext, size_t ciphertextlen,
                const uint8_t *key, size_t keylen,
                const uint8_t *nonce, size_t noncelen,
                const uint8_t *ad, size_t adlen,
                void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  ssize_t rc;
  (void)tconn;
  rc = Curl_qc_decrypt(dest, destlen, ciphertext, ciphertextlen,
                       &conn->quic.crypto_ctx,
                       key, keylen, nonce, noncelen, ad, adlen);
  if(rc < 0)
    return NGTCP2_ERR_TLS_DECRYPT;
  return rc;
}

static int cb_recv_stream_data(ngtcp2_conn *tconn, int64_t stream_id,
                               int fin, uint64_t offset,
                               const uint8_t *buf, size_t buflen,
                               void *user_data, void *stream_user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)fin;
  (void)offset;
  (void)stream_user_data;
  /* TODO: handle the data */
  infof(conn->data, "Received %ld bytes at %p\n", buflen, buf);
  ngtcp2_conn_extend_max_stream_offset(tconn, stream_id, buflen);
  ngtcp2_conn_extend_max_offset(tconn, buflen);
  return 0;
}

static int cb_acked_crypto_offset(ngtcp2_conn *tconn,
                                  uint64_t offset, size_t datalen,
                                  void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)conn;
  (void)tconn;
  (void)offset;
  (void)datalen;

  /* TODO: uhm... what should it do? */

  return 0;
}

static int
cb_acked_stream_data_offset(ngtcp2_conn *tconn, int64_t stream_id,
                            uint64_t offset, size_t datalen, void *user_data,
                            void *stream_user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)conn;
  (void)stream_id;
  (void)tconn;
  (void)offset;
  (void)datalen;
  (void)stream_user_data;

  /* TODO: implement */

  return 0;
}

static int cb_stream_close(ngtcp2_conn *tconn, int64_t stream_id,
                           uint16_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)conn;
  (void)tconn;
  (void)stream_id;
  (void)app_error_code;
  (void)stream_user_data;
  /* stream is closed... */

  return 0;
}

static int cb_recv_retry(ngtcp2_conn *tconn, const ngtcp2_pkt_hd *hd,
                         const ngtcp2_pkt_retry *retry, void *user_data)
{
  /* Re-generate handshake secrets here because connection ID might change. */
  struct connectdata *conn = (struct connectdata *)user_data;
  (void)tconn;
  (void)hd;
  (void)retry;

  quic_init_ssl(conn);
  setup_initial_crypto_context(conn);

  return 0;
}

static ssize_t cb_in_hp_mask(ngtcp2_conn *tconn, uint8_t *dest, size_t destlen,
                             const uint8_t *key, size_t keylen,
                             const uint8_t *sample, size_t samplelen,
                             void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  ssize_t nwrite;
  (void)tconn;

  nwrite = Curl_qc_hp_mask(dest, destlen, &conn->quic.hs_crypto_ctx,
                           key, keylen, sample, samplelen);
  if(nwrite < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return nwrite;
}

static ssize_t cb_hp_mask(ngtcp2_conn *tconn, uint8_t *dest, size_t destlen,
                          const uint8_t *key, size_t keylen,
                          const uint8_t *sample, size_t samplelen,
                          void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  ssize_t nwrite;
  (void)tconn;

  nwrite = Curl_qc_hp_mask(dest, destlen, &conn->quic.crypto_ctx,
                           key, keylen, sample, samplelen);
  if(nwrite < 0)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return nwrite;
}

static int cb_extend_max_streams_bidi(ngtcp2_conn *tconn, uint64_t max_streams,
                                      void *user_data)
{
  /* struct connectdata *conn = (struct connectdata *)user_data; */
  (void)tconn;
  (void)max_streams;
  (void)user_data;
  return 0;
}

static int cb_get_new_connection_id(ngtcp2_conn *tconn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data)
{
  struct connectdata *conn = (struct connectdata *)user_data;
  CURLcode result;
  (void)tconn;

  result = Curl_rand(conn->data, cid->data, cidlen);
  if(result)
    return 1;

  result = Curl_rand(conn->data, token, NGTCP2_STATELESS_RESET_TOKENLEN);
  if(result)
    return 1;

  return 0;
}

static void quic_callbacks(ngtcp2_conn_callbacks *c)
{
  memset(c, 0, sizeof(ngtcp2_conn_callbacks));
  c->client_initial = cb_initial;
  /* recv_client_initial = NULL */
  c->recv_crypto_data = cb_recv_crypto_data;
  c->handshake_completed = cb_handshake_completed;
  /* recv_version_negotiation = NULL */
  c->in_encrypt = cb_in_encrypt;
  c->in_decrypt = cb_in_decrypt;
  c->encrypt = cb_encrypt_data;
  c->decrypt = cb_decrypt_data;
  c->in_hp_mask = cb_in_hp_mask;
  c->hp_mask = cb_hp_mask;
  c->recv_stream_data = cb_recv_stream_data;
  c->acked_crypto_offset = cb_acked_crypto_offset;
  c->acked_stream_data_offset = cb_acked_stream_data_offset;
  /* stream_open = NULL */
  c->stream_close = cb_stream_close;
  /* recv_stateless_reset = NULL */
  c->recv_retry = cb_recv_retry;
  c->extend_max_streams_bidi = cb_extend_max_streams_bidi;
  /* extend_max_streams_uni = NULL */
  /* rand = NULL */
  c->get_new_connection_id = cb_get_new_connection_id;
  /* remove_connection_id = NULL */
}


CURLcode Curl_quic_connect(struct connectdata *conn,
                           curl_socket_t sockfd,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  int rc;
  struct quicsocket *qs = &conn->quic;
  CURLcode result;
  ngtcp2_path path; /* TODO: this must be initialized properly */
  (void)sockfd;
  (void)addr;
  (void)addrlen;
  infof(conn->data, "Connecting socket %d over QUIC\n", sockfd);

  qs->sslctx = quic_ssl_ctx(conn->data);
  if(!qs->sslctx)
    return CURLE_FAILED_INIT; /* TODO: better return code */

  if(quic_init_ssl(conn))
    return CURLE_FAILED_INIT; /* TODO: better return code */

  qs->dcid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(conn->data, qs->dcid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  qs->scid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(conn->data, qs->scid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  quic_settings(&qs->settings);
  quic_callbacks(&qs->callbacks);

#ifdef NGTCP2_PROTO_VER_D18
#define QUICVER NGTCP2_PROTO_VER_D18
#else
#error "unsupported ngtcp2 version"
#endif
  rc = ngtcp2_conn_client_new(&qs->conn, &qs->dcid, &qs->scid,
                              &path,
                              QUICVER, &qs->callbacks, &qs->settings, conn);
  if(rc)
    return CURLE_FAILED_INIT; /* TODO: create a QUIC error code */

  rc = setup_initial_crypto_context(conn);
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
  return msnprintf(p, len, " ngtcp2/blabla");
}

CURLcode Curl_quic_is_connected(struct connectdata *conn, int sockindex,
                                bool *done)
{
  (void)conn;
  (void)sockindex;
  *done = FALSE;
  return CURLE_OK;
}
#endif
