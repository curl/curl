/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Jacob Hoffman-Andrews,
 * <github@hoffman-andrews.com>
 * Copyright (C) kpcyrd, <kpcyrd@archlinux.org>
 * Copyright (C) Daniel McCarney, <daniel@binaryparadox.net>
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

#ifdef USE_RUSTLS

#include "../curl_printf.h"

#include <rustls.h>

#include "../curlx/inet_pton.h"
#include "../urldata.h"
#include "../sendf.h"
#include "vtls.h"
#include "vtls_int.h"
#include "rustls.h"
#include "keylog.h"
#include "../strerror.h"
#include "cipher_suite.h"
#include "x509asn1.h"

struct rustls_ssl_backend_data
{
  const struct rustls_client_config *config;
  struct rustls_connection *conn;
  size_t plain_out_buffered;
  BIT(data_in_pending);
  BIT(sent_shutdown);
};

/* For a given rustls_result error code, return the best-matching CURLcode. */
static CURLcode map_error(const rustls_result r)
{
  if(rustls_result_is_cert_error(r)) {
    return CURLE_PEER_FAILED_VERIFICATION;
  }
  switch(r) {
    case RUSTLS_RESULT_OK:
      return CURLE_OK;
    case RUSTLS_RESULT_NULL_PARAMETER:
      return CURLE_BAD_FUNCTION_ARGUMENT;
    default:
      return CURLE_RECV_ERROR;
  }
}

static void
rustls_failf(struct Curl_easy *data, const rustls_result rr, const char *msg)
{
  char errorbuf[STRERROR_LEN];
  size_t errorlen;
  rustls_error(rr, errorbuf, sizeof(errorbuf), &errorlen);
  failf(data, "%s: %.*s", msg, (int)errorlen, errorbuf);
}

static bool
cr_data_pending(struct Curl_cfilter *cf, const struct Curl_easy *data)
{
  const struct ssl_connect_data *ctx = cf->ctx;
  struct rustls_ssl_backend_data *backend;

  (void)data;
  DEBUGASSERT(ctx && ctx->backend);
  backend = (struct rustls_ssl_backend_data *)ctx->backend;
  return backend->data_in_pending;
}

struct io_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
};

static int
read_cb(void *userdata, uint8_t *buf, uintptr_t len, uintptr_t *out_n)
{
  const struct io_ctx *io_ctx = userdata;
  struct ssl_connect_data *const connssl = io_ctx->cf->ctx;
  CURLcode result;
  int ret = 0;
  ssize_t nread = Curl_conn_cf_recv(io_ctx->cf->next, io_ctx->data,
                                    (char *)buf, len, &result);
  if(nread < 0) {
    nread = 0;
    /* !checksrc! disable ERRNOVAR 4 */
    if(CURLE_AGAIN == result)
      ret = EAGAIN;
    else
      ret = EINVAL;
  }
  else if(nread == 0)
    connssl->peer_closed = TRUE;
  *out_n = (uintptr_t)nread;
  CURL_TRC_CF(io_ctx->data, io_ctx->cf, "cf->next recv(len=%zu) -> %zd, %d",
              len, nread, result);
  return ret;
}

static int
write_cb(void *userdata, const uint8_t *buf, uintptr_t len, uintptr_t *out_n)
{
  const struct io_ctx *io_ctx = userdata;
  CURLcode result;
  int ret = 0;
  ssize_t nwritten = Curl_conn_cf_send(io_ctx->cf->next, io_ctx->data,
                                       (const char *)buf, len, FALSE,
                                       &result);
  if(nwritten < 0) {
    nwritten = 0;
    if(CURLE_AGAIN == result)
      ret = EAGAIN;
    else
      ret = EINVAL;
  }
  *out_n = (uintptr_t)nwritten;
  CURL_TRC_CF(io_ctx->data, io_ctx->cf, "cf->next send(len=%zu) -> %zd, %d",
              len, nwritten, result);
  return ret;
}

static ssize_t tls_recv_more(struct Curl_cfilter *cf,
                             struct Curl_easy *data, CURLcode *err)
{
  const struct ssl_connect_data *const connssl = cf->ctx;
  struct rustls_ssl_backend_data *const backend =
    (struct rustls_ssl_backend_data *)connssl->backend;
  struct io_ctx io_ctx;
  size_t tls_bytes_read = 0;
  rustls_io_result io_error;
  rustls_result rresult = 0;

  io_ctx.cf = cf;
  io_ctx.data = data;
  io_error = rustls_connection_read_tls(backend->conn, read_cb, &io_ctx,
                                        &tls_bytes_read);
  if(io_error == EAGAIN || io_error == EWOULDBLOCK) {
    *err = CURLE_AGAIN;
    return -1;
  }
  else if(io_error) {
    char buffer[STRERROR_LEN];
    failf(data, "reading from socket: %s",
          Curl_strerror(io_error, buffer, sizeof(buffer)));
    *err = CURLE_RECV_ERROR;
    return -1;
  }

  rresult = rustls_connection_process_new_packets(backend->conn);
  if(rresult != RUSTLS_RESULT_OK) {
    rustls_failf(data, rresult, "rustls_connection_process_new_packets");
    *err = map_error(rresult);
    return -1;
  }

  backend->data_in_pending = TRUE;
  *err = CURLE_OK;
  return (ssize_t)tls_bytes_read;
}

/*
 * On each run:
 *  - Read a chunk of bytes from the socket into Rustls' TLS input buffer.
 *  - Tell Rustls to process any new packets.
 *  - Read out as many plaintext bytes from Rustls as possible, until hitting
 *    error, EOF, or EAGAIN/EWOULDBLOCK, or plainbuf/plainlen is filled up.
 *
 * it is okay to call this function with plainbuf == NULL and plainlen == 0. In
 * that case, it will copy bytes from the socket into Rustls' TLS input
 * buffer, and process packets, but will not consume bytes from Rustls'
 * plaintext output buffer.
 */
static ssize_t
cr_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
            char *plainbuf, size_t plainlen, CURLcode *err)
{
  const struct ssl_connect_data *const connssl = cf->ctx;
  struct rustls_ssl_backend_data *const backend =
    (struct rustls_ssl_backend_data *)connssl->backend;
  struct rustls_connection *rconn = NULL;
  size_t n = 0;
  size_t plain_bytes_copied = 0;
  rustls_result rresult = 0;
  ssize_t nread;
  bool eof = FALSE;

  DEBUGASSERT(backend);
  rconn = backend->conn;

  while(plain_bytes_copied < plainlen) {
    if(!backend->data_in_pending) {
      if(tls_recv_more(cf, data, err) < 0) {
        if(*err != CURLE_AGAIN) {
          nread = -1;
          goto out;
        }
        break;
      }
    }

    rresult = rustls_connection_read(rconn,
                                     (uint8_t *)plainbuf + plain_bytes_copied,
                                     plainlen - plain_bytes_copied,
                                     &n);
    if(rresult == RUSTLS_RESULT_PLAINTEXT_EMPTY) {
      backend->data_in_pending = FALSE;
    }
    else if(rresult == RUSTLS_RESULT_UNEXPECTED_EOF) {
      failf(data, "rustls: peer closed TCP connection "
            "without first closing TLS connection");
      *err = CURLE_RECV_ERROR;
      nread = -1;
      goto out;
    }
    else if(rresult != RUSTLS_RESULT_OK) {
      /* n always equals 0 in this case, do not need to check it */
      rustls_failf(data, rresult, "rustls_connection_read");
      *err = CURLE_RECV_ERROR;
      nread = -1;
      goto out;
    }
    else if(n == 0) {
      /* n == 0 indicates clean EOF, but we may have read some other
         plaintext bytes before we reached this. Break out of the loop
         so we can figure out whether to return success or EOF. */
      eof = TRUE;
      break;
    }
    else {
      plain_bytes_copied += n;
    }
  }

  if(plain_bytes_copied) {
    *err = CURLE_OK;
    nread = (ssize_t)plain_bytes_copied;
  }
  else if(eof) {
    *err = CURLE_OK;
    nread = 0;
  }
  else {
    *err = CURLE_AGAIN;
    nread = -1;
  }

out:
  CURL_TRC_CF(data, cf, "cf_recv(len=%zu) -> %zd, %d",
              plainlen, nread, *err);
  return nread;
}

static CURLcode cr_flush_out(struct Curl_cfilter *cf, struct Curl_easy *data,
                             struct rustls_connection *rconn)
{
  struct io_ctx io_ctx;
  rustls_io_result io_error;
  size_t tlswritten = 0;
  size_t tlswritten_total = 0;

  io_ctx.cf = cf;
  io_ctx.data = data;

  while(rustls_connection_wants_write(rconn)) {
    io_error = rustls_connection_write_tls(rconn, write_cb, &io_ctx,
                                           &tlswritten);
    if(io_error == EAGAIN || io_error == EWOULDBLOCK) {
      CURL_TRC_CF(data, cf, "cf_send: EAGAIN after %zu bytes",
                  tlswritten_total);
      return CURLE_AGAIN;
    }
    else if(io_error) {
      char buffer[STRERROR_LEN];
      failf(data, "writing to socket: %s",
            Curl_strerror(io_error, buffer, sizeof(buffer)));
      return CURLE_SEND_ERROR;
    }
    if(tlswritten == 0) {
      failf(data, "EOF in swrite");
      return CURLE_SEND_ERROR;
    }
    CURL_TRC_CF(data, cf, "cf_send: wrote %zu TLS bytes", tlswritten);
    tlswritten_total += tlswritten;
  }
  return CURLE_OK;
}

/*
 * On each call:
 *  - Copy `plainlen` bytes into Rustls' plaintext input buffer (if > 0).
 *  - Fully drain Rustls' plaintext output buffer into the socket until
 *    we get either an error or EAGAIN/EWOULDBLOCK.
 *
 * it is okay to call this function with plainbuf == NULL and plainlen == 0.
 * In that case, it will not read anything into Rustls' plaintext input buffer.
 * It will only drain Rustls' plaintext output buffer into the socket.
 */
static ssize_t
cr_send(struct Curl_cfilter *cf, struct Curl_easy *data,
        const void *plainbuf, size_t plainlen, CURLcode *err)
{
  const struct ssl_connect_data *const connssl = cf->ctx;
  struct rustls_ssl_backend_data *const backend =
    (struct rustls_ssl_backend_data *)connssl->backend;
  struct rustls_connection *rconn = NULL;
  size_t plainwritten = 0;
  const unsigned char *buf = plainbuf;
  size_t blen = plainlen;
  ssize_t nwritten = 0;

  DEBUGASSERT(backend);
  rconn = backend->conn;
  DEBUGASSERT(rconn);

  CURL_TRC_CF(data, cf, "cf_send(len=%zu)", plainlen);

  /* If a previous send blocked, we already added its plain bytes
   * to rustsls and must not do that again. Flush the TLS bytes and,
   * if successful, deduct the previous plain bytes from the current
   * send. */
  if(backend->plain_out_buffered) {
    *err = cr_flush_out(cf, data, rconn);
    CURL_TRC_CF(data, cf, "cf_send: flushing %zu previously added bytes -> %d",
                backend->plain_out_buffered, *err);
    if(*err)
      return -1;
    if(blen > backend->plain_out_buffered) {
      blen -= backend->plain_out_buffered;
      buf += backend->plain_out_buffered;
    }
    else
      blen = 0;
    nwritten += (ssize_t)backend->plain_out_buffered;
    backend->plain_out_buffered = 0;
  }

  if(blen > 0) {
    rustls_result rresult;
    CURL_TRC_CF(data, cf, "cf_send: adding %zu plain bytes to Rustls", blen);
    rresult = rustls_connection_write(rconn, buf, blen, &plainwritten);
    if(rresult != RUSTLS_RESULT_OK) {
      rustls_failf(data, rresult, "rustls_connection_write");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }
    else if(plainwritten == 0) {
      failf(data, "rustls_connection_write: EOF");
      *err = CURLE_WRITE_ERROR;
      return -1;
    }
  }

  *err = cr_flush_out(cf, data, rconn);
  if(*err) {
    if(CURLE_AGAIN == *err) {
      /* The TLS bytes may have been partially written, but we fail the
       * complete send() and remember how much we already added to Rustls. */
      CURL_TRC_CF(data, cf, "cf_send: EAGAIN, remember we added %zu plain"
                  " bytes already to Rustls", blen);
      backend->plain_out_buffered = plainwritten;
      if(nwritten) {
        *err = CURLE_OK;
        return (ssize_t)nwritten;
      }
    }
    return -1;
  }
  else
    nwritten += (ssize_t)plainwritten;

  CURL_TRC_CF(data, cf, "cf_send(len=%zu) -> %d, %zd",
              plainlen, *err, nwritten);
  return nwritten;
}

/* A server certificate verify callback for Rustls that always returns
   RUSTLS_RESULT_OK, or in other words disable certificate verification. */
static uint32_t
cr_verify_none(void *userdata UNUSED_PARAM,
               const rustls_verify_server_cert_params *params UNUSED_PARAM)
{
  return RUSTLS_RESULT_OK;
}

static int
read_file_into(const char *filename,
               struct dynbuf *out)
{
  FILE *f = fopen(filename, FOPEN_READTEXT);
  if(!f) {
    return 0;
  }

  while(!feof(f)) {
    uint8_t buf[256];
    const size_t rr = fread(buf, 1, sizeof(buf), f);
    if(rr == 0 ||
       CURLE_OK != curlx_dyn_addn(out, buf, rr)) {
      fclose(f);
      return 0;
    }
  }

  return fclose(f) == 0;
}

static void
cr_get_selected_ciphers(struct Curl_easy *data,
                        const char *ciphers12,
                        const char *ciphers13,
                        const struct rustls_supported_ciphersuite **selected,
                        size_t *selected_size)
{
  const size_t supported_len = *selected_size;
  const size_t default_len = rustls_default_crypto_provider_ciphersuites_len();
  const struct rustls_supported_ciphersuite *entry;
  const char *ciphers = ciphers12;
  size_t count = 0, default13_count = 0, i, j;
  const char *ptr, *end;

  DEBUGASSERT(default_len <= supported_len);

  if(!ciphers13) {
    /* Add default TLSv1.3 ciphers to selection */
    for(j = 0; j < default_len; j++) {
      entry = rustls_default_crypto_provider_ciphersuites_get(j);
      if(rustls_supported_ciphersuite_protocol_version(entry) !=
         RUSTLS_TLS_VERSION_TLSV1_3)
        continue;

      selected[count++] = entry;
    }

    default13_count = count;

    if(!ciphers)
      ciphers = "";
  }
  else
    ciphers = ciphers13;

add_ciphers:
  for(ptr = ciphers; ptr[0] != '\0' && count < supported_len; ptr = end) {
    uint16_t id = Curl_cipher_suite_walk_str(&ptr, &end);

    /* Check if cipher is supported */
    if(id) {
      for(i = 0; i < supported_len; i++) {
        entry = rustls_default_crypto_provider_ciphersuites_get(i);
        if(rustls_supported_ciphersuite_get_suite(entry) == id)
          break;
      }
      if(i == supported_len)
        id = 0;
    }
    if(!id) {
      if(ptr[0] != '\0')
        infof(data, "rustls: unknown cipher in list: \"%.*s\"",
              (int) (end - ptr), ptr);
      continue;
    }

    /* No duplicates allowed (so selected cannot overflow) */
    for(i = 0; i < count && selected[i] != entry; i++);
    if(i < count) {
      if(i >= default13_count)
        infof(data, "rustls: duplicate cipher in list: \"%.*s\"",
              (int) (end - ptr), ptr);
      continue;
    }

    selected[count++] = entry;
  }

  if(ciphers == ciphers13 && ciphers12) {
    ciphers = ciphers12;
    goto add_ciphers;
  }

  if(!ciphers12) {
    /* Add default TLSv1.2 ciphers to selection */
    for(j = 0; j < default_len; j++) {
      entry = rustls_default_crypto_provider_ciphersuites_get(j);
      if(rustls_supported_ciphersuite_protocol_version(entry) ==
          RUSTLS_TLS_VERSION_TLSV1_3)
        continue;

      /* No duplicates allowed (so selected cannot overflow) */
      for(i = 0; i < count && selected[i] != entry; i++);
      if(i < count)
        continue;

      selected[count++] = entry;
    }
  }

  *selected_size = count;
}

static void
cr_keylog_log_cb(struct rustls_str label,
                 const uint8_t *client_random, size_t client_random_len,
                 const uint8_t *secret, size_t secret_len)
{
  char clabel[KEYLOG_LABEL_MAXLEN];
  (void)client_random_len;
  DEBUGASSERT(client_random_len == CLIENT_RANDOM_SIZE);
  /* Turning a "rustls_str" into a null delimited "c" string */
  msnprintf(clabel, label.len + 1, "%.*s", (int)label.len, label.data);
  Curl_tls_keylog_write(clabel, client_random, secret, secret_len);
}

static CURLcode
init_config_builder(struct Curl_easy *data,
                    const struct ssl_primary_config *conn_config,
                    struct rustls_client_config_builder **config_builder)
{
  const struct rustls_supported_ciphersuite **cipher_suites = NULL;
  struct rustls_crypto_provider_builder *custom_provider_builder = NULL;
  const struct rustls_crypto_provider *custom_provider = NULL;

  uint16_t tls_versions[2] = {
      RUSTLS_TLS_VERSION_TLSV1_2,
      RUSTLS_TLS_VERSION_TLSV1_3,
  };
  size_t tls_versions_len = 2;
  size_t cipher_suites_len =
    rustls_default_crypto_provider_ciphersuites_len();

  CURLcode result = CURLE_OK;
  rustls_result rr;

  switch(conn_config->version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
  case CURL_SSLVERSION_TLSv1_2:
    break;
  case CURL_SSLVERSION_TLSv1_3:
    tls_versions[0] = RUSTLS_TLS_VERSION_TLSV1_3;
    tls_versions_len = 1;
    break;
  default:
    failf(data, "rustls: unsupported minimum TLS version value");
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto cleanup;
  }

  switch(conn_config->version_max) {
  case CURL_SSLVERSION_MAX_DEFAULT:
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_TLSv1_3:
    break;
  case CURL_SSLVERSION_MAX_TLSv1_2:
    if(tls_versions[0] == RUSTLS_TLS_VERSION_TLSV1_2) {
      tls_versions_len = 1;
      break;
    }
    FALLTHROUGH();
  case CURL_SSLVERSION_MAX_TLSv1_1:
  case CURL_SSLVERSION_MAX_TLSv1_0:
  default:
    failf(data, "rustls: unsupported maximum TLS version value");
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto cleanup;
  }

#if defined(USE_ECH)
  if(ECH_ENABLED(data)) {
    tls_versions[0] = RUSTLS_TLS_VERSION_TLSV1_3;
    tls_versions_len = 1;
    infof(data, "rustls: ECH enabled, forcing TLSv1.3");
  }
#endif /* USE_ECH */

  cipher_suites = malloc(sizeof(cipher_suites) * (cipher_suites_len));
  if(!cipher_suites) {
    result = CURLE_OUT_OF_MEMORY;
    goto cleanup;
  }

  cr_get_selected_ciphers(data,
                          conn_config->cipher_list,
                          conn_config->cipher_list13,
                          cipher_suites, &cipher_suites_len);
  if(cipher_suites_len == 0) {
    failf(data, "rustls: no supported cipher in list");
    result = CURLE_SSL_CIPHER;
    goto cleanup;
  }

  rr = rustls_crypto_provider_builder_new_from_default(
    &custom_provider_builder);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr,
      "failed to create crypto provider builder from default");
    result = CURLE_SSL_CIPHER;
    goto cleanup;
  }

  rr =
    rustls_crypto_provider_builder_set_cipher_suites(
      custom_provider_builder,
      cipher_suites,
      cipher_suites_len);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr,
      "failed to set ciphersuites for crypto provider builder");
    result = CURLE_SSL_CIPHER;
    goto cleanup;
  }

  rr = rustls_crypto_provider_builder_build(
    custom_provider_builder, &custom_provider);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "failed to build custom crypto provider");
    result = CURLE_SSL_CIPHER;
    goto cleanup;
  }

  rr = rustls_client_config_builder_new_custom(custom_provider,
                                                     tls_versions,
                                                     tls_versions_len,
                                                     config_builder);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "failed to create client config builder");
    result = CURLE_SSL_CIPHER;
    goto cleanup;
  }

cleanup:
  if(cipher_suites) {
    free(cipher_suites);
  }
  if(custom_provider_builder) {
    rustls_crypto_provider_builder_free(custom_provider_builder);
  }
  if(custom_provider) {
    rustls_crypto_provider_free(custom_provider);
  }
  return result;
}

static void
init_config_builder_alpn(struct Curl_easy *data,
                         const struct ssl_connect_data *connssl,
                         struct rustls_client_config_builder *config_builder) {
  struct alpn_proto_buf proto;
  rustls_slice_bytes alpn[ALPN_ENTRIES_MAX];
  size_t i;

  for(i = 0; i < connssl->alpn->count; ++i) {
    alpn[i].data = (const uint8_t *)connssl->alpn->entries[i];
    alpn[i].len = strlen(connssl->alpn->entries[i]);
  }
  rustls_client_config_builder_set_alpn_protocols(config_builder, alpn,
                                                  connssl->alpn->count);
  Curl_alpn_to_proto_str(&proto, connssl->alpn);
  infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
}

static CURLcode
init_config_builder_verifier_crl(
  struct Curl_easy *data,
  const struct ssl_primary_config *conn_config,
  struct rustls_web_pki_server_cert_verifier_builder *builder)
{
  CURLcode result = CURLE_OK;
  struct dynbuf crl_contents;
  rustls_result rr;

  curlx_dyn_init(&crl_contents, DYN_CRLFILE_SIZE);
  if(!read_file_into(conn_config->CRLfile, &crl_contents)) {
    failf(data, "rustls: failed to read revocation list file");
    result = CURLE_SSL_CRL_BADFILE;
    goto cleanup;
  }

  rr = rustls_web_pki_server_cert_verifier_builder_add_crl(
    builder,
    curlx_dyn_uptr(&crl_contents),
    curlx_dyn_len(&crl_contents));
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "failed to parse revocation list");
    result = CURLE_SSL_CRL_BADFILE;
    goto cleanup;
  }

cleanup:
  curlx_dyn_free(&crl_contents);
  return result;
}

static CURLcode
init_config_builder_verifier(struct Curl_easy *data,
                             struct rustls_client_config_builder *builder,
                             const struct ssl_primary_config *conn_config,
                             const struct curl_blob *ca_info_blob,
                             const char * const ssl_cafile) {
  const struct rustls_root_cert_store *roots = NULL;
  struct rustls_root_cert_store_builder *roots_builder = NULL;
  struct rustls_web_pki_server_cert_verifier_builder *verifier_builder = NULL;
  struct rustls_server_cert_verifier *server_cert_verifier = NULL;
  rustls_result rr = RUSTLS_RESULT_OK;
  CURLcode result = CURLE_OK;

  roots_builder = rustls_root_cert_store_builder_new();
  if(ca_info_blob) {
    rr = rustls_root_cert_store_builder_add_pem(roots_builder,
                                                ca_info_blob->data,
                                                ca_info_blob->len,
                                                1);
    if(rr != RUSTLS_RESULT_OK) {
      rustls_failf(data, rr, "failed to parse trusted certificates from blob");

      result = CURLE_SSL_CACERT_BADFILE;
      goto cleanup;
    }
  }
  else if(ssl_cafile) {
    rr = rustls_root_cert_store_builder_load_roots_from_file(roots_builder,
                                                             ssl_cafile,
                                                             1);
    if(rr != RUSTLS_RESULT_OK) {
      rustls_failf(data, rr, "failed to load trusted certificates");

      result = CURLE_SSL_CACERT_BADFILE;
      goto cleanup;
    }
  }

  rr = rustls_root_cert_store_builder_build(roots_builder, &roots);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "failed to build trusted root certificate store");
    result = CURLE_SSL_CACERT_BADFILE;
  }

  verifier_builder = rustls_web_pki_server_cert_verifier_builder_new(roots);

  if(conn_config->CRLfile) {
    result = init_config_builder_verifier_crl(data,
                                             conn_config,
                                             verifier_builder);
    if(result != CURLE_OK) {
      goto cleanup;
    }
  }

  rr = rustls_web_pki_server_cert_verifier_builder_build(
    verifier_builder, &server_cert_verifier);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "failed to build certificate verifier");
    result = CURLE_SSL_CACERT_BADFILE;
    goto cleanup;
  }

  rustls_client_config_builder_set_server_verifier(builder,
                                                   server_cert_verifier);
cleanup:
  if(roots_builder) {
    rustls_root_cert_store_builder_free(roots_builder);
  }
  if(roots) {
    rustls_root_cert_store_free(roots);
  }
  if(verifier_builder) {
    rustls_web_pki_server_cert_verifier_builder_free(verifier_builder);
  }
  if(server_cert_verifier) {
    rustls_server_cert_verifier_free(server_cert_verifier);
  }

  return result;
}

static CURLcode
init_config_builder_platform_verifier(
  struct Curl_easy *data,
  struct rustls_client_config_builder *builder)
{
  struct rustls_server_cert_verifier *server_cert_verifier = NULL;
  CURLcode result = CURLE_OK;
  rustls_result rr;

  rr = rustls_platform_server_cert_verifier(&server_cert_verifier);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "failed to create platform certificate verifier");
    result = CURLE_SSL_CACERT_BADFILE;
    goto cleanup;
  }

  rustls_client_config_builder_set_server_verifier(builder,
                                                   server_cert_verifier);

cleanup:
  if(server_cert_verifier) {
    rustls_server_cert_verifier_free(server_cert_verifier);
  }
  return result;
}

static CURLcode
init_config_builder_keylog(struct Curl_easy *data,
                           struct rustls_client_config_builder *builder)
{
  rustls_result rr;

  Curl_tls_keylog_open();
  if(!Curl_tls_keylog_enabled()) {
    return CURLE_OK;
  }

  rr = rustls_client_config_builder_set_key_log(builder,
                                                cr_keylog_log_cb,
                                                NULL);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "rustls_client_config_builder_set_key_log");
    Curl_tls_keylog_close();
    return map_error(rr);
  }

  return CURLE_OK;
}

static CURLcode
init_config_builder_client_auth(struct Curl_easy *data,
                                const struct ssl_primary_config *conn_config,
                                const struct ssl_config_data *ssl_config,
                                struct rustls_client_config_builder *builder)
{
  struct dynbuf cert_contents;
  struct dynbuf key_contents;
  rustls_result rr;
  const struct rustls_certified_key *certified_key = NULL;
  CURLcode result = CURLE_OK;

  if(conn_config->clientcert && !ssl_config->key) {
    failf(data, "rustls: must provide key with certificate '%s'",
          conn_config->clientcert);
    return CURLE_SSL_CERTPROBLEM;
  }
  else if(!conn_config->clientcert && ssl_config->key) {
    failf(data, "rustls: must provide certificate with key '%s'",
          conn_config->clientcert);
    return CURLE_SSL_CERTPROBLEM;
  }

  curlx_dyn_init(&cert_contents, DYN_CERTFILE_SIZE);
  curlx_dyn_init(&key_contents, DYN_KEYFILE_SIZE);

  if(!read_file_into(conn_config->clientcert, &cert_contents)) {
    failf(data, "rustls: failed to read client certificate file: '%s'",
          conn_config->clientcert);
    result = CURLE_SSL_CERTPROBLEM;
    goto cleanup;
  }

  if(!read_file_into(ssl_config->key, &key_contents)) {
    failf(data, "rustls: failed to read key file: '%s'", ssl_config->key);
    result = CURLE_SSL_CERTPROBLEM;
    goto cleanup;
  }

  rr = rustls_certified_key_build(curlx_dyn_uptr(&cert_contents),
                                  curlx_dyn_len(&cert_contents),
                                  curlx_dyn_uptr(&key_contents),
                                  curlx_dyn_len(&key_contents),
                                  &certified_key);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "rustls: failed to build certified key");
    result = CURLE_SSL_CERTPROBLEM;
    goto cleanup;
  }

  rr = rustls_certified_key_keys_match(certified_key);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data,
                 rr,
                 "rustls: client certificate and keypair files do not match:");

    result = CURLE_SSL_CERTPROBLEM;
    goto cleanup;
  }

  rr = rustls_client_config_builder_set_certified_key(builder,
                                                      &certified_key,
                                                      1);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "rustls: failed to set certified key");
    result = CURLE_SSL_CERTPROBLEM;
    goto cleanup;
  }

cleanup:
  curlx_dyn_free(&cert_contents);
  curlx_dyn_free(&key_contents);
  if(certified_key) {
    rustls_certified_key_free(certified_key);
  }
  return result;
}

#if defined(USE_ECH)
static CURLcode
init_config_builder_ech(struct Curl_easy *data,
                        const struct ssl_connect_data *connssl,
                        struct rustls_client_config_builder *builder)
{
  const rustls_hpke *hpke = rustls_supported_hpke();
  unsigned char *ech_config = NULL;
  size_t ech_config_len = 0;
  struct Curl_dns_entry *dns = NULL;
  struct Curl_https_rrinfo *rinfo = NULL;
  CURLcode result = CURLE_OK;
  rustls_result rr;

  if(!hpke) {
    failf(data,
          "rustls: ECH unavailable, rustls-ffi built without "
          "HPKE compatible crypto provider");
    result = CURLE_SSL_CONNECT_ERROR;
    goto cleanup;
  }

  if(data->set.str[STRING_ECH_PUBLIC]) {
    failf(data, "rustls: ECH outername not supported");
    result = CURLE_SSL_CONNECT_ERROR;
    goto cleanup;
  }

  if(data->set.tls_ech == CURLECH_GREASE) {
    rr = rustls_client_config_builder_enable_ech_grease(builder, hpke);
    if(rr != RUSTLS_RESULT_OK) {
      rustls_failf(data, rr, "rustls: failed to configure ECH GREASE");
      result = CURLE_SSL_CONNECT_ERROR;
      goto cleanup;
    }
    return CURLE_OK;
  }

  if(data->set.tls_ech & CURLECH_CLA_CFG && data->set.str[STRING_ECH_CONFIG]) {
    const char *b64 = data->set.str[STRING_ECH_CONFIG];
    size_t decode_result;
    if(!b64) {
      infof(data, "rustls: ECHConfig from command line empty");
      result = CURLE_SSL_CONNECT_ERROR;
      goto cleanup;
    }
    /* rustls-ffi expects the raw TLS encoded ECHConfigList bytes */
    decode_result = curlx_base64_decode(b64, &ech_config, &ech_config_len);
    if(decode_result || !ech_config) {
      infof(data, "rustls: cannot base64 decode ECHConfig from command line");
      result = CURLE_SSL_CONNECT_ERROR;
      goto cleanup;
    }
  }
  else {
    if(connssl->peer.hostname) {
      dns = Curl_dnscache_get(data, connssl->peer.hostname,
                              connssl->peer.port, data->conn->ip_version);
    }
    if(!dns) {
      failf(data, "rustls: ECH requested but no DNS info available");
      result = CURLE_SSL_CONNECT_ERROR;
      goto cleanup;
    }
    rinfo = dns->hinfo;
    if(!rinfo || !rinfo->echconfiglist) {
      failf(data, "rustls: ECH requested but no ECHConfig available");
      result = CURLE_SSL_CONNECT_ERROR;
      goto cleanup;
    }
    ech_config = rinfo->echconfiglist;
    ech_config_len = rinfo->echconfiglist_len;
  }

  rr = rustls_client_config_builder_enable_ech(builder,
                                               ech_config,
                                               ech_config_len,
                                               hpke);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "rustls: failed to configure ECH");
    result = CURLE_SSL_CONNECT_ERROR;
    goto cleanup;
  }
cleanup:
  /* if we base64 decoded, we can free now */
  if(data->set.tls_ech & CURLECH_CLA_CFG && data->set.str[STRING_ECH_CONFIG]) {
    free(ech_config);
  }
  if(dns) {
    Curl_resolv_unlink(data, &dns);
  }
  return result;
}
#endif /* USE_ECH */

static CURLcode
cr_init_backend(struct Curl_cfilter *cf, struct Curl_easy *data,
                struct rustls_ssl_backend_data *const backend)
{
  const struct ssl_connect_data *connssl = cf->ctx;
  const struct ssl_primary_config *conn_config =
    Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct rustls_connection *rconn = NULL;
  struct rustls_client_config_builder *config_builder = NULL;

  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ca_info_blob ? NULL : conn_config->CAfile);
  CURLcode result = CURLE_OK;
  rustls_result rr;

  DEBUGASSERT(backend);
  rconn = backend->conn;

  result = init_config_builder(data, conn_config, &config_builder);
  if(result != CURLE_OK) {
    return result;
  }

  if(connssl->alpn) {
    init_config_builder_alpn(data, connssl, config_builder);
  }

  if(!conn_config->verifypeer) {
    rustls_client_config_builder_dangerous_set_certificate_verifier(
      config_builder, cr_verify_none);
  }
  else if(ssl_config->native_ca_store) {
    result = init_config_builder_platform_verifier(data, config_builder);
    if(result != CURLE_OK) {
      rustls_client_config_builder_free(config_builder);
      return result;
    }
  }
  else if(ca_info_blob || ssl_cafile) {
    result = init_config_builder_verifier(data,
                                          config_builder,
                                          conn_config,
                                          ca_info_blob,
                                          ssl_cafile);
    if(result != CURLE_OK) {
      rustls_client_config_builder_free(config_builder);
      return result;
    }
  }

  if(conn_config->clientcert || ssl_config->key) {
    result = init_config_builder_client_auth(data,
                                             conn_config,
                                             ssl_config,
                                             config_builder);
    if(result != CURLE_OK) {
      rustls_client_config_builder_free(config_builder);
      return result;
    }
  }

#if defined(USE_ECH)
  if(ECH_ENABLED(data)) {
    result = init_config_builder_ech(data, connssl, config_builder);
    if(result != CURLE_OK && data->set.tls_ech & CURLECH_HARD) {
      rustls_client_config_builder_free(config_builder);
      return result;
    }
  }
#endif /* USE_ECH */

  result = init_config_builder_keylog(data, config_builder);
  if(result != CURLE_OK) {
    rustls_client_config_builder_free(config_builder);
    return result;
  }

  rr = rustls_client_config_builder_build(
    config_builder,
    &backend->config);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, rr, "failed to build client config");
    rustls_client_config_builder_free(config_builder);
    rustls_client_config_free(backend->config);
    return CURLE_SSL_CONNECT_ERROR;
  }

  DEBUGASSERT(rconn == NULL);
  rr = rustls_client_connection_new(backend->config,
                                    connssl->peer.hostname,
                                    &rconn);
  if(rr != RUSTLS_RESULT_OK) {
    rustls_failf(data, result, "rustls_client_connection_new");
    return CURLE_COULDNT_CONNECT;
  }
  DEBUGASSERT(rconn);
  rustls_connection_set_userdata(rconn, backend);
  backend->conn = rconn;

  return result;
}

static void
cr_set_negotiated_alpn(struct Curl_cfilter *cf, struct Curl_easy *data,
  const struct rustls_connection *rconn)
{
  struct ssl_connect_data *const connssl = cf->ctx;
  const uint8_t *protocol = NULL;
  size_t len = 0;

  rustls_connection_get_alpn_protocol(rconn, &protocol, &len);
  Curl_alpn_set_negotiated(cf, data, connssl, protocol, len);
}

/* Given an established network connection, do a TLS handshake.
 *
 * This function will set `*done` to true once the handshake is complete.
 * This function never reads the value of `*done*`.
 */
static CURLcode
cr_connect(struct Curl_cfilter *cf,
           struct Curl_easy *data, bool *done)
{
  struct ssl_connect_data *const connssl = cf->ctx;
  const struct rustls_ssl_backend_data *const backend =
    (struct rustls_ssl_backend_data *)connssl->backend;
  const struct rustls_connection *rconn = NULL;
  CURLcode tmperr = CURLE_OK;
  int result;
  bool wants_read;
  bool wants_write;

  DEBUGASSERT(backend);

  CURL_TRC_CF(data, cf, "cr_connect, state=%d", connssl->state);
  *done = FALSE;

  if(!backend->conn) {
    result = cr_init_backend(cf, data,
               (struct rustls_ssl_backend_data *)connssl->backend);
    CURL_TRC_CF(data, cf, "cr_connect, init backend -> %d", result);
    if(result != CURLE_OK) {
      return result;
    }
    connssl->state = ssl_connection_negotiating;
  }
  rconn = backend->conn;

  /* Read/write data until the handshake is done or the socket would block. */
  for(;;) {
    /*
    * Connection has been established according to Rustls. Set send/recv
    * handlers, and update the state machine.
    */
    connssl->io_need = CURL_SSL_IO_NEED_NONE;
    if(!rustls_connection_is_handshaking(rconn)) {
      /* Rustls claims it is no longer handshaking *before* it has
       * send its FINISHED message off. We attempt to let it write
       * one more time. Oh my.
       */
      cr_set_negotiated_alpn(cf, data, rconn);
      cr_send(cf, data, NULL, 0, &tmperr);
      if(tmperr == CURLE_AGAIN) {
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        return CURLE_OK;
      }
      else if(tmperr != CURLE_OK) {
        return tmperr;
      }
      /* REALLY Done with the handshake. */
      {
        const uint16_t proto =
          rustls_connection_get_protocol_version(rconn);
        const uint16_t cipher =
          rustls_connection_get_negotiated_ciphersuite(rconn);
        char buf[64] = "";
        const char *ver = "TLS version unknown";
        if(proto == RUSTLS_TLS_VERSION_TLSV1_3)
          ver = "TLSv1.3";
        if(proto == RUSTLS_TLS_VERSION_TLSV1_2)
          ver = "TLSv1.2";
        Curl_cipher_suite_get_str(cipher, buf, sizeof(buf), TRUE);
        infof(data, "rustls: handshake complete, %s, cipher: %s",
              ver, buf);
      }
      if(data->set.ssl.certinfo) {
        size_t num_certs = 0;
        while(rustls_connection_get_peer_certificate(rconn, (int)num_certs)) {
          num_certs++;
        }
        result = Curl_ssl_init_certinfo(data, (int)num_certs);
        if(result)
          return result;
        for(size_t i = 0; i < num_certs; i++) {
          const rustls_certificate *cert;
          const unsigned char *der_data;
          size_t der_len;
          rustls_result rresult = RUSTLS_RESULT_OK;
          cert = rustls_connection_get_peer_certificate(rconn, i);
          DEBUGASSERT(cert); /* Should exist since we counted already */
          rresult = rustls_certificate_get_der(cert, &der_data, &der_len);
          if(rresult != RUSTLS_RESULT_OK) {
            char errorbuf[255];
            size_t errorlen;
            rustls_error(rresult, errorbuf, sizeof(errorbuf), &errorlen);
            failf(data,
              "Failed getting DER of server certificate #%ld: %.*s", i,
              (int)errorlen, errorbuf);
            return map_error(rresult);
          }
          {
            const char *beg;
            const char *end;
            beg = (const char *)der_data;
            end = (const char *)(der_data + der_len);
            result = Curl_extract_certinfo(data, (int)i, beg, end);
            if(result)
              return result;
          }
        }
      }

      connssl->state = ssl_connection_complete;
      *done = TRUE;
      return CURLE_OK;
    }

    connssl->connecting_state = ssl_connect_2;
    wants_read = rustls_connection_wants_read(rconn);
    wants_write = rustls_connection_wants_write(rconn) ||
                  backend->plain_out_buffered;
    DEBUGASSERT(wants_read || wants_write);

    if(wants_write) {
      CURL_TRC_CF(data, cf, "rustls_connection wants us to write_tls.");
      cr_send(cf, data, NULL, 0, &tmperr);
      if(tmperr == CURLE_AGAIN) {
        CURL_TRC_CF(data, cf, "writing would block");
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        return CURLE_OK;
      }
      else if(tmperr != CURLE_OK) {
        return tmperr;
      }
    }

    if(wants_read) {
      CURL_TRC_CF(data, cf, "rustls_connection wants us to read_tls.");
      if(tls_recv_more(cf, data, &tmperr) < 0) {
        if(tmperr == CURLE_AGAIN) {
          CURL_TRC_CF(data, cf, "reading would block");
          connssl->io_need = CURL_SSL_IO_NEED_RECV;
          return CURLE_OK;
        }
        else if(tmperr == CURLE_RECV_ERROR) {
          return CURLE_SSL_CONNECT_ERROR;
        }
        else {
          return tmperr;
        }
      }
    }
  }

  /* We should never fall through the loop. We should return either because
     the handshake is done or because we cannot read/write without blocking. */
  DEBUGASSERT(FALSE);
}

static void *
cr_get_internals(struct ssl_connect_data *connssl,
                 CURLINFO info UNUSED_PARAM)
{
  struct rustls_ssl_backend_data *backend =
    (struct rustls_ssl_backend_data *)connssl->backend;
  DEBUGASSERT(backend);
  return &backend->conn;
}

static CURLcode
cr_shutdown(struct Curl_cfilter *cf,
            struct Curl_easy *data,
            const bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct rustls_ssl_backend_data *backend =
    (struct rustls_ssl_backend_data *)connssl->backend;
  CURLcode result = CURLE_OK;
  ssize_t nwritten, nread;
  size_t i;

  DEBUGASSERT(backend);
  if(!backend->conn || cf->shutdown) {
    *done = TRUE;
    goto out;
  }

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  *done = FALSE;

  if(!backend->sent_shutdown) {
    /* do this only once */
    backend->sent_shutdown = TRUE;
    if(send_shutdown) {
      rustls_connection_send_close_notify(backend->conn);
    }
  }

  nwritten = cr_send(cf, data, NULL, 0, &result);
  if(nwritten < 0) {
    if(result == CURLE_AGAIN) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
      result = CURLE_OK;
      goto out;
    }
    DEBUGASSERT(result);
    CURL_TRC_CF(data, cf, "shutdown send failed: %d", result);
    goto out;
  }

  for(i = 0; i < 10; ++i) {
    char buf[1024];
    nread = cr_recv(cf, data, buf, (int)sizeof(buf), &result);
    if(nread <= 0)
      break;
  }

  if(nread > 0) {
    /* still data coming in? */
  }
  else if(nread == 0) {
    /* We got the close notify alert and are done. */
    *done = TRUE;
  }
  else if(result == CURLE_AGAIN) {
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    result = CURLE_OK;
  }
  else {
    DEBUGASSERT(result);
    CURL_TRC_CF(data, cf, "shutdown, error: %d", result);
  }

out:
  cf->shutdown = (result || *done);
  return result;
}

static void
cr_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  const struct ssl_connect_data *connssl = cf->ctx;
  struct rustls_ssl_backend_data *backend =
    (struct rustls_ssl_backend_data *)connssl->backend;

  (void)data;
  DEBUGASSERT(backend);
  if(backend->conn) {
    rustls_connection_free(backend->conn);
    backend->conn = NULL;
  }
  if(backend->config) {
    rustls_client_config_free(backend->config);
    backend->config = NULL;
  }
}

static size_t cr_version(char *buffer, size_t size)
{
  const struct rustls_str ver = rustls_version();
  return msnprintf(buffer, size, "%.*s", (int)ver.len, ver.data);
}

static CURLcode
cr_random(struct Curl_easy *data, unsigned char *entropy, size_t length)
{
  rustls_result rresult = 0;
  (void)data;
  rresult =
    rustls_default_crypto_provider_random(entropy, length);
  return map_error(rresult);
}

static void cr_cleanup(void)
{
  Curl_tls_keylog_close();
}

const struct Curl_ssl Curl_ssl_rustls = {
  { CURLSSLBACKEND_RUSTLS, "rustls" },
  SSLSUPP_CAINFO_BLOB |            /* supports */
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST |
  SSLSUPP_TLS13_CIPHERSUITES |
  SSLSUPP_CERTINFO |
  SSLSUPP_ECH,
  sizeof(struct rustls_ssl_backend_data),

  NULL,                            /* init */
  cr_cleanup,                      /* cleanup */
  cr_version,                      /* version */
  cr_shutdown,                     /* shutdown */
  cr_data_pending,                 /* data_pending */
  cr_random,                       /* random */
  NULL,                            /* cert_status_request */
  cr_connect,                      /* connect */
  Curl_ssl_adjust_pollset,         /* adjust_pollset */
  cr_get_internals,                /* get_internals */
  cr_close,                        /* close_one */
  NULL,                            /* close_all */
  NULL,                            /* set_engine */
  NULL,                            /* set_engine_default */
  NULL,                            /* engines_list */
  NULL,                            /* false_start */
  NULL,                            /* sha256sum */
  cr_recv,                         /* recv decrypted data */
  cr_send,                         /* send data to encrypt */
  NULL,                            /* get_channel_binding */
};

#endif /* USE_RUSTLS */
