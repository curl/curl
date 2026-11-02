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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "unitcheck.h"

#if defined(USE_OPENSSL) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
#include "urldata.h"
#include "cfilters.h"
#include "curl_trc.h"
#include "vtls/openssl.h"
#include "vtls/vtls.h"
#include "vtls/vtls_int.h"
#include <errno.h>

static bool t2641_send_error;
static bool t2641_read_after_error;
static bool t2641_write_failed;
static bool t2641_fail_writes;

static bool t2641_contains(const char *buf, size_t size, const char *text)
{
  size_t i, len = strlen(text);
  for(i = 0; i + len <= size; i++) {
    if(!memcmp(buf + i, text, len))
      return TRUE;
  }
  return FALSE;
}

/* The post-send read trace detects SSL_read() even if OpenSSL returns
 * without calling the BIO. The initial read has a different trace message. */
static int t2641_debug(CURL *handle, curl_infotype type, char *buf,
                       size_t size, void *userptr)
{
  (void)handle;
  (void)userptr;
  if(type == CURLINFO_TEXT && size) {
    if(t2641_contains(buf, size, "SSL shutdown, ignore send error:"))
      t2641_send_error = TRUE;
    if(t2641_contains(buf, size, "SSL shutdown read ->"))
      t2641_read_after_error = TRUE;
  }
  return 0;
}

/* Forward traffic and retry flags during the handshake, then inject a
 * non-retryable write failure when shutdown sends close_notify. */
static int t2641_bio_create(BIO *bio)
{
  BIO_set_init(bio, 1);
  return 1;
}

static int t2641_bio_write(BIO *bio, const char *buf, int len)
{
  int rc;
  BIO_clear_retry_flags(bio);
  if(t2641_fail_writes) {
    t2641_write_failed = TRUE;
    errno = EPIPE;
    return -1;
  }
  rc = BIO_write(BIO_next(bio), buf, len);
  BIO_copy_next_retry(bio);
  return rc;
}

static int t2641_bio_read(BIO *bio, char *buf, int len)
{
  int rc;
  BIO_clear_retry_flags(bio);
  rc = BIO_read(BIO_next(bio), buf, len);
  BIO_copy_next_retry(bio);
  return rc;
}

static long t2641_bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
  return BIO_ctrl(BIO_next(bio), cmd, num, ptr);
}

/* Advance one peer of the in-memory handshake, accepting blocked I/O. */
static bool t2641_handshake_step(SSL *ssl)
{
  int rc, error;
  if(SSL_is_init_finished(ssl))
    return TRUE;
  rc = SSL_do_handshake(ssl);
  if(rc == 1)
    return TRUE;
  error = SSL_get_error(ssl, rc);
  return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}
#endif

static CURLcode test_unit2641(const char *arg)
{
#if defined(USE_OPENSSL) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
  CURL *easy = NULL;
  SSL_CTX *client_ctx = NULL, *server_ctx = NULL;
  SSL *client = NULL, *server = NULL;
  BIO *client_bio = NULL, *server_bio = NULL, *filter = NULL;
  BIO_METHOD *method = NULL;
  struct ossl_ctx backend;
  struct ssl_connect_data connssl;
  struct connectdata connection;
  struct Curl_cfilter cf;
  struct Curl_cftype cft;
  CURLcode result;
  bool done = FALSE;
  int i;

  UNITTEST_BEGIN_SIMPLE
  global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  abort_unless(easy, "curl_easy_init");
  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, t2641_debug);
  t2641_send_error = t2641_read_after_error = t2641_write_failed = FALSE;
  t2641_fail_writes = FALSE;

  /* Connect real client and server SSL objects over an in-memory BIO pair.
   * The test harness supplies the server certificate and key. */
  client_ctx = SSL_CTX_new(TLS_client_method());
  server_ctx = SSL_CTX_new(TLS_server_method());
  abort_unless(client_ctx && server_ctx, "SSL contexts");
  abort_unless(arg && SSL_CTX_use_certificate_file(server_ctx, arg,
                                                    SSL_FILETYPE_PEM) == 1,
               "server certificate");
  abort_unless(SSL_CTX_use_PrivateKey_file(server_ctx, arg,
                                           SSL_FILETYPE_PEM) == 1,
               "server private key");
  client = SSL_new(client_ctx);
  server = SSL_new(server_ctx);
  abort_unless(client && server, "SSL connections");
  abort_unless(BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) == 1,
               "BIO pair");
  /* Place the fault-injection filter on the client side before handshaking. */
  method = BIO_meth_new(BIO_TYPE_FILTER, "unit2641 failing write");
  abort_unless(method, "BIO method");
  abort_unless(BIO_meth_set_write(method, t2641_bio_write) &&
               BIO_meth_set_read(method, t2641_bio_read) &&
               BIO_meth_set_create(method, t2641_bio_create) &&
               BIO_meth_set_ctrl(method, t2641_bio_ctrl), "BIO callbacks");
  filter = BIO_new(method);
  abort_unless(filter, "filter BIO");
  BIO_push(filter, client_bio);
  client_bio = NULL;
  SSL_set_bio(client, filter, filter);
  filter = NULL;
  SSL_set_bio(server, server_bio, server_bio);
  server_bio = NULL;
  SSL_set_connect_state(client);
  SSL_set_accept_state(server);
  for(i = 0; i < 100 &&
      (!SSL_is_init_finished(client) || !SSL_is_init_finished(server)); i++)
    abort_unless(t2641_handshake_step(client) && t2641_handshake_step(server),
                 "TLS handshake step");
  abort_unless(SSL_is_init_finished(client) && SSL_is_init_finished(server),
               "TLS handshake complete");

  /* Leave the read side connected but fail the close_notify write. */
  t2641_fail_writes = TRUE;

  /* Give the backend shutdown entry point a minimal filter context with the
   * established client SSL object. Enable its trace for the assertions. */
  memset(&backend, 0, sizeof(backend));
  memset(&connssl, 0, sizeof(connssl));
  memset(&connection, 0, sizeof(connection));
  memset(&cf, 0, sizeof(cf));
  cft = Curl_cft_ssl;
  cft.log_level = CURL_LOG_LVL_INFO;
  backend.ssl = client;
  connssl.backend = &backend;
  connssl.ssl_impl = &Curl_ssl_openssl;
  cf.cft = &cft;
  cf.ctx = &connssl;
  cf.conn = &connection;
  result = Curl_ssl_openssl.shut_down(&cf, easy, TRUE, &done);
  /* Check that the write failure reached the terminal path and that the
   * post-send read path was not entered. Shutdown itself is best-effort. */
  fail_unless(result == CURLE_OK, "best-effort shutdown");
  fail_unless(t2641_write_failed, "close_notify write failed");
  fail_unless(t2641_send_error, "shutdown error was terminal");
  fail_unless(done, "shutdown finished after terminal error");
  fail_unless(!t2641_read_after_error, "no read after terminal error");
  /* !checksrc! disable CLOSEBRACE 1 */
  }
unit_test_abort:
  BIO_free_all(filter);
  BIO_free(client_bio);
  BIO_free(server_bio);
  SSL_free(client);
  SSL_free(server);
  BIO_meth_free(method);
  SSL_CTX_free(client_ctx);
  SSL_CTX_free(server_ctx);
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  return (CURLcode)unitfail;
#else
  (void)arg;
  return CURLE_OK;
#endif
}
