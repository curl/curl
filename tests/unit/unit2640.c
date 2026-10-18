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
#include "unitcheck.h"

#include "urldata.h"
#include "cfilters.h"
#include "curl_trc.h"
#include "vtls/vtls_int.h"
#include "vtls/rustls.h"

#ifdef USE_RUSTLS

struct t2640_ctx {
  size_t calls;
  size_t written;
  size_t write_once;
  bool blocked;
  bool fatal;
};

static void t2640_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  (void)cf;
  (void)data;
}

static CURLcode t2640_send(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           const uint8_t *buf, size_t len, bool eos,
                           size_t *pnwritten)
{
  struct t2640_ctx *ctx = cf->ctx;
  (void)data;
  (void)buf;
  (void)eos;

  ++ctx->calls;
  *pnwritten = 0;
  if(ctx->fatal)
    return CURLE_SEND_ERROR;
  if(ctx->write_once) {
    len = CURLMIN(len, ctx->write_once);
    ctx->write_once = 0;
  }
  else if(ctx->blocked)
    return CURLE_AGAIN;
  ctx->written += len;
  *pnwritten = len;
  return CURLE_OK;
}

static const struct Curl_cftype t2640_cft = {
  "TEST",
  CF_TYPE_IP_CONNECT,
  CURL_LOG_LVL_NONE,
  t2640_destroy,
  Curl_cf_def_connect,
  Curl_cf_def_shutdown,
  Curl_cf_def_adjust_pollset,
  Curl_cf_def_data_pending,
  t2640_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static void t2640_run(struct Curl_easy *data, const struct Curl_cftype *cft,
                      size_t partial, bool extend, bool flush_only, bool fatal)
{
  struct ssl_connect_data connssl;
  struct t2640_ctx transport_ctx;
  struct Curl_cfilter transport_cf;
  struct Curl_cfilter rustls_cf;
  unsigned char buf[1024], retry[1536];
  size_t nwritten = 0, retrylen;
#ifndef DEBUGBUILD
  size_t calls;
#endif
  CURLcode result;

  memset(&connssl, 0, sizeof(connssl));
  memset(&transport_ctx, 0, sizeof(transport_ctx));
  memset(&transport_cf, 0, sizeof(transport_cf));
  memset(&rustls_cf, 0, sizeof(rustls_cf));
  memset(buf, 'x', sizeof(buf));
  memset(retry, 'x', sizeof(retry));

  connssl.backend = curlx_calloc(1, Curl_ssl_rustls.sizeof_ssl_backend_data);
  abort_unless(connssl.backend, "Rustls backend allocation failed");
  connssl.ssl_impl = &Curl_ssl_rustls;
  transport_ctx.blocked = TRUE;
  transport_ctx.write_once = partial;
  transport_cf.cft = &t2640_cft;
  transport_cf.ctx = &transport_ctx;
  transport_cf.connected = TRUE;
  rustls_cf.cft = cft;
  rustls_cf.next = &transport_cf;
  rustls_cf.ctx = &connssl;

  result = rustls_test_init(&connssl, 2 * sizeof(buf));
  abort_unless(!result, "Rustls test connection initialization failed");

  /* The ClientHello supplies TLS output to block, while application data
   * goes into the pre-handshake plaintext buffer. This exercises the real
   * send bookkeeping without a server, certificates or timing assumptions.
   * ssl_cf_send allows ssl_connection_none through; only
   * ssl_connection_deferred triggers a handshake there. */
  result = Curl_conn_cf_send(&rustls_cf, data, buf, sizeof(buf), FALSE,
                             &nwritten);
  fail_unless(result == CURLE_AGAIN && !nwritten,
              "blocked send acknowledged plaintext");
  fail_unless(transport_ctx.written == partial,
              "partial TLS write did not precede blocking");

  /* Moving the buffer is fine, but the unacknowledged prefix must remain. */
  result = Curl_conn_cf_send(&rustls_cf, data, retry, sizeof(buf), FALSE,
                             &nwritten);
  fail_unless(result == CURLE_AGAIN && !nwritten,
              "blocked retry acknowledged plaintext");

#ifndef DEBUGBUILD
  /* Short retries assert in debug builds; check the returned error in
   * non-debug builds. */
  calls = transport_ctx.calls;
  nwritten = 99;
  result = Curl_conn_cf_send(&rustls_cf, data, retry, sizeof(buf) - 1,
                             FALSE, &nwritten);
  fail_unless(result == CURLE_BAD_FUNCTION_ARGUMENT && !nwritten,
              "short retry was not rejected while blocked");
  fail_unless(transport_ctx.calls == calls,
              "invalid retry attempted a TLS write");
#endif

  if(flush_only) {
    nwritten = 99;
    result = Curl_ssl_rustls.send_plain(&rustls_cf, data, NULL, 0, &nwritten);
    fail_unless(result == CURLE_AGAIN && !nwritten,
                "blocked flush-only send acknowledged plaintext");
  }

  if(fatal) {
    transport_ctx.fatal = TRUE;
    result = Curl_conn_cf_send(&rustls_cf, data, retry, sizeof(buf), FALSE,
                               &nwritten);
    fail_unless(result == CURLE_SEND_ERROR && !nwritten,
                "retry hid a fatal TLS write error");
    goto unit_test_abort;
  }

  transport_ctx.blocked = FALSE;
  if(flush_only) {
    nwritten = 99;
    result = Curl_ssl_rustls.send_plain(&rustls_cf, data, NULL, 0, &nwritten);
    fail_unless(!result && !nwritten,
                "flush-only send acknowledged plaintext");
    fail_unless(transport_ctx.written > partial,
                "flush-only send did not drain TLS output");
  }

#ifndef DEBUGBUILD
  calls = transport_ctx.calls;
  nwritten = 99;
  result = Curl_conn_cf_send(&rustls_cf, data, retry, sizeof(buf) - 1,
                             FALSE, &nwritten);
  fail_unless(result == CURLE_BAD_FUNCTION_ARGUMENT && !nwritten,
              "short retry was not rejected after unblocking");
  fail_unless(transport_ctx.calls == calls,
              "invalid retry wrote TLS output after unblocking");
#endif

  /* Retry both the original length and an extended buffer with the same
   * prefix. Only bytes beyond the saved count may be added to Rustls. */
  retrylen = extend ? sizeof(retry) : sizeof(buf);
  result = Curl_conn_cf_send(&rustls_cf, data, retry, retrylen, FALSE,
                             &nwritten);
  fail_unless(!result && nwritten == retrylen,
              "valid retry did not acknowledge the correct byte count");
  fail_unless(transport_ctx.written > partial,
              "valid retry did not drain TLS output");

  /* Exactly this much room remains. Re-enqueuing a retry would fill the
   * buffer early. */
  result = Curl_conn_cf_send(&rustls_cf, data, buf, 2 * sizeof(buf) - retrylen,
                             FALSE, &nwritten);
  fail_unless(!result && nwritten == 2 * sizeof(buf) - retrylen,
              "retry duplicated plaintext");

unit_test_abort:
  if(connssl.backend)
    Curl_ssl_rustls.close(&rustls_cf, data);
  curlx_free(connssl.backend);
}

#endif /* USE_RUSTLS */

static void t2640_stop(struct Curl_easy *data)
{
  curl_easy_cleanup(data);
  curl_global_cleanup();
}

static CURLcode test_unit2640(const char *arg)
{
  struct Curl_easy *data = NULL;

  UNITTEST_BEGIN_SIMPLE

#ifdef USE_RUSTLS
  static const size_t partials[] = { 0, 7 };
  size_t i;
  int extend, flush_only, fatal;

  abort_unless(!curl_global_init(CURL_GLOBAL_ALL), "global init failed");
  data = curl_easy_init();
  abort_unless(data, "easy handle allocation failed");
  for(i = 0; i < CURL_ARRAYSIZE(partials); ++i) {
    for(extend = 0; extend <= 1; ++extend) {
      for(flush_only = 0; flush_only <= 1; ++flush_only) {
        for(fatal = 0; fatal <= 1; ++fatal) {
          t2640_run(data, &Curl_cft_ssl, partials[i], extend != 0,
                    flush_only != 0, fatal != 0);
#ifndef CURL_DISABLE_PROXY
          t2640_run(data, &Curl_cft_ssl_proxy, partials[i], extend != 0,
                    flush_only != 0, fatal != 0);
#endif
        }
      }
    }
  }
#endif /* USE_RUSTLS */

  UNITTEST_END(t2640_stop(data))
}
