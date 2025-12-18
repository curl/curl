#ifndef HEADER_CURL_WOLFSSL_H
#define HEADER_CURL_WOLFSSL_H
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

#ifdef USE_WOLFSSL

#include "../urldata.h"

struct alpn_spec;
struct ssl_peer;
struct Curl_ssl_session;

struct WOLFSSL;
struct WOLFSSL_CTX;
struct WOLFSSL_SESSION;

extern const struct Curl_ssl Curl_ssl_wolfssl;

struct wssl_ctx {
  struct WOLFSSL_CTX *ssl_ctx;
  struct WOLFSSL     *ssl;
  CURLcode    io_result;   /* result of last BIO cfilter operation */
  CURLcode    hs_result;   /* result of handshake */
  int io_send_blocked_len; /* length of last BIO write that EAGAIN-ed */
  BIT(x509_store_setup);   /* x509 store has been set up */
  BIT(shutting_down);      /* TLS is being shut down */
};

size_t Curl_wssl_version(char *buffer, size_t size);

typedef CURLcode Curl_wssl_ctx_setup_cb(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        void *user_data);

typedef CURLcode Curl_wssl_init_session_reuse_cb(struct Curl_cfilter *cf,
                                                 struct Curl_easy *data,
                                                 struct alpn_spec *alpns,
                                                 struct Curl_ssl_session *scs,
                                                 bool *do_early_data);

CURLcode Curl_wssl_ctx_init(struct wssl_ctx *wctx,
                            struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct ssl_peer *peer,
                            const struct alpn_spec *alpns,
                            Curl_wssl_ctx_setup_cb *cb_setup,
                            void *cb_user_data,
                            void *ssl_user_data,
                            Curl_wssl_init_session_reuse_cb *sess_reuse_cb);

CURLcode Curl_wssl_setup_x509_store(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct wssl_ctx *wssl);

CURLcode Curl_wssl_cache_session(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const char *ssl_peer_key,
                                 struct WOLFSSL_SESSION *session,
                                 int ietf_tls_id,
                                 const char *alpn,
                                 unsigned char *quic_tp,
                                 size_t quic_tp_len);

CURLcode Curl_wssl_verify_pinned(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct wssl_ctx *wssl);

void Curl_wssl_report_handshake(struct Curl_easy *data,
                                struct wssl_ctx *wssl);

#endif /* USE_WOLFSSL */
#endif /* HEADER_CURL_WOLFSSL_H */
