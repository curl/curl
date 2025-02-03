#ifndef HEADER_FETCH_WOLFSSL_H
#define HEADER_FETCH_WOLFSSL_H
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

#ifdef USE_WOLFSSL

#include "urldata.h"

struct WOLFSSL;
typedef struct WOLFSSL WOLFSSL;
struct WOLFSSL_CTX;
typedef struct WOLFSSL_CTX WOLFSSL_CTX;
struct WOLFSSL_SESSION;
typedef struct WOLFSSL_SESSION WOLFSSL_SESSION;

extern const struct Fetch_ssl Fetch_ssl_wolfssl;

struct wolfssl_ctx
{
  WOLFSSL_CTX *ctx;
  WOLFSSL *handle;
  FETCHcode io_result;     /* result of last BIO cfilter operation */
  int io_send_blocked_len; /* length of last BIO write that EAGAINed */
  BIT(x509_store_setup);   /* x509 store has been set up */
  BIT(shutting_down);      /* TLS is being shut down */
};

size_t Fetch_wssl_version(char *buffer, size_t size);

FETCHcode Fetch_wssl_setup_x509_store(struct Fetch_cfilter *cf,
                                     struct Fetch_easy *data,
                                     struct wolfssl_ctx *wssl);

FETCHcode Fetch_wssl_setup_session(struct Fetch_cfilter *cf,
                                  struct Fetch_easy *data,
                                  struct wolfssl_ctx *wss,
                                  const char *ssl_peer_key);

FETCHcode Fetch_wssl_cache_session(struct Fetch_cfilter *cf,
                                  struct Fetch_easy *data,
                                  const char *ssl_peer_key,
                                  WOLFSSL_SESSION *session,
                                  int ietf_tls_id,
                                  const char *alpn);

#endif /* USE_WOLFSSL */
#endif /* HEADER_FETCH_WOLFSSL_H */
