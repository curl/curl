#ifndef HEADER_CURL_HMAC_H
#define HEADER_CURL_HMAC_H
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

#if !defined(CURL_DISABLE_AWS) || !defined(CURL_DISABLE_HTTPSIG) || \
  !defined(CURL_DISABLE_DIGEST_AUTH) ||                             \
  defined(USE_LIBSSH2) || defined(USE_SSL)

typedef CURLcode (*HMAC_hinit)(void *context);
typedef CURLcode (*HMAC_hupdate)(void *context,
                                 const void *input, size_t input_len);
typedef CURLcode (*HMAC_hfinal)(uint8_t *digest, void *context);

/* Per-hash function HMAC parameters. */
struct HMAC_params {
  HMAC_hinit hinit;        /* Initialize context procedure. */
  HMAC_hupdate hupdate;    /* Update context with data. */
  HMAC_hfinal hfinal;      /* Get final result procedure. */
  unsigned int ctxtsize;   /* Context structure size. */
  size_t key_len_max;      /* Maximum key length (bytes). */
  size_t digest_len;       /* Result length (bytes). */
};

/* HMAC computation context. */
struct HMAC_context {
  const struct HMAC_params *hash; /* Hash function definition. */
  void *hashctxt1;         /* Hash function context 1. */
  void *hashctxt2;         /* Hash function context 2. */
};

/* Prototypes. */
struct HMAC_context *Curl_HMAC_init(const struct HMAC_params *hashparams,
                                    const void *key, size_t key_len);
CURLcode Curl_HMAC_update(struct HMAC_context *ctxt,
                          const void *input, size_t input_len);
CURLcode Curl_HMAC_final(struct HMAC_context *ctxt, uint8_t *mac);

CURLcode Curl_hmacit(const struct HMAC_params *hashparams,
                     const void *key, const size_t key_len,
                     const void *input, size_t input_len,
                     uint8_t *mac);
#endif

#endif /* HEADER_CURL_HMAC_H */
