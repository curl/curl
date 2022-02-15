#ifndef HEADER_CURL_NTLM_CORE_H
#define HEADER_CURL_NTLM_CORE_H
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
 ***************************************************************************/

#include "curl_setup.h"

#if defined(USE_CURL_NTLM_CORE)

/* If NSS is the first available SSL backend (see order in curl_ntlm_core.c)
   then it must be initialized to be used by NTLM. */
#if !defined(USE_OPENSSL) && \
    !defined(USE_WOLFSSL) && \
    !defined(USE_GNUTLS) && \
    defined(USE_NSS)
#define NTLM_NEEDS_NSS_INIT
#endif

#if defined(USE_OPENSSL) || defined(USE_WOLFSSL)
#ifdef USE_WOLFSSL
#  include <wolfssl/options.h>
#endif
#  include <openssl/ssl.h>
#endif

/* Helpers to generate function byte arguments in little endian order */
#define SHORTPAIR(x) ((int)((x) & 0xff)), ((int)(((x) >> 8) & 0xff))
#define LONGQUARTET(x) ((int)((x) & 0xff)), ((int)(((x) >> 8) & 0xff)), \
  ((int)(((x) >> 16) & 0xff)), ((int)(((x) >> 24) & 0xff))

void Curl_ntlm_core_lm_resp(const unsigned char *keys,
                            const unsigned char *plaintext,
                            unsigned char *results);

CURLcode Curl_ntlm_core_mk_lm_hash(const char *password,
                                   unsigned char *lmbuffer /* 21 bytes */);

CURLcode Curl_ntlm_core_mk_nt_hash(const char *password,
                                   unsigned char *ntbuffer /* 21 bytes */);

#if !defined(USE_WINDOWS_SSPI)

CURLcode Curl_hmac_md5(const unsigned char *key, unsigned int keylen,
                       const unsigned char *data, unsigned int datalen,
                       unsigned char *output);

CURLcode Curl_ntlm_core_mk_ntlmv2_hash(const char *user, size_t userlen,
                                       const char *domain, size_t domlen,
                                       unsigned char *ntlmhash,
                                       unsigned char *ntlmv2hash);

CURLcode  Curl_ntlm_core_mk_ntlmv2_resp(unsigned char *ntlmv2hash,
                                        unsigned char *challenge_client,
                                        struct ntlmdata *ntlm,
                                        unsigned char **ntresp,
                                        unsigned int *ntresp_len);

CURLcode  Curl_ntlm_core_mk_lmv2_resp(unsigned char *ntlmv2hash,
                                      unsigned char *challenge_client,
                                      unsigned char *challenge_server,
                                      unsigned char *lmresp);

#endif /* !USE_WINDOWS_SSPI */

#endif /* USE_CURL_NTLM_CORE */

#endif /* HEADER_CURL_NTLM_CORE_H */
