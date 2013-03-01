#ifndef HEADER_CURL_NTLM_CORE_H
#define HEADER_CURL_NTLM_CORE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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

#if defined(USE_NTLM) && !defined(USE_WINDOWS_SSPI)

#ifdef USE_SSLEAY
#  if !defined(OPENSSL_VERSION_NUMBER) && \
      !defined(HEADER_SSL_H) && !defined(HEADER_MD5_H)
#    error "curl_ntlm_core.h shall not be included before OpenSSL headers."
#  endif
#  ifdef OPENSSL_NO_MD4
#    define USE_NTRESPONSES 0
#    define USE_NTLM2SESSION 0
#  endif
#endif

/*
 * Define USE_NTRESPONSES to 1 in order to make the type-3 message include
 * the NT response message. Define USE_NTLM2SESSION to 1 in order to make
 * the type-3 message include the NTLM2Session response message, requires
 * USE_NTRESPONSES defined to 1.
 */

#ifndef USE_NTRESPONSES
#  define USE_NTRESPONSES 1
#  define USE_NTLM2SESSION 1
#endif

void Curl_ntlm_core_lm_resp(const unsigned char *keys,
                            const unsigned char *plaintext,
                            unsigned char *results);

void Curl_ntlm_core_mk_lm_hash(struct SessionHandle *data,
                               const char *password,
                               unsigned char *lmbuffer /* 21 bytes */);

#if USE_NTRESPONSES
CURLcode Curl_ntlm_core_mk_nt_hash(struct SessionHandle *data,
                                   const char *password,
                                   unsigned char *ntbuffer /* 21 bytes */);
#endif

#endif /* USE_NTLM && !USE_WINDOWS_SSPI */

#endif /* HEADER_CURL_NTLM_CORE_H */
