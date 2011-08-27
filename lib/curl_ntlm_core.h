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

#ifdef USE_NTLM

void Curl_ntlm_core_lm_resp(const unsigned char *keys,
                            const unsigned char *plaintext,
                            unsigned char *results);

void Curl_ntlm_core_mk_lm_hash(struct SessionHandle *data,
                               const char *password,
                               unsigned char *lmbuffer /* 21 bytes */);

#if !defined(USE_WINDOWS_SSPI) && (USE_NTRESPONSES != 0)
CURLcode Curl_ntlm_core_mk_nt_hash(struct SessionHandle *data,
                                   const char *password,
                                   unsigned char *ntbuffer /* 21 bytes */);
#endif

#endif /* USE_NTLM */

#endif /* HEADER_CURL_NTLM_CORE_H */
