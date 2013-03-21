#ifndef HEADER_CURL_SASL_H
#define HEADER_CURL_SASL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "pingpong.h"

/* Authentication mechanism flags */
#define SASL_MECH_LOGIN         0x0001
#define SASL_MECH_PLAIN         0x0002
#define SASL_MECH_CRAM_MD5      0x0004
#define SASL_MECH_DIGEST_MD5    0x0008
#define SASL_MECH_GSSAPI        0x0010
#define SASL_MECH_EXTERNAL      0x0020
#define SASL_MECH_NTLM          0x0040

/* This is used to generate a base64 encoded PLAIN authentication message */
CURLcode Curl_sasl_create_plain_message(struct SessionHandle *data,
                                        const char *userp,
                                        const char *passwdp,
                                        char **outptr, size_t *outlen);

/* This is used to generate a base64 encoded LOGIN authentication message
   containing either the user name or password details */
CURLcode Curl_sasl_create_login_message(struct SessionHandle *data,
                                        const char *valuep, char **outptr,
                                        size_t *outlen);

#ifndef CURL_DISABLE_CRYPTO_AUTH
/* This is used to generate a base64 encoded CRAM-MD5 response message */
CURLcode Curl_sasl_create_cram_md5_message(struct SessionHandle *data,
                                           const char *chlg64,
                                           const char *user,
                                           const char *passwdp,
                                           char **outptr, size_t *outlen);

/* This is used to generate a base64 encoded DIGEST-MD5 response message */
CURLcode Curl_sasl_create_digest_md5_message(struct SessionHandle *data,
                                             const char *chlg64,
                                             const char *user,
                                             const char *passwdp,
                                             const char *service,
                                             char **outptr, size_t *outlen);
#endif

#ifdef USE_NTLM
/* This is used to generate a base64 encoded NTLM type-1 message */
CURLcode Curl_sasl_create_ntlm_type1_message(const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr,
                                             size_t *outlen);

/* This is used to decode an incoming NTLM type-2 message and generate a
   base64 encoded type-3 response */
CURLcode Curl_sasl_create_ntlm_type3_message(struct SessionHandle *data,
                                             const char *header,
                                             const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen);

#endif /* USE_NTLM */

/* This is used to cleanup any libraries or curl modules used by the sasl
   functions */
void Curl_sasl_cleanup(struct connectdata *conn, unsigned int authused);

#endif /* HEADER_CURL_SASL_H */
