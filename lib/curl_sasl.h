#ifndef HEADER_CURL_SASL_H
#define HEADER_CURL_SASL_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include <curl/curl.h>

struct SessionHandle;
struct connectdata;
struct ntlmdata;

/* Authentication mechanism values */
#define SASL_AUTH_NONE          0
#define SASL_AUTH_ANY           ~0U

/* Authentication mechanism flags */
#define SASL_MECH_LOGIN             (1 << 0)
#define SASL_MECH_PLAIN             (1 << 1)
#define SASL_MECH_CRAM_MD5          (1 << 2)
#define SASL_MECH_DIGEST_MD5        (1 << 3)
#define SASL_MECH_GSSAPI            (1 << 4)
#define SASL_MECH_EXTERNAL          (1 << 5)
#define SASL_MECH_NTLM              (1 << 6)
#define SASL_MECH_XOAUTH2           (1 << 7)

/* Authentication mechanism strings */
#define SASL_MECH_STRING_LOGIN      "LOGIN"
#define SASL_MECH_STRING_PLAIN      "PLAIN"
#define SASL_MECH_STRING_CRAM_MD5   "CRAM-MD5"
#define SASL_MECH_STRING_DIGEST_MD5 "DIGEST-MD5"
#define SASL_MECH_STRING_GSSAPI     "GSSAPI"
#define SASL_MECH_STRING_EXTERNAL   "EXTERNAL"
#define SASL_MECH_STRING_NTLM       "NTLM"
#define SASL_MECH_STRING_XOAUTH2    "XOAUTH2"

/* This is used to test whether the line starts with the given mechanism */
#define sasl_mech_equal(line, wordlen, mech) \
  (wordlen == (sizeof(mech) - 1) / sizeof(char) && \
   !memcmp(line, mech, wordlen))

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
/* This is used to decode a base64 encoded CRAM-MD5 challange message */
CURLcode Curl_sasl_decode_cram_md5_message(const char *chlg64, char **outptr,
                                           size_t *outlen);

/* This is used to generate a base64 encoded CRAM-MD5 response message */
CURLcode Curl_sasl_create_cram_md5_message(struct SessionHandle *data,
                                           const char *chlg,
                                           const char *user,
                                           const char *passwdp,
                                           char **outptr, size_t *outlen);

/* This is used to generate a base64 encoded DIGEST-MD5 response message */
CURLcode Curl_sasl_create_digest_md5_message(struct SessionHandle *data,
                                             const char *chlg64,
                                             const char *userp,
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

/* This is used to decode a base64 encoded NTLM type-2 message */
CURLcode Curl_sasl_decode_ntlm_type2_message(struct SessionHandle *data,
                                             const char *type2msg,
                                             struct ntlmdata *ntlm);

/* This is used to generate a base64 encoded NTLM type-3 message */
CURLcode Curl_sasl_create_ntlm_type3_message(struct SessionHandle *data,
                                             const char *userp,
                                             const char *passwdp,
                                             struct ntlmdata *ntlm,
                                             char **outptr, size_t *outlen);

#endif /* USE_NTLM */

/* This is used to generate a base64 encoded XOAUTH2 authentication message
   containing the user name and bearer token */
CURLcode Curl_sasl_create_xoauth2_message(struct SessionHandle *data,
                                          const char *user,
                                          const char *bearer,
                                          char **outptr, size_t *outlen);

/* This is used to cleanup any libraries or curl modules used by the sasl
   functions */
void Curl_sasl_cleanup(struct connectdata *conn, unsigned int authused);

#endif /* HEADER_CURL_SASL_H */
