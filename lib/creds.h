#ifndef HEADER_CURL_CREDS_H
#define HEADER_CURL_CREDS_H
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

struct Curl_easy;

#define CREDS_NONE   0 /* used for default username/passwd */
#define CREDS_URL    1 /* username/passwd from URL */
#define CREDS_OPTION 2 /* username/passwd set with a CURLOPT_ */
#define CREDS_NETRC  3 /* username/passwd found in netrc */

struct Curl_creds {
  const char *user; /* non-NULL, maybe empty string */
  const char *passwd; /* non-NULL, maybe empty string */
  const char *sasl_authzid; /* non-NULL, maybe empty string */
  const char *oauth_bearer; /* non-NULL, maybe empty string */
  uint32_t refcount;
  uint8_t source; /* CREDS_* value */
  char buf[1];
};

CURLcode Curl_creds_create(const char *user,
                           const char *passwd,
                           const char *sasl_authzid,
                           const char *oauth_bearer,
                           uint8_t source,
                           struct Curl_creds **pcreds);

/* Create credentials by overriding `user` and/or `passwd` in `creds_in` */
CURLcode Curl_creds_merge(const char *user,
                          const char *passwd,
                          struct Curl_creds *creds_in,
                          uint8_t source,
                          struct Curl_creds **pcreds_out);

/* Unlink any creds in `*pdest`, assign src, increase src
 * refcount when not NULL. */
void Curl_creds_link(struct Curl_creds **pdest, struct Curl_creds *src);

/* Drop a reference, creds may be passed as NULL */
void Curl_creds_unlink(struct Curl_creds **pcreds);

/* TRUE if both creds are NULL or have same username and password. */
bool Curl_creds_same(struct Curl_creds *c1, struct Curl_creds *c2);
bool Curl_creds_same_user(struct Curl_creds *creds, const char *user);
bool Curl_creds_same_passwd(struct Curl_creds *creds, const char *passwd);


/* Provides properties for creds or, if creds is NULL, the empty string */
#define Curl_creds_has_user(c)           ((c) && (c)->user[0])
#define Curl_creds_has_passwd(c)         ((c) && (c)->passwd[0])
#define Curl_creds_has_oauth_bearer(c)   ((c) && (c)->oauth_bearer[0])
#define Curl_creds_user(c)               ((c)? (c)->user : "")
#define Curl_creds_passwd(c)             ((c)? (c)->passwd : "")
#define Curl_creds_sasl_authzid(c)       ((c)? (c)->sasl_authzid : "")
#define Curl_creds_oauth_bearer(c)       ((c)? (c)->oauth_bearer : "")


#ifdef CURLVERBOSE
void Curl_creds_trace(struct Curl_easy *data, struct Curl_creds *creds,
                      const char *msg);
#endif

#endif /* HEADER_CURL_CREDS_H */
