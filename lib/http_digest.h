#ifndef __HTTP_DIGEST_H
#define __HTTP_DIGEST_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

typedef enum {
  CURLDIGEST_NONE, /* not a digest */
  CURLDIGEST_BAD,  /* a digest, but one we don't like */
  CURLDIGEST_BADALGO, /* unsupported algorithm requested */
  CURLDIGEST_NOMEM,
  CURLDIGEST_FINE, /* a digest we act on */

  CURLDIGEST_LAST  /* last entry in this enum, don't use */
} CURLdigest;

enum {
  CURLDIGESTALGO_MD5,
  CURLDIGESTALGO_MD5SESS
};

/* this is for digest header input */
CURLdigest Curl_input_digest(struct connectdata *conn,
                             bool proxy, char *header);

/* this is for creating digest header output */
CURLcode Curl_output_digest(struct connectdata *conn,
                            bool proxy,
                            unsigned char *request,
                            unsigned char *uripath);
void Curl_digest_cleanup_one(struct digestdata *dig);

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_CRYPTO_AUTH)
void Curl_digest_cleanup(struct SessionHandle *data);
#else
#define Curl_digest_cleanup(x) do {} while(0)
#endif

#endif
