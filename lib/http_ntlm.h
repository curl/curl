#ifndef HEADER_CURL_HTTP_NTLM_H
#define HEADER_CURL_HTTP_NTLM_H
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

typedef enum {
  CURLNTLM_NONE, /* not a ntlm */
  CURLNTLM_BAD,  /* an ntlm, but one we don't like */
  CURLNTLM_FIRST, /* the first 401-reply we got with NTLM */
  CURLNTLM_FINE, /* an ntlm we act on */

  CURLNTLM_LAST  /* last entry in this enum, don't use */
} CURLntlm;

/* this is for ntlm header input */
CURLntlm Curl_input_ntlm(struct connectdata *conn, bool proxy,
                         const char *header);

/* this is for creating ntlm header output */
CURLcode Curl_output_ntlm(struct connectdata *conn, bool proxy);

#ifdef WINBIND_NTLM_AUTH_ENABLED
/* this is for creating ntlm header output by delegating challenge/response
   to Samba's winbind daemon helper ntlm_auth */
CURLcode Curl_output_ntlm_sso(struct connectdata *conn, bool proxy);
#endif

#ifdef USE_NTLM
void Curl_http_ntlm_cleanup(struct connectdata *conn);
#else
#define Curl_http_ntlm_cleanup(x)
#endif

#include "curl_ntlm.h"

#endif /* HEADER_CURL_HTTP_NTLM_H */
