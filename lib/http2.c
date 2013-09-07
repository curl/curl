/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef USE_NGHTTP2
#define _MPRINTF_REPLACE
#include <curl/mprintf.h>

#include <nghttp2/nghttp2.h>
#include "urldata.h"
#include "http2.h"
#include "http.h"

/*
 * Store nghttp2 version info in this buffer, Prefix with a space.  Return
 * total length written.
 */
int Curl_http2_ver(char *p, size_t len)
{
  nghttp2_info *h2 = nghttp2_version(0);
  return snprintf(p, len, " nghttp2/%s", h2->version_str);
}

/*
 * Append headers to ask for a HTTP1.1 to HTTP2 upgrade.
 */
CURLcode Curl_http2_request(Curl_send_buffer *req,
                            struct connectdata *conn)
{
  const char *base64="AABBCC"; /* a fake string to start with */
  CURLcode result =
    Curl_add_bufferf(req,
                     "Connection: Upgrade, HTTP2-Settings\r\n"
                     "Upgrade: HTTP/2.0\r\n"
                     "HTTP2-Settings: %s\r\n",
                     base64);
  (void)conn;
  return result;
}

#endif
