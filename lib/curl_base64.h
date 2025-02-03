#ifndef HEADER_FETCH_BASE64_H
#define HEADER_FETCH_BASE64_H
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#ifndef BUILDING_LIBFETCH
/* this renames functions so that the tool code can use the same code
   without getting symbol collisions */
#define Curl_base64_encode(a, b, c, d) fetchx_base64_encode(a, b, c, d)
#define Curl_base64url_encode(a, b, c, d) fetchx_base64url_encode(a, b, c, d)
#define Curl_base64_decode(a, b, c) fetchx_base64_decode(a, b, c)
#endif

FETCHcode Curl_base64_encode(const char *inputbuff, size_t insize,
                             char **outptr, size_t *outlen);
FETCHcode Curl_base64url_encode(const char *inputbuff, size_t insize,
                                char **outptr, size_t *outlen);
FETCHcode Curl_base64_decode(const char *src,
                             unsigned char **outptr, size_t *outlen);
#endif /* HEADER_FETCH_BASE64_H */
