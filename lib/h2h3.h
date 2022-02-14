#ifndef HEADER_CURL_H2H3_H
#define HEADER_CURL_H2H3_H
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

#define H2H3_PSEUDO_METHOD ":method"
#define H2H3_PSEUDO_SCHEME ":scheme"
#define H2H3_PSEUDO_AUTHORITY ":authority"
#define H2H3_PSEUDO_PATH ":path"
#define H2H3_PSEUDO_STATUS ":status"

struct h2h3pseudo {
  const char *name;
  size_t namelen;
  const char *value;
  size_t valuelen;
};

struct h2h3req {
  size_t entries;
  struct h2h3pseudo header[1]; /* the array is allocated to contain entries */
};

/*
 * Curl_pseudo_headers() creates the array with pseudo headers to be
 * used in a HTTP/2 or HTTP/3 request. Returns an allocated struct.
 * Free it with Curl_pseudo_free().
 */
CURLcode Curl_pseudo_headers(struct Curl_easy *data,
                             const char *request,
                             const size_t len,
                             struct h2h3req **hp);

/*
 * Curl_pseudo_free() frees a h2h3req struct.
 */
void Curl_pseudo_free(struct h2h3req *hp);

#endif /* HEADER_CURL_H2H3_H */
