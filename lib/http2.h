#ifndef HEADER_FETCH_HTTP2_H
#define HEADER_FETCH_HTTP2_H
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
 * are also available at https://fetch.se/docs/copyright.html.
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

#include "fetch_setup.h"

#ifdef USE_NGHTTP2
#include "http.h"

/* value for MAX_CONCURRENT_STREAMS we use until we get an updated setting
   from the peer */
#define DEFAULT_MAX_CONCURRENT_STREAMS 100

/*
 * Store nghttp2 version info in this buffer.
 */
void Fetch_http2_ver(char *p, size_t len);

FETCHcode Fetch_http2_request_upgrade(struct dynbuf *req,
                                     struct Fetch_easy *data);

/* returns true if the HTTP/2 stream error was HTTP_1_1_REQUIRED */
bool Fetch_h2_http_1_1_error(struct Fetch_easy *data);

bool Fetch_http2_may_switch(struct Fetch_easy *data);

FETCHcode Fetch_http2_switch(struct Fetch_easy *data);

FETCHcode Fetch_http2_switch_at(struct Fetch_cfilter *cf, struct Fetch_easy *data);

FETCHcode Fetch_http2_upgrade(struct Fetch_easy *data,
                             struct connectdata *conn, int sockindex,
                             const char *ptr, size_t nread);

void *Fetch_nghttp2_malloc(size_t size, void *user_data);
void Fetch_nghttp2_free(void *ptr, void *user_data);
void *Fetch_nghttp2_calloc(size_t nmemb, size_t size, void *user_data);
void *Fetch_nghttp2_realloc(void *ptr, size_t size, void *user_data);

extern struct Fetch_cftype Fetch_cft_nghttp2;

#else /* USE_NGHTTP2 */

#define Fetch_http2_may_switch(a) FALSE

#define Fetch_http2_request_upgrade(x, y) FETCHE_UNSUPPORTED_PROTOCOL
#define Fetch_http2_switch(a) FETCHE_UNSUPPORTED_PROTOCOL
#define Fetch_http2_upgrade(a, b, c, d, e) FETCHE_UNSUPPORTED_PROTOCOL
#define Fetch_h2_http_1_1_error(x) 0
#endif

#endif /* HEADER_FETCH_HTTP2_H */
