#ifndef HEADER_CURL_WS_H
#define HEADER_CURL_WS_H
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
#include "curl_setup.h"

#ifdef USE_WEBSOCKETS

#ifdef USE_HYPER
#define REQTYPE void
#else
#define REQTYPE struct dynbuf
#endif

/* this is the largest single fragment size we support */
#define MAX_WS_SIZE 65535

/* part of 'struct HTTP', when used in the 'struct SingleRequest' in the
   Curl_easy struct */
struct websocket {
  bool contfragment; /* set TRUE if the previous fragment sent was not final */
  unsigned char mask[4]; /* 32 bit mask for this connection */
  struct Curl_easy *data; /* used for write callback handling */
  struct dynbuf buf;
  size_t usedbuf; /* number of leading bytes in 'buf' the most recent complete
                     websocket frame uses */
  struct curl_ws_frame frame; /* the struct used for frame state */
  curl_off_t oleft; /* outstanding number of payload bytes left from the
                       server */
  size_t stillblen; /* number of bytes left in the buffer to deliver in
                         the next curl_ws_recv() call */
  char *stillb; /* the stillblen pending bytes are here */
  curl_off_t sleft; /* outstanding number of payload bytes left to send */
  unsigned int xori; /* xor index */
};

CURLcode Curl_ws_request(struct Curl_easy *data, REQTYPE *req);
CURLcode Curl_ws_accept(struct Curl_easy *data);

size_t Curl_ws_writecb(char *buffer, size_t size, size_t nitems, void *userp);
void Curl_ws_done(struct Curl_easy *data);
CURLcode Curl_ws_disconnect(struct Curl_easy *data,
                            struct connectdata *conn,
                            bool dead_connection);

#else
#define Curl_ws_request(x,y) CURLE_OK
#define Curl_ws_done(x) Curl_nop_stmt
#endif

#endif /* HEADER_CURL_WS_H */
