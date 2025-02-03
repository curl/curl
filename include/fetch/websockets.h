#ifndef FETCHINC_WEBSOCKETS_H
#define FETCHINC_WEBSOCKETS_H
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

#ifdef  __cplusplus
extern "C" {
#endif

struct fetch_ws_frame {
  int age;              /* zero */
  int flags;            /* See the FETCHWS_* defines */
  fetch_off_t offset;    /* the offset of this data into the frame */
  fetch_off_t bytesleft; /* number of pending bytes left of the payload */
  size_t len;           /* size of the current data chunk */
};

/* flag bits */
#define FETCHWS_TEXT       (1<<0)
#define FETCHWS_BINARY     (1<<1)
#define FETCHWS_CONT       (1<<2)
#define FETCHWS_CLOSE      (1<<3)
#define FETCHWS_PING       (1<<4)
#define FETCHWS_OFFSET     (1<<5)

/*
 * NAME fetch_ws_recv()
 *
 * DESCRIPTION
 *
 * Receives data from the websocket connection. Use after successful
 * fetch_easy_perform() with FETCHOPT_CONNECT_ONLY option.
 */
FETCH_EXTERN FETCHcode fetch_ws_recv(FETCH *fetch, void *buffer, size_t buflen,
                                  size_t *recv,
                                  const struct fetch_ws_frame **metap);

/* flags for fetch_ws_send() */
#define FETCHWS_PONG       (1<<6)

/*
 * NAME fetch_ws_send()
 *
 * DESCRIPTION
 *
 * Sends data over the websocket connection. Use after successful
 * fetch_easy_perform() with FETCHOPT_CONNECT_ONLY option.
 */
FETCH_EXTERN FETCHcode fetch_ws_send(FETCH *fetch, const void *buffer,
                                  size_t buflen, size_t *sent,
                                  fetch_off_t fragsize,
                                  unsigned int flags);

/* bits for the FETCHOPT_WS_OPTIONS bitmask: */
#define FETCHWS_RAW_MODE (1<<0)

FETCH_EXTERN const struct fetch_ws_frame *fetch_ws_meta(FETCH *fetch);

#ifdef  __cplusplus
}
#endif

#endif /* FETCHINC_WEBSOCKETS_H */
