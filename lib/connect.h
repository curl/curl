#ifndef HEADER_CURL_CONNECT_H
#define HEADER_CURL_CONNECT_H
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

#include "hostip.h"
#include "curlx/timeval.h"

struct Curl_peer;
struct Curl_str;

enum alpnid Curl_alpn2alpnid(const unsigned char *name, size_t len);

/* generic function that returns how much time there is left to run, according
   to the timeouts set */
timediff_t Curl_timeleft_ms(struct Curl_easy *data);

#define DEFAULT_CONNECT_TIMEOUT 300000 /* milliseconds == five minutes */

#define DEFAULT_SHUTDOWN_TIMEOUT_MS   (2 * 1000)

void Curl_shutdown_start(struct Curl_easy *data, int sockindex,
                         int timeout_ms);

/* return how much time there is left to shutdown the connection at
 * sockindex. Returns 0 if there is no limit or shutdown has not started. */
timediff_t Curl_shutdown_timeleft(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  int sockindex);

/* return how much time there is left to shutdown the connection.
 * Returns 0 if there is no limit or shutdown has not started. */
timediff_t Curl_conn_shutdown_timeleft(struct Curl_easy *data,
                                       struct connectdata *conn);

void Curl_shutdown_clear(struct Curl_easy *data, int sockindex);

/* TRUE iff shutdown has been started */
bool Curl_shutdown_started(struct connectdata *conn, int sockindex);

/*
 * Used to extract socket and connectdata struct for the most recent
 * transfer on the given Curl_easy.
 *
 * The returned socket will be CURL_SOCKET_BAD in case of failure!
 */
curl_socket_t Curl_getconnectinfo(struct Curl_easy *data,
                                  struct connectdata **connp);

/*
 * Curl_conncontrol() manipulates the `conn->bits.close` bit on
 * a connection:
 * - CONNCTRL_CONN_KEEP: clear the bit
 * - CONNCTRL_CONN_CLOSE: set the bit
 * - CONNCTRL_STREAM_CLOSE: set the bit when the connection is not
 *                          multiplexed
 * The call does *NOT* cause any immediate connection close.
 */
#define CONNCTRL_CONN_KEEP       0
#define CONNCTRL_CONN_CLOSE      1
#define CONNCTRL_STREAM_CLOSE    2

void Curl_conncontrol(struct connectdata *conn, int ctrl);

#define streamclose(x) Curl_conncontrol((x), CONNCTRL_STREAM_CLOSE)
#define connclose(x)   Curl_conncontrol((x), CONNCTRL_CONN_CLOSE)
#define connkeep(x)    Curl_conncontrol((x), CONNCTRL_CONN_KEEP)

/**
 * Setup the cfilters at `sockindex` in connection `conn`.
 * If no filter chain is installed yet, inspects the configuration
 * in `data` and `conn` to install a suitable filter chain.
 */
CURLcode Curl_conn_setup(struct Curl_easy *data,
                         struct connectdata *conn,
                         int sockindex,
                         int ssl_mode);

/**
 * Bring the filter chain at `sockindex` for connection `data->conn` into
 * connected state. Which will set `*done` to TRUE.
 * This can be called on an already connected chain with no side effects.
 * When not `blocking`, calls may return without error and `*done != TRUE`,
 * while the individual filters negotiated the connection.
 */
CURLcode Curl_conn_connect(struct Curl_easy *data, int sockindex,
                           bool blocking, bool *done);

/* Set conn to allow multiplexing. */
void Curl_conn_set_multiplex(struct connectdata *conn);

/* Get the origin peer at sockindex. */
struct Curl_peer *Curl_conn_get_origin(struct connectdata *conn,
                                       int sockindex);

/* Get the peer the connection actually connects to at sockindex.
 * Often the same as "origin", but can be redirected via "connect-to"
 * or "alt-svc". May tunnel through proxies. */
struct Curl_peer *Curl_conn_get_destination(struct connectdata *conn,
                                            int sockindex);

/* Get the peer curl connects its socket to.
 * Can be origin, "connect-to" or the first proxy. */
struct Curl_peer *Curl_conn_get_first_peer(struct connectdata *conn,
                                           int sockindex);

#endif /* HEADER_CURL_CONNECT_H */
