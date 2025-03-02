#ifndef HEADER_CURL_CSHUTDN_H
#define HEADER_CURL_CSHUTDN_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Linus Nielsen Feltzing, <linus@haxx.se>
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

#include <curl/curl.h>
#include "timeval.h"

struct connectdata;
struct Curl_easy;
struct curl_pollfds;
struct Curl_waitfds;
struct Curl_multi;
struct Curl_share;

/* Run the shutdown of the connection once.
 * Will shortly attach/detach `data` to `conn` while doing so.
 * `done` will be set TRUE if any error was encountered or if
 * the connection was shut down completely. */
void Curl_cshutdn_run_once(struct Curl_easy *data,
                           struct connectdata *conn,
                           bool *done);

/* Terminates the connection, e.g. closes and destroys it.
 * If `run_shutdown` is TRUE, the shutdown will be run once before
 * terminating it.
 * Takes ownership of `conn`. */
void Curl_cshutdn_terminate(struct Curl_easy *data,
                            struct connectdata *conn,
                            bool run_shutdown);

/* A `cshutdown` is always owned by a multi handle to maintain
 * the connections to be shut down. It registers timers and
 * sockets to monitor via the multi handle. */
struct cshutdn {
  struct Curl_llist list;    /* connections being shut down */
  struct Curl_multi *multi;  /* the multi owning this */
  BIT(initialised);
};

/* Init as part of the given multi handle. */
int Curl_cshutdn_init(struct cshutdn *cshutdn,
                      struct Curl_multi *multi);

/* Terminate all remaining connections and free resources. */
void Curl_cshutdn_destroy(struct cshutdn *cshutdn,
                          struct Curl_easy *data);

/* Number of connections being shut down. */
size_t Curl_cshutdn_count(struct Curl_easy *data);

/* Number of connections to the destination being shut down. */
size_t Curl_cshutdn_dest_count(struct Curl_easy *data,
                               const char *destination);

/* Add a connection to have it shut down. Will terminate the oldest
 * connection when total connection limit of multi is being reached. */
void Curl_cshutdn_add(struct cshutdn *cshutdn,
                      struct connectdata *conn,
                      size_t conns_in_pool);

/* Add sockets and POLLIN/OUT flags for connections being shut down. */
CURLcode Curl_cshutdn_add_pollfds(struct cshutdn *cshutdn,
                                  struct Curl_easy *data,
                                  struct curl_pollfds *cpfds);

unsigned int Curl_cshutdn_add_waitfds(struct cshutdn *cshutdn,
                                      struct Curl_easy *data,
                                      struct Curl_waitfds *cwfds);

void Curl_cshutdn_setfds(struct cshutdn *cshutdn,
                         struct Curl_easy *data,
                         fd_set *read_fd_set, fd_set *write_fd_set,
                         int *maxfd);

/* Run shut down connections using socket. If socket is CURL_SOCKET_TIMEOUT,
 * run maintenance on all connections. */
void Curl_cshutdn_perform(struct cshutdn *cshutdn,
                          struct Curl_easy *data,
                          curl_socket_t s);

#endif /* HEADER_CURL_CSHUTDN_H */
