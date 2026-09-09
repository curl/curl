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
struct connectdata;
struct Curl_easy;
struct curl_pollfds;
struct Curl_waitfds;
struct Curl_multi;
struct Curl_share;
struct Curl_sigpipe_ctx;


/* Terminates the connection, e.g. closes and destroys it.
 * If `do_shutdown` is TRUE, the shutdown will be run once.
 * Takes ownership of `conn`. `conn` MUST no longer be in
 * a pool or on a shutdown list. */
void Curl_cshutdn_terminate(struct Curl_easy *admin,
                            struct connectdata *conn,
                            bool do_shutdown);

/* Start the shutdown timer,
 * marks the connection sockindex as being shut down. */
void Curl_cshutdn_start_timer(struct Curl_easy *data, int8_t sockindex,
                              int timeout_ms);
/* Clear the shutdown timer at sockindex again. */
void Curl_cshutdn_clear_timer(struct Curl_easy *data, int8_t sockindex);

/* return how much time there is left to shutdown the connection at
 * sockindex. Returns 0 if there is no limit or shutdown has not started. */
timediff_t Curl_cshutdn_timeleft_ms(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int8_t sockindex);

/* TRUE iff shutdown at sockindex has been started */
bool Curl_cshutdn_has_started(struct connectdata *conn, int8_t sockindex);

/* Shutdown the connection at `sockindex` non-blocking.
 * Will start the shutdown timer if not already set.
 * Return CURLE_OK and *done == FALSE if not finished. */
CURLcode Curl_cshutdn_try_once_idx(struct Curl_easy *data,
                                   int8_t sockindex, bool *done);

/* Run the shutdown of the connection once non-blocking for both
 * socket indices. Will start the shutdown timer if not already set.
 * Shortly attach/detach the admin handle to `conn` while doing so.
 * `done` will be set TRUE if any error was encountered or if
 * the connection was shut down completely. */
void Curl_cshutdn_try_once(struct Curl_easy *admin,
                           struct connectdata *conn, bool *done);

/* A `cshutdown` is always owned by a multi handle to maintain
 * the connections to be shut down. It registers timers and
 * sockets to monitor via the multi handle. */
struct cshutdn {
  struct Curl_llist list;    /* connections being shut down */
};

/* Init as part of the given multi handle. */
void Curl_cshutdn_init(struct cshutdn *cshutdn);

/* Terminate all remaining connections and free resources. */
void Curl_cshutdn_destroy(struct cshutdn *cshutdn,
                          struct Curl_easy *admin);

/* Number of connections being shut down. */
size_t Curl_cshutdn_count(struct cshutdn *cshutdn);

/* Number of connections to the destination being shut down. */
size_t Curl_cshutdn_dest_count(struct cshutdn *cshutdn,
                               const char *destination);

/* Close the oldest connection in shutdown to destination or,
 * when destination is NULL for any destination.
 * Return TRUE if a connection has been closed. */
bool Curl_cshutdn_close_oldest(struct cshutdn *cshutdn,
                               struct Curl_easy *admin,
                               const char *destination);

/* Add a connection to have it shut down. Terminate the oldest
 * connection when shutdowns exceed max_shutdowns. */
void Curl_cshutdn_add(struct cshutdn *cshutdn,
                      struct Curl_multi *multi,
                      struct connectdata *conn,
                      size_t max_shutdowns);

/* Add sockets and POLLIN/OUT flags for connections being shut down. */
CURLcode Curl_cshutdn_add_pollfds(struct cshutdn *cshutdn,
                                  struct Curl_easy *admin,
                                  struct curl_pollfds *cpfds);

unsigned int Curl_cshutdn_add_waitfds(struct cshutdn *cshutdn,
                                      struct Curl_easy *admin,
                                      struct Curl_waitfds *cwfds);

void Curl_cshutdn_setfds(struct cshutdn *cshutdn,
                         struct Curl_easy *admin,
                         fd_set *read_fd_set, fd_set *write_fd_set,
                         int *maxfd);

/* Run maintenance on all connections. */
void Curl_cshutdn_perform(struct cshutdn *cshutdn,
                          struct Curl_easy *admin,
                          struct Curl_sigpipe_ctx *sigpipe_ctx);

#endif /* HEADER_CURL_CSHUTDN_H */
