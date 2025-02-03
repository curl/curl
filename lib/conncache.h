#ifndef HEADER_FETCH_CONNCACHE_H
#define HEADER_FETCH_CONNCACHE_H
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

#include <fetch/fetch.h>
#include "timeval.h"

struct connectdata;
struct Fetch_easy;
struct fetch_pollfds;
struct Fetch_waitfds;
struct Fetch_multi;
struct Fetch_share;

/**
 * Callback invoked when disconnecting connections.
 * @param data    transfer last handling the connection, not attached
 * @param conn    the connection to discard
 * @param aborted if the connection is being aborted
 * @return if the connection is being aborted, e.g. should NOT perform
 *         a shutdown and just close.
 **/
typedef bool Fetch_cpool_disconnect_cb(struct Fetch_easy *data,
                                      struct connectdata *conn,
                                      bool aborted);

struct cpool
{
  /* the pooled connections, bundled per destination */
  struct Fetch_hash dest2bundle;
  size_t num_conn;
  fetch_off_t next_connection_id;
  fetch_off_t next_easy_id;
  struct fetchtime last_cleanup;
  struct Fetch_llist shutdowns; /* The connections being shut down */
  struct Fetch_easy *idata;     /* internal handle used for discard */
  struct Fetch_multi *multi;    /* != NULL iff pool belongs to multi */
  struct Fetch_share *share;    /* != NULL iff pool belongs to share */
  Fetch_cpool_disconnect_cb *disconnect_cb;
  BIT(locked);
};

/* Init the pool, pass multi only if pool is owned by it.
 * returns 1 on error, 0 is fine.
 */
int Fetch_cpool_init(struct cpool *cpool,
                    Fetch_cpool_disconnect_cb *disconnect_cb,
                    struct Fetch_multi *multi,
                    struct Fetch_share *share,
                    size_t size);

/* Destroy all connections and free all members */
void Fetch_cpool_destroy(struct cpool *connc);

/* Init the transfer to be used within its connection pool.
 * Assigns `data->id`. */
void Fetch_cpool_xfer_init(struct Fetch_easy *data);

/**
 * Get the connection with the given id from the transfer's pool.
 */
struct connectdata *Fetch_cpool_get_conn(struct Fetch_easy *data,
                                        fetch_off_t conn_id);

FETCHcode Fetch_cpool_add_conn(struct Fetch_easy *data,
                              struct connectdata *conn) WARN_UNUSED_RESULT;

/**
 * Return if the pool has reached its configured limits for adding
 * the given connection. Will try to discard the oldest, idle
 * connections to make space.
 */
#define CPOOL_LIMIT_OK 0
#define CPOOL_LIMIT_DEST 1
#define CPOOL_LIMIT_TOTAL 2
int Fetch_cpool_check_limits(struct Fetch_easy *data,
                            struct connectdata *conn);

/* Return of conn is suitable. If so, stops iteration. */
typedef bool Fetch_cpool_conn_match_cb(struct connectdata *conn,
                                      void *userdata);

/* Act on the result of the find, may override it. */
typedef bool Fetch_cpool_done_match_cb(bool result, void *userdata);

/**
 * Find a connection in the pool matching `destination`.
 * All callbacks are invoked while the pool's lock is held.
 * @param data        current transfer
 * @param destination match agaonst `conn->destination` in pool
 * @param dest_len    destination length, including terminating NUL
 * @param conn_cb     must be present, called for each connection in the
 *                    bundle until it returns TRUE
 * @return combined result of last conn_db and result_cb or FALSE if no
                      connections were present.
 */
bool Fetch_cpool_find(struct Fetch_easy *data,
                     const char *destination, size_t dest_len,
                     Fetch_cpool_conn_match_cb *conn_cb,
                     Fetch_cpool_done_match_cb *done_cb,
                     void *userdata);

/*
 * A connection (already in the pool) is now idle. Do any
 * cleanups in regard to the pool's limits.
 *
 * Return TRUE if idle connection kept in pool, FALSE if closed.
 */
bool Fetch_cpool_conn_now_idle(struct Fetch_easy *data,
                              struct connectdata *conn);

/**
 * Remove the connection from the pool and tear it down.
 * If `aborted` is FALSE, the connection will be shut down first
 * before closing and destroying it.
 * If the shutdown is not immediately complete, the connection
 * will be placed into the pool's shutdown queue.
 */
void Fetch_cpool_disconnect(struct Fetch_easy *data,
                           struct connectdata *conn,
                           bool aborted);

/**
 * This function scans the data's connection pool for half-open/dead
 * connections, closes and removes them.
 * The cleanup is done at most once per second.
 *
 * When called, this transfer has no connection attached.
 */
void Fetch_cpool_prune_dead(struct Fetch_easy *data);

/**
 * Perform upkeep actions on connections in the transfer's pool.
 */
FETCHcode Fetch_cpool_upkeep(void *data);

typedef void Fetch_cpool_conn_do_cb(struct connectdata *conn,
                                   struct Fetch_easy *data,
                                   void *cbdata);

/**
 * Invoke the callback on the pool's connection with the
 * given connection id (if it exists).
 */
void Fetch_cpool_do_by_id(struct Fetch_easy *data,
                         fetch_off_t conn_id,
                         Fetch_cpool_conn_do_cb *cb, void *cbdata);

/**
 * Invoked the callback for the given data + connection under the
 * connection pool's lock.
 * The callback is always invoked, even if the transfer has no connection
 * pool associated.
 */
void Fetch_cpool_do_locked(struct Fetch_easy *data,
                          struct connectdata *conn,
                          Fetch_cpool_conn_do_cb *cb, void *cbdata);

/**
 * Add sockets and POLLIN/OUT flags for connections handled by the pool.
 */
FETCHcode Fetch_cpool_add_pollfds(struct cpool *connc,
                                 struct fetch_pollfds *cpfds);
unsigned int Fetch_cpool_add_waitfds(struct cpool *connc,
                                    struct Fetch_waitfds *cwfds);

void Fetch_cpool_setfds(struct cpool *cpool,
                       fd_set *read_fd_set, fd_set *write_fd_set,
                       int *maxfd);

/**
 * Perform maintenance on connections in the pool. Specifically,
 * progress the shutdown of connections in the queue.
 */
void Fetch_cpool_multi_perform(struct Fetch_multi *multi);

void Fetch_cpool_multi_socket(struct Fetch_multi *multi,
                             fetch_socket_t s, int ev_bitmask);

#endif /* HEADER_FETCH_CONNCACHE_H */
