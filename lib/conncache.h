#ifndef HEADER_CURL_CONNCACHE_H
#define HEADER_CURL_CONNCACHE_H
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
#include "curlx/timeval.h"

struct connectdata;
struct Curl_easy;
struct curl_pollfds;
struct Curl_waitfds;
struct Curl_multi;
struct Curl_share;

/**
 * Terminate the connection, e.g. close and destroy.
 * If the connection is in a cpool, remove it.
 * If a `cshutdn` is available (e.g. data has a multi handle),
 * pass the connection to that for controlled shutdown.
 * Otherwise terminate it right away.
 * Takes ownership of `conn`.
 * `data` should not be attached to a connection.
 */
void Curl_conn_terminate(struct Curl_easy *data,
                         struct connectdata *conn,
                         bool aborted);

struct cpool {
   /* the pooled connections, bundled per destination */
  struct Curl_hash dest2bundle;
  size_t num_conn;
  curl_off_t next_connection_id;
  curl_off_t next_easy_id;
  struct curltime last_cleanup;
  struct Curl_easy *idata; /* internal handle for maintenance */
  struct Curl_share *share; /* != NULL if pool belongs to share */
  BIT(locked);
  BIT(initialised);
};

/* Init the pool, pass multi only if pool is owned by it.
 * Cannot fail.
 */
void Curl_cpool_init(struct cpool *cpool,
                     struct Curl_easy *idata,
                     struct Curl_share *share,
                     size_t size);

/* Destroy all connections and free all members */
void Curl_cpool_destroy(struct cpool *connc);

/* Init the transfer to be used within its connection pool.
 * Assigns `data->id`. */
void Curl_cpool_xfer_init(struct Curl_easy *data);

/* Get the connection with the given id from `data`'s conn pool. */
struct connectdata *Curl_cpool_get_conn(struct Curl_easy *data,
                                        curl_off_t conn_id);

/* Add the connection to the pool. */
CURLcode Curl_cpool_add(struct Curl_easy *data,
                        struct connectdata *conn) WARN_UNUSED_RESULT;

/**
 * Return if the pool has reached its configured limits for adding
 * the given connection. Will try to discard the oldest, idle
 * connections to make space.
 */
#define CPOOL_LIMIT_OK     0
#define CPOOL_LIMIT_DEST   1
#define CPOOL_LIMIT_TOTAL  2
int Curl_cpool_check_limits(struct Curl_easy *data,
                            struct connectdata *conn);

/* Return of conn is suitable. If so, stops iteration. */
typedef bool Curl_cpool_conn_match_cb(struct connectdata *conn,
                                      void *userdata);

/* Act on the result of the find, may override it. */
typedef bool Curl_cpool_done_match_cb(bool result, void *userdata);

/**
 * Find a connection in the pool matching `destination`.
 * All callbacks are invoked while the pool's lock is held.
 * @param data        current transfer
 * @param destination match against `conn->destination` in pool
 * @param conn_cb     must be present, called for each connection in the
 *                    bundle until it returns TRUE
 * @return combined result of last conn_db and result_cb or FALSE if no
                      connections were present.
 */
bool Curl_cpool_find(struct Curl_easy *data,
                     const char *destination,
                     Curl_cpool_conn_match_cb *conn_cb,
                     Curl_cpool_done_match_cb *done_cb,
                     void *userdata);

/*
 * A connection (already in the pool) is now idle. Do any
 * cleanups in regard to the pool's limits.
 *
 * Return TRUE if idle connection kept in pool, FALSE if closed.
 */
bool Curl_cpool_conn_now_idle(struct Curl_easy *data,
                              struct connectdata *conn);

/**
 * This function scans the data's connection pool for half-open/dead
 * connections, closes and removes them.
 * The cleanup is done at most once per second.
 *
 * When called, this transfer has no connection attached.
 */
void Curl_cpool_prune_dead(struct Curl_easy *data);

/**
 * Perform upkeep actions on connections in the transfer's pool.
 */
CURLcode Curl_cpool_upkeep(void *data);

typedef void Curl_cpool_conn_do_cb(struct connectdata *conn,
                                   struct Curl_easy *data,
                                   void *cbdata);

/**
 * Invoke the callback on the pool's connection with the
 * given connection id (if it exists).
 */
void Curl_cpool_do_by_id(struct Curl_easy *data,
                         curl_off_t conn_id,
                         Curl_cpool_conn_do_cb *cb, void *cbdata);

/**
 * Invoked the callback for the given data + connection under the
 * connection pool's lock.
 * The callback is always invoked, even if the transfer has no connection
 * pool associated.
 */
void Curl_cpool_do_locked(struct Curl_easy *data,
                          struct connectdata *conn,
                          Curl_cpool_conn_do_cb *cb, void *cbdata);

/* Close all unused connections, prevent reuse of existing ones. */
void Curl_cpool_nw_changed(struct Curl_easy *data);


#endif /* HEADER_CURL_CONNCACHE_H */
