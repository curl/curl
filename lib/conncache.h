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
#include "uint-bset.h"
#include "uint-table.h"
#include "curlx/timeval.h"

struct connectdata;
struct Curl_easy;
struct curl_pollfds;
struct Curl_waitfds;
struct Curl_multi;
struct Curl_share;

/**
 * Close and destroy the connection.
 * If the connection is in a cpool, remove it.
 * If a `cshutdn` is available (e.g. data has a multi handle),
 * pass the connection to that for controlled shutdown.
 * Otherwise terminate it right away.
 * Takes ownership of `conn`.
 * `data` should not be attached to a connection.
 */
void Curl_conn_close(struct Curl_easy *data,
                     struct connectdata *conn,
                     bool aborted);

struct cpool {
  struct uint32_tbl conns; /* connections added to this pool */
  struct uint32_bset idles; /* pool_ids of conns being idle */
  struct Curl_hash dest2bundle; /* conn destination sets */
  curl_off_t next_connection_id;
  curl_off_t next_easy_id;
  struct curltime last_cleanup;
  struct Curl_share *share; /* != NULL if pool belongs to share */
  BIT(locked);
  BIT(initialized);
  BIT(in_shutdown);
};

/* Get connection pool instance for data or NULL if none exists */
struct cpool *Curl_cpool_get_instance(struct Curl_easy *data);

/* Init the pool, pass multi only if pool is owned by it.
 * Cannot fail.
 */
void Curl_cpool_init(struct cpool *cpool,
                     struct Curl_share *share,
                     size_t size);

/* Destroy all connections and free all members */
void Curl_cpool_destroy(struct cpool *cpool,
                        struct Curl_easy *admin);

/* Init the transfer to be used within its connection pool.
 * Assigns `data->id`. */
void Curl_cpool_xfer_init(struct Curl_easy *data);

/* Get the connection last used by data,
 * if there was one and it still exists. */
struct connectdata *Curl_cpool_get_last_conn(struct Curl_easy *data);

/* Add the connection to the pool. */
CURLcode Curl_cpool_add(struct Curl_easy *data,
                        struct connectdata *conn,
                        uint32_t max_total,
                        uint32_t max_host,
                        const struct curltime *pnow) WARN_UNUSED_RESULT;

/* Connection was used at the given time. */
void Curl_cpool_conn_was_used(struct Curl_easy *data,
                              struct connectdata *conn,
                              const struct curltime *pnow);

/* Return connection age in milliseconds since its creation. */
timediff_t Curl_cpool_conn_age_ms(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  const struct curltime *pnow);

typedef enum {
  CPOOL_MATCH_FOUND, /* The passed `conn` matches, stop looking further */
  CPOOL_MATCH_CONT,  /* No match, continue looking */
  CPOOL_MATCH_CLOSE, /* No match, close `conn`, continue looking */
  CPOOL_MATCH_TOO_OLD /* No match, `conn` is too old, close when idle */
} cpool_match_result;

/* Return of conn is suitable. If so, stops iteration. */
typedef cpool_match_result
 Curl_cpool_conn_match_cb(struct connectdata *conn, void *userdata);

/* Act on the result of the find, may override it. */
typedef bool Curl_cpool_done_match_cb(void *userdata);

/**
 * Find a connection in the pool matching `destination`.
 * All callbacks are invoked while the pool's lock is held.
 * @param data        current transfer
 * @param destination match against `conn->destination` in pool
 * @param prune_dead  perform reaping of dead connections at start
 * @param pnow        timestamp of operation
 * @param conn_cb     must be present, called for each connection in the
 *                    bundle until it returns TRUE
 * @return combined result of last conn_db and result_cb or FALSE if no
                      connections were present.
 */
bool Curl_cpool_find(struct Curl_easy *data,
                     const char *destination,
                     bool prune_dead,
                     const struct curltime *pnow,
                     Curl_cpool_conn_match_cb *conn_cb,
                     Curl_cpool_done_match_cb *done_cb,
                     void *userdata);

/**
 * Perform upkeep actions on connections in the transfer's pool.
 */
CURLcode Curl_cpool_upkeep(struct Curl_easy *data);

typedef enum {
  CPOOL_DO_KEEP, /* Keep the connection, still in use */
  CPOOL_DO_IDLE, /* Connection is idle, may get closed now */
  CPOOL_DO_CLOSE, /* Close the connection (clean) */
  CPOOL_DO_TERMINATE /* Terminate the connection (unclean) */
} cpool_do_result;

typedef cpool_do_result Curl_cpool_return_cb(struct Curl_easy *data,
                                             struct connectdata *conn,
                                             void *cbdata,
                                             const struct curltime *pnow);

/**
 * Invoked the callback for the given data + connection under the
 * connection pool's lock.
 * The callback is always invoked, even if the transfer has no connection
 * pool associated.
 */
void Curl_cpool_return(struct Curl_easy *data,
                       struct connectdata *conn,
                       Curl_cpool_return_cb *cb, void *cbdata,
                       const struct curltime *pnow);

/* Close all unused connections, prevent reuse of existing ones. */
void Curl_cpool_nw_changed(struct cpool *cpool, struct Curl_easy *admin);

/* Return TRUE iff the given connection is considered healthy, e.g.
 * usable for more transfers. */
bool Curl_cpool_conn_seems_healthy(struct connectdata *conn,
                                   struct Curl_easy *data,
                                   const struct curltime *pnow);

#endif /* HEADER_CURL_CONNCACHE_H */
