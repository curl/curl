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

/*
 * All accesses to struct fields and changing of data in the connection cache
 * and connectbundles must be done with the conncache LOCKED. The cache might
 * be shared.
 */

#include <curl/curl.h>
#include "timeval.h"

struct connectdata;
struct curl_pollfds;
struct curl_waitfds;
struct Curl_multi;
struct Curl_share;

struct connshutdowns {
  struct Curl_llist conn_list;  /* The connectdata to shut down */
  BIT(iter_locked);  /* TRUE while iterating the list */
};

struct conncache {
  struct Curl_hash hash;
  size_t num_conn;
  curl_off_t next_connection_id;
  curl_off_t next_easy_id;
  struct curltime last_cleanup;
  struct connshutdowns shutdowns;
  /* handle used for closing cached connections */
  struct Curl_easy *closure_handle;
  struct Curl_multi *multi; /* != NULL iff cache belongs to multi */
  struct Curl_share *share; /* != NULL iff cache belongs to share */
#ifdef DEBUGBUILD
  BIT(locked);
#endif
};

#define BUNDLE_NO_MULTIUSE -1
#define BUNDLE_UNKNOWN     0  /* initial value */
#define BUNDLE_MULTIPLEX   2

#ifdef DEBUGBUILD
/* the debug versions of these macros make extra certain that the lock is
   never doubly locked or unlocked */
#define CONNCACHE_LOCK(x)                                               \
  do {                                                                  \
    if(CURL_SHARE_KEEP_CONNECT((x)->share)) {                           \
      struct conncache *connc = Curl_get_conncache(x);                  \
      Curl_share_lock((x), CURL_LOCK_DATA_CONNECT,                      \
                      CURL_LOCK_ACCESS_SINGLE);                         \
      DEBUGASSERT(!connc->locked);                                      \
      connc->locked = TRUE;                                             \
    }                                                                   \
  } while(0)

#define CONNCACHE_UNLOCK(x)                                             \
  do {                                                                  \
    if(CURL_SHARE_KEEP_CONNECT((x)->share)) {                           \
      struct conncache *connc = Curl_get_conncache(x);                  \
      DEBUGASSERT(connc->locked);                                       \
      connc->locked = FALSE;                                            \
      Curl_share_unlock((x), CURL_LOCK_DATA_CONNECT);                   \
    }                                                                   \
  } while(0)
#else
#define CONNCACHE_LOCK(x) if((x)->share)                                \
    Curl_share_lock((x), CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE)
#define CONNCACHE_UNLOCK(x) if((x)->share)              \
    Curl_share_unlock((x), CURL_LOCK_DATA_CONNECT)
#endif

struct connectbundle {
  int multiuse;                 /* supports multi-use */
  size_t num_connections;       /* Number of connections in the bundle */
  struct Curl_llist conn_list;  /* The connectdata members of the bundle */
};

/* Init the cache, pass multi only if cache is owned by it.
 * returns 1 on error, 0 is fine.
 */
int Curl_conncache_init(struct conncache *,
                        struct Curl_multi *multi,
                        struct Curl_share *share,
                        size_t size);
void Curl_conncache_destroy(struct conncache *connc);

/* Init the transfer to be used with the conncache.
 * Assigns `data->id`.
 */
void Curl_conncache_init_data(struct conncache *connc, struct Curl_easy *data);

/* Return the conncache instance used by `data`.
 * May return NULL for transfers without share or multi handles.
 */
struct conncache *Curl_get_conncache(struct Curl_easy *data);

/* return the correct bundle, to a host or a proxy */
struct connectbundle *Curl_conncache_find_bundle(struct Curl_easy *data,
                                                 struct connectdata *conn);

/* Shrink the cache's bundle for `conn` to have less than
 * `max_host_connections` (if the bundle exists).
 * Returns FALSE iff the limit could not be enforced, e.g. there is a
 * bundle and none of its connections could be discarded.
 */
bool Curl_conncache_shrink_bundle(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  size_t max_host_connections);

/* returns number of connections currently held in the connection cache */
size_t Curl_conncache_size(struct Curl_easy *data);

bool Curl_conncache_return_conn(struct Curl_easy *data,
                                struct connectdata *conn);
CURLcode Curl_conncache_add_conn(struct Curl_easy *data) WARN_UNUSED_RESULT;
void Curl_conncache_remove_conn(struct Curl_easy *data,
                                struct connectdata *conn,
                                bool lock);

struct connectdata *
Curl_conncache_find_first_connection(struct conncache *connc);

struct connectdata *
Curl_conncache_extract_oldest(struct Curl_easy *data);
void Curl_conncache_close_all_connections(struct conncache *connc);
void Curl_conncache_print(struct conncache *connc);

/**
 * Tear down the connection. If `aborted` is FALSE, the connection
 * will be shut down first before discarding. If the shutdown
 * is not immediately complete, the connection
 * will be placed into the cache is shutdown queue.
 */
void Curl_conncache_disconnect(struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted);

/**
 * Add sockets and POLLIN/OUT flags for connections handled by the cache.
 */
CURLcode Curl_conncache_add_pollfds(struct conncache *connc,
                                    struct curl_pollfds *cpfds);
CURLcode Curl_conncache_add_waitfds(struct conncache *connc,
                                    struct curl_waitfds *cwfds);

/**
 * Perform maintenance on connections in the cache. Specifically,
 * progress the shutdown of connections in the queue.
 */
void Curl_conncache_multi_perform(struct Curl_multi *multi);

void Curl_conncache_multi_socket(struct Curl_multi *multi,
                                 curl_socket_t s, int ev_bitmask);

/**
 * Get the connection with the given id.
 * WARNING: this is not safe in shared connection caches.
 */
struct connectdata *Curl_conncache_get_conn(struct conncache *connc,
                                            curl_off_t conn_id);

/**
 * This function scans the data's connection cache for half-open/dead
 * connections, closes and removes them.
 * The cleanup is done at most once per second.
 *
 * When called, this transfer has no connection attached.
 */
void Curl_conncache_prune_dead(struct Curl_easy *data);

/**
 * Perform upkeep actions on connections in the cache.
 */
CURLcode Curl_conncache_upkeep(struct conncache *conn_cache, void *data);

typedef void Curl_conncache_conn_do_cb(struct connectdata *conn,
                                       struct Curl_easy *data,
                                       void *cbdata);

/**
 * Invoke the callback on the data's cached connection with the
 * given connection id (if it exists).
 */
void Curl_conncache_do_by_id(struct Curl_easy *data,
                             curl_off_t conn_id,
                             Curl_conncache_conn_do_cb *cb, void *cbdata);

/**
 * Invoked the callback for the given data + connection under the
 * connection cache's lock.
 * The callback is always invoked, even if the transfer has no connection
 * cache associated.
 */
void Curl_conncache_do_locked(struct Curl_easy *data,
                              struct connectdata *conn,
                              Curl_conncache_conn_do_cb *cb, void *cbdata);

#endif /* HEADER_CURL_CONNCACHE_H */
