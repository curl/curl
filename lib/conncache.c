/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Linus Nielsen Feltzing, <linus@haxx.se>
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

#include <curl/curl.h>

#include "urldata.h"
#include "url.h"
#include "cfilters.h"
#include "progress.h"
#include "multiif.h"
#include "sendf.h"
#include "conncache.h"
#include "http_negotiate.h"
#include "http_ntlm.h"
#include "share.h"
#include "sigpipe.h"
#include "connect.h"
#include "select.h"
#include "strcase.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#ifdef DEBUGBUILD
/* the debug versions of these macros make extra certain that the lock is
   never doubly locked or unlocked */
#define CONNC_LOCK(c)                                                   \
  do {                                                                  \
    if((c) && CURL_SHARE_KEEP_CONNECT((c)->share)) {                    \
      Curl_share_lock(((c)->closure_handle), CURL_LOCK_DATA_CONNECT,    \
                      CURL_LOCK_ACCESS_SINGLE);                         \
      DEBUGASSERT(!(c)->locked);                                        \
      (c)->locked = TRUE;                                               \
    }                                                                   \
  } while(0)

#define CONNC_UNLOCK(c)                                                 \
  do {                                                                  \
    if((c) && CURL_SHARE_KEEP_CONNECT((c)->share)) {                    \
      DEBUGASSERT((c)->locked);                                         \
      (c)->locked = FALSE;                                              \
      Curl_share_unlock((c)->closure_handle, CURL_LOCK_DATA_CONNECT);   \
    }                                                                   \
  } while(0)

#else
#define CONNC_LOCK(c) if((c) && CURL_SHARE_KEEP_CONNECT((c)->share))    \
    Curl_share_lock((c)->closure_handle, CURL_LOCK_DATA_CONNECT,        \
                    CURL_LOCK_ACCESS_SINGLE)
#define CONNC_UNLOCK(c) if((c) && CURL_SHARE_KEEP_CONNECT((c)->share))  \
    Curl_share_unlock((c)->closure_handle, CURL_LOCK_DATA_CONNECT)
#endif /* !DEBUG_BUILD */

static void connc_discard_conn(struct conncache *connc,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted);
static void connc_close_and_destroy(struct conncache *connc,
                                    struct connectdata *conn,
                                    struct Curl_easy *data,
                                    bool do_shutdown);
static void connc_run_conn_shutdown(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    bool *done);
static void connc_run_conn_shutdown_handler(struct Curl_easy *data,
                                            struct connectdata *conn);
static CURLMcode connc_update_shutdown_ev(struct Curl_multi *multi,
                                          struct Curl_easy *data,
                                          struct connectdata *conn);
static void connc_shutdown_all(struct conncache *connc,
                               struct Curl_easy *data, int timeout_ms);
static void connc_close_and_destroy_all(struct conncache *connc);

static CURLcode bundle_create(struct connectbundle **bundlep)
{
  DEBUGASSERT(*bundlep == NULL);
  *bundlep = malloc(sizeof(struct connectbundle));
  if(!*bundlep)
    return CURLE_OUT_OF_MEMORY;

  (*bundlep)->num_connections = 0;
  Curl_llist_init(&(*bundlep)->conn_list, NULL);
  return CURLE_OK;
}

static void bundle_destroy(struct connectbundle *bundle)
{
  DEBUGASSERT(!Curl_llist_count(&bundle->conn_list));
  free(bundle);
}

/* Add a connection to a bundle */
static void bundle_add_conn(struct connectbundle *bundle,
                            struct connectdata *conn)
{
  Curl_llist_append(&bundle->conn_list, conn, &conn->conncache_node);
  conn->bits.in_conncache = TRUE;
  bundle->num_connections++;
}

/* Remove a connection from a bundle */
static int bundle_remove_conn(struct connectbundle *bundle,
                              struct connectdata *conn)
{
  struct Curl_llist_node *curr = Curl_llist_head(&bundle->conn_list);
  while(curr) {
    if(Curl_node_elem(curr) == conn) {
      Curl_node_remove(curr);
      bundle->num_connections--;
      conn->bits.in_conncache = FALSE;
      return 1; /* we removed a handle */
    }
    curr = Curl_node_next(curr);
  }
  DEBUGASSERT(0);
  return 0;
}

static void free_bundle_hash_entry(void *freethis)
{
  struct connectbundle *b = (struct connectbundle *) freethis;

  bundle_destroy(b);
}

int Curl_conncache_init(struct conncache *connc,
                        struct Curl_multi *multi,
                        struct Curl_share *share,
                        size_t size)
{
  DEBUGASSERT(!!multi != !!share); /* either one */
  Curl_hash_init(&connc->key2bundle, size, Curl_hash_str,
                 Curl_str_key_compare, free_bundle_hash_entry);
  Curl_llist_init(&connc->shutdowns.conn_list, NULL);

  /* allocate a new easy handle to use when closing cached connections */
  connc->closure_handle = curl_easy_init();
  if(!connc->closure_handle)
    return 1; /* bad */
  connc->closure_handle->state.internal = true;
  /* TODO: this is quirky. We need an internal handle for certain
   * operations, but we do not add it to the multi (if there is one).
   * But we give it the multi so that socket event operations can work.
   * Probably better to have an internal handle owned by the multi that
   * can be used for conncache operations. */
  connc->closure_handle->multi = multi;
 #ifdef DEBUGBUILD
  if(getenv("CURL_DEBUG"))
    connc->closure_handle->set.verbose = true;
#endif

  connc->closure_handle->multi = connc->multi = multi;
  connc->closure_handle->share = connc->share = share;

  return 0; /* good */
}

void Curl_conncache_destroy(struct conncache *connc)
{
  if(connc) {
    if(connc->closure_handle) {
      connc_close_and_destroy_all(connc);
      /* The internal closure handle is special and we need to
       * disconnect it from multi/share before closing it down. */
      connc->closure_handle->multi = NULL;
      connc->closure_handle->share = NULL;
      Curl_close(&connc->closure_handle);
    }
    Curl_hash_destroy(&connc->key2bundle);
    connc->multi = NULL;
  }
}

struct conncache *Curl_get_conncache(struct Curl_easy *data)
{
  if(data) {
    if(CURL_SHARE_KEEP_CONNECT(data->share))
      return &data->share->conn_cache;
    else if(data->multi_easy)
      return &data->multi_easy->conn_cache;
    else if(data->multi)
      return &data->multi->conn_cache;
  }
  return NULL;
}

void Curl_conncache_init_data(struct conncache *connc, struct Curl_easy *data)
{
  CONNC_LOCK(connc);
  /* the identifier inside the connection cache */
  data->id = connc->next_easy_id++;
  if(connc->next_easy_id <= 0)
    connc->next_easy_id = 0;
  data->state.lastconnect_id = -1;

  /* The closure handle only ever has default timeouts set. To improve the
     state somewhat we clone the timeouts from each added handle so that the
     closure handle always has the same timeouts as the most recently added
     easy handle. */
  connc->closure_handle->set.timeout = data->set.timeout;
  connc->closure_handle->set.server_response_timeout =
    data->set.server_response_timeout;
  connc->closure_handle->set.no_signal = data->set.no_signal;

  CONNC_UNLOCK(connc);
}

/* Returns number of connections currently held in the connection cache.
   Locks/unlocks the cache itself!
*/
size_t Curl_conncache_size(struct Curl_easy *data)
{
  struct conncache *connc = Curl_get_conncache(data);
  size_t num = 0;
  if(connc) {
    CONNC_LOCK(connc);
    num = connc->num_conn;
    CONNC_UNLOCK(connc);
  }
  return num;
}

static struct connectbundle *connc_find_bundle(struct conncache *connc,
                                               struct connectdata *conn)
{
  return Curl_hash_pick(&connc->key2bundle,
                        conn->destination, conn->destination_len);
}

static struct connectbundle *
connc_add_bundle(struct conncache *connc, struct connectdata *conn)
{
  struct connectbundle *bundle = NULL;

  if(bundle_create(&bundle))
    return NULL;

  if(!Curl_hash_add(&connc->key2bundle, conn->destination,
                    conn->destination_len, bundle)) {
    bundle_destroy(bundle);
    return NULL;
  }
  return bundle;
}

static void connc_remove_bundle(struct conncache *connc,
                                struct connectbundle *bundle)
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;

  if(!connc)
    return;

  Curl_hash_start_iterate(&connc->key2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    if(he->ptr == bundle) {
      /* The bundle is destroyed by the hash destructor function,
         free_bundle_hash_entry() */
      Curl_hash_delete(&connc->key2bundle, he->key, he->key_len);
      return;
    }

    he = Curl_hash_next_element(&iter);
  }
}

static struct connectdata *
connc_extract_bundle(struct Curl_easy *data, struct connectbundle *bundle);

bool Curl_conncache_shrink_bundle(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  size_t max_host_connections)
{
  struct conncache *connc = Curl_get_conncache(data);
  struct connectbundle *bundle;
  bool space_available = TRUE;

  if(connc && max_host_connections > 0) {
    while(1) {
      struct connectdata *conn_candidate = NULL;

      CONNC_LOCK(connc);
      bundle = connc_find_bundle(connc, conn);
      if(bundle && (bundle->num_connections >= max_host_connections)) {
        /* The bundle is full. Extract the oldest connection that may
         * be removed now, if there is one. */
        conn_candidate = connc_extract_bundle(data, bundle);
        space_available = FALSE;
      }
      else
        space_available = TRUE;
      CONNC_UNLOCK(connc);

      if(!conn_candidate)
        break;
      /* disconnect the old conn and continue */
      Curl_disconnect(data, conn_candidate, FALSE);
    }
  }
  return space_available;
}

CURLcode Curl_conncache_add_conn(struct Curl_easy *data,
                                 struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct connectbundle *bundle = NULL;
  struct conncache *connc = Curl_get_conncache(data);
  DEBUGASSERT(conn);
  DEBUGASSERT(connc);

  if(!connc)
    return CURLE_FAILED_INIT;

  CONNC_LOCK(connc);
  bundle = connc_find_bundle(connc, conn);
  if(!bundle) {
    bundle = connc_add_bundle(connc, conn);
    if(!bundle) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  bundle_add_conn(bundle, conn);
  conn->connection_id = connc->next_connection_id++;
  connc->num_conn++;
  DEBUGF(infof(data, "Added connection %" CURL_FORMAT_CURL_OFF_T ". "
               "The cache now contains %zu members",
               conn->connection_id, connc->num_conn));
out:
  CONNC_UNLOCK(connc);

  return result;
}

static void connc_remove_conn(struct conncache *connc,
                              struct connectdata *conn)
{
  if(conn->bits.in_conncache) {
    /* if the connection is marked, the bundle MUST exist. */
    struct connectbundle *bundle = connc_find_bundle(connc, conn);
    DEBUGASSERT(bundle);
    if(bundle) {
      DEBUGASSERT(conn->bits.in_conncache);
      bundle_remove_conn(bundle, conn);
      if(connc && bundle->num_connections == 0)
        connc_remove_bundle(connc, bundle);
      conn->bits.in_conncache = FALSE;
      if(connc)
        connc->num_conn--;
    }
  }
}

/*
 * Removes the connectdata object from the connection cache, but the transfer
 * still owns this connection.
 *
 * Pass TRUE/FALSE in the 'lock' argument depending on if the parent function
 * already holds the lock or not.
 */
void Curl_conncache_remove_conn(struct Curl_easy *data,
                                struct connectdata *conn, bool lock)
{
  struct conncache *connc = Curl_get_conncache(data);

  DEBUGASSERT(connc);
  if(!connc)
    return;

  if(lock)
    CONNC_LOCK(connc);
  connc_remove_conn(connc, conn);
  if(lock)
    CONNC_UNLOCK(connc);
  if(connc)
    DEBUGF(infof(data, "The cache now contains %zu members",
                 connc->num_conn));
}

/* This function iterates the entire connection cache and calls the function
   func() with the connection pointer as the first argument and the supplied
   'param' argument as the other.

   The conncache lock is still held when the callback is called. It needs it,
   so that it can safely continue traversing the lists once the callback
   returns.

   Returns TRUE if the loop was aborted due to the callback's return code.

   Return 0 from func() to continue the loop, return 1 to abort it.
 */
static bool connc_foreach(struct Curl_easy *data,
                          struct conncache *connc,
                          void *param,
                          int (*func)(struct Curl_easy *data,
                                      struct connectdata *conn, void *param))
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;

  if(!connc)
    return FALSE;

  CONNC_LOCK(connc);
  Curl_hash_start_iterate(&connc->key2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct Curl_llist_node *curr;
    struct connectbundle *bundle = he->ptr;
    he = Curl_hash_next_element(&iter);

    curr = Curl_llist_head(&bundle->conn_list);
    while(curr) {
      /* Yes, we need to update curr before calling func(), because func()
         might decide to remove the connection */
      struct connectdata *conn = Curl_node_elem(curr);
      curr = Curl_node_next(curr);

      if(1 == func(data, conn, param)) {
        CONNC_UNLOCK(connc);
        return TRUE;
      }
    }
  }
  CONNC_UNLOCK(connc);
  return FALSE;
}

/* Return the first connection found in the cache. Used when closing all
   connections.

   NOTE: no locking is done here as this is presumably only done when cleaning
   up a cache!
*/
static struct connectdata *
connc_find_first_connection(struct conncache *connc)
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;
  struct connectbundle *bundle;

  Curl_hash_start_iterate(&connc->key2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct Curl_llist_node *curr;
    bundle = he->ptr;

    curr = Curl_llist_head(&bundle->conn_list);
    if(curr) {
      return Curl_node_elem(curr);
    }

    he = Curl_hash_next_element(&iter);
  }

  return NULL;
}

/*
 * A connection (already in the cache) has become idle. Do any
 * cleanups in regard to the cache's limits.
 *
 * Return TRUE if idle connection kept in cache, FALSE if closed.
 */
bool Curl_conncache_conn_is_idle(struct Curl_easy *data,
                                 struct connectdata *conn)
{
  unsigned int maxconnects = !data->multi->maxconnects ?
    data->multi->num_easy * 4: data->multi->maxconnects;
  struct connectdata *oldest_idle = NULL;
  struct conncache *connc = Curl_get_conncache(data);

  conn->lastused = Curl_now(); /* it was used up until now */
  if(connc && maxconnects && Curl_conncache_size(data) > maxconnects) {
    infof(data, "Connection cache is full, closing the oldest one");

    oldest_idle = Curl_conncache_remove_oldest_idle(data);
    if(oldest_idle) {
      /* Use the closure handle for this disconnect so that anything that
         happens during the disconnect is not stored and associated with the
         'data' handle which already just finished a transfer and it is
         important that details from this (unrelated) disconnect does not
         taint meta-data in the data handle. */
      connc_close_and_destroy(connc, oldest_idle, NULL, TRUE);
    }
  }

  return (oldest_idle == conn) ? FALSE : TRUE;

}

/*
 * This function finds the connection in the connection bundle that has been
 * unused for the longest time.
 *
 * Does not lock the connection cache!
 *
 * Returns the pointer to the oldest idle connection, or NULL if none was
 * found.
 */
static struct connectdata *
connc_extract_bundle(struct Curl_easy *data, struct connectbundle *bundle)
{
  struct conncache *connc = Curl_get_conncache(data);
  struct Curl_llist_node *curr;
  timediff_t highscore = -1;
  timediff_t score;
  struct curltime now;
  struct connectdata *conn_candidate = NULL;
  struct connectdata *conn;

  (void)data;
  DEBUGASSERT(connc);

  now = Curl_now();

  curr = Curl_llist_head(&bundle->conn_list);
  while(curr) {
    conn = Curl_node_elem(curr);

    if(!CONN_INUSE(conn)) {
      /* Set higher score for the age passed since the connection was used */
      score = Curl_timediff(now, conn->lastused);

      if(score > highscore) {
        highscore = score;
        conn_candidate = conn;
      }
    }
    curr = Curl_node_next(curr);
  }
  if(conn_candidate) {
    /* remove it to prevent another thread from nicking it */
    bundle_remove_conn(bundle, conn_candidate);
    connc->num_conn--;
    DEBUGF(infof(data, "The cache now contains %zu members", connc->num_conn));
  }

  return conn_candidate;
}

/*
 * This function finds the connection in the connection cache that has been
 * unused for the longest time and extracts that from the bundle.
 *
 * Returns the pointer to the connection, or NULL if none was found.
 */
struct connectdata *
Curl_conncache_remove_oldest_idle(struct Curl_easy *data)
{
  struct conncache *connc = Curl_get_conncache(data);
  struct Curl_hash_iterator iter;
  struct Curl_llist_node *curr;
  struct Curl_hash_element *he;
  timediff_t highscore =- 1;
  timediff_t score;
  struct curltime now;
  struct connectdata *conn_candidate = NULL;
  struct connectbundle *bundle;
  struct connectbundle *bundle_candidate = NULL;

  DEBUGASSERT(connc);
  if(!connc)
    return NULL;

  now = Curl_now();

  CONNC_LOCK(connc);
  Curl_hash_start_iterate(&connc->key2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectdata *conn;

    bundle = he->ptr;

    curr = Curl_llist_head(&bundle->conn_list);
    while(curr) {
      conn = Curl_node_elem(curr);

      if(!CONN_INUSE(conn) && !conn->bits.close &&
         !conn->connect_only) {
        /* Set higher score for the age passed since the connection was used */
        score = Curl_timediff(now, conn->lastused);

        if(score > highscore) {
          highscore = score;
          conn_candidate = conn;
          bundle_candidate = bundle;
        }
      }
      curr = Curl_node_next(curr);
    }

    he = Curl_hash_next_element(&iter);
  }
  if(conn_candidate) {
    /* remove it to prevent another thread from nicking it */
    bundle_remove_conn(bundle_candidate, conn_candidate);
    connc->num_conn--;
    DEBUGF(infof(data, "The cache now contains %zu members",
                 connc->num_conn));
  }
  CONNC_UNLOCK(connc);

  return conn_candidate;
}

bool Curl_conncache_find_conn(struct Curl_easy *data,
                              const char *destination, size_t dest_len,
                              Curl_conncache_conn_match_cb *conn_cb,
                              Curl_conncache_done_match_cb *done_cb,
                              void *userdata)
{
  struct conncache *connc = Curl_get_conncache(data);
  struct connectbundle *bundle;
  bool result = FALSE;

  DEBUGASSERT(connc);
  DEBUGASSERT(conn_cb);
  if(!connc)
    return FALSE;

  CONNC_LOCK(connc);
  bundle = Curl_hash_pick(&connc->key2bundle, (void *)destination, dest_len);
  if(bundle) {
    struct Curl_llist_node *curr = Curl_llist_head(&bundle->conn_list);
    while(curr) {
      struct connectdata *conn = Curl_node_elem(curr);
      /* Get next node now. The callback might discard the current
       * element */
      curr = Curl_node_next(curr);

      if(conn_cb(conn, userdata)) {
        result = TRUE;
        break;
      }
    }
  }

  if(done_cb) {
    result = done_cb(result, userdata);
  }
  CONNC_UNLOCK(connc);
  return result;
}

static void connc_shutdown_discard_all(struct conncache *connc)
{
  struct Curl_llist_node *e = Curl_llist_head(&connc->shutdowns.conn_list);
  struct connectdata *conn;

  if(!e)
    return;

  DEBUGF(infof(connc->closure_handle, "conncache_shutdown_discard_all"));
  DEBUGASSERT(!connc->shutdowns.iter_locked);
  connc->shutdowns.iter_locked = TRUE;
  while(e) {
    conn = Curl_node_elem(e);
    Curl_node_remove(e);
    DEBUGF(infof(connc->closure_handle, "discard connection #%"
                 CURL_FORMAT_CURL_OFF_T, conn->connection_id));
    connc_close_and_destroy(connc, conn, NULL, FALSE);
    e = Curl_llist_head(&connc->shutdowns.conn_list);
  }
  connc->shutdowns.iter_locked = FALSE;
}

static void connc_close_and_destroy_all(struct conncache *connc)
{
  struct Curl_easy *idata = connc->closure_handle;
  struct connectdata *conn;
  int timeout_ms = 0;
  SIGPIPE_VARIABLE(pipe_st);

  if(!idata)
    return;

  /* Move all connections to the shutdown list */
  sigpipe_init(&pipe_st);
  CONNC_LOCK(connc);
  conn = connc_find_first_connection(connc);
  while(conn) {
    connc_remove_conn(connc, conn);
    sigpipe_apply(connc->closure_handle, &pipe_st);
    /* This will remove the connection from the cache */
    connclose(conn, "kill all");
    Curl_conncache_remove_conn(idata, conn, FALSE);
    connc_discard_conn(connc, idata, conn, FALSE);

    conn = connc_find_first_connection(connc);
  }
  CONNC_UNLOCK(connc);

    /* Just for testing, run graceful shutdown */
#ifdef DEBUGBUILD
  {
    char *p = getenv("CURL_GRACEFUL_SHUTDOWN");
    if(p) {
      long l = strtol(p, NULL, 10);
      if(l > 0 && l < INT_MAX)
        timeout_ms = (int)l;
    }
  }
#endif
  sigpipe_apply(idata, &pipe_st);
  connc_shutdown_all(connc, idata, timeout_ms);

  /* discard all connections in the shutdown list */
  connc_shutdown_discard_all(connc);

  sigpipe_apply(idata, &pipe_st);
  Curl_hostcache_clean(idata, idata->dns.hostcache);
  sigpipe_restore(&pipe_st);
}


static void connc_shutdown_destroy_oldest(struct conncache *connc)
{
  struct Curl_llist_node *e;
  struct connectdata *conn;

  DEBUGASSERT(!connc->shutdowns.iter_locked);
  if(connc->shutdowns.iter_locked)
    return;

  e = Curl_llist_head(&connc->shutdowns.conn_list);
  if(e) {
    SIGPIPE_VARIABLE(pipe_st);
    conn = Curl_node_elem(e);
    Curl_node_remove(e);
    sigpipe_init(&pipe_st);
    sigpipe_apply(connc->closure_handle, &pipe_st);
    connc_close_and_destroy(connc, conn, NULL, FALSE);
    sigpipe_restore(&pipe_st);
  }
}

static void connc_discard_conn(struct conncache *connc,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted)
{
  bool done = FALSE;

  DEBUGASSERT(data);
  DEBUGASSERT(connc);
  DEBUGASSERT(!conn->bits.in_conncache);

  /*
   * If this connection is not marked to force-close, leave it open if there
   * are other users of it
   */
  if(CONN_INUSE(conn) && !aborted) {
    DEBUGF(infof(data, "[CCACHE] not discarding #%" CURL_FORMAT_CURL_OFF_T
                       " still in use by %zu transfers", conn->connection_id,
                       CONN_INUSE(conn)));
    return;
  }

  /* treat the connection as aborted in CONNECT_ONLY situations, we do
   * not know what the APP did with it. */
  if(conn->connect_only)
    aborted = TRUE;
  conn->bits.aborted = aborted;

  /* We do not shutdown dead connections. The term 'dead' can be misleading
   * here, as we also mark errored connections/transfers as 'dead'.
   * If we do a shutdown for an aborted transfer, the server might think
   * it was successful otherwise (for example an ftps: upload). This is
   * not what we want. */
  if(aborted)
    done = TRUE;
  if(!done) {
    /* Attempt to shutdown the connection right away. */
    Curl_attach_connection(data, conn);
    connc_run_conn_shutdown(data, conn, &done);
    DEBUGF(infof(data, "[CCACHE] shutdown #%" CURL_FORMAT_CURL_OFF_T
                       ", done=%d",conn->connection_id, done));
    Curl_detach_connection(data);
  }

  if(done) {
    connc_close_and_destroy(connc, conn, data, FALSE);
    return;
  }

  DEBUGASSERT(!connc->shutdowns.iter_locked);
  if(connc->shutdowns.iter_locked) {
    DEBUGF(infof(data, "[CCACHE] discarding #%" CURL_FORMAT_CURL_OFF_T
                       ", list locked", conn->connection_id));
    connc_close_and_destroy(connc, conn, data, FALSE);
    return;
  }

  /* Add the connection to our shutdown list for non-blocking shutdown
   * during multi processing. */
  if(data->multi && data->multi->max_shutdown_connections > 0 &&
     (data->multi->max_shutdown_connections >=
      (long)Curl_llist_count(&connc->shutdowns.conn_list))) {
    DEBUGF(infof(data, "[CCACHE] discarding oldest shutdown connection "
                       "due to limit of %ld",
                       data->multi->max_shutdown_connections));
    connc_shutdown_destroy_oldest(connc);
  }

  if(data->multi && data->multi->socket_cb) {
    DEBUGASSERT(connc == &data->multi->conn_cache);
    /* Start with an empty shutdown pollset, so out internal closure handle
     * is added to the sockets. */
    memset(&conn->shutdown_poll, 0, sizeof(conn->shutdown_poll));
    if(connc_update_shutdown_ev(data->multi, connc->closure_handle, conn)) {
      DEBUGF(infof(data, "[CCACHE] update events for shutdown failed, "
                         "discarding #%" CURL_FORMAT_CURL_OFF_T,
                         conn->connection_id));
      connc_close_and_destroy(connc, conn, data, FALSE);
      return;
    }
  }

  Curl_llist_append(&connc->shutdowns.conn_list, conn, &conn->conncache_node);
  DEBUGF(infof(data, "[CCACHE] added #%" CURL_FORMAT_CURL_OFF_T
                     " to shutdown list of length %zu", conn->connection_id,
                     Curl_llist_count(&connc->shutdowns.conn_list)));
}

void Curl_conncache_disconnect(struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted)
{
  DEBUGASSERT(data);
  /* Connection must no longer be in and connection cache */
  DEBUGASSERT(!conn->bits.in_conncache);

  if(data->multi) {
    /* Add it to the multi's conncache for shutdown handling */
    infof(data, "%s connection #%" CURL_FORMAT_CURL_OFF_T,
          aborted? "closing" : "shutting down", conn->connection_id);
    connc_discard_conn(&data->multi->conn_cache, data, conn, aborted);
  }
  else {
    /* No multi available. Make a best-effort shutdown + close */
    infof(data, "closing connection #%" CURL_FORMAT_CURL_OFF_T,
          conn->connection_id);
    DEBUGASSERT(!conn->bits.in_conncache);
    connc_run_conn_shutdown_handler(data, conn);
    connc_close_and_destroy(NULL, conn, data, !aborted);
  }
}

static void connc_run_conn_shutdown_handler(struct Curl_easy *data,
                                            struct connectdata *conn)
{
  if(!conn->bits.shutdown_handler) {
    if(conn->dns_entry)
      Curl_resolv_unlink(data, &conn->dns_entry);

    /* Cleanup NTLM connection-related data */
    Curl_http_auth_cleanup_ntlm(conn);

    /* Cleanup NEGOTIATE connection-related data */
    Curl_http_auth_cleanup_negotiate(conn);

    if(conn->handler && conn->handler->disconnect) {
      /* This is set if protocol-specific cleanups should be made */
      DEBUGF(infof(data, "connection #%" CURL_FORMAT_CURL_OFF_T
                   ", shutdown protocol handler (aborted=%d)",
                   conn->connection_id, conn->bits.aborted));
      conn->handler->disconnect(data, conn, conn->bits.aborted);
    }

    /* possible left-overs from the async name resolvers */
    Curl_resolver_cancel(data);

    conn->bits.shutdown_handler = TRUE;
  }
}

static void connc_run_conn_shutdown(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    bool *done)
{
  CURLcode r1, r2;
  bool done1, done2;

  /* We expect to be attached when called */
  DEBUGASSERT(data->conn == conn);

  connc_run_conn_shutdown_handler(data, conn);

  if(conn->bits.shutdown_filters) {
    *done = TRUE;
    return;
  }

  if(!conn->connect_only && Curl_conn_is_connected(conn, FIRSTSOCKET))
    r1 = Curl_conn_shutdown(data, FIRSTSOCKET, &done1);
  else {
    r1 = CURLE_OK;
    done1 = TRUE;
  }

  if(!conn->connect_only && Curl_conn_is_connected(conn, SECONDARYSOCKET))
    r2 = Curl_conn_shutdown(data, SECONDARYSOCKET, &done2);
  else {
    r2 = CURLE_OK;
    done2 = TRUE;
  }

  /* we are done when any failed or both report success */
  *done = (r1 || r2 || (done1 && done2));
  if(*done)
    conn->bits.shutdown_filters = TRUE;
}

CURLcode Curl_conncache_add_pollfds(struct conncache *connc,
                                    struct curl_pollfds *cpfds)
{
  CURLcode result = CURLE_OK;

  DEBUGASSERT(!connc->shutdowns.iter_locked);
  connc->shutdowns.iter_locked = TRUE;
  if(Curl_llist_head(&connc->shutdowns.conn_list)) {
    struct Curl_llist_node *e;
    struct easy_pollset ps;
    struct connectdata *conn;

    for(e = Curl_llist_head(&connc->shutdowns.conn_list); e;
        e = Curl_node_next(e)) {
      conn = Curl_node_elem(e);
      memset(&ps, 0, sizeof(ps));
      Curl_attach_connection(connc->closure_handle, conn);
      Curl_conn_adjust_pollset(connc->closure_handle, &ps);
      Curl_detach_connection(connc->closure_handle);

      result = Curl_pollfds_add_ps(cpfds, &ps);
      if(result) {
        Curl_pollfds_cleanup(cpfds);
        goto out;
      }
    }
  }
out:
  connc->shutdowns.iter_locked = FALSE;
  return result;
}

CURLcode Curl_conncache_add_waitfds(struct conncache *connc,
                                    struct curl_waitfds *cwfds)
{
  CURLcode result = CURLE_OK;

  DEBUGASSERT(!connc->shutdowns.iter_locked);
  connc->shutdowns.iter_locked = TRUE;
  if(Curl_llist_head(&connc->shutdowns.conn_list)) {
    struct Curl_llist_node *e;
    struct easy_pollset ps;
    struct connectdata *conn;

    for(e = Curl_llist_head(&connc->shutdowns.conn_list); e;
        e = Curl_node_next(e)) {
      conn = Curl_node_elem(e);
      memset(&ps, 0, sizeof(ps));
      Curl_attach_connection(connc->closure_handle, conn);
      Curl_conn_adjust_pollset(connc->closure_handle, &ps);
      Curl_detach_connection(connc->closure_handle);

      result = Curl_waitfds_add_ps(cwfds, &ps);
      if(result)
        goto out;
    }
  }
out:
  connc->shutdowns.iter_locked = FALSE;
  return result;
}

static void connc_perform(struct conncache *connc)
{
  struct Curl_easy *data = connc->closure_handle;
  struct Curl_llist_node *e = Curl_llist_head(&connc->shutdowns.conn_list);
  struct Curl_llist_node *enext;
  struct connectdata *conn;
  struct curltime *nowp = NULL;
  struct curltime now;
  timediff_t next_from_now_ms = 0, ms;
  bool done;

  if(!e)
    return;

  DEBUGASSERT(data);
  DEBUGASSERT(!connc->shutdowns.iter_locked);
  DEBUGF(infof(data, "[CCACHE] perform, %zu connections being shutdown",
               Curl_llist_count(&connc->shutdowns.conn_list)));
  connc->shutdowns.iter_locked = TRUE;
  while(e) {
    enext = Curl_node_next(e);
    conn = Curl_node_elem(e);
    Curl_attach_connection(data, conn);
    connc_run_conn_shutdown(data, conn, &done);
    DEBUGF(infof(data, "[CCACHE] shutdown #%" CURL_FORMAT_CURL_OFF_T
                 ", done=%d", conn->connection_id, done));
    Curl_detach_connection(data);
    if(done) {
      Curl_node_remove(e);
      connc_close_and_destroy(connc, conn, NULL, FALSE);
    }
    else {
      /* Not done, when does this connection time out? */
      if(!nowp) {
        now = Curl_now();
        nowp = &now;
      }
      ms = Curl_conn_shutdown_timeleft(conn, nowp);
      if(ms && ms < next_from_now_ms)
        next_from_now_ms = ms;
    }
    e = enext;
  }
  connc->shutdowns.iter_locked = FALSE;

  if(next_from_now_ms)
    Curl_expire(data, next_from_now_ms, EXPIRE_RUN_NOW);
}

void Curl_conncache_multi_perform(struct Curl_multi *multi)
{
  connc_perform(&multi->conn_cache);
}


/*
 * Close and destroy the connection. Run the shutdown sequence once,
 * of so requested.
 */
static void connc_close_and_destroy(struct conncache *connc,
                                    struct connectdata *conn,
                                    struct Curl_easy *data,
                                    bool do_shutdown)
{
  bool done;

  /* there must be a connection to close */
  DEBUGASSERT(conn);
  /* it must be removed from the connection cache */
  DEBUGASSERT(!conn->bits.in_conncache);
  /* there must be an associated transfer */
  DEBUGASSERT(data || connc);
  if(!data)
    data = connc->closure_handle;

  /* the transfer must be detached from the connection */
  DEBUGASSERT(data && !data->conn);

  Curl_attach_connection(data, conn);

  connc_run_conn_shutdown_handler(data, conn);
  if(do_shutdown) {
    /* Make a last attempt to shutdown handlers and filters, if
     * not done so already. */
    connc_run_conn_shutdown(data, conn, &done);
  }

  if(connc)
    DEBUGF(infof(data, "[CCACHE] closing #%" CURL_FORMAT_CURL_OFF_T,
                 conn->connection_id));
  else
    DEBUGF(infof(data, "closing connection #%" CURL_FORMAT_CURL_OFF_T,
                 conn->connection_id));
  Curl_conn_close(data, SECONDARYSOCKET);
  Curl_conn_close(data, FIRSTSOCKET);
  Curl_detach_connection(data);

  Curl_conn_free(data, conn);
}


static CURLMcode connc_update_shutdown_ev(struct Curl_multi *multi,
                                          struct Curl_easy *data,
                                          struct connectdata *conn)
{
  struct easy_pollset ps;
  CURLMcode mresult;

  DEBUGASSERT(data);
  DEBUGASSERT(multi);
  DEBUGASSERT(multi->socket_cb);

  memset(&ps, 0, sizeof(ps));
  Curl_attach_connection(data, conn);
  Curl_conn_adjust_pollset(data, &ps);
  Curl_detach_connection(data);

  mresult = Curl_multi_pollset_ev(multi, data, &ps, &conn->shutdown_poll);

  if(!mresult) /* Remember for next time */
    memcpy(&conn->shutdown_poll, &ps, sizeof(ps));
  return mresult;
}

void Curl_conncache_multi_socket(struct Curl_multi *multi,
                                 curl_socket_t s, int ev_bitmask)
{
  struct conncache *connc = &multi->conn_cache;
  struct Curl_easy *data = connc->closure_handle;
  struct Curl_llist_node *e = Curl_llist_head(&connc->shutdowns.conn_list);
  struct connectdata *conn;
  bool done;

  (void)ev_bitmask;
  DEBUGASSERT(multi->socket_cb);
  if(!e)
    return;

  connc->shutdowns.iter_locked = TRUE;
  while(e) {
    conn = Curl_node_elem(e);
    if(s == conn->sock[FIRSTSOCKET] || s == conn->sock[SECONDARYSOCKET]) {
      Curl_attach_connection(data, conn);
      connc_run_conn_shutdown(data, conn, &done);
      DEBUGF(infof(data, "[CCACHE] shutdown #%" CURL_FORMAT_CURL_OFF_T
                   ", done=%d", conn->connection_id, done));
      Curl_detach_connection(data);
      if(done || connc_update_shutdown_ev(multi, data, conn)) {
        Curl_node_remove(e);
        connc_close_and_destroy(connc, conn, NULL, FALSE);
      }
      break;
    }
    e = Curl_node_next(e);
  }
  connc->shutdowns.iter_locked = FALSE;
}

#define NUM_POLLS_ON_STACK 10

static CURLcode connc_shutdown_wait(struct conncache *connc, int timeout_ms)
{
  struct pollfd a_few_on_stack[NUM_POLLS_ON_STACK];
  struct curl_pollfds cpfds;
  CURLcode result;

  Curl_pollfds_init(&cpfds, a_few_on_stack, NUM_POLLS_ON_STACK);

  result = Curl_conncache_add_pollfds(connc, &cpfds);
  if(result)
    goto out;

  Curl_poll(cpfds.pfds, cpfds.n, CURLMIN(timeout_ms, 1000));

out:
  Curl_pollfds_cleanup(&cpfds);
  return result;
}

static void connc_shutdown_all(struct conncache *connc,
                               struct Curl_easy *data, int timeout_ms)
{
  struct connectdata *conn;
  struct curltime started = Curl_now();

  if(!data)
    return;
  (void)data;

  DEBUGF(infof(data, "conncache shutdown all"));

  /* Move all connections into the shutdown queue */
  conn = connc_find_first_connection(connc);
  while(conn) {
    /* This will remove the connection from the cache */
    DEBUGF(infof(data, "moving connection %" CURL_FORMAT_CURL_OFF_T
                 " to shutdown queue", conn->connection_id));
    connc_remove_conn(connc, conn);
    connc_discard_conn(connc, data, conn, FALSE);
    conn = connc_find_first_connection(connc);
  }

  DEBUGASSERT(!connc->shutdowns.iter_locked);
  while(Curl_llist_head(&connc->shutdowns.conn_list)) {
    timediff_t timespent;
    int remain_ms;

    connc_perform(connc);

    if(!Curl_llist_head(&connc->shutdowns.conn_list)) {
      DEBUGF(infof(data, "conncache shutdown ok"));
      break;
    }

    /* wait for activity, timeout or "nothing" */
    timespent = Curl_timediff(Curl_now(), started);
    if(timespent >= (timediff_t)timeout_ms) {
      DEBUGF(infof(data, "conncache shutdown %s",
                   (timeout_ms > 0)? "timeout" : "best effort done"));
      break;
    }

    remain_ms = timeout_ms - (int)timespent;
    if(connc_shutdown_wait(connc, remain_ms)) {
      DEBUGF(infof(data, "conncache shutdown all, abort"));
      break;
    }
  }

  /* Due to errors/timeout, we might come here without being full ydone. */
  connc_shutdown_discard_all(connc);
}

struct ccache_reaper_ctx {
  struct curltime now;
  struct connectdata *conn;
};

static int call_conn_seems_dead(struct Curl_easy *data,
                                struct connectdata *conn, void *param)
{
  struct ccache_reaper_ctx *rctx = param;
  if(Curl_conn_seems_dead(conn, data, &rctx->now)) {
    /* stop the iteration here, pass back the connection that was pruned */
    Curl_conncache_remove_conn(data, conn, FALSE);
    rctx->conn = conn;
    return 1;
  }
  return 0; /* continue iteration */
}

/*
 * This function scans the data's connection cache for half-open/dead
 * connections, closes and removes them.
 * The cleanup is done at most once per second.
 *
 * When called, this transfer has no connection attached.
 */
void Curl_conncache_prune_dead(struct Curl_easy *data)
{
  struct conncache *connc = Curl_get_conncache(data);
  struct ccache_reaper_ctx rctx;
  timediff_t elapsed;

  if(!connc || !data)
    return;

  DEBUGASSERT(!data->conn); /* no connection */

  rctx.now = Curl_now();
  CONNC_LOCK(connc);
  elapsed = Curl_timediff(rctx.now, connc->last_cleanup);
  CONNC_UNLOCK(connc);

  if(elapsed >= 1000L) {
    /* foreach locks the connection cache during its iteration */
    rctx.conn = NULL;
    while(connc_foreach(data, Curl_get_conncache(data), &rctx,
                        call_conn_seems_dead)) {
      /* unlocked */
      /* connection was removed from cache in call_conn_seems_dead() */
      /* disconnect it, do not treat as aborted */
      Curl_disconnect(data, rctx.conn, FALSE);
    }
    CONNC_LOCK(connc);
    connc->last_cleanup = rctx.now;
    CONNC_UNLOCK(connc);
  }
}

static int conn_upkeep(struct Curl_easy *data,
                       struct connectdata *conn,
                       void *param)
{
  struct curltime *now = param;
  /* TODO, shall we reap connections that return an error here? */
  Curl_conn_upkeep(data, conn, now);
  return 0; /* continue iteration */
}

CURLcode Curl_conncache_upkeep(struct conncache *conn_cache, void *data)
{
  struct curltime now = Curl_now();
  connc_foreach(data, conn_cache, &now, conn_upkeep);
  return CURLE_OK;
}

struct ccache_find_ctx {
  curl_off_t id;
  struct connectdata *conn;
};

static int connc_find_conn(struct Curl_easy *data,
                           struct connectdata *conn, void *param)
{
  struct ccache_find_ctx *fctx = param;
  (void)data;
  if(conn->connection_id == fctx->id) {
    fctx->conn = conn;
    return 1;
  }
  return 0;
}

struct connectdata *Curl_conncache_get_conn(struct conncache *connc,
                                            curl_off_t conn_id)
{
  struct ccache_find_ctx fctx;

  if(!connc)
    return NULL;
  fctx.id = conn_id;
  fctx.conn = NULL;
  connc_foreach(connc->closure_handle, connc, &fctx, connc_find_conn);
  return fctx.conn;
}

struct ccache_do_conn_ctx {
  curl_off_t id;
  Curl_conncache_conn_do_cb *cb;
  void *cbdata;
};

static int connc_do_conn(struct Curl_easy *data,
                         struct connectdata *conn, void *param)
{
  struct ccache_do_conn_ctx *dctx = param;
  (void)data;
  if(conn->connection_id == dctx->id) {
    dctx->cb(conn, data, dctx->cbdata);
    return 1;
  }
  return 0;
}

void Curl_conncache_do_by_id(struct Curl_easy *data, curl_off_t conn_id,
                             Curl_conncache_conn_do_cb *cb, void *cbdata)
{
  struct conncache *connc = Curl_get_conncache(data);
  struct ccache_do_conn_ctx dctx;

  if(!connc)
    return;
  dctx.id = conn_id;
  dctx.cb = cb;
  dctx.cbdata = cbdata;
  connc_foreach(data, connc, &dctx, connc_do_conn);
}

void Curl_conncache_do_locked(struct Curl_easy *data,
                              struct connectdata *conn,
                              Curl_conncache_conn_do_cb *cb, void *cbdata)
{
  struct conncache *connc = Curl_get_conncache(data);
  if(connc) {
    CONNC_LOCK(connc);
    cb(conn, data, cbdata);
    CONNC_UNLOCK(connc);
  }
  else
    cb(conn, data, cbdata);
}

#if 0
/* Useful for debugging the connection cache */
void Curl_conncache_print(struct conncache *connc)
{
  struct Curl_hash_iterator iter;
  struct Curl_llist_node *curr;
  struct Curl_hash_element *he;

  if(!connc)
    return;

  fprintf(stderr, "=Bundle cache=\n");

  Curl_hash_start_iterate(connc->key2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectbundle *bundle;
    struct connectdata *conn;

    bundle = he->ptr;

    fprintf(stderr, "%s -", he->key);
    curr = Curl_llist_head(bundle->conn_list);
    while(curr) {
      conn = Curl_node_elem(curr);

      fprintf(stderr, " [%p %d]", (void *)conn, conn->refcount);
      curr = Curl_node_next(curr);
    }
    fprintf(stderr, "\n");

    he = Curl_hash_next_element(&iter);
  }
}
#endif
