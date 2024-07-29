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

#define HASHKEY_SIZE 128

static void connc_discard_conn(struct conncache *connc,
                               struct Curl_easy *last_data,
                               struct connectdata *conn,
                               bool aborted);
static void connc_disconnect(struct Curl_easy *data,
                             struct connectdata *conn,
                             struct conncache *connc,
                             bool do_shutdown);
static void connc_run_conn_shutdown(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    bool *done);
static void connc_run_conn_shutdown_handler(struct Curl_easy *data,
                                            struct connectdata *conn);
static CURLMcode connc_update_shutdown_ev(struct Curl_multi *multi,
                                          struct Curl_easy *data,
                                          struct connectdata *conn);
static void connc_shutdown_all(struct conncache *connc, int timeout_ms);

static CURLcode bundle_create(struct connectbundle **bundlep)
{
  DEBUGASSERT(*bundlep == NULL);
  *bundlep = malloc(sizeof(struct connectbundle));
  if(!*bundlep)
    return CURLE_OUT_OF_MEMORY;

  (*bundlep)->num_connections = 0;
  (*bundlep)->multiuse = BUNDLE_UNKNOWN;

  Curl_llist_init(&(*bundlep)->conn_list, NULL);
  return CURLE_OK;
}

static void bundle_destroy(struct connectbundle *bundle)
{
  free(bundle);
}

/* Add a connection to a bundle */
static void bundle_add_conn(struct connectbundle *bundle,
                            struct connectdata *conn)
{
  Curl_llist_append(&bundle->conn_list, conn, &conn->bundle_node);
  conn->bundle = bundle;
  bundle->num_connections++;
}

/* Remove a connection from a bundle */
static int bundle_remove_conn(struct connectbundle *bundle,
                              struct connectdata *conn)
{
  struct Curl_llist_element *curr;

  curr = bundle->conn_list.head;
  while(curr) {
    if(curr->ptr == conn) {
      Curl_llist_remove(&bundle->conn_list, curr, NULL);
      bundle->num_connections--;
      conn->bundle = NULL;
      return 1; /* we removed a handle */
    }
    curr = curr->next;
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
                        struct Curl_multi *multi, size_t size)
{
  /* allocate a new easy handle to use when closing cached connections */
  connc->closure_handle = curl_easy_init();
  if(!connc->closure_handle)
    return 1; /* bad */
  connc->closure_handle->state.internal = true;
 #ifdef DEBUGBUILD
  if(getenv("CURL_DEBUG"))
    connc->closure_handle->set.verbose = true;
#endif

  Curl_hash_init(&connc->hash, size, Curl_hash_str,
                 Curl_str_key_compare, free_bundle_hash_entry);
  connc->closure_handle->state.conn_cache = connc;
  connc->multi = multi;
  Curl_llist_init(&connc->shutdowns.conn_list, NULL);

  return 0; /* good */
}

void Curl_conncache_destroy(struct conncache *connc)
{
  if(connc) {
    Curl_hash_destroy(&connc->hash);
    connc->multi = NULL;
    DEBUGASSERT(!Curl_llist_count(&connc->shutdowns.conn_list));
  }
}

/* creates a key to find a bundle for this connection */
static void hashkey(struct connectdata *conn, char *buf, size_t len)
{
  const char *hostname;
  long port = conn->remote_port;
  DEBUGASSERT(len >= HASHKEY_SIZE);
#ifndef CURL_DISABLE_PROXY
  if(conn->bits.httpproxy && !conn->bits.tunnel_proxy) {
    hostname = conn->http_proxy.host.name;
    port = conn->primary.remote_port;
  }
  else
#endif
    if(conn->bits.conn_to_host)
      hostname = conn->conn_to_host.name;
  else
    hostname = conn->host.name;

  /* put the numbers first so that the hostname gets cut off if too long */
#ifdef USE_IPV6
  msnprintf(buf, len, "%u/%ld/%s", conn->scope_id, port, hostname);
#else
  msnprintf(buf, len, "%ld/%s", port, hostname);
#endif
  Curl_strntolower(buf, buf, len);
}

/* Returns number of connections currently held in the connection cache.
   Locks/unlocks the cache itself!
*/
size_t Curl_conncache_size(struct Curl_easy *data)
{
  size_t num;
  CONNCACHE_LOCK(data);
  num = data->state.conn_cache->num_conn;
  CONNCACHE_UNLOCK(data);
  return num;
}

/* Look up the bundle with all the connections to the same host this
   connectdata struct is setup to use.

   **NOTE**: When it returns, it holds the connection cache lock! */
struct connectbundle *
Curl_conncache_find_bundle(struct Curl_easy *data,
                           struct connectdata *conn,
                           struct conncache *connc)
{
  struct connectbundle *bundle = NULL;
  CONNCACHE_LOCK(data);
  if(connc) {
    char key[HASHKEY_SIZE];
    hashkey(conn, key, sizeof(key));
    bundle = Curl_hash_pick(&connc->hash, key, strlen(key));
  }

  return bundle;
}

static void *connc_add_bundle(struct conncache *connc,
                              char *key, struct connectbundle *bundle)
{
  return Curl_hash_add(&connc->hash, key, strlen(key), bundle);
}

static void connc_remove_bundle(struct conncache *connc,
                                struct connectbundle *bundle)
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;

  if(!connc)
    return;

  Curl_hash_start_iterate(&connc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    if(he->ptr == bundle) {
      /* The bundle is destroyed by the hash destructor function,
         free_bundle_hash_entry() */
      Curl_hash_delete(&connc->hash, he->key, he->key_len);
      return;
    }

    he = Curl_hash_next_element(&iter);
  }
}

CURLcode Curl_conncache_add_conn(struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct connectbundle *bundle = NULL;
  struct connectdata *conn = data->conn;
  struct conncache *connc = data->state.conn_cache;
  DEBUGASSERT(conn);

  /* *find_bundle() locks the connection cache */
  bundle = Curl_conncache_find_bundle(data, conn, data->state.conn_cache);
  if(!bundle) {
    char key[HASHKEY_SIZE];

    result = bundle_create(&bundle);
    if(result) {
      goto unlock;
    }

    hashkey(conn, key, sizeof(key));

    if(!connc_add_bundle(data->state.conn_cache, key, bundle)) {
      bundle_destroy(bundle);
      result = CURLE_OUT_OF_MEMORY;
      goto unlock;
    }
  }

  bundle_add_conn(bundle, conn);
  conn->connection_id = connc->next_connection_id++;
  connc->num_conn++;

  DEBUGF(infof(data, "Added connection %" CURL_FORMAT_CURL_OFF_T ". "
               "The cache now contains %zu members",
               conn->connection_id, connc->num_conn));

unlock:
  CONNCACHE_UNLOCK(data);

  return result;
}

static void connc_remove_conn(struct conncache *connc,
                              struct connectdata *conn)
{
  struct connectbundle *bundle = conn->bundle;

  /* The bundle pointer can be NULL, since this function can be called
     due to a failed connection attempt, before being added to a bundle */
  if(bundle) {
    bundle_remove_conn(bundle, conn);
    if(connc && bundle->num_connections == 0)
      connc_remove_bundle(connc, bundle);
    conn->bundle = NULL; /* removed from it */
    if(connc)
      connc->num_conn--;
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
  struct conncache *connc = data->state.conn_cache;

  if(lock)
    CONNCACHE_LOCK(data);
  connc_remove_conn(connc, conn);
  if(lock)
    CONNCACHE_UNLOCK(data);
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

   Returns 1 if the loop was aborted due to the callback's return code.

   Return 0 from func() to continue the loop, return 1 to abort it.
 */
bool Curl_conncache_foreach(struct Curl_easy *data,
                            struct conncache *connc,
                            void *param,
                            int (*func)(struct Curl_easy *data,
                                        struct connectdata *conn, void *param))
{
  struct Curl_hash_iterator iter;
  struct Curl_llist_element *curr;
  struct Curl_hash_element *he;

  if(!connc)
    return FALSE;

  CONNCACHE_LOCK(data);
  Curl_hash_start_iterate(&connc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectbundle *bundle;

    bundle = he->ptr;
    he = Curl_hash_next_element(&iter);

    curr = bundle->conn_list.head;
    while(curr) {
      /* Yes, we need to update curr before calling func(), because func()
         might decide to remove the connection */
      struct connectdata *conn = curr->ptr;
      curr = curr->next;

      if(1 == func(data, conn, param)) {
        CONNCACHE_UNLOCK(data);
        return TRUE;
      }
    }
  }
  CONNCACHE_UNLOCK(data);
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

  Curl_hash_start_iterate(&connc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct Curl_llist_element *curr;
    bundle = he->ptr;

    curr = bundle->conn_list.head;
    if(curr) {
      return curr->ptr;
    }

    he = Curl_hash_next_element(&iter);
  }

  return NULL;
}

/*
 * Give ownership of a connection back to the connection cache. Might
 * disconnect the oldest existing in there to make space.
 *
 * Return TRUE if stored, FALSE if closed.
 */
bool Curl_conncache_return_conn(struct Curl_easy *data,
                                struct connectdata *conn)
{
  unsigned int maxconnects = !data->multi->maxconnects ?
    data->multi->num_easy * 4: data->multi->maxconnects;
  struct connectdata *conn_candidate = NULL;

  conn->lastused = Curl_now(); /* it was used up until now */
  if(maxconnects && Curl_conncache_size(data) > maxconnects) {
    infof(data, "Connection cache is full, closing the oldest one");

    conn_candidate = Curl_conncache_extract_oldest(data);
    if(conn_candidate) {
      /* Use the closure handle for this disconnect so that anything that
         happens during the disconnect is not stored and associated with the
         'data' handle which already just finished a transfer and it is
         important that details from this (unrelated) disconnect does not
         taint meta-data in the data handle. */
      struct conncache *connc = data->state.conn_cache;
      connc_disconnect(NULL, conn_candidate, connc, TRUE);
    }
  }

  return (conn_candidate == conn) ? FALSE : TRUE;

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
struct connectdata *
Curl_conncache_extract_bundle(struct Curl_easy *data,
                              struct connectbundle *bundle)
{
  struct Curl_llist_element *curr;
  timediff_t highscore = -1;
  timediff_t score;
  struct curltime now;
  struct connectdata *conn_candidate = NULL;
  struct connectdata *conn;

  (void)data;

  now = Curl_now();

  curr = bundle->conn_list.head;
  while(curr) {
    conn = curr->ptr;

    if(!CONN_INUSE(conn)) {
      /* Set higher score for the age passed since the connection was used */
      score = Curl_timediff(now, conn->lastused);

      if(score > highscore) {
        highscore = score;
        conn_candidate = conn;
      }
    }
    curr = curr->next;
  }
  if(conn_candidate) {
    /* remove it to prevent another thread from nicking it */
    bundle_remove_conn(bundle, conn_candidate);
    data->state.conn_cache->num_conn--;
    DEBUGF(infof(data, "The cache now contains %zu members",
                 data->state.conn_cache->num_conn));
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
Curl_conncache_extract_oldest(struct Curl_easy *data)
{
  struct conncache *connc = data->state.conn_cache;
  struct Curl_hash_iterator iter;
  struct Curl_llist_element *curr;
  struct Curl_hash_element *he;
  timediff_t highscore =- 1;
  timediff_t score;
  struct curltime now;
  struct connectdata *conn_candidate = NULL;
  struct connectbundle *bundle;
  struct connectbundle *bundle_candidate = NULL;

  now = Curl_now();

  CONNCACHE_LOCK(data);
  Curl_hash_start_iterate(&connc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectdata *conn;

    bundle = he->ptr;

    curr = bundle->conn_list.head;
    while(curr) {
      conn = curr->ptr;

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
      curr = curr->next;
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
  CONNCACHE_UNLOCK(data);

  return conn_candidate;
}

static void connc_shutdown_discard_all(struct conncache *connc)
{
  struct Curl_llist_element *e = connc->shutdowns.conn_list.head;
  struct connectdata *conn;

  if(!e)
    return;

  DEBUGF(infof(connc->closure_handle, "conncache_shutdown_discard_all"));
  DEBUGASSERT(!connc->shutdowns.iter_locked);
  connc->shutdowns.iter_locked = TRUE;
  while(e) {
    conn = e->ptr;
    Curl_llist_remove(&connc->shutdowns.conn_list, e, NULL);
    DEBUGF(infof(connc->closure_handle, "discard connection #%"
                 CURL_FORMAT_CURL_OFF_T, conn->connection_id));
    connc_disconnect(NULL, conn, connc, FALSE);
    e = connc->shutdowns.conn_list.head;
  }
  connc->shutdowns.iter_locked = FALSE;
}

static void connc_close_all(struct conncache *connc)
{
  struct Curl_easy *data = connc->closure_handle;
  struct connectdata *conn;
  int timeout_ms = 0;
  SIGPIPE_VARIABLE(pipe_st);

  if(!data)
    return;

  /* Move all connections to the shutdown list */
  sigpipe_init(&pipe_st);
  conn = connc_find_first_connection(connc);
  while(conn) {
    connc_remove_conn(connc, conn);
    sigpipe_apply(data, &pipe_st);
    /* This will remove the connection from the cache */
    connclose(conn, "kill all");
    Curl_conncache_remove_conn(connc->closure_handle, conn, TRUE);
    connc_discard_conn(connc, connc->closure_handle, conn, FALSE);

    conn = connc_find_first_connection(connc);
  }

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
  connc_shutdown_all(connc, timeout_ms);

  /* discard all connections in the shutdown list */
  connc_shutdown_discard_all(connc);

  sigpipe_apply(data, &pipe_st);
  Curl_hostcache_clean(data, data->dns.hostcache);
  Curl_close(&data);
  sigpipe_restore(&pipe_st);
}

void Curl_conncache_close_all_connections(struct conncache *connc)
{
  connc_close_all(connc);
}

static void connc_shutdown_discard_oldest(struct conncache *connc)
{
  struct Curl_llist_element *e;
  struct connectdata *conn;

  DEBUGASSERT(!connc->shutdowns.iter_locked);
  if(connc->shutdowns.iter_locked)
    return;

  e = connc->shutdowns.conn_list.head;
  if(e) {
    SIGPIPE_VARIABLE(pipe_st);
    conn = e->ptr;
    Curl_llist_remove(&connc->shutdowns.conn_list, e, NULL);
    sigpipe_init(&pipe_st);
    sigpipe_apply(connc->closure_handle, &pipe_st);
    connc_disconnect(NULL, conn, connc, FALSE);
    sigpipe_restore(&pipe_st);
  }
}

static void connc_discard_conn(struct conncache *connc,
                               struct Curl_easy *last_data,
                               struct connectdata *conn,
                               bool aborted)
{
  /* `last_data`, if present, is the transfer that last worked with
   * the connection. It is present when the connection is being shut down
   * via `Curl_conncache_discard_conn()`, e.g. when the transfer failed
   * or does not allow connection reuse.
   * Using the original handle is necessary for shutting down the protocol
   * handler belonging to the connection. Protocols like 'file:' rely on
   * being invoked to clean up their allocations in the easy handle.
   * When a connection comes from the cache, the transfer is no longer
   * there and we use the cache is own closure handle.
   */
  struct Curl_easy *data = last_data? last_data : connc->closure_handle;
  bool done = FALSE;

  DEBUGASSERT(data);
  DEBUGASSERT(connc);
  DEBUGASSERT(!conn->bundle);

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
    connc_disconnect(data, conn, connc, FALSE);
    return;
  }

  DEBUGASSERT(!connc->shutdowns.iter_locked);
  if(connc->shutdowns.iter_locked) {
    DEBUGF(infof(data, "[CCACHE] discarding #%" CURL_FORMAT_CURL_OFF_T
                       ", list locked", conn->connection_id));
    connc_disconnect(data, conn, connc, FALSE);
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
    connc_shutdown_discard_oldest(connc);
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
      connc_disconnect(data, conn, connc, FALSE);
      return;
    }
  }

  Curl_llist_append(&connc->shutdowns.conn_list, conn, &conn->bundle_node);
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
  DEBUGASSERT(!conn->bundle);

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
    DEBUGASSERT(!conn->bundle);
    connc_run_conn_shutdown_handler(data, conn);
    connc_disconnect(data, conn, NULL, !aborted);
  }
}

static void connc_run_conn_shutdown_handler(struct Curl_easy *data,
                                            struct connectdata *conn)
{
  if(!conn->bits.shutdown_handler) {
    if(conn->dns_entry) {
      Curl_resolv_unlock(data, conn->dns_entry);
      conn->dns_entry = NULL;
    }

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
  if(connc->shutdowns.conn_list.head) {
    struct Curl_llist_element *e;
    struct easy_pollset ps;
    struct connectdata *conn;

    for(e = connc->shutdowns.conn_list.head; e; e = e->next) {
      conn = e->ptr;
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
  if(connc->shutdowns.conn_list.head) {
    struct Curl_llist_element *e;
    struct easy_pollset ps;
    struct connectdata *conn;

    for(e = connc->shutdowns.conn_list.head; e; e = e->next) {
      conn = e->ptr;
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
  struct Curl_llist_element *e = connc->shutdowns.conn_list.head;
  struct Curl_llist_element *enext;
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
    enext = e->next;
    conn = e->ptr;
    Curl_attach_connection(data, conn);
    connc_run_conn_shutdown(data, conn, &done);
    DEBUGF(infof(data, "[CCACHE] shutdown #%" CURL_FORMAT_CURL_OFF_T
                 ", done=%d", conn->connection_id, done));
    Curl_detach_connection(data);
    if(done) {
      Curl_llist_remove(&connc->shutdowns.conn_list, e, NULL);
      connc_disconnect(NULL, conn, connc, FALSE);
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
 * Disconnects the given connection. Note the connection may not be the
 * primary connection, like when freeing room in the connection cache or
 * killing of a dead old connection.
 *
 * A connection needs an easy handle when closing down. We support this passed
 * in separately since the connection to get closed here is often already
 * disassociated from an easy handle.
 *
 * This function MUST NOT reset state in the Curl_easy struct if that
 * is not strictly bound to the life-time of *this* particular connection.
 *
 */
static void connc_disconnect(struct Curl_easy *data,
                             struct connectdata *conn,
                             struct conncache *connc,
                             bool do_shutdown)
{
  bool done;

  /* there must be a connection to close */
  DEBUGASSERT(conn);
  /* it must be removed from the connection cache */
  DEBUGASSERT(!conn->bundle);
  /* there must be an associated transfer */
  DEBUGASSERT(data || connc);
  if(!data)
    data = connc->closure_handle;

  /* the transfer must be detached from the connection */
  DEBUGASSERT(data && !data->conn);

  Curl_attach_connection(data, conn);

  if(connc && connc->multi && connc->multi->socket_cb) {
    struct easy_pollset ps;
    /* With an empty pollset, all previously polled sockets will be removed
     * via the multi_socket API callback. */
    memset(&ps, 0, sizeof(ps));
    (void)Curl_multi_pollset_ev(connc->multi, data, &ps, &conn->shutdown_poll);
  }

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
  struct Curl_llist_element *e = connc->shutdowns.conn_list.head;
  struct connectdata *conn;
  bool done;

  (void)ev_bitmask;
  DEBUGASSERT(multi->socket_cb);
  if(!e)
    return;

  connc->shutdowns.iter_locked = TRUE;
  while(e) {
    conn = e->ptr;
    if(s == conn->sock[FIRSTSOCKET] || s == conn->sock[SECONDARYSOCKET]) {
      Curl_attach_connection(data, conn);
      connc_run_conn_shutdown(data, conn, &done);
      DEBUGF(infof(data, "[CCACHE] shutdown #%" CURL_FORMAT_CURL_OFF_T
                   ", done=%d", conn->connection_id, done));
      Curl_detach_connection(data);
      if(done || connc_update_shutdown_ev(multi, data, conn)) {
        Curl_llist_remove(&connc->shutdowns.conn_list, e, NULL);
        connc_disconnect(NULL, conn, connc, FALSE);
      }
      break;
    }
    e = e->next;
  }
  connc->shutdowns.iter_locked = FALSE;
}

void Curl_conncache_multi_close_all(struct Curl_multi *multi)
{
  connc_close_all(&multi->conn_cache);
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

static void connc_shutdown_all(struct conncache *connc, int timeout_ms)
{
  struct Curl_easy *data = connc->closure_handle;
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
    connc_discard_conn(connc, NULL, conn, FALSE);
    conn = connc_find_first_connection(connc);
  }

  DEBUGASSERT(!connc->shutdowns.iter_locked);
  while(connc->shutdowns.conn_list.head) {
    timediff_t timespent;
    int remain_ms;

    connc_perform(connc);

    if(!connc->shutdowns.conn_list.head) {
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

#if 0
/* Useful for debugging the connection cache */
void Curl_conncache_print(struct conncache *connc)
{
  struct Curl_hash_iterator iter;
  struct Curl_llist_element *curr;
  struct Curl_hash_element *he;

  if(!connc)
    return;

  fprintf(stderr, "=Bundle cache=\n");

  Curl_hash_start_iterate(connc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectbundle *bundle;
    struct connectdata *conn;

    bundle = he->ptr;

    fprintf(stderr, "%s -", he->key);
    curr = bundle->conn_list->head;
    while(curr) {
      conn = curr->ptr;

      fprintf(stderr, " [%p %d]", (void *)conn, conn->inuse);
      curr = curr->next;
    }
    fprintf(stderr, "\n");

    he = Curl_hash_next_element(&iter);
  }
}
#endif
