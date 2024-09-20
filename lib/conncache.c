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


#define CPOOL_IS_LOCKED(c)    ((c) && (c)->locked)

#define CPOOL_LOCK(c)                                                   \
  do {                                                                  \
    if((c)) {                                                           \
      if(CURL_SHARE_KEEP_CONNECT((c)->share))                           \
        Curl_share_lock(((c)->idata), CURL_LOCK_DATA_CONNECT,           \
                        CURL_LOCK_ACCESS_SINGLE);                       \
      DEBUGASSERT(!(c)->locked);                                        \
      (c)->locked = TRUE;                                               \
    }                                                                   \
  } while(0)

#define CPOOL_UNLOCK(c)                                                 \
  do {                                                                  \
    if((c)) {                                                           \
      DEBUGASSERT((c)->locked);                                         \
      (c)->locked = FALSE;                                              \
      if(CURL_SHARE_KEEP_CONNECT((c)->share))                           \
        Curl_share_unlock((c)->idata, CURL_LOCK_DATA_CONNECT);          \
    }                                                                   \
  } while(0)


/* A list of connections to the same destinationn. */
struct cpool_bundle {
  struct Curl_llist conns; /* connections in the bundle */
  size_t dest_len; /* total length of destination, including NUL */
  char *dest[1]; /* destination of bundle, allocated to keep dest_len bytes */
};


static void cpool_discard_conn(struct cpool *cpool,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted);
static void cpool_close_and_destroy(struct cpool *cpool,
                                    struct connectdata *conn,
                                    struct Curl_easy *data,
                                    bool do_shutdown);
static void cpool_run_conn_shutdown(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    bool *done);
static void cpool_run_conn_shutdown_handler(struct Curl_easy *data,
                                            struct connectdata *conn);
static CURLMcode cpool_update_shutdown_ev(struct Curl_multi *multi,
                                          struct Curl_easy *data,
                                          struct connectdata *conn);
static void cpool_shutdown_all(struct cpool *cpool,
                               struct Curl_easy *data, int timeout_ms);
static void cpool_close_and_destroy_all(struct cpool *cpool);
static struct connectdata *cpool_get_oldest_idle(struct cpool *cpool);

static struct cpool_bundle *cpool_bundle_create(const char *dest,
                                                size_t dest_len)
{
  struct cpool_bundle *bundle;
  bundle = calloc(1, sizeof(*bundle) + dest_len);
  if(!bundle)
    return NULL;
  Curl_llist_init(&bundle->conns, NULL);
  bundle->dest_len = dest_len;
  memcpy(bundle->dest, dest, dest_len);
  return bundle;
}

static void cpool_bundle_destroy(struct cpool_bundle *bundle)
{
  DEBUGASSERT(!Curl_llist_count(&bundle->conns));
  free(bundle);
}

/* Add a connection to a bundle */
static void cpool_bundle_add(struct cpool_bundle *bundle,
                             struct connectdata *conn)
{
  DEBUGASSERT(!Curl_node_llist(&conn->cpool_node));
  Curl_llist_append(&bundle->conns, conn, &conn->cpool_node);
  conn->bits.in_cpool = TRUE;
}

/* Remove a connection from a bundle */
static void cpool_bundle_remove(struct cpool_bundle *bundle,
                                struct connectdata *conn)
{
  (void)bundle;
  DEBUGASSERT(Curl_node_llist(&conn->cpool_node) == &bundle->conns);
  Curl_node_remove(&conn->cpool_node);
  conn->bits.in_cpool = FALSE;
}

static void cpool_bundle_free_entry(void *freethis)
{
  cpool_bundle_destroy((struct cpool_bundle *)freethis);
}

int Curl_cpool_init(struct cpool *cpool,
                        Curl_cpool_disconnect_cb *disconnect_cb,
                        struct Curl_multi *multi,
                        struct Curl_share *share,
                        size_t size)
{
  DEBUGASSERT(!!multi != !!share); /* either one */
  Curl_hash_init(&cpool->dest2bundle, size, Curl_hash_str,
                 Curl_str_key_compare, cpool_bundle_free_entry);
  Curl_llist_init(&cpool->shutdowns, NULL);

  DEBUGASSERT(disconnect_cb);
  if(!disconnect_cb)
    return 1;

  /* allocate a new easy handle to use when closing cached connections */
  cpool->idata = curl_easy_init();
  if(!cpool->idata)
    return 1; /* bad */
  cpool->idata->state.internal = true;
  /* TODO: this is quirky. We need an internal handle for certain
   * operations, but we do not add it to the multi (if there is one).
   * But we give it the multi so that socket event operations can work.
   * Probably better to have an internal handle owned by the multi that
   * can be used for cpool operations. */
  cpool->idata->multi = multi;
 #ifdef DEBUGBUILD
  if(getenv("CURL_DEBUG"))
    cpool->idata->set.verbose = true;
#endif

  cpool->disconnect_cb = disconnect_cb;
  cpool->idata->multi = cpool->multi = multi;
  cpool->idata->share = cpool->share = share;

  return 0; /* good */
}

void Curl_cpool_destroy(struct cpool *cpool)
{
  if(cpool) {
    if(cpool->idata) {
      cpool_close_and_destroy_all(cpool);
      /* The internal closure handle is special and we need to
       * disconnect it from multi/share before closing it down. */
      cpool->idata->multi = NULL;
      cpool->idata->share = NULL;
      Curl_close(&cpool->idata);
    }
    Curl_hash_destroy(&cpool->dest2bundle);
    cpool->multi = NULL;
  }
}

static struct cpool *cpool_get_instance(struct Curl_easy *data)
{
  if(data) {
    if(CURL_SHARE_KEEP_CONNECT(data->share))
      return &data->share->cpool;
    else if(data->multi_easy)
      return &data->multi_easy->cpool;
    else if(data->multi)
      return &data->multi->cpool;
  }
  return NULL;
}

void Curl_cpool_xfer_init(struct Curl_easy *data)
{
  struct cpool *cpool = cpool_get_instance(data);

  DEBUGASSERT(cpool);
  if(cpool) {
    CPOOL_LOCK(cpool);
    /* the identifier inside the connection cache */
    data->id = cpool->next_easy_id++;
    if(cpool->next_easy_id <= 0)
      cpool->next_easy_id = 0;
    data->state.lastconnect_id = -1;

    /* The closure handle only ever has default timeouts set. To improve the
       state somewhat we clone the timeouts from each added handle so that the
       closure handle always has the same timeouts as the most recently added
       easy handle. */
    cpool->idata->set.timeout = data->set.timeout;
    cpool->idata->set.server_response_timeout =
      data->set.server_response_timeout;
    cpool->idata->set.no_signal = data->set.no_signal;

    CPOOL_UNLOCK(cpool);
  }
  else {
    /* We should not get here, but in a non-debug build, do something */
    data->id = 0;
    data->state.lastconnect_id = -1;
  }
}

static struct cpool_bundle *cpool_find_bundle(struct cpool *cpool,
                                              struct connectdata *conn)
{
  return Curl_hash_pick(&cpool->dest2bundle,
                        conn->destination, conn->destination_len);
}

static struct cpool_bundle *
cpool_add_bundle(struct cpool *cpool, struct connectdata *conn)
{
  struct cpool_bundle *bundle;

  bundle = cpool_bundle_create(conn->destination, conn->destination_len);
  if(!bundle)
    return NULL;

  if(!Curl_hash_add(&cpool->dest2bundle,
                    bundle->dest, bundle->dest_len, bundle)) {
    cpool_bundle_destroy(bundle);
    return NULL;
  }
  return bundle;
}

static void cpool_remove_bundle(struct cpool *cpool,
                                struct cpool_bundle *bundle)
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;

  if(!cpool)
    return;

  Curl_hash_start_iterate(&cpool->dest2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    if(he->ptr == bundle) {
      /* The bundle is destroyed by the hash destructor function,
         free_bundle_hash_entry() */
      Curl_hash_delete(&cpool->dest2bundle, he->key, he->key_len);
      return;
    }

    he = Curl_hash_next_element(&iter);
  }
}

static struct connectdata *
cpool_bundle_get_oldest_idle(struct cpool_bundle *bundle);

int Curl_cpool_check_limits(struct Curl_easy *data,
                            struct connectdata *conn)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct cpool_bundle *bundle;
  size_t dest_limit = 0;
  size_t total_limit = 0;
  int result = CPOOL_LIMIT_OK;

  if(!cpool)
    return CPOOL_LIMIT_OK;

  if(data && data->multi) {
    dest_limit = data->multi->max_host_connections;
    total_limit = data->multi->max_total_connections;
  }

  if(!dest_limit && !total_limit)
    return CPOOL_LIMIT_OK;

  CPOOL_LOCK(cpool);
  if(dest_limit) {
    bundle = cpool_find_bundle(cpool, conn);
    while(bundle && (Curl_llist_count(&bundle->conns) >= dest_limit)) {
      struct connectdata *oldest_idle = NULL;
      /* The bundle is full. Extract the oldest connection that may
       * be removed now, if there is one. */
      oldest_idle = cpool_bundle_get_oldest_idle(bundle);
      if(!oldest_idle)
        break;
      /* disconnect the old conn and continue */
      DEBUGF(infof(data, "Discarding connection #%"
                   FMT_OFF_T " from %zu to reach destination "
                   "limit of %zu", oldest_idle->connection_id,
                   Curl_llist_count(&bundle->conns), dest_limit));
      Curl_cpool_disconnect(data, oldest_idle, FALSE);
    }
    if(bundle && (Curl_llist_count(&bundle->conns) >= dest_limit)) {
      result = CPOOL_LIMIT_DEST;
      goto out;
    }
  }

  if(total_limit) {
    while(cpool->num_conn >= total_limit) {
      struct connectdata *oldest_idle = cpool_get_oldest_idle(cpool);
      if(!oldest_idle)
        break;
      /* disconnect the old conn and continue */
      DEBUGF(infof(data, "Discarding connection #%"
                   FMT_OFF_T " from %zu to reach total "
                   "limit of %zu",
                   oldest_idle->connection_id, cpool->num_conn, total_limit));
      Curl_cpool_disconnect(data, oldest_idle, FALSE);
    }
    if(cpool->num_conn >= total_limit) {
      result = CPOOL_LIMIT_TOTAL;
      goto out;
    }
  }

out:
  CPOOL_UNLOCK(cpool);
  return result;
}

CURLcode Curl_cpool_add_conn(struct Curl_easy *data,
                             struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct cpool_bundle *bundle = NULL;
  struct cpool *cpool = cpool_get_instance(data);
  DEBUGASSERT(conn);

  DEBUGASSERT(cpool);
  if(!cpool)
    return CURLE_FAILED_INIT;

  CPOOL_LOCK(cpool);
  bundle = cpool_find_bundle(cpool, conn);
  if(!bundle) {
    bundle = cpool_add_bundle(cpool, conn);
    if(!bundle) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  cpool_bundle_add(bundle, conn);
  conn->connection_id = cpool->next_connection_id++;
  cpool->num_conn++;
  DEBUGF(infof(data, "Added connection %" FMT_OFF_T ". "
               "The cache now contains %zu members",
               conn->connection_id, cpool->num_conn));
out:
  CPOOL_UNLOCK(cpool);

  return result;
}

static void cpool_remove_conn(struct cpool *cpool,
                              struct connectdata *conn)
{
  struct Curl_llist *list = Curl_node_llist(&conn->cpool_node);
  DEBUGASSERT(cpool);
  if(list) {
    /* The connection is certainly in the pool, but where? */
    struct cpool_bundle *bundle = cpool_find_bundle(cpool, conn);
    if(bundle && (list == &bundle->conns)) {
      cpool_bundle_remove(bundle, conn);
      if(!Curl_llist_count(&bundle->conns))
        cpool_remove_bundle(cpool, bundle);
      conn->bits.in_cpool = FALSE;
      cpool->num_conn--;
    }
    else {
      /* Not in  a bundle, already in the shutdown list? */
      DEBUGASSERT(list == &cpool->shutdowns);
    }
  }
}

/* This function iterates the entire connection pool and calls the function
   func() with the connection pointer as the first argument and the supplied
   'param' argument as the other.

   The cpool lock is still held when the callback is called. It needs it,
   so that it can safely continue traversing the lists once the callback
   returns.

   Returns TRUE if the loop was aborted due to the callback's return code.

   Return 0 from func() to continue the loop, return 1 to abort it.
 */
static bool cpool_foreach(struct Curl_easy *data,
                          struct cpool *cpool,
                          void *param,
                          int (*func)(struct Curl_easy *data,
                                      struct connectdata *conn, void *param))
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;

  if(!cpool)
    return FALSE;

  Curl_hash_start_iterate(&cpool->dest2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct Curl_llist_node *curr;
    struct cpool_bundle *bundle = he->ptr;
    he = Curl_hash_next_element(&iter);

    curr = Curl_llist_head(&bundle->conns);
    while(curr) {
      /* Yes, we need to update curr before calling func(), because func()
         might decide to remove the connection */
      struct connectdata *conn = Curl_node_elem(curr);
      curr = Curl_node_next(curr);

      if(1 == func(data, conn, param)) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

/* Return a live connection in the pool or NULL. */
static struct connectdata *cpool_get_live_conn(struct cpool *cpool)
{
  struct Curl_hash_iterator iter;
  struct Curl_hash_element *he;
  struct cpool_bundle *bundle;
  struct Curl_llist_node *conn_node;

  Curl_hash_start_iterate(&cpool->dest2bundle, &iter);
  for(he = Curl_hash_next_element(&iter); he;
      he = Curl_hash_next_element(&iter)) {
    bundle = he->ptr;
    conn_node = Curl_llist_head(&bundle->conns);
    if(conn_node)
      return Curl_node_elem(conn_node);
  }
  return NULL;
}

/*
 * A connection (already in the pool) has become idle. Do any
 * cleanups in regard to the pool's limits.
 *
 * Return TRUE if idle connection kept in pool, FALSE if closed.
 */
bool Curl_cpool_conn_now_idle(struct Curl_easy *data,
                              struct connectdata *conn)
{
  unsigned int maxconnects = !data->multi->maxconnects ?
    data->multi->num_easy * 4 : data->multi->maxconnects;
  struct connectdata *oldest_idle = NULL;
  struct cpool *cpool = cpool_get_instance(data);
  bool kept = TRUE;

  conn->lastused = Curl_now(); /* it was used up until now */
  if(cpool && maxconnects) {
    /* may be called form a callback already under lock */
    bool do_lock = !CPOOL_IS_LOCKED(cpool);
    if(do_lock)
      CPOOL_LOCK(cpool);
    if(cpool->num_conn > maxconnects) {
      infof(data, "Connection pool is full, closing the oldest one");

      oldest_idle = cpool_get_oldest_idle(cpool);
      kept = (oldest_idle != conn);
      if(oldest_idle) {
        Curl_cpool_disconnect(cpool->idata, oldest_idle, FALSE);
      }
    }
    if(do_lock)
      CPOOL_UNLOCK(cpool);
  }

  return kept;
}

/*
 * This function finds the connection in the connection bundle that has been
 * unused for the longest time.
 */
static struct connectdata *
cpool_bundle_get_oldest_idle(struct cpool_bundle *bundle)
{
  struct Curl_llist_node *curr;
  timediff_t highscore = -1;
  timediff_t score;
  struct curltime now;
  struct connectdata *oldest_idle = NULL;
  struct connectdata *conn;

  now = Curl_now();
  curr = Curl_llist_head(&bundle->conns);
  while(curr) {
    conn = Curl_node_elem(curr);

    if(!CONN_INUSE(conn)) {
      /* Set higher score for the age passed since the connection was used */
      score = Curl_timediff(now, conn->lastused);

      if(score > highscore) {
        highscore = score;
        oldest_idle = conn;
      }
    }
    curr = Curl_node_next(curr);
  }
  return oldest_idle;
}

static struct connectdata *cpool_get_oldest_idle(struct cpool *cpool)
{
  struct Curl_hash_iterator iter;
  struct Curl_llist_node *curr;
  struct Curl_hash_element *he;
  struct connectdata *oldest_idle = NULL;
  struct cpool_bundle *bundle;
  struct curltime now;
  timediff_t highscore =- 1;
  timediff_t score;

  now = Curl_now();
  Curl_hash_start_iterate(&cpool->dest2bundle, &iter);

  for(he = Curl_hash_next_element(&iter); he;
      he = Curl_hash_next_element(&iter)) {
    struct connectdata *conn;
    bundle = he->ptr;

    for(curr = Curl_llist_head(&bundle->conns); curr;
        curr = Curl_node_next(curr)) {
      conn = Curl_node_elem(curr);
      if(CONN_INUSE(conn) || conn->bits.close || conn->connect_only)
        continue;
      /* Set higher score for the age passed since the connection was used */
      score = Curl_timediff(now, conn->lastused);
      if(score > highscore) {
        highscore = score;
        oldest_idle = conn;
      }
    }
  }
  return oldest_idle;
}

bool Curl_cpool_find(struct Curl_easy *data,
                     const char *destination, size_t dest_len,
                     Curl_cpool_conn_match_cb *conn_cb,
                     Curl_cpool_done_match_cb *done_cb,
                     void *userdata)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct cpool_bundle *bundle;
  bool result = FALSE;

  DEBUGASSERT(cpool);
  DEBUGASSERT(conn_cb);
  if(!cpool)
    return FALSE;

  CPOOL_LOCK(cpool);
  bundle = Curl_hash_pick(&cpool->dest2bundle, (void *)destination, dest_len);
  if(bundle) {
    struct Curl_llist_node *curr = Curl_llist_head(&bundle->conns);
    while(curr) {
      struct connectdata *conn = Curl_node_elem(curr);
      /* Get next node now. callback might discard current */
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
  CPOOL_UNLOCK(cpool);
  return result;
}

static void cpool_shutdown_discard_all(struct cpool *cpool)
{
  struct Curl_llist_node *e = Curl_llist_head(&cpool->shutdowns);
  struct connectdata *conn;

  if(!e)
    return;

  DEBUGF(infof(cpool->idata, "cpool_shutdown_discard_all"));
  while(e) {
    conn = Curl_node_elem(e);
    Curl_node_remove(e);
    DEBUGF(infof(cpool->idata, "discard connection #%" FMT_OFF_T,
                 conn->connection_id));
    cpool_close_and_destroy(cpool, conn, NULL, FALSE);
    e = Curl_llist_head(&cpool->shutdowns);
  }
}

static void cpool_close_and_destroy_all(struct cpool *cpool)
{
  struct connectdata *conn;
  int timeout_ms = 0;
  SIGPIPE_VARIABLE(pipe_st);

  DEBUGASSERT(cpool);
  /* Move all connections to the shutdown list */
  sigpipe_init(&pipe_st);
  CPOOL_LOCK(cpool);
  conn = cpool_get_live_conn(cpool);
  while(conn) {
    cpool_remove_conn(cpool, conn);
    sigpipe_apply(cpool->idata, &pipe_st);
    connclose(conn, "kill all");
    cpool_discard_conn(cpool, cpool->idata, conn, FALSE);

    conn = cpool_get_live_conn(cpool);
  }
  CPOOL_UNLOCK(cpool);

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
  sigpipe_apply(cpool->idata, &pipe_st);
  cpool_shutdown_all(cpool, cpool->idata, timeout_ms);

  /* discard all connections in the shutdown list */
  cpool_shutdown_discard_all(cpool);

  Curl_hostcache_clean(cpool->idata, cpool->idata->dns.hostcache);
  sigpipe_restore(&pipe_st);
}


static void cpool_shutdown_destroy_oldest(struct cpool *cpool)
{
  struct Curl_llist_node *e;
  struct connectdata *conn;

  e = Curl_llist_head(&cpool->shutdowns);
  if(e) {
    SIGPIPE_VARIABLE(pipe_st);
    conn = Curl_node_elem(e);
    Curl_node_remove(e);
    sigpipe_init(&pipe_st);
    sigpipe_apply(cpool->idata, &pipe_st);
    cpool_close_and_destroy(cpool, conn, NULL, FALSE);
    sigpipe_restore(&pipe_st);
  }
}

static void cpool_discard_conn(struct cpool *cpool,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted)
{
  bool done = FALSE;

  DEBUGASSERT(data);
  DEBUGASSERT(cpool);
  DEBUGASSERT(!conn->bits.in_cpool);

  /*
   * If this connection is not marked to force-close, leave it open if there
   * are other users of it
   */
  if(CONN_INUSE(conn) && !aborted) {
    DEBUGF(infof(data, "[CCACHE] not discarding #%" FMT_OFF_T
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
    cpool_run_conn_shutdown(data, conn, &done);
    DEBUGF(infof(data, "[CCACHE] shutdown #%" FMT_OFF_T ", done=%d",
                 conn->connection_id, done));
    Curl_detach_connection(data);
  }

  if(done) {
    cpool_close_and_destroy(cpool, conn, data, FALSE);
    return;
  }

  /* Add the connection to our shutdown list for non-blocking shutdown
   * during multi processing. */
  if(data->multi && data->multi->max_shutdown_connections > 0 &&
     (data->multi->max_shutdown_connections >=
      (long)Curl_llist_count(&cpool->shutdowns))) {
    DEBUGF(infof(data, "[CCACHE] discarding oldest shutdown connection "
                       "due to limit of %ld",
                       data->multi->max_shutdown_connections));
    cpool_shutdown_destroy_oldest(cpool);
  }

  if(data->multi && data->multi->socket_cb) {
    DEBUGASSERT(cpool == &data->multi->cpool);
    /* Start with an empty shutdown pollset, so out internal closure handle
     * is added to the sockets. */
    memset(&conn->shutdown_poll, 0, sizeof(conn->shutdown_poll));
    if(cpool_update_shutdown_ev(data->multi, cpool->idata, conn)) {
      DEBUGF(infof(data, "[CCACHE] update events for shutdown failed, "
                   "discarding #%" FMT_OFF_T,
                   conn->connection_id));
      cpool_close_and_destroy(cpool, conn, data, FALSE);
      return;
    }
  }

  Curl_llist_append(&cpool->shutdowns, conn, &conn->cpool_node);
  DEBUGF(infof(data, "[CCACHE] added #%" FMT_OFF_T
               " to shutdown list of length %zu", conn->connection_id,
               Curl_llist_count(&cpool->shutdowns)));
}

void Curl_cpool_disconnect(struct Curl_easy *data,
                           struct connectdata *conn,
                           bool aborted)
{
  struct cpool *cpool = cpool_get_instance(data);
  bool do_lock;

  DEBUGASSERT(cpool);
  DEBUGASSERT(data && !data->conn);
  if(!cpool)
    return;

  /* If this connection is not marked to force-close, leave it open if there
   * are other users of it */
  if(CONN_INUSE(conn) && !aborted) {
    DEBUGASSERT(0); /* does this ever happen? */
    DEBUGF(infof(data, "Curl_disconnect when inuse: %zu", CONN_INUSE(conn)));
    return;
  }

  /* This method may be called while we are under lock, e.g. from a
   * user callback in find. */
  do_lock = !CPOOL_IS_LOCKED(cpool);
  if(do_lock)
    CPOOL_LOCK(cpool);

  if(conn->bits.in_cpool) {
    cpool_remove_conn(cpool, conn);
    DEBUGASSERT(!conn->bits.in_cpool);
  }

  /* Run the callback to let it clean up anything it wants to. */
  aborted = cpool->disconnect_cb(data, conn, aborted);

  if(data->multi) {
    /* Add it to the multi's cpool for shutdown handling */
    infof(data, "%s connection #%" FMT_OFF_T,
          aborted ? "closing" : "shutting down", conn->connection_id);
    cpool_discard_conn(&data->multi->cpool, data, conn, aborted);
  }
  else {
    /* No multi available. Make a best-effort shutdown + close */
    infof(data, "closing connection #%" FMT_OFF_T, conn->connection_id);
    cpool_close_and_destroy(NULL, conn, data, !aborted);
  }

  if(do_lock)
    CPOOL_UNLOCK(cpool);
}

static void cpool_run_conn_shutdown_handler(struct Curl_easy *data,
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
      DEBUGF(infof(data, "connection #%" FMT_OFF_T
                   ", shutdown protocol handler (aborted=%d)",
                   conn->connection_id, conn->bits.aborted));

      conn->handler->disconnect(data, conn, conn->bits.aborted);
    }

    /* possible left-overs from the async name resolvers */
    Curl_resolver_cancel(data);

    conn->bits.shutdown_handler = TRUE;
  }
}

static void cpool_run_conn_shutdown(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    bool *done)
{
  CURLcode r1, r2;
  bool done1, done2;

  /* We expect to be attached when called */
  DEBUGASSERT(data->conn == conn);

  cpool_run_conn_shutdown_handler(data, conn);

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

static CURLcode cpool_add_pollfds(struct cpool *cpool,
                                  struct curl_pollfds *cpfds)
{
  CURLcode result = CURLE_OK;

  if(Curl_llist_head(&cpool->shutdowns)) {
    struct Curl_llist_node *e;
    struct easy_pollset ps;
    struct connectdata *conn;

    for(e = Curl_llist_head(&cpool->shutdowns); e;
        e = Curl_node_next(e)) {
      conn = Curl_node_elem(e);
      memset(&ps, 0, sizeof(ps));
      Curl_attach_connection(cpool->idata, conn);
      Curl_conn_adjust_pollset(cpool->idata, &ps);
      Curl_detach_connection(cpool->idata);

      result = Curl_pollfds_add_ps(cpfds, &ps);
      if(result) {
        Curl_pollfds_cleanup(cpfds);
        goto out;
      }
    }
  }
out:
  return result;
}

CURLcode Curl_cpool_add_pollfds(struct cpool *cpool,
                                struct curl_pollfds *cpfds)
{
  CURLcode result;
  CPOOL_LOCK(cpool);
  result = cpool_add_pollfds(cpool, cpfds);
  CPOOL_UNLOCK(cpool);
  return result;
}

CURLcode Curl_cpool_add_waitfds(struct cpool *cpool,
                                struct curl_waitfds *cwfds)
{
  CURLcode result = CURLE_OK;

  CPOOL_LOCK(cpool);
  if(Curl_llist_head(&cpool->shutdowns)) {
    struct Curl_llist_node *e;
    struct easy_pollset ps;
    struct connectdata *conn;

    for(e = Curl_llist_head(&cpool->shutdowns); e;
        e = Curl_node_next(e)) {
      conn = Curl_node_elem(e);
      memset(&ps, 0, sizeof(ps));
      Curl_attach_connection(cpool->idata, conn);
      Curl_conn_adjust_pollset(cpool->idata, &ps);
      Curl_detach_connection(cpool->idata);

      result = Curl_waitfds_add_ps(cwfds, &ps);
      if(result)
        goto out;
    }
  }
out:
  CPOOL_UNLOCK(cpool);
  return result;
}

static void cpool_perform(struct cpool *cpool)
{
  struct Curl_easy *data = cpool->idata;
  struct Curl_llist_node *e = Curl_llist_head(&cpool->shutdowns);
  struct Curl_llist_node *enext;
  struct connectdata *conn;
  struct curltime *nowp = NULL;
  struct curltime now;
  timediff_t next_from_now_ms = 0, ms;
  bool done;

  if(!e)
    return;

  DEBUGASSERT(data);
  DEBUGF(infof(data, "[CCACHE] perform, %zu connections being shutdown",
               Curl_llist_count(&cpool->shutdowns)));
  while(e) {
    enext = Curl_node_next(e);
    conn = Curl_node_elem(e);
    Curl_attach_connection(data, conn);
    cpool_run_conn_shutdown(data, conn, &done);
    DEBUGF(infof(data, "[CCACHE] shutdown #%" FMT_OFF_T ", done=%d",
                 conn->connection_id, done));
    Curl_detach_connection(data);
    if(done) {
      Curl_node_remove(e);
      cpool_close_and_destroy(cpool, conn, NULL, FALSE);
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

  if(next_from_now_ms)
    Curl_expire(data, next_from_now_ms, EXPIRE_RUN_NOW);
}

void Curl_cpool_multi_perform(struct Curl_multi *multi)
{
  CPOOL_LOCK(&multi->cpool);
  cpool_perform(&multi->cpool);
  CPOOL_UNLOCK(&multi->cpool);
}


/*
 * Close and destroy the connection. Run the shutdown sequence once,
 * of so requested.
 */
static void cpool_close_and_destroy(struct cpool *cpool,
                                    struct connectdata *conn,
                                    struct Curl_easy *data,
                                    bool do_shutdown)
{
  bool done;

  /* there must be a connection to close */
  DEBUGASSERT(conn);
  /* it must be removed from the connection pool */
  DEBUGASSERT(!conn->bits.in_cpool);
  /* there must be an associated transfer */
  DEBUGASSERT(data || cpool);
  if(!data)
    data = cpool->idata;

  /* the transfer must be detached from the connection */
  DEBUGASSERT(data && !data->conn);

  Curl_attach_connection(data, conn);

  cpool_run_conn_shutdown_handler(data, conn);
  if(do_shutdown) {
    /* Make a last attempt to shutdown handlers and filters, if
     * not done so already. */
    cpool_run_conn_shutdown(data, conn, &done);
  }

  if(cpool)
    DEBUGF(infof(data, "[CCACHE] closing #%" FMT_OFF_T,
                 conn->connection_id));
  else
    DEBUGF(infof(data, "closing connection #%" FMT_OFF_T,
                 conn->connection_id));
  Curl_conn_close(data, SECONDARYSOCKET);
  Curl_conn_close(data, FIRSTSOCKET);
  Curl_detach_connection(data);

  Curl_conn_free(data, conn);
}


static CURLMcode cpool_update_shutdown_ev(struct Curl_multi *multi,
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

void Curl_cpool_multi_socket(struct Curl_multi *multi,
                             curl_socket_t s, int ev_bitmask)
{
  struct cpool *cpool = &multi->cpool;
  struct Curl_easy *data = cpool->idata;
  struct Curl_llist_node *e;
  struct connectdata *conn;
  bool done;

  (void)ev_bitmask;
  DEBUGASSERT(multi->socket_cb);
  CPOOL_LOCK(cpool);
  e = Curl_llist_head(&cpool->shutdowns);
  while(e) {
    conn = Curl_node_elem(e);
    if(s == conn->sock[FIRSTSOCKET] || s == conn->sock[SECONDARYSOCKET]) {
      Curl_attach_connection(data, conn);
      cpool_run_conn_shutdown(data, conn, &done);
      DEBUGF(infof(data, "[CCACHE] shutdown #%" FMT_OFF_T ", done=%d",
                   conn->connection_id, done));
      Curl_detach_connection(data);
      if(done || cpool_update_shutdown_ev(multi, data, conn)) {
        Curl_node_remove(e);
        cpool_close_and_destroy(cpool, conn, NULL, FALSE);
      }
      break;
    }
    e = Curl_node_next(e);
  }
  CPOOL_UNLOCK(cpool);
}

#define NUM_POLLS_ON_STACK 10

static CURLcode cpool_shutdown_wait(struct cpool *cpool, int timeout_ms)
{
  struct pollfd a_few_on_stack[NUM_POLLS_ON_STACK];
  struct curl_pollfds cpfds;
  CURLcode result;

  Curl_pollfds_init(&cpfds, a_few_on_stack, NUM_POLLS_ON_STACK);

  result = cpool_add_pollfds(cpool, &cpfds);
  if(result)
    goto out;

  Curl_poll(cpfds.pfds, cpfds.n, CURLMIN(timeout_ms, 1000));

out:
  Curl_pollfds_cleanup(&cpfds);
  return result;
}

static void cpool_shutdown_all(struct cpool *cpool,
                               struct Curl_easy *data, int timeout_ms)
{
  struct connectdata *conn;
  struct curltime started = Curl_now();

  if(!data)
    return;
  (void)data;

  DEBUGF(infof(data, "cpool shutdown all"));

  /* Move all connections into the shutdown queue */
  for(conn = cpool_get_live_conn(cpool); conn;
      conn = cpool_get_live_conn(cpool)) {
    /* Move conn from live set to shutdown or destroy right away */
    DEBUGF(infof(data, "moving connection #%" FMT_OFF_T
                 " to shutdown queue", conn->connection_id));
    cpool_remove_conn(cpool, conn);
    cpool_discard_conn(cpool, data, conn, FALSE);
  }

  while(Curl_llist_head(&cpool->shutdowns)) {
    timediff_t timespent;
    int remain_ms;

    cpool_perform(cpool);

    if(!Curl_llist_head(&cpool->shutdowns)) {
      DEBUGF(infof(data, "cpool shutdown ok"));
      break;
    }

    /* wait for activity, timeout or "nothing" */
    timespent = Curl_timediff(Curl_now(), started);
    if(timespent >= (timediff_t)timeout_ms) {
      DEBUGF(infof(data, "cpool shutdown %s",
                   (timeout_ms > 0) ? "timeout" : "best effort done"));
      break;
    }

    remain_ms = timeout_ms - (int)timespent;
    if(cpool_shutdown_wait(cpool, remain_ms)) {
      DEBUGF(infof(data, "cpool shutdown all, abort"));
      break;
    }
  }

  /* Due to errors/timeout, we might come here without being done. */
  cpool_shutdown_discard_all(cpool);
}

struct cpool_reaper_ctx {
  struct curltime now;
};

static int cpool_reap_dead_cb(struct Curl_easy *data,
                              struct connectdata *conn, void *param)
{
  struct cpool_reaper_ctx *rctx = param;
  if(Curl_conn_seems_dead(conn, data, &rctx->now)) {
    /* stop the iteration here, pass back the connection that was pruned */
    Curl_cpool_disconnect(data, conn, FALSE);
    return 1;
  }
  return 0; /* continue iteration */
}

/*
 * This function scans the data's connection pool for half-open/dead
 * connections, closes and removes them.
 * The cleanup is done at most once per second.
 *
 * When called, this transfer has no connection attached.
 */
void Curl_cpool_prune_dead(struct Curl_easy *data)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct cpool_reaper_ctx rctx;
  timediff_t elapsed;

  if(!cpool)
    return;

  rctx.now = Curl_now();
  CPOOL_LOCK(cpool);
  elapsed = Curl_timediff(rctx.now, cpool->last_cleanup);

  if(elapsed >= 1000L) {
    while(cpool_foreach(data, cpool, &rctx, cpool_reap_dead_cb))
      ;
    cpool->last_cleanup = rctx.now;
  }
  CPOOL_UNLOCK(cpool);
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

CURLcode Curl_cpool_upkeep(void *data)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct curltime now = Curl_now();

  if(!cpool)
    return CURLE_OK;

  CPOOL_LOCK(cpool);
  cpool_foreach(data, cpool, &now, conn_upkeep);
  CPOOL_UNLOCK(cpool);
  return CURLE_OK;
}

struct cpool_find_ctx {
  curl_off_t id;
  struct connectdata *conn;
};

static int cpool_find_conn(struct Curl_easy *data,
                           struct connectdata *conn, void *param)
{
  struct cpool_find_ctx *fctx = param;
  (void)data;
  if(conn->connection_id == fctx->id) {
    fctx->conn = conn;
    return 1;
  }
  return 0;
}

struct connectdata *Curl_cpool_get_conn(struct Curl_easy *data,
                                        curl_off_t conn_id)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct cpool_find_ctx fctx;

  if(!cpool)
    return NULL;
  fctx.id = conn_id;
  fctx.conn = NULL;
  CPOOL_LOCK(cpool);
  cpool_foreach(cpool->idata, cpool, &fctx, cpool_find_conn);
  CPOOL_UNLOCK(cpool);
  return fctx.conn;
}

struct cpool_do_conn_ctx {
  curl_off_t id;
  Curl_cpool_conn_do_cb *cb;
  void *cbdata;
};

static int cpool_do_conn(struct Curl_easy *data,
                         struct connectdata *conn, void *param)
{
  struct cpool_do_conn_ctx *dctx = param;
  (void)data;
  if(conn->connection_id == dctx->id) {
    dctx->cb(conn, data, dctx->cbdata);
    return 1;
  }
  return 0;
}

void Curl_cpool_do_by_id(struct Curl_easy *data, curl_off_t conn_id,
                         Curl_cpool_conn_do_cb *cb, void *cbdata)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct cpool_do_conn_ctx dctx;

  if(!cpool)
    return;
  dctx.id = conn_id;
  dctx.cb = cb;
  dctx.cbdata = cbdata;
  CPOOL_LOCK(cpool);
  cpool_foreach(data, cpool, &dctx, cpool_do_conn);
  CPOOL_UNLOCK(cpool);
}

void Curl_cpool_do_locked(struct Curl_easy *data,
                          struct connectdata *conn,
                          Curl_cpool_conn_do_cb *cb, void *cbdata)
{
  struct cpool *cpool = cpool_get_instance(data);
  if(cpool) {
    CPOOL_LOCK(cpool);
    cb(conn, data, cbdata);
    CPOOL_UNLOCK(cpool);
  }
  else
    cb(conn, data, cbdata);
}

#if 0
/* Useful for debugging the connection pool */
void Curl_cpool_print(struct cpool *cpool)
{
  struct Curl_hash_iterator iter;
  struct Curl_llist_node *curr;
  struct Curl_hash_element *he;

  if(!cpool)
    return;

  fprintf(stderr, "=Bundle cache=\n");

  Curl_hash_start_iterate(cpool->dest2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct cpool_bundle *bundle;
    struct connectdata *conn;

    bundle = he->ptr;

    fprintf(stderr, "%s -", he->key);
    curr = Curl_llist_head(bundle->conns);
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
