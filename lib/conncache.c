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

#include "urldata.h"
#include "url.h"
#include "cfilters.h"
#include "progress.h"
#include "multiif.h"
#include "curl_trc.h"
#include "cshutdn.h"
#include "conncache.h"
#include "curl_share.h"
#include "sigpipe.h"


#define CPOOL_IS_LOCKED(c)    ((c) && (c)->locked)

#define CPOOL_LOCK(c, d)                                                \
  do {                                                                  \
    if(c) {                                                             \
      if(CURL_SHARE_KEEP_CONNECT((c)->share))                           \
        Curl_share_lock_share((c)->share, (d), CURL_LOCK_DATA_CONNECT,  \
                        CURL_LOCK_ACCESS_SINGLE);                       \
      DEBUGASSERT(!(c)->locked);                                        \
      (c)->locked = TRUE;                                               \
    }                                                                   \
  } while(0)

#define CPOOL_UNLOCK(c, d)                                              \
  do {                                                                  \
    if(c) {                                                             \
      DEBUGASSERT((c)->locked);                                         \
      (c)->locked = FALSE;                                              \
      if(CURL_SHARE_KEEP_CONNECT((c)->share))                           \
        Curl_share_unlock_share((c)->share, (d), CURL_LOCK_DATA_CONNECT); \
    }                                                                   \
  } while(0)

/* A list of connections to the same destination. */
struct cpool_bundle {
  struct Curl_llist conns; /* connections in the bundle */
};

static struct cpool_bundle *cpool_bundle_create(void)
{
  struct cpool_bundle *bundle = curlx_calloc(1, sizeof(*bundle));
  if(bundle)
    Curl_llist_init(&bundle->conns, NULL);
  return bundle;
}

static void cpool_bundle_destroy(struct cpool_bundle *bundle)
{
  DEBUGASSERT(!Curl_llist_count(&bundle->conns));
  curlx_free(bundle);
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

void Curl_cpool_init(struct cpool *cpool,
                     struct Curl_share *share,
                     size_t size)
{
  Curl_hash_init(&cpool->dest2bundle, size, CURL_HASH_TYPE_BYTES,
                 cpool_bundle_free_entry);

  cpool->share = share;
  cpool->initialized = TRUE;
}

/* Return the "first" connection in the pool or NULL. */
static struct connectdata *cpool_get_first(struct cpool *cpool)
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

static struct cpool_bundle *cpool_find_bundle(struct cpool *cpool,
                                              const char *destination)
{
  return Curl_hash_pick(
    &cpool->dest2bundle, destination, strlen(destination) + 1);
}

static void cpool_remove_bundle(struct cpool *cpool,
                                const char *destination)
{
  if(!cpool)
    return;
  Curl_hash_delete(&cpool->dest2bundle, destination, strlen(destination) + 1);
}

static void cpool_remove_conn(struct cpool *cpool,
                              struct connectdata *conn)
{
  struct Curl_llist *list = Curl_node_llist(&conn->cpool_node);
  DEBUGASSERT(cpool);
  if(list) {
    /* The connection is certainly in the pool, but where? */
    struct cpool_bundle *bundle = cpool_find_bundle(cpool, conn->destination);
    if(bundle && (list == &bundle->conns)) {
      cpool_bundle_remove(bundle, conn);
      if(!Curl_llist_count(&bundle->conns))
        cpool_remove_bundle(cpool, conn->destination);
      conn->bits.in_cpool = FALSE;
      cpool->num_conn--;
    }
    else {
      /* Should have been in the bundle list */
      DEBUGASSERT(NULL);
    }
  }
}

static void cpool_discard_conn(struct cpool *cpool,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted)
{
  struct Curl_easy *admin;
  bool done = FALSE;

  DEBUGASSERT(data);
  DEBUGASSERT(!data->conn);
  DEBUGASSERT(cpool);
  DEBUGASSERT(!conn->bits.in_cpool);

  admin = Curl_get_admin(data);
  /*
   * If this connection is not marked to force-close, leave it open if there
   * are other users of it
   */
  if(CONN_INUSE(conn) && !aborted) {
    CURL_TRC_M(admin, "[CPOOL] not discarding #%" FMT_OFF_T
               " still in use by %u transfers", conn->connection_id,
               conn->attached_xfers);
    return;
  }

  /* treat the connection as aborted in CONNECT_ONLY situations, we do
   * not know what the APP did with it. */
  if(conn->bits.connect_only)
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
    Curl_cshutdn_try_once(admin, conn, &done);
  }

  if(done || !data->multi)
    Curl_cshutdn_terminate(admin, conn, FALSE);
  else {
    struct Curl_multi *multi = data->multi;
    size_t max_shutdowns = multi->max_total_connections;
    if(cpool->num_conn < max_shutdowns)
      max_shutdowns -= cpool->num_conn;
    else if(max_shutdowns)
      max_shutdowns = 1;
    else /* no connection limit set, let's restrict growth nevertheless */
      max_shutdowns = CURLMAX(cpool->num_conn / 4, 128);
    Curl_cshutdn_add(&multi->cshutdn, multi, conn, max_shutdowns);
  }
}

void Curl_cpool_destroy(struct cpool *cpool, struct Curl_easy *admin)
{
  if(cpool && cpool->initialized && admin) {
    struct connectdata *conn;
    struct Curl_sigpipe_ctx pipe_ctx;

    CURL_TRC_M(admin, "%s[CPOOL] destroy, %zu connections",
               cpool->share ? "[SHARE] " : "", cpool->num_conn);
    /* Move all connections to the shutdown list */
    sigpipe_init(&pipe_ctx);
    CPOOL_LOCK(cpool, admin);
    conn = cpool_get_first(cpool);
    if(conn)
      sigpipe_apply(admin, &pipe_ctx);
    while(conn) {
      cpool_remove_conn(cpool, conn);
      cpool_discard_conn(cpool, admin, conn, FALSE);
      conn = cpool_get_first(cpool);
    }
    CPOOL_UNLOCK(cpool, admin);
    sigpipe_restore(&pipe_ctx);
    Curl_hash_destroy(&cpool->dest2bundle);
  }
}

static struct cpool *cpool_get_instance(struct Curl_easy *data)
{
  /* admin handles do not necessarily find the correct pool */
  DEBUGASSERT(data->mid);
  if(CURL_SHARE_KEEP_CONNECT(data->share))
    return &data->share->cpool;
  else if(data->multi_easy)
    return &data->multi_easy->cpool;
  else if(data->multi)
    return &data->multi->cpool;
  return NULL;
}

struct cpool *Curl_cpool_get_instance(struct Curl_easy *data)
{
  return cpool_get_instance(data);
}

void Curl_cpool_xfer_init(struct Curl_easy *data)
{
  struct cpool *cpool = cpool_get_instance(data);

  if(cpool) {
    CPOOL_LOCK(cpool, data);
    /* the identifier inside the connection cache */
    data->id = cpool->next_easy_id++;
    if(cpool->next_easy_id == CURL_OFF_T_MAX)
      cpool->next_easy_id = 0;
    data->state.lastconnect_id = -1;

    CPOOL_UNLOCK(cpool, data);
  }
  else {
    /* We should not get here, but in a non-debug build, do something */
    DEBUGASSERT(0);
    data->id = 0;
    data->state.lastconnect_id = -1;
  }
}

static struct cpool_bundle *cpool_add_bundle(struct cpool *cpool,
                                             const char *destination)
{
  struct cpool_bundle *bundle;

  bundle = cpool_bundle_create();
  if(!bundle)
    return NULL;

  if(!Curl_hash_add(&cpool->dest2bundle,
                    destination, strlen(destination) + 1, bundle)) {
    cpool_bundle_destroy(bundle);
    return NULL;
  }
  return bundle;
}

static struct connectdata *cpool_bundle_get_oldest_idle(
  struct cpool_bundle *bundle,
  const struct curltime *pnow)
{
  struct Curl_llist_node *curr;
  struct connectdata *oldest_idle = NULL;
  timediff_t unused_ms;
  timediff_t oldest_ms = -1;
  struct connectdata *conn;

  curr = Curl_llist_head(&bundle->conns);
  while(curr) {
    conn = Curl_node_elem(curr);

    /* CONNECT_ONLY sockets remain in use by the application. */
    if(!CONN_INUSE(conn) && !conn->bits.close && !conn->bits.connect_only) {
      /* Set higher score for the age passed since the connection was used */
      unused_ms = curlx_ptimediff_ms(pnow, &conn->created) - conn->lastused_ms;
      if(unused_ms > oldest_ms) {
        oldest_ms = unused_ms;
        oldest_idle = conn;
      }
    }
    curr = Curl_node_next(curr);
  }
  return oldest_idle;
}

static struct connectdata *cpool_get_oldest_idle(struct cpool *cpool,
                                                 const struct curltime *pnow,
                                                 timediff_t min_age_ms)
{
  struct Curl_hash_iterator iter;
  struct Curl_llist_node *curr;
  struct Curl_hash_element *he;
  struct cpool_bundle *bundle;
  struct connectdata *oldest_idle = NULL;
  timediff_t oldest_idle_ms = -1;
  timediff_t idle_ms;

  Curl_hash_start_iterate(&cpool->dest2bundle, &iter);

  for(he = Curl_hash_next_element(&iter); he;
      he = Curl_hash_next_element(&iter)) {
    struct connectdata *conn;
    bundle = he->ptr;

    for(curr = Curl_llist_head(&bundle->conns); curr;
        curr = Curl_node_next(curr)) {
      conn = Curl_node_elem(curr);
      if(CONN_INUSE(conn) || conn->bits.close || conn->bits.connect_only)
        continue;
      idle_ms = curlx_ptimediff_ms(pnow, &conn->created) - conn->lastused_ms;
      if((idle_ms >= min_age_ms) && (idle_ms > oldest_idle_ms)) {
        oldest_idle_ms = idle_ms;
        oldest_idle = conn;
      }
    }
  }
  return oldest_idle;
}

static void cpool_conn_close(struct cpool *cpool,
                             struct Curl_easy *data,
                             struct connectdata *conn,
                             bool aborted)
{
  struct Curl_easy *admin;
  bool do_lock;

  DEBUGASSERT(cpool);
  DEBUGASSERT(data && !data->conn);
  if(!cpool)
    return;

  /* If this connection is not marked to force-close, leave it open if there
   * are other users of it */
  if(CONN_INUSE(conn) && !aborted) {
    DEBUGASSERT(0); /* does this ever happen? */
    DEBUGF(infof(data, "conn terminate when inuse: %u", conn->attached_xfers));
    return;
  }

  /* This method may be called while we are under lock, e.g. from a
   * user callback in find. */
  admin = Curl_get_admin(data);
  do_lock = !CPOOL_IS_LOCKED(cpool);
  if(do_lock)
    CPOOL_LOCK(cpool, admin);

  if(conn->bits.in_cpool) {
    cpool_remove_conn(cpool, conn);
    DEBUGASSERT(!conn->bits.in_cpool);
  }

  /* treat the connection as aborted in CONNECT_ONLY situations,
   * so no graceful shutdown is attempted. */
  if(conn->bits.connect_only)
    aborted = TRUE;

  if(data->multi) {
    /* Add it to the multi's cpool for shutdown handling */
    infof(data, "%s connection #%" FMT_OFF_T,
          aborted ? "closing" : "shutting down", conn->connection_id);
    cpool_discard_conn(&data->multi->cpool, data, conn, aborted);
  }
  else {
    /* No multi available, terminate */
    infof(data, "closing connection #%" FMT_OFF_T, conn->connection_id);
    Curl_cshutdn_terminate(admin, conn, !aborted);
  }

  if(do_lock)
    CPOOL_UNLOCK(cpool, admin);
}

void Curl_conn_close(struct Curl_easy *data,
                     struct connectdata *conn,
                     bool aborted)
{
  struct cpool *cpool = cpool_get_instance(data);
  cpool_conn_close(cpool, data, conn, aborted);
}

/* Evict an idle connection to make room in the pool. A pool owned by
 * a share has no multi that could perform a controlled shutdown of the
 * connection; terminate it right away. Otherwise, hand it to the
 * transfer's multi for shutdown. Expects the pool to be locked. */
static void cpool_evict_conn(struct cpool *cpool,
                             struct Curl_easy *admin,
                             struct connectdata *conn)
{
  if(cpool->share) {
    cpool_remove_conn(cpool, conn);
    Curl_cshutdn_terminate(admin, conn, TRUE);
  }
  else
    cpool_conn_close(cpool, admin, conn, FALSE);
}

#define CPOOL_LIMIT_OK     0
#define CPOOL_LIMIT_DEST   1
#define CPOOL_LIMIT_TOTAL  2

static int cpool_check_limits(struct Curl_easy *data,
                              uint32_t max_total,
                              struct connectdata *to_add,
                              uint32_t max_host,
                              struct cpool_bundle **pbundle,
                              const struct curltime *pnow)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct cshutdn *cshutdn = data->multi ? &data->multi->cshutdn : NULL;
  struct Curl_easy *admin = NULL;

  if(!cpool)
    return CPOOL_LIMIT_OK;

  if(!max_total && !max_host)
    return CPOOL_LIMIT_OK;

  if(max_host && *pbundle) {
    size_t live, shutdowns = 0;
    /* if we are at or above `dest_limit`, try to get rid of connections
     * in shutdown and, if that does not lower it, evict idle connections
     * from the pool. */
    admin = Curl_get_admin(data);
    live = Curl_llist_count(&(*pbundle)->conns);
    if(live >= max_host) {
      size_t over = live - max_host + 1;
      for(; over && *pbundle; --over) {
        struct connectdata *oldest_idle =
          cpool_bundle_get_oldest_idle(*pbundle, pnow);
        if(!oldest_idle)
          break;
        /* disconnect the old conn and continue */
        CURL_TRC_M(admin, "Shutting down connection #%" FMT_OFF_T
                   " to '%s' due to destination limit of %u",
                   oldest_idle->connection_id, oldest_idle->destination,
                   max_host);
        cpool_evict_conn(cpool, admin, oldest_idle);
        /* in case the bundle was destroyed in disconnect, look it up again */
        *pbundle = cpool_find_bundle(cpool, to_add->destination);
      }
      live = *pbundle ? Curl_llist_count(&(*pbundle)->conns) : 0;
    }
    if(cshutdn) {
      shutdowns = Curl_cshutdn_dest_count(cshutdn, to_add->destination);
      if(shutdowns && ((live + shutdowns) >= max_host)) {
        size_t over = live + shutdowns - max_host + 1;
        shutdowns -= Curl_cshutdn_close_oldest(cshutdn, admin,
                                               to_add->destination, over);
      }
    }
    /* We may not have gotten rid of as many connections as we wanted to */
    if((live + shutdowns) >= max_host)
      return CPOOL_LIMIT_DEST;
  }

  /* Internal transfers are outside the total limit */
  if(max_total && !data->state.internal) {
    size_t shutdowns = 0;

    if(!admin)
      admin = Curl_get_admin(data);
    if(cpool->num_conn >= max_total) {
      size_t over = cpool->num_conn - max_total + 1;
      for(; over; --over) {
        struct connectdata *oldest_idle =
          cpool_get_oldest_idle(cpool, pnow, 0);
        if(!oldest_idle)
          break;
        /* disconnect the old conn and continue */
        CURL_TRC_M(admin, "Shutting down idle connection #%"
                   FMT_OFF_T " to '%s' due to total limit of %u",
                   oldest_idle->connection_id, oldest_idle->destination,
                   max_total);
        cpool_evict_conn(cpool, admin, oldest_idle);
      }
      /* bundle might be gone due to evictions */
      if(*pbundle)
        *pbundle = cpool_find_bundle(cpool, to_add->destination);
    }
    if(cshutdn) {
      shutdowns = Curl_cshutdn_count(cshutdn);
      if(shutdowns && (cpool->num_conn + shutdowns) >= max_total) {
        size_t over = cpool->num_conn + shutdowns - max_total + 1;
        shutdowns -= Curl_cshutdn_close_oldest(cshutdn, admin, NULL, over);
      }
    }
    if((cpool->num_conn + shutdowns) >= max_total)
      return CPOOL_LIMIT_TOTAL;
  }

  return CPOOL_LIMIT_OK;
}

CURLcode Curl_cpool_add(struct Curl_easy *data,
                        struct connectdata *conn,
                        uint32_t max_total,
                        uint32_t max_host,
                        const struct curltime *pnow)
{
  CURLcode result = CURLE_OK;
  struct cpool_bundle *bundle = NULL;
  struct cpool *cpool = cpool_get_instance(data);
  DEBUGASSERT(conn);

  DEBUGASSERT(cpool);
  if(!cpool)
    return CURLE_FAILED_INIT;

  conn->created = *pnow;
  conn->shutdown.start_ms[FIRSTSOCKET] =
    conn->shutdown.start_ms[SECONDARYSOCKET] = -1;

  CPOOL_LOCK(cpool, data);

  /* Find the bundle, should it exist, and check the limits */
  bundle = cpool_find_bundle(cpool, conn->destination);

  switch(cpool_check_limits(data, max_total, conn, max_host, &bundle, pnow)) {
  case CPOOL_LIMIT_DEST:
    infof(data, "No more connections allowed to host");
    result = CURLE_NO_CONNECTION_AVAILABLE;
    goto out;
  case CPOOL_LIMIT_TOTAL:
    infof(data, "No connections available, total of %u reached.",
          data->multi->max_total_connections);
    result = CURLE_NO_CONNECTION_AVAILABLE;
    goto out;
  default:
    break;
  }

  if(!bundle) {
    bundle = cpool_add_bundle(cpool, conn->destination);
    if(!bundle) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
  }

  cpool_bundle_add(bundle, conn);
  conn->connection_id = cpool->next_connection_id++;
  cpool->num_conn++;
  CURL_TRC_M(data, "[CPOOL] added connection %" FMT_OFF_T ". "
             "The cache now contains %zu members",
             conn->connection_id, cpool->num_conn);
out:
  CPOOL_UNLOCK(cpool, data);

  return result;
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
                          int (*func)(struct cpool *cpool,
                                      struct Curl_easy *data,
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

      if(func(cpool, data, conn, param) == 1) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

/*
 * A connection (already in the pool) has become idle. Do any
 * cleanups in regard to the pool's limits.
 *
 * Return TRUE if idle connection kept in pool, FALSE if closed.
 */
bool Curl_cpool_conn_now_idle(struct Curl_easy *data,
                              struct connectdata *conn,
                              const struct curltime *pnow)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct connectdata *oldest_idle = NULL;
  struct Curl_easy *admin;
  unsigned int maxconnects;
  bool kept = TRUE;
  timediff_t min_age_ms = 0;

  if(!data || !data->multi)
    return kept;

  if(!data->multi->maxconnects) {
    /* Attached transfers is a weak indicator of business. */
    uint32_t attached = Curl_multi_xfers_attached(data->multi);
    maxconnects = (attached <= UINT_MAX / 2) ? attached * 2 : UINT_MAX;
    /* We are guessing. So, only evict a "seemingly superfluous" connection
     * when has not been used for this long, */
    min_age_ms = 1000;
  }
  else {
    maxconnects = data->multi->maxconnects;
  }

  /* remember times, connection had been used just before */
  conn->lastchecked_ms = conn->lastupkeep_ms = conn->lastused_ms =
    curlx_ptimediff_ms(pnow, &conn->created);
  if(cpool && maxconnects) {
    /* may be called form a callback already under lock */
    bool do_lock = !CPOOL_IS_LOCKED(cpool);

    admin = Curl_get_admin(data);
    if(do_lock)
      CPOOL_LOCK(cpool, admin);
    if(cpool->num_conn > maxconnects) {
      infof(data, "Connection pool is full, closing the oldest of %zu/%u",
            cpool->num_conn, maxconnects);

      oldest_idle = cpool_get_oldest_idle(cpool, pnow, min_age_ms);
      kept = (oldest_idle != conn);
      if(oldest_idle) {
        cpool_evict_conn(cpool, admin, oldest_idle);
      }
    }
    if(do_lock)
      CPOOL_UNLOCK(cpool, admin);
  }

  return kept;
}

static void cpool_prune_dead(struct cpool *cpool,
                             struct Curl_easy *data,
                             const struct curltime *pnow);

static bool cpool_find_act(struct cpool *cpool,
                           struct Curl_easy *data,
                           struct cpool_bundle *bundle,
                           struct connectdata *conn,
                           cpool_match_result match)
{
  switch(match) {
  case CPOOL_MATCH_FOUND:
    return TRUE;
  case CPOOL_MATCH_TOO_OLD:
    if(CONN_INUSE(conn))
      return FALSE;
    FALLTHROUGH();
  case CPOOL_MATCH_CLOSE:
    DEBUGASSERT(conn->bits.in_cpool);
    if(conn->bits.in_cpool) {
      cpool_bundle_remove(bundle, conn);
      conn->bits.in_cpool = FALSE;
      cpool->num_conn--;
    }
    cpool_conn_close(cpool, data, conn, FALSE);
    break;
  default:
    break;
  }
  return FALSE;
}

bool Curl_cpool_find(struct Curl_easy *data,
                     const char *destination,
                     bool prune_dead,
                     const struct curltime *pnow,
                     Curl_cpool_conn_match_cb *conn_cb,
                     Curl_cpool_done_match_cb *done_cb,
                     void *userdata)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct cpool_bundle *bundle;
  struct Curl_llist_node *curr;
  struct connectdata *conn;
  bool found = FALSE;

  DEBUGASSERT(cpool);
  DEBUGASSERT(conn_cb);
  if(!cpool)
    return FALSE;

  CPOOL_LOCK(cpool, data);

  if(prune_dead)
    cpool_prune_dead(cpool, data, pnow);

  bundle = Curl_hash_pick(&cpool->dest2bundle,
                          destination, strlen(destination) + 1);
  if(bundle) {
    if(data->state.lastconnect_id >= 0) {
      /* Try to find the previously used connection in this bundle
       * and if it still matches, use that one. This assures that
       * an authentication involving several requests is using
       * the same connection again. */
      curr = Curl_llist_head(&bundle->conns);
      while(!found && curr) {
        conn = Curl_node_elem(curr);
        curr = Curl_node_next(curr);
        if(data->state.lastconnect_id != conn->connection_id)
          continue;
        found = cpool_find_act(cpool, data, bundle, conn,
                               conn_cb(conn, userdata));
        break;
      }
    }

    if(!found) {
      curr = Curl_llist_head(&bundle->conns);
      while(!found && curr) {
        conn = Curl_node_elem(curr);
        curr = Curl_node_next(curr);
        /* Already tried a matching connection above. */
        if(data->state.lastconnect_id == conn->connection_id)
          continue;
        found = cpool_find_act(cpool, data, bundle, conn,
                               conn_cb(conn, userdata));
      }
    }

    if(!Curl_llist_count(&bundle->conns))
      cpool_remove_bundle(cpool, destination);
  }

  if(done_cb) {
    found = done_cb(userdata);
  }
  CPOOL_UNLOCK(cpool, data);
  return found;
}

struct cpool_reaper_ctx {
  size_t reaped;
  const struct curltime *pnow;
};

static int cpool_reap_dead_cb(struct cpool *cpool,
                              struct Curl_easy *admin,
                              struct connectdata *conn, void *param)
{
  struct cpool_reaper_ctx *reaper = param;

  if(!CONN_INUSE(conn)) {
    if(conn->bits.no_reuse || conn->bits.close ||
       !Curl_cpool_conn_seems_healthy(conn, admin, reaper->pnow)) {
      /* terminate conn and stop the iteration */
      reaper->reaped++;
      cpool_conn_close(cpool, admin, conn, FALSE);
      return 1;
    }
  }
  return 0; /* continue iteration */
}

/*
 * This function scans the data's connection pool for half-open/dead
 * connections, closes and removes them.
 * The cleanup is done at most once per second.
 */
static void cpool_prune_dead(struct cpool *cpool,
                             struct Curl_easy *data,
                             const struct curltime *pnow)
{
  timediff_t elapsed_ms = curlx_ptimediff_ms(pnow, &cpool->last_cleanup);

  if(elapsed_ms >= 1000L) {
    struct Curl_easy *admin = Curl_get_admin(data);
    struct cpool_reaper_ctx reaper;

    memset(&reaper, 0, sizeof(reaper));
    reaper.pnow = pnow;
    while(cpool_foreach(admin, cpool, &reaper, cpool_reap_dead_cb))
      ;
    cpool->last_cleanup = *pnow;
  }
}

static int conn_upkeep(struct cpool *cpool,
                       struct Curl_easy *admin,
                       struct connectdata *conn,
                       void *param)
{
  const struct curltime *pnow = Curl_pgrs_now(admin);

  (void)param;
  if((curlx_ptimediff_ms(pnow, &conn->created) - conn->lastupkeep_ms) >=
     admin->set.upkeep_interval_ms) {
    CURLcode result;

    conn->lastupkeep_ms = curlx_ptimediff_ms(pnow, &conn->created);
    /* briefly attach for action */
    Curl_attach_connection(admin, conn, FALSE);
    result = Curl_conn_keep_alive(admin, conn);
    Curl_detach_connection(admin);

    if(result && !CONN_INUSE(conn)) {
      cpool_conn_close(cpool, admin, conn, FALSE);
      return 1;
    }
  }
  return 0; /* continue iteration */
}

CURLcode Curl_cpool_upkeep(struct Curl_easy *data)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct Curl_easy *admin = Curl_get_admin(data);

  if(!cpool)
    return CURLE_OK;

  CPOOL_LOCK(cpool, admin);
  while(cpool_foreach(admin, cpool, NULL, conn_upkeep))
    ;
  CPOOL_UNLOCK(cpool, admin);
  return CURLE_OK;
}

struct cpool_find_ctx {
  curl_off_t id;
  struct connectdata *conn;
};

static int cpool_find_conn(struct cpool *cpool,
                           struct Curl_easy *data,
                           struct connectdata *conn, void *param)
{
  struct cpool_find_ctx *fctx = param;
  (void)cpool;
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
  CPOOL_LOCK(cpool, data);
  cpool_foreach(data, cpool, &fctx, cpool_find_conn);
  CPOOL_UNLOCK(cpool, data);
  return fctx.conn;
}

void Curl_cpool_do_locked(struct Curl_easy *data,
                          struct connectdata *conn,
                          Curl_cpool_conn_do_cb *cb, void *cbdata)
{
  struct cpool *cpool = cpool_get_instance(data);
  if(cpool) {
    CPOOL_LOCK(cpool, data);
    cb(conn, data, cbdata);
    CPOOL_UNLOCK(cpool, data);
  }
  else
    cb(conn, data, cbdata);
}

static int cpool_mark_stale(struct cpool *cpool,
                            struct Curl_easy *admin,
                            struct connectdata *conn, void *param)
{
  (void)cpool;
  (void)admin;
  (void)param;
  conn->bits.no_reuse = TRUE;
  return 0;
}

static int cpool_reap_no_reuse(struct cpool *cpool,
                               struct Curl_easy *admin,
                               struct connectdata *conn, void *param)
{
  (void)param;
  if(!CONN_INUSE(conn) && conn->bits.no_reuse) {
    cpool_conn_close(cpool, admin, conn, FALSE);
    return 1;
  }
  return 0; /* continue iteration */
}

void Curl_cpool_nw_changed(struct cpool *cpool, struct Curl_easy *admin)
{
  if(cpool && admin) {
    CPOOL_LOCK(cpool, admin);
    cpool_foreach(admin, cpool, NULL, cpool_mark_stale);
    while(cpool_foreach(admin, cpool, NULL, cpool_reap_no_reuse))
      ;
    CPOOL_UNLOCK(cpool, admin);
  }
}

/* A connection has to have been idle for less than 'conn_max_idle_ms'
   (the success rate is too low after this), or created less than
   'conn_max_age_ms' ago, to be subject for reuse. */
static bool cpool_conn_too_old(struct Curl_easy *data,
                               struct connectdata *conn,
                               const struct curltime *pnow)
{
  timediff_t age_ms;

  if(data->set.conn_max_idle_ms) {
    age_ms = curlx_ptimediff_ms(pnow, &conn->created) - conn->lastused_ms;
    if(age_ms > data->set.conn_max_idle_ms) {
      infof(data, "Too old connection (%" FMT_TIMEDIFF_T
            " ms idle, max idle is %" FMT_TIMEDIFF_T " ms), disconnect it",
            age_ms, data->set.conn_max_idle_ms);
      return TRUE;
    }
  }

  if(data->set.conn_max_age_ms) {
    age_ms = curlx_ptimediff_ms(pnow, &conn->created);
    if(age_ms > data->set.conn_max_age_ms) {
      infof(data,
            "Too old connection (created %" FMT_TIMEDIFF_T
            " ms ago, max lifetime is %" FMT_TIMEDIFF_T " ms), disconnect it",
            age_ms, data->set.conn_max_age_ms);
      return TRUE;
    }
  }

  return FALSE;
}

bool Curl_cpool_conn_seems_healthy(struct connectdata *conn,
                                   struct Curl_easy *data,
                                   const struct curltime *pnow)
{
  struct Curl_easy *admin;
  bool healthy = TRUE;

  DEBUGASSERT(!data->conn);
  if(!CONN_INUSE(conn) && cpool_conn_too_old(data, conn, pnow))
    return FALSE;
  if((curlx_ptimediff_ms(pnow, &conn->created) - conn->lastchecked_ms) < 1000)
    return TRUE;

  admin = Curl_get_admin(data);
  if(conn->scheme->run->connection_is_dead) {
    Curl_attach_connection(admin, conn, FALSE);
    healthy = !conn->scheme->run->connection_is_dead(admin, conn);
    Curl_detach_connection(admin);
  }
  else {
    bool input_pending = FALSE;

    Curl_attach_connection(admin, conn, FALSE);
    healthy = Curl_conn_is_alive(admin, conn, &input_pending);
    Curl_detach_connection(admin);
    if(healthy && input_pending &&
       !CONN_INUSE(conn) && !Curl_conn_is_multiplex(conn, FIRSTSOCKET)) {
      /* Non-multiplexed connections without attached transfers should
       * not have input pending. The input might be a TLS Notify Close,
       * for all we know. */
      DEBUGF(infof(data, "connection has no transfer but input, not healthy"));
      healthy = FALSE;
    }
  }

  if(healthy)
    conn->lastchecked_ms = curlx_ptimediff_ms(pnow, &conn->created);
  return healthy;
}

void Curl_cpool_conn_was_used(struct Curl_easy *data,
                              struct connectdata *conn,
                              const struct curltime *pnow)
{
  (void)data;
  conn->lastupkeep_ms = curlx_ptimediff_ms(pnow, &conn->created);
}

timediff_t Curl_cpool_conn_age_ms(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  const struct curltime *pnow)
{
  (void)data;
  return curlx_ptimediff_ms(pnow, &conn->created);
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

  curl_mfprintf(stderr, "=Bundle cache=\n");

  Curl_hash_start_iterate(cpool->dest2bundle, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct cpool_bundle *bundle;
    struct connectdata *conn;

    bundle = he->ptr;

    curl_mfprintf(stderr, "%s -", he->key);
    curr = Curl_llist_head(bundle->conns);
    while(curr) {
      conn = Curl_node_elem(curr);

      curl_mfprintf(stderr, " [%p %d]", (void *)conn, conn->refcount);
      curr = Curl_node_next(curr);
    }
    curl_mfprintf(stderr, "\n");

    he = Curl_hash_next_element(&iter);
  }
}
#endif
