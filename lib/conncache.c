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
#include "multi_ev.h"
#include "sendf.h"
#include "cshutdn.h"
#include "conncache.h"
#include "http_negotiate.h"
#include "http_ntlm.h"
#include "share.h"
#include "sigpipe.h"
#include "connect.h"
#include "select.h"
#include "strcase.h"
#include "strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#define CPOOL_IS_LOCKED(c)    ((c) && (c)->locked)

#define CPOOL_LOCK(c,d)                                                 \
  do {                                                                  \
    if((c)) {                                                           \
      if(CURL_SHARE_KEEP_CONNECT((c)->share))                           \
        Curl_share_lock((d), CURL_LOCK_DATA_CONNECT,                    \
                        CURL_LOCK_ACCESS_SINGLE);                       \
      DEBUGASSERT(!(c)->locked);                                        \
      (c)->locked = TRUE;                                               \
    }                                                                   \
  } while(0)

#define CPOOL_UNLOCK(c,d)                                                 \
  do {                                                                  \
    if((c)) {                                                           \
      DEBUGASSERT((c)->locked);                                         \
      (c)->locked = FALSE;                                              \
      if(CURL_SHARE_KEEP_CONNECT((c)->share))                           \
        Curl_share_unlock((d), CURL_LOCK_DATA_CONNECT);                 \
    }                                                                   \
  } while(0)


/* A list of connections to the same destination. */
struct cpool_bundle {
  struct Curl_llist conns; /* connections in the bundle */
  size_t dest_len; /* total length of destination, including NUL */
  char *dest[1]; /* destination of bundle, allocated to keep dest_len bytes */
};


static void cpool_discard_conn(struct cpool *cpool,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted);

static struct cpool_bundle *cpool_bundle_create(const char *dest)
{
  struct cpool_bundle *bundle;
  size_t dest_len = strlen(dest);

  bundle = calloc(1, sizeof(*bundle) + dest_len);
  if(!bundle)
    return NULL;
  Curl_llist_init(&bundle->conns, NULL);
  bundle->dest_len = dest_len + 1;
  memcpy(bundle->dest, dest, bundle->dest_len);
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
                    struct Curl_easy *idata,
                    struct Curl_share *share,
                    size_t size)
{
  Curl_hash_init(&cpool->dest2bundle, size, Curl_hash_str,
                 Curl_str_key_compare, cpool_bundle_free_entry);

  DEBUGASSERT(idata);

  cpool->idata = idata;
  cpool->share = share;
  cpool->initialised = TRUE;
  return 0; /* good */
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
                                              struct connectdata *conn)
{
  return Curl_hash_pick(&cpool->dest2bundle,
                        conn->destination, strlen(conn->destination) + 1);
}


static void cpool_remove_bundle(struct cpool *cpool,
                                struct cpool_bundle *bundle)
{
  if(!cpool)
    return;
  Curl_hash_delete(&cpool->dest2bundle, bundle->dest, bundle->dest_len);
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
      /* Should have been in the bundle list */
      DEBUGASSERT(NULL);
    }
  }
}

void Curl_cpool_destroy(struct cpool *cpool)
{
  if(cpool && cpool->initialised && cpool->idata) {
    struct connectdata *conn;
    SIGPIPE_VARIABLE(pipe_st);

    CURL_TRC_M(cpool->idata, "%s[CPOOL] destroy, %zu connections",
               cpool->share ? "[SHARE] " : "", cpool->num_conn);
    /* Move all connections to the shutdown list */
    sigpipe_init(&pipe_st);
    CPOOL_LOCK(cpool, cpool->idata);
    conn = cpool_get_first(cpool);
    while(conn) {
      cpool_remove_conn(cpool, conn);
      sigpipe_apply(cpool->idata, &pipe_st);
      connclose(conn, "kill all");
      cpool_discard_conn(cpool, cpool->idata, conn, FALSE);
      conn = cpool_get_first(cpool);
    }
    CPOOL_UNLOCK(cpool, cpool->idata);
    sigpipe_restore(&pipe_st);
    Curl_hash_destroy(&cpool->dest2bundle);
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
    CPOOL_LOCK(cpool, data);
    /* the identifier inside the connection cache */
    data->id = cpool->next_easy_id++;
    if(cpool->next_easy_id <= 0)
      cpool->next_easy_id = 0;
    data->state.lastconnect_id = -1;

    CPOOL_UNLOCK(cpool, data);
  }
  else {
    /* We should not get here, but in a non-debug build, do something */
    data->id = 0;
    data->state.lastconnect_id = -1;
  }
}

static struct cpool_bundle *
cpool_add_bundle(struct cpool *cpool, struct connectdata *conn)
{
  struct cpool_bundle *bundle;

  bundle = cpool_bundle_create(conn->destination);
  if(!bundle)
    return NULL;

  if(!Curl_hash_add(&cpool->dest2bundle,
                    bundle->dest, bundle->dest_len, bundle)) {
    cpool_bundle_destroy(bundle);
    return NULL;
  }
  return bundle;
}

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


int Curl_cpool_check_limits(struct Curl_easy *data,
                            struct connectdata *conn)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct cpool_bundle *bundle;
  size_t dest_limit = 0;
  size_t total_limit = 0;
  size_t shutdowns;
  int result = CPOOL_LIMIT_OK;

  if(!cpool)
    return CPOOL_LIMIT_OK;

  if(cpool->idata->multi) {
    dest_limit = cpool->idata->multi->max_host_connections;
    total_limit = cpool->idata->multi->max_total_connections;
  }

  if(!dest_limit && !total_limit)
    return CPOOL_LIMIT_OK;

  CPOOL_LOCK(cpool, cpool->idata);
  if(dest_limit) {
    size_t live;

    bundle = cpool_find_bundle(cpool, conn);
    live = bundle ? Curl_llist_count(&bundle->conns) : 0;
      shutdowns = Curl_cshutdn_dest_count(data, conn->destination);
    while(!shutdowns && bundle && live >= dest_limit) {
      struct connectdata *oldest_idle = NULL;
      /* The bundle is full. Extract the oldest connection that may
       * be removed now, if there is one. */
      oldest_idle = cpool_bundle_get_oldest_idle(bundle);
      if(!oldest_idle)
        break;
      /* disconnect the old conn and continue */
      CURL_TRC_M(data, "Discarding connection #%"
                   FMT_OFF_T " from %zu to reach destination "
                   "limit of %zu", oldest_idle->connection_id,
                   Curl_llist_count(&bundle->conns), dest_limit);
      Curl_conn_terminate(cpool->idata, oldest_idle, FALSE);

      /* in case the bundle was destroyed in disconnect, look it up again */
      bundle = cpool_find_bundle(cpool, conn);
      live = bundle ? Curl_llist_count(&bundle->conns) : 0;
      shutdowns = Curl_cshutdn_dest_count(cpool->idata, conn->destination);
    }
    if((live + shutdowns) >= dest_limit) {
      result = CPOOL_LIMIT_DEST;
      goto out;
    }
  }

  if(total_limit) {
    shutdowns = Curl_cshutdn_count(cpool->idata);
    while((cpool->num_conn + shutdowns) >= total_limit) {
      struct connectdata *oldest_idle = cpool_get_oldest_idle(cpool);
      if(!oldest_idle)
        break;
      /* disconnect the old conn and continue */
      CURL_TRC_M(data, "Discarding connection #%"
                 FMT_OFF_T " from %zu to reach total "
                 "limit of %zu",
                 oldest_idle->connection_id, cpool->num_conn, total_limit);
      Curl_conn_terminate(cpool->idata, oldest_idle, FALSE);
      shutdowns = Curl_cshutdn_count(cpool->idata);
    }
    if((cpool->num_conn + shutdowns) >= total_limit) {
      result = CPOOL_LIMIT_TOTAL;
      goto out;
    }
  }

out:
  CPOOL_UNLOCK(cpool, cpool->idata);
  return result;
}

CURLcode Curl_cpool_add(struct Curl_easy *data,
                        struct connectdata *conn)
{
  CURLcode result = CURLE_OK;
  struct cpool_bundle *bundle = NULL;
  struct cpool *cpool = cpool_get_instance(data);
  DEBUGASSERT(conn);

  DEBUGASSERT(cpool);
  if(!cpool)
    return CURLE_FAILED_INIT;

  CPOOL_LOCK(cpool, data);
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
      CPOOL_LOCK(cpool, data);
    if(cpool->num_conn > maxconnects) {
      infof(data, "Connection pool is full, closing the oldest of %zu/%u",
            cpool->num_conn, maxconnects);

      oldest_idle = cpool_get_oldest_idle(cpool);
      kept = (oldest_idle != conn);
      if(oldest_idle) {
        Curl_conn_terminate(data, oldest_idle, FALSE);
      }
    }
    if(do_lock)
      CPOOL_UNLOCK(cpool, data);
  }

  return kept;
}

bool Curl_cpool_find(struct Curl_easy *data,
                     const char *destination,
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

  CPOOL_LOCK(cpool, data);
  bundle = Curl_hash_pick(&cpool->dest2bundle,
                          CURL_UNCONST(destination),
                          strlen(destination) + 1);
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
  CPOOL_UNLOCK(cpool, data);
  return result;
}

static void cpool_discard_conn(struct cpool *cpool,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               bool aborted)
{
  bool done = FALSE;

  DEBUGASSERT(data);
  DEBUGASSERT(!data->conn);
  DEBUGASSERT(cpool);
  DEBUGASSERT(!conn->bits.in_cpool);

  /*
   * If this connection is not marked to force-close, leave it open if there
   * are other users of it
   */
  if(CONN_INUSE(conn) && !aborted) {
    CURL_TRC_M(data, "[CPOOL] not discarding #%" FMT_OFF_T
               " still in use by %zu transfers", conn->connection_id,
               CONN_INUSE(conn));
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
    Curl_cshutdn_run_once(cpool->idata, conn, &done);
  }

  if(done || !data->multi)
    Curl_cshutdn_terminate(cpool->idata, conn, FALSE);
  else
    Curl_cshutdn_add(&data->multi->cshutdn, conn, cpool->num_conn);
}

void Curl_conn_terminate(struct Curl_easy *data,
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
    CPOOL_LOCK(cpool, data);

  if(conn->bits.in_cpool) {
    cpool_remove_conn(cpool, conn);
    DEBUGASSERT(!conn->bits.in_cpool);
  }

  /* treat the connection as aborted in CONNECT_ONLY situations,
   * so no graceful shutdown is attempted. */
  if(conn->connect_only)
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
    Curl_cshutdn_terminate(cpool->idata, conn, !aborted);
  }

  if(do_lock)
    CPOOL_UNLOCK(cpool, data);
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
    Curl_conn_terminate(data, conn, FALSE);
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
  CPOOL_LOCK(cpool, data);
  elapsed = Curl_timediff(rctx.now, cpool->last_cleanup);

  if(elapsed >= 1000L) {
    while(cpool_foreach(data, cpool, &rctx, cpool_reap_dead_cb))
      ;
    cpool->last_cleanup = rctx.now;
  }
  CPOOL_UNLOCK(cpool, data);
}

static int conn_upkeep(struct Curl_easy *data,
                       struct connectdata *conn,
                       void *param)
{
  struct curltime *now = param;
  Curl_conn_upkeep(data, conn, now);
  return 0; /* continue iteration */
}

CURLcode Curl_cpool_upkeep(void *data)
{
  struct cpool *cpool = cpool_get_instance(data);
  struct curltime now = Curl_now();

  if(!cpool)
    return CURLE_OK;

  CPOOL_LOCK(cpool, data);
  cpool_foreach(data, cpool, &now, conn_upkeep);
  CPOOL_UNLOCK(cpool, data);
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
  CPOOL_LOCK(cpool, data);
  cpool_foreach(data, cpool, &fctx, cpool_find_conn);
  CPOOL_UNLOCK(cpool, data);
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
  CPOOL_LOCK(cpool, data);
  cpool_foreach(data, cpool, &dctx, cpool_do_conn);
  CPOOL_UNLOCK(cpool, data);
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
