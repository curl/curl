/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2016, Linus Nielsen Feltzing, <linus@haxx.se>
 * Copyright (C) 2012 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

#include "urldata.h"
#include "url.h"
#include "progress.h"
#include "multiif.h"
#include "sendf.h"
#include "conncache.h"
#include "share.h"
#include "sigpipe.h"
#include "connect.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifdef CURLDEBUG
/* the debug versions of these macros make extra certain that the lock is
   never doubly locked or unlocked */
#define CONN_LOCK(x) if((x)->share) {                                   \
    Curl_share_lock((x), CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE); \
    DEBUGASSERT(!(x)->state.conncache_lock);                            \
    (x)->state.conncache_lock = TRUE;                                   \
  }

#define CONN_UNLOCK(x) if((x)->share) {                                 \
    DEBUGASSERT((x)->state.conncache_lock);                             \
    (x)->state.conncache_lock = FALSE;                                  \
    Curl_share_unlock((x), CURL_LOCK_DATA_CONNECT);                     \
  }
#else
#define CONN_LOCK(x) if((x)->share)                                     \
    Curl_share_lock((x), CURL_LOCK_DATA_CONNECT, CURL_LOCK_ACCESS_SINGLE)
#define CONN_UNLOCK(x) if((x)->share)                   \
    Curl_share_unlock((x), CURL_LOCK_DATA_CONNECT)
#endif

static void conn_llist_dtor(void *user, void *element)
{
  struct connectdata *data = element;
  (void)user;

  data->bundle = NULL;
}

static CURLcode bundle_create(struct Curl_easy *data,
                              struct connectbundle **cb_ptr)
{
  (void)data;
  DEBUGASSERT(*cb_ptr == NULL);
  *cb_ptr = malloc(sizeof(struct connectbundle));
  if(!*cb_ptr)
    return CURLE_OUT_OF_MEMORY;

  (*cb_ptr)->num_connections = 0;
  (*cb_ptr)->multiuse = BUNDLE_UNKNOWN;

  Curl_llist_init(&(*cb_ptr)->conn_list, (curl_llist_dtor) conn_llist_dtor);
  return CURLE_OK;
}

static void bundle_destroy(struct connectbundle *cb_ptr)
{
  if(!cb_ptr)
    return;

  Curl_llist_destroy(&cb_ptr->conn_list, NULL);

  free(cb_ptr);
}

/* Add a connection to a bundle */
static CURLcode bundle_add_conn(struct connectbundle *cb_ptr,
                                struct connectdata *conn)
{
  Curl_llist_insert_next(&cb_ptr->conn_list, cb_ptr->conn_list.tail, conn,
                         &conn->bundle_node);
  conn->bundle = cb_ptr;
  cb_ptr->num_connections++;
  return CURLE_OK;
}

/* Remove a connection from a bundle */
static int bundle_remove_conn(struct connectbundle *cb_ptr,
                              struct connectdata *conn)
{
  struct curl_llist_element *curr;

  curr = cb_ptr->conn_list.head;
  while(curr) {
    if(curr->ptr == conn) {
      Curl_llist_remove(&cb_ptr->conn_list, curr, NULL);
      cb_ptr->num_connections--;
      conn->bundle = NULL;
      return 1; /* we removed a handle */
    }
    curr = curr->next;
  }
  return 0;
}

static void free_bundle_hash_entry(void *freethis)
{
  struct connectbundle *b = (struct connectbundle *) freethis;

  bundle_destroy(b);
}

int Curl_conncache_init(struct conncache *connc, int size)
{
  int rc;

  /* allocate a new easy handle to use when closing cached connections */
  connc->closure_handle = curl_easy_init();
  if(!connc->closure_handle)
    return 1; /* bad */

  rc = Curl_hash_init(&connc->hash, size, Curl_hash_str,
                      Curl_str_key_compare, free_bundle_hash_entry);
  if(rc) {
    Curl_close(connc->closure_handle);
    connc->closure_handle = NULL;
  }
  else
    connc->closure_handle->state.conn_cache = connc;

  return rc;
}

void Curl_conncache_destroy(struct conncache *connc)
{
  if(connc)
    Curl_hash_destroy(&connc->hash);
}

/* creates a key to find a bundle for this connection */
static void hashkey(struct connectdata *conn, char *buf,
                    size_t len) /* something like 128 is fine */
{
  const char *hostname;

  if(conn->bits.socksproxy)
    hostname = conn->socks_proxy.host.name;
  else if(conn->bits.httpproxy)
    hostname = conn->http_proxy.host.name;
  else if(conn->bits.conn_to_host)
    hostname = conn->conn_to_host.name;
  else
    hostname = conn->host.name;

  DEBUGASSERT(len > 32);

  /* put the number first so that the hostname gets cut off if too long */
  snprintf(buf, len, "%ld%s", conn->port, hostname);
}

void Curl_conncache_unlock(struct connectdata *conn)
{
  CONN_UNLOCK(conn->data);
}

/* Returns number of connections currently held in the connection cache.
   Locks/unlocks the cache itself!
*/
size_t Curl_conncache_size(struct Curl_easy *data)
{
  size_t num;
  CONN_LOCK(data);
  num = data->state.conn_cache->num_conn;
  CONN_UNLOCK(data);
  return num;
}

/* Returns number of connections currently held in the connections's bundle
   Locks/unlocks the cache itself!
*/
size_t Curl_conncache_bundle_size(struct connectdata *conn)
{
  size_t num;
  CONN_LOCK(conn->data);
  num = conn->bundle->num_connections;
  CONN_UNLOCK(conn->data);
  return num;
}

/* Look up the bundle with all the connections to the same host this
   connectdata struct is setup to use.

   **NOTE**: When it returns, it holds the connection cache lock! */
struct connectbundle *Curl_conncache_find_bundle(struct connectdata *conn,
                                                 struct conncache *connc)
{
  struct connectbundle *bundle = NULL;
  CONN_LOCK(conn->data);
  if(connc) {
    char key[128];
    hashkey(conn, key, sizeof(key));
    bundle = Curl_hash_pick(&connc->hash, key, strlen(key));
  }

  return bundle;
}

static bool conncache_add_bundle(struct conncache *connc,
                                 char *key,
                                 struct connectbundle *bundle)
{
  void *p = Curl_hash_add(&connc->hash, key, strlen(key), bundle);

  return p?TRUE:FALSE;
}

static void conncache_remove_bundle(struct conncache *connc,
                                    struct connectbundle *bundle)
{
  struct curl_hash_iterator iter;
  struct curl_hash_element *he;

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

CURLcode Curl_conncache_add_conn(struct conncache *connc,
                                 struct connectdata *conn)
{
  CURLcode result;
  struct connectbundle *bundle;
  struct connectbundle *new_bundle = NULL;
  struct Curl_easy *data = conn->data;

  /* *find_bundle() locks the connection cache */
  bundle = Curl_conncache_find_bundle(conn, data->state.conn_cache);
  if(!bundle) {
    int rc;
    char key[128];

    result = bundle_create(data, &new_bundle);
    if(result) {
      goto unlock;
    }

    hashkey(conn, key, sizeof(key));
    rc = conncache_add_bundle(data->state.conn_cache, key, new_bundle);

    if(!rc) {
      bundle_destroy(new_bundle);
      result = CURLE_OUT_OF_MEMORY;
      goto unlock;
    }
    bundle = new_bundle;
  }

  result = bundle_add_conn(bundle, conn);
  if(result) {
    if(new_bundle)
      conncache_remove_bundle(data->state.conn_cache, new_bundle);
    goto unlock;
  }

  conn->connection_id = connc->next_connection_id++;
  connc->num_conn++;

  DEBUGF(infof(conn->data, "Added connection %ld. "
               "The cache now contains %" CURL_FORMAT_CURL_OFF_TU " members\n",
               conn->connection_id, (curl_off_t) connc->num_conn));

  unlock:
  CONN_UNLOCK(data);

  return result;
}

void Curl_conncache_remove_conn(struct connectdata *conn, bool lock)
{
  struct Curl_easy *data = conn->data;
  struct connectbundle *bundle = conn->bundle;
  struct conncache *connc = data->state.conn_cache;

  /* The bundle pointer can be NULL, since this function can be called
     due to a failed connection attempt, before being added to a bundle */
  if(bundle) {
    if(lock) {
      CONN_LOCK(conn->data);
    }
    bundle_remove_conn(bundle, conn);
    if(bundle->num_connections == 0)
      conncache_remove_bundle(connc, bundle);
    conn->bundle = NULL; /* removed from it */
    if(connc) {
      connc->num_conn--;
      DEBUGF(infof(conn->data, "The cache now contains %"
                   CURL_FORMAT_CURL_OFF_TU " members\n",
                   (curl_off_t) connc->num_conn));
    }
    if(lock) {
      CONN_UNLOCK(conn->data);
    }
  }
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
                            int (*func)(struct connectdata *conn, void *param))
{
  struct curl_hash_iterator iter;
  struct curl_llist_element *curr;
  struct curl_hash_element *he;

  if(!connc)
    return FALSE;

  CONN_LOCK(data);
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

      if(1 == func(conn, param)) {
        CONN_UNLOCK(data);
        return TRUE;
      }
    }
  }
  CONN_UNLOCK(data);
  return FALSE;
}

/* Return the first connection found in the cache. Used when closing all
   connections.

   NOTE: no locking is done here as this is presumably only done when cleaning
   up a cache!
*/
struct connectdata *
Curl_conncache_find_first_connection(struct conncache *connc)
{
  struct curl_hash_iterator iter;
  struct curl_hash_element *he;
  struct connectbundle *bundle;

  Curl_hash_start_iterate(&connc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct curl_llist_element *curr;
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
bool Curl_conncache_return_conn(struct connectdata *conn)
{
  struct Curl_easy *data = conn->data;

  /* data->multi->maxconnects can be negative, deal with it. */
  size_t maxconnects =
    (data->multi->maxconnects < 0) ? data->multi->num_easy * 4:
    data->multi->maxconnects;
  struct connectdata *conn_candidate = NULL;

  if(maxconnects > 0 &&
     Curl_conncache_size(data) > maxconnects) {
    infof(data, "Connection cache is full, closing the oldest one.\n");

    conn_candidate = Curl_conncache_extract_oldest(data);

    if(conn_candidate) {
      /* Set the connection's owner correctly */
      conn_candidate->data = data;

      /* the winner gets the honour of being disconnected */
      (void)Curl_disconnect(conn_candidate, /* dead_connection */ FALSE);
    }
  }
  CONN_LOCK(data);
  conn->inuse = FALSE; /* Mark the connection unused */
  CONN_UNLOCK(data);

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
  struct curl_llist_element *curr;
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

    if(!conn->inuse) {
      /* Set higher score for the age passed since the connection was used */
      score = Curl_timediff(now, conn->now);

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
    DEBUGF(infof(data, "The cache now contains %"
                 CURL_FORMAT_CURL_OFF_TU " members\n",
                 (curl_off_t) data->state.conn_cache->num_conn));
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
  struct curl_hash_iterator iter;
  struct curl_llist_element *curr;
  struct curl_hash_element *he;
  timediff_t highscore =- 1;
  timediff_t score;
  struct curltime now;
  struct connectdata *conn_candidate = NULL;
  struct connectbundle *bundle;
  struct connectbundle *bundle_candidate = NULL;

  now = Curl_now();

  CONN_LOCK(data);
  Curl_hash_start_iterate(&connc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectdata *conn;

    bundle = he->ptr;

    curr = bundle->conn_list.head;
    while(curr) {
      conn = curr->ptr;

      if(!conn->inuse) {
        /* Set higher score for the age passed since the connection was used */
        score = Curl_timediff(now, conn->now);

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
    DEBUGF(infof(data, "The cache now contains %"
                 CURL_FORMAT_CURL_OFF_TU " members\n",
                 (curl_off_t) connc->num_conn));
  }
  CONN_UNLOCK(data);

  return conn_candidate;
}

void Curl_conncache_close_all_connections(struct conncache *connc)
{
  struct connectdata *conn;

  conn = Curl_conncache_find_first_connection(connc);
  while(conn) {
    SIGPIPE_VARIABLE(pipe_st);
    conn->data = connc->closure_handle;

    sigpipe_ignore(conn->data, &pipe_st);
    conn->data->easy_conn = NULL; /* clear the easy handle's connection
                                     pointer */
    /* This will remove the connection from the cache */
    connclose(conn, "kill all");
    (void)Curl_disconnect(conn, FALSE);
    sigpipe_restore(&pipe_st);

    conn = Curl_conncache_find_first_connection(connc);
  }

  if(connc->closure_handle) {
    SIGPIPE_VARIABLE(pipe_st);
    sigpipe_ignore(connc->closure_handle, &pipe_st);

    Curl_hostcache_clean(connc->closure_handle,
                         connc->closure_handle->dns.hostcache);
    Curl_close(connc->closure_handle);
    sigpipe_restore(&pipe_st);
  }
}

#if 0
/* Useful for debugging the connection cache */
void Curl_conncache_print(struct conncache *connc)
{
  struct curl_hash_iterator iter;
  struct curl_llist_element *curr;
  struct curl_hash_element *he;

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
