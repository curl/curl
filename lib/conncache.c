/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, 2016, Linus Nielsen Feltzing, <linus@haxx.se>
 * Copyright (C) 2012 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

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

  (*cb_ptr)->conn_list = Curl_llist_alloc((curl_llist_dtor) conn_llist_dtor);
  if(!(*cb_ptr)->conn_list) {
    Curl_safefree(*cb_ptr);
    return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

static void bundle_destroy(struct connectbundle *cb_ptr)
{
  if(!cb_ptr)
    return;

  if(cb_ptr->conn_list) {
    Curl_llist_destroy(cb_ptr->conn_list, NULL);
    cb_ptr->conn_list = NULL;
  }
  free(cb_ptr);
}

/* Add a connection to a bundle */
static CURLcode bundle_add_conn(struct connectbundle *cb_ptr,
                              struct connectdata *conn)
{
  if(!Curl_llist_insert_next(cb_ptr->conn_list, cb_ptr->conn_list->tail, conn))
    return CURLE_OUT_OF_MEMORY;

  conn->bundle = cb_ptr;

  cb_ptr->num_connections++;
  return CURLE_OK;
}

/* Remove a connection from a bundle */
static int bundle_remove_conn(struct connectbundle *cb_ptr,
                              struct connectdata *conn)
{
  struct curl_llist_element *curr;

  curr = cb_ptr->conn_list->head;
  while(curr) {
    if(curr->ptr == conn) {
      Curl_llist_remove(cb_ptr->conn_list, curr, NULL);
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
  return Curl_hash_init(&connc->hash, size, Curl_hash_str,
                        Curl_str_key_compare, free_bundle_hash_entry);
}

void Curl_conncache_destroy(struct conncache *connc)
{
  if(connc)
    Curl_hash_destroy(&connc->hash);
}

/* returns an allocated key to find a bundle for this connection */
static char *hashkey(struct connectdata *conn)
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

  return aprintf("%s:%d", hostname, conn->port);
}

/* Look up the bundle with all the connections to the same host this
   connectdata struct is setup to use. */
struct connectbundle *Curl_conncache_find_bundle(struct connectdata *conn,
                                                 struct conncache *connc)
{
  struct connectbundle *bundle = NULL;
  if(connc) {
    char *key = hashkey(conn);
    if(key) {
      bundle = Curl_hash_pick(&connc->hash, key, strlen(key));
      free(key);
    }
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

  bundle = Curl_conncache_find_bundle(conn, data->state.conn_cache);
  if(!bundle) {
    char *key;
    int rc;

    result = bundle_create(data, &new_bundle);
    if(result)
      return result;

    key = hashkey(conn);
    if(!key) {
      bundle_destroy(new_bundle);
      return CURLE_OUT_OF_MEMORY;
    }

    rc = conncache_add_bundle(data->state.conn_cache, key, new_bundle);
    free(key);
    if(!rc) {
      bundle_destroy(new_bundle);
      return CURLE_OUT_OF_MEMORY;
    }
    bundle = new_bundle;
  }

  result = bundle_add_conn(bundle, conn);
  if(result) {
    if(new_bundle)
      conncache_remove_bundle(data->state.conn_cache, new_bundle);
    return result;
  }

  conn->connection_id = connc->next_connection_id++;
  connc->num_connections++;

  DEBUGF(infof(conn->data, "Added connection %ld. "
               "The cache now contains %" CURL_FORMAT_CURL_OFF_TU " members\n",
               conn->connection_id, (curl_off_t) connc->num_connections));

  return CURLE_OK;
}

void Curl_conncache_remove_conn(struct conncache *connc,
                                struct connectdata *conn)
{
  struct connectbundle *bundle = conn->bundle;

  /* The bundle pointer can be NULL, since this function can be called
     due to a failed connection attempt, before being added to a bundle */
  if(bundle) {
    bundle_remove_conn(bundle, conn);
    if(bundle->num_connections == 0) {
      conncache_remove_bundle(connc, bundle);
    }

    if(connc) {
      connc->num_connections--;

      DEBUGF(infof(conn->data, "The cache now contains %"
                   CURL_FORMAT_CURL_OFF_TU " members\n",
                   (curl_off_t) connc->num_connections));
    }
  }
}

/* This function iterates the entire connection cache and calls the
   function func() with the connection pointer as the first argument
   and the supplied 'param' argument as the other,

   Return 0 from func() to continue the loop, return 1 to abort it.
 */
void Curl_conncache_foreach(struct conncache *connc,
                            void *param,
                            int (*func)(struct connectdata *conn, void *param))
{
  struct curl_hash_iterator iter;
  struct curl_llist_element *curr;
  struct curl_hash_element *he;

  if(!connc)
    return;

  Curl_hash_start_iterate(&connc->hash, &iter);

  he = Curl_hash_next_element(&iter);
  while(he) {
    struct connectbundle *bundle;

    bundle = he->ptr;
    he = Curl_hash_next_element(&iter);

    curr = bundle->conn_list->head;
    while(curr) {
      /* Yes, we need to update curr before calling func(), because func()
         might decide to remove the connection */
      struct connectdata *conn = curr->ptr;
      curr = curr->next;

      if(1 == func(conn, param))
        return;
    }
  }
}

/* Return the first connection found in the cache. Used when closing all
   connections */
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

    curr = bundle->conn_list->head;
    if(curr) {
      return curr->ptr;
    }

    he = Curl_hash_next_element(&iter);
  }

  return NULL;
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
