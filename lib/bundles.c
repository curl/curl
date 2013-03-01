/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, Linus Nielsen Feltzing, <linus@haxx.se>
 * Copyright (C) 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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
#include "bundles.h"
#include "sendf.h"
#include "rawstr.h"

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

static void conn_llist_dtor(void *user, void *element)
{
  struct connectdata *data = element;
  (void)user;

  data->bundle = NULL;
}

CURLcode Curl_bundle_create(struct SessionHandle *data,
                            struct connectbundle **cb_ptr)
{
  (void)data;
  DEBUGASSERT(*cb_ptr == NULL);
  *cb_ptr = malloc(sizeof(struct connectbundle));
  if(!*cb_ptr)
    return CURLE_OUT_OF_MEMORY;

  (*cb_ptr)->num_connections = 0;
  (*cb_ptr)->server_supports_pipelining = FALSE;

  (*cb_ptr)->conn_list = Curl_llist_alloc((curl_llist_dtor) conn_llist_dtor);
  if(!(*cb_ptr)->conn_list) {
    Curl_safefree(*cb_ptr);
    return CURLE_OUT_OF_MEMORY;
  }
  return CURLE_OK;
}

void Curl_bundle_destroy(struct connectbundle *cb_ptr)
{
  if(!cb_ptr)
    return;

  if(cb_ptr->conn_list) {
    Curl_llist_destroy(cb_ptr->conn_list, NULL);
    cb_ptr->conn_list = NULL;
  }
  Curl_safefree(cb_ptr);
}

/* Add a connection to a bundle */
CURLcode Curl_bundle_add_conn(struct connectbundle *cb_ptr,
                              struct connectdata *conn)
{
  if(!Curl_llist_insert_next(cb_ptr->conn_list, cb_ptr->conn_list->tail, conn))
    return CURLE_OUT_OF_MEMORY;

  conn->bundle = cb_ptr;

  cb_ptr->num_connections++;
  return CURLE_OK;
}

/* Remove a connection from a bundle */
int Curl_bundle_remove_conn(struct connectbundle *cb_ptr,
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
