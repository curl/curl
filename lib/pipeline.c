/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2013, Linus Nielsen Feltzing, <linus@haxx.se>
 * Copyright (C) 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "pipeline.h"
#include "sendf.h"
#include "rawstr.h"
#include "bundles.h"

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

struct site_blacklist_entry {
  char *hostname;
  unsigned short port;
};

static void site_blacklist_llist_dtor(void *user, void *element)
{
  struct site_blacklist_entry *entry = element;
  (void)user;

  Curl_safefree(entry->hostname);
  Curl_safefree(entry);
}

static void server_blacklist_llist_dtor(void *user, void *element)
{
  char *server_name = element;
  (void)user;

  Curl_safefree(server_name);
}

bool Curl_pipeline_penalized(struct SessionHandle *data,
                             struct connectdata *conn)
{
  if(data) {
    bool penalized = FALSE;
    curl_off_t penalty_size =
      Curl_multi_content_length_penalty_size(data->multi);
    curl_off_t chunk_penalty_size =
      Curl_multi_chunk_length_penalty_size(data->multi);
    curl_off_t recv_size = -2; /* Make it easy to spot in the log */

    /* Find the head of the recv pipe, if any */
    if(conn->recv_pipe && conn->recv_pipe->head) {
      struct SessionHandle *recv_handle = conn->recv_pipe->head->ptr;

      recv_size = recv_handle->req.size;

      if(penalty_size > 0 && recv_size > penalty_size)
        penalized = TRUE;
    }

    if(chunk_penalty_size > 0 &&
       (curl_off_t)conn->chunk.datasize > chunk_penalty_size)
      penalized = TRUE;

    infof(data, "Conn: %ld (%p) Receive pipe weight: (%" FORMAT_OFF_T
          "/%zu), penalized: %s\n",
          conn->connection_id, (void *)conn, recv_size,
          conn->chunk.datasize, penalized?"TRUE":"FALSE");
    return penalized;
  }
  return FALSE;
}

CURLcode Curl_add_handle_to_pipeline(struct SessionHandle *handle,
                                     struct connectdata *conn)
{
  struct curl_llist_element *sendhead = conn->send_pipe->head;
  struct curl_llist *pipeline;
  CURLcode rc;

  pipeline = conn->send_pipe;

  infof(conn->data, "Adding handle: conn: %p\n", (void *)conn);
  infof(conn->data, "Adding handle: send: %d\n", conn->send_pipe->size);
  infof(conn->data, "Adding handle: recv: %d\n", conn->recv_pipe->size);
  rc = Curl_addHandleToPipeline(handle, pipeline);

  if(pipeline == conn->send_pipe && sendhead != conn->send_pipe->head) {
    /* this is a new one as head, expire it */
    conn->writechannel_inuse = FALSE; /* not in use yet */
#ifdef DEBUGBUILD
    infof(conn->data, "%p is at send pipe head!\n",
          (void *)conn->send_pipe->head->ptr);
#endif
    Curl_expire(conn->send_pipe->head->ptr, 1);
  }

  print_pipeline(conn);

  return rc;
}

/* Move this transfer from the sending list to the receiving list.

   Pay special attention to the new sending list "leader" as it needs to get
   checked to update what sockets it acts on.

*/
void Curl_move_handle_from_send_to_recv_pipe(struct SessionHandle *handle,
                                             struct connectdata *conn)
{
  struct curl_llist_element *curr;

  curr = conn->send_pipe->head;
  while(curr) {
    if(curr->ptr == handle) {
      Curl_llist_move(conn->send_pipe, curr,
                      conn->recv_pipe, conn->recv_pipe->tail);

      if(conn->send_pipe->head) {
        /* Since there's a new easy handle at the start of the send pipeline,
           set its timeout value to 1ms to make it trigger instantly */
        conn->writechannel_inuse = FALSE; /* not used now */
#ifdef DEBUGBUILD
        infof(conn->data, "%p is at send pipe head B!\n",
              (void *)conn->send_pipe->head->ptr);
#endif
        Curl_expire(conn->send_pipe->head->ptr, 1);
      }

      /* The receiver's list is not really interesting here since either this
         handle is now first in the list and we'll deal with it soon, or
         another handle is already first and thus is already taken care of */

      break; /* we're done! */
    }
    curr = curr->next;
  }
}

bool Curl_pipeline_site_blacklisted(struct SessionHandle *handle,
                                    struct connectdata *conn)
{
  if(handle->multi) {
    struct curl_llist *blacklist =
      Curl_multi_pipelining_site_bl(handle->multi);

    if(blacklist) {
      struct curl_llist_element *curr;

      curr = blacklist->head;
      while(curr) {
        struct site_blacklist_entry *site;

        site = curr->ptr;
        if(Curl_raw_equal(site->hostname, conn->host.name) &&
           site->port == conn->remote_port) {
          infof(handle, "Site %s:%d is pipeline blacklisted\n",
                conn->host.name, conn->remote_port);
          return TRUE;
        }
        curr = curr->next;
      }
    }
  }
  return FALSE;
}

CURLMcode Curl_pipeline_set_site_blacklist(char **sites,
                                           struct curl_llist **list_ptr)
{
  struct curl_llist *old_list = *list_ptr;
  struct curl_llist *new_list = NULL;

  if(sites) {
    new_list = Curl_llist_alloc((curl_llist_dtor) site_blacklist_llist_dtor);
    if(!new_list)
      return CURLM_OUT_OF_MEMORY;

    /* Parse the URLs and populate the list */
    while(*sites) {
      char *hostname;
      char *port;
      struct site_blacklist_entry *entry;

      entry = malloc(sizeof(struct site_blacklist_entry));

      hostname = strdup(*sites);
      if(!hostname)
        return CURLM_OUT_OF_MEMORY;

      port = strchr(hostname, ':');
      if(port) {
        *port = '\0';
        port++;
        entry->port = (unsigned short)strtol(port, NULL, 10);
      }
      else {
        /* Default port number for HTTP */
        entry->port = 80;
      }

      entry->hostname = hostname;

      if(!Curl_llist_insert_next(new_list, new_list->tail, entry))
        return CURLM_OUT_OF_MEMORY;

      sites++;
    }
  }

  /* Free the old list */
  if(old_list) {
    Curl_llist_destroy(old_list, NULL);
  }

  /* This might be NULL if sites == NULL, i.e the blacklist is cleared */
  *list_ptr = new_list;

  return CURLM_OK;
}

bool Curl_pipeline_server_blacklisted(struct SessionHandle *handle,
                                      char *server_name)
{
  if(handle->multi) {
    struct curl_llist *blacklist =
      Curl_multi_pipelining_server_bl(handle->multi);

    if(blacklist) {
      struct curl_llist_element *curr;

      curr = blacklist->head;
      while(curr) {
        char *bl_server_name;

        bl_server_name = curr->ptr;
        if(Curl_raw_nequal(bl_server_name, server_name,
                           strlen(bl_server_name))) {
          infof(handle, "Server %s is blacklisted\n", server_name);
          return TRUE;
        }
        curr = curr->next;
      }
    }

    infof(handle, "Server %s is not blacklisted\n", server_name);
  }
  return FALSE;
}

CURLMcode Curl_pipeline_set_server_blacklist(char **servers,
                                             struct curl_llist **list_ptr)
{
  struct curl_llist *old_list = *list_ptr;
  struct curl_llist *new_list = NULL;

  if(servers) {
    new_list = Curl_llist_alloc((curl_llist_dtor) server_blacklist_llist_dtor);
    if(!new_list)
      return CURLM_OUT_OF_MEMORY;

    /* Parse the URLs and populate the list */
    while(*servers) {
      char *server_name;

      server_name = strdup(*servers);
      if(!server_name)
        return CURLM_OUT_OF_MEMORY;

      if(!Curl_llist_insert_next(new_list, new_list->tail, server_name))
        return CURLM_OUT_OF_MEMORY;

      servers++;
    }
  }

  /* Free the old list */
  if(old_list) {
    Curl_llist_destroy(old_list, NULL);
  }

  /* This might be NULL if sites == NULL, i.e the blacklist is cleared */
  *list_ptr = new_list;

  return CURLM_OK;
}


void print_pipeline(struct connectdata *conn)
{
  struct curl_llist_element *curr;
  struct connectbundle *cb_ptr;
  struct SessionHandle *data = conn->data;

  cb_ptr = conn->bundle;

  if(cb_ptr) {
    curr = cb_ptr->conn_list->head;
    while(curr) {
      conn = curr->ptr;
      infof(data, "- Conn %ld (%p) send_pipe: %zu, recv_pipe: %zu\n",
            conn->connection_id,
            (void *)conn,
            conn->send_pipe->size,
            conn->recv_pipe->size);
      curr = curr->next;
    }
  }
}
