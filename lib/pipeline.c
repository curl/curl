/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2013, Linus Nielsen Feltzing, <linus@haxx.se>
 * Copyright (C) 2013 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "pipeline.h"
#include "sendf.h"
#include "strcase.h"

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

struct site_blacklist_entry {
  struct curl_llist_element list;
  unsigned short port;
  char hostname[1];
};

static void site_blacklist_llist_dtor(void *user, void *element)
{
  struct site_blacklist_entry *entry = element;
  (void)user;
  free(entry);
}

static void server_blacklist_llist_dtor(void *user, void *element)
{
  (void)user;
  free(element);
}

bool Curl_pipeline_penalized(struct Curl_easy *data,
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
    if(conn->recv_pipe.head) {
      struct Curl_easy *recv_handle = conn->recv_pipe.head->ptr;

      recv_size = recv_handle->req.size;

      if(penalty_size > 0 && recv_size > penalty_size)
        penalized = TRUE;
    }

    if(chunk_penalty_size > 0 &&
       (curl_off_t)conn->chunk.datasize > chunk_penalty_size)
      penalized = TRUE;

    infof(data, "Conn: %ld (%p) Receive pipe weight: (%"
          CURL_FORMAT_CURL_OFF_T "/%zu), penalized: %s\n",
          conn->connection_id, (void *)conn, recv_size,
          conn->chunk.datasize, penalized?"TRUE":"FALSE");
    return penalized;
  }
  return FALSE;
}

static CURLcode addHandleToPipeline(struct Curl_easy *data,
                                    struct curl_llist *pipeline)
{
  Curl_llist_insert_next(pipeline, pipeline->tail, data,
                         &data->pipeline_queue);
  return CURLE_OK;
}


CURLcode Curl_add_handle_to_pipeline(struct Curl_easy *handle,
                                     struct connectdata *conn)
{
  struct curl_llist_element *sendhead = conn->send_pipe.head;
  struct curl_llist *pipeline;
  CURLcode result;

  pipeline = &conn->send_pipe;

  result = addHandleToPipeline(handle, pipeline);

  if(pipeline == &conn->send_pipe && sendhead != conn->send_pipe.head) {
    /* this is a new one as head, expire it */
    Curl_pipeline_leave_write(conn); /* not in use yet */
    Curl_expire(conn->send_pipe.head->ptr, 0, EXPIRE_RUN_NOW);
  }

#if 0 /* enable for pipeline debugging */
  print_pipeline(conn);
#endif

  return result;
}

/* Move this transfer from the sending list to the receiving list.

   Pay special attention to the new sending list "leader" as it needs to get
   checked to update what sockets it acts on.

*/
void Curl_move_handle_from_send_to_recv_pipe(struct Curl_easy *handle,
                                             struct connectdata *conn)
{
  struct curl_llist_element *curr;

  curr = conn->send_pipe.head;
  while(curr) {
    if(curr->ptr == handle) {
      Curl_llist_move(&conn->send_pipe, curr,
                      &conn->recv_pipe, conn->recv_pipe.tail);

      if(conn->send_pipe.head) {
        /* Since there's a new easy handle at the start of the send pipeline,
           set its timeout value to 1ms to make it trigger instantly */
        Curl_pipeline_leave_write(conn); /* not used now */
#ifdef DEBUGBUILD
        infof(conn->data, "%p is at send pipe head B!\n",
              (void *)conn->send_pipe.head->ptr);
#endif
        Curl_expire(conn->send_pipe.head->ptr, 0, EXPIRE_RUN_NOW);
      }

      /* The receiver's list is not really interesting here since either this
         handle is now first in the list and we'll deal with it soon, or
         another handle is already first and thus is already taken care of */

      break; /* we're done! */
    }
    curr = curr->next;
  }
}

bool Curl_pipeline_site_blacklisted(struct Curl_easy *handle,
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
        if(strcasecompare(site->hostname, conn->host.name) &&
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
                                           struct curl_llist *list)
{
  /* Free the old list */
  if(list->size)
    Curl_llist_destroy(list, NULL);

  if(sites) {
    Curl_llist_init(list, (curl_llist_dtor) site_blacklist_llist_dtor);

    /* Parse the URLs and populate the list */
    while(*sites) {
      char *port;
      struct site_blacklist_entry *entry;

      entry = malloc(sizeof(struct site_blacklist_entry) + strlen(*sites));
      if(!entry) {
        Curl_llist_destroy(list, NULL);
        return CURLM_OUT_OF_MEMORY;
      }
      strcpy(entry->hostname, *sites);

      port = strchr(entry->hostname, ':');
      if(port) {
        *port = '\0';
        port++;
        entry->port = (unsigned short)strtol(port, NULL, 10);
      }
      else {
        /* Default port number for HTTP */
        entry->port = 80;
      }

      Curl_llist_insert_next(list, list->tail, entry, &entry->list);
      sites++;
    }
  }

  return CURLM_OK;
}

struct blacklist_node {
  struct curl_llist_element list;
  char server_name[1];
};

bool Curl_pipeline_server_blacklisted(struct Curl_easy *handle,
                                      char *server_name)
{
  if(handle->multi && server_name) {
    struct curl_llist *list =
      Curl_multi_pipelining_server_bl(handle->multi);

    struct curl_llist_element *e = list->head;
    while(e) {
      struct blacklist_node *bl = (struct blacklist_node *)e;
      if(strncasecompare(bl->server_name, server_name,
                         strlen(bl->server_name))) {
        infof(handle, "Server %s is blacklisted\n", server_name);
        return TRUE;
      }
      e = e->next;
    }

    DEBUGF(infof(handle, "Server %s is not blacklisted\n", server_name));
  }
  return FALSE;
}

CURLMcode Curl_pipeline_set_server_blacklist(char **servers,
                                             struct curl_llist *list)
{
  /* Free the old list */
  if(list->size)
    Curl_llist_destroy(list, NULL);

  if(servers) {
    Curl_llist_init(list, (curl_llist_dtor) server_blacklist_llist_dtor);

    /* Parse the URLs and populate the list */
    while(*servers) {
      struct blacklist_node *n;
      size_t len = strlen(*servers);

      n = malloc(sizeof(struct blacklist_node) + len);
      if(!n) {
        Curl_llist_destroy(list, NULL);
        return CURLM_OUT_OF_MEMORY;
      }
      strcpy(n->server_name, *servers);

      Curl_llist_insert_next(list, list->tail, n, &n->list);
      servers++;
    }
  }


  return CURLM_OK;
}

static bool pipe_head(struct Curl_easy *data,
                      struct curl_llist *pipeline)
{
  if(pipeline) {
    struct curl_llist_element *curr = pipeline->head;
    if(curr)
      return (curr->ptr == data) ? TRUE : FALSE;
  }
  return FALSE;
}

/* returns TRUE if the given handle is head of the recv pipe */
bool Curl_recvpipe_head(struct Curl_easy *data,
                        struct connectdata *conn)
{
  return pipe_head(data, &conn->recv_pipe);
}

/* returns TRUE if the given handle is head of the send pipe */
bool Curl_sendpipe_head(struct Curl_easy *data,
                        struct connectdata *conn)
{
  return pipe_head(data, &conn->send_pipe);
}


/*
 * Check if the write channel is available and this handle as at the head,
 * then grab the channel and return TRUE.
 *
 * If not available, return FALSE.
 */

bool Curl_pipeline_checkget_write(struct Curl_easy *data,
                                  struct connectdata *conn)
{
  if(conn->bits.multiplex)
    /* when multiplexing, we can use it at once */
    return TRUE;

  if(!conn->writechannel_inuse && Curl_sendpipe_head(data, conn)) {
    /* Grab the channel */
    conn->writechannel_inuse = TRUE;
    return TRUE;
  }
  return FALSE;
}


/*
 * Check if the read channel is available and this handle as at the head, then
 * grab the channel and return TRUE.
 *
 * If not available, return FALSE.
 */

bool Curl_pipeline_checkget_read(struct Curl_easy *data,
                                 struct connectdata *conn)
{
  if(conn->bits.multiplex)
    /* when multiplexing, we can use it at once */
    return TRUE;

  if(!conn->readchannel_inuse && Curl_recvpipe_head(data, conn)) {
    /* Grab the channel */
    conn->readchannel_inuse = TRUE;
    return TRUE;
  }
  return FALSE;
}

/*
 * The current user of the pipeline write channel gives it up.
 */
void Curl_pipeline_leave_write(struct connectdata *conn)
{
  conn->writechannel_inuse = FALSE;
}

/*
 * The current user of the pipeline read channel gives it up.
 */
void Curl_pipeline_leave_read(struct connectdata *conn)
{
  conn->readchannel_inuse = FALSE;
}


#if 0
void print_pipeline(struct connectdata *conn)
{
  struct curl_llist_element *curr;
  struct connectbundle *cb_ptr;
  struct Curl_easy *data = conn->data;

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

#endif
