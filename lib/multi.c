/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2001, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

#include "setup.h"
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "multi.h" /* will become <curl/multi.h> soon */

#include "urldata.h"
#include "transfer.h"
#include "url.h"

struct Curl_message {
  /* the 'CURLMsg' is the part that is visible to the external user */
  struct CURLMsg extmsg;
  struct Curl_message *next;
};

typedef enum {
  CURLM_STATE_INIT,
  CURLM_STATE_CONNECT,
  CURLM_STATE_DO,
  CURLM_STATE_PERFORM,
  CURLM_STATE_DONE,
  CURLM_STATE_COMPLETED,

  CURLM_STATE_LAST /* not a true state, never use this */
} CURLMstate;

struct Curl_one_easy {
  /* first, two fields for the linked list of these */
  struct Curl_one_easy *next;
  struct Curl_one_easy *prev;
  
  struct SessionHandle *easy_handle; /* the easy handle for this unit */
  struct connectdata *easy_conn;     /* the "unit's" connection */

  CURLMstate state;  /* the handle's state */
  CURLcode result;   /* previous result */
};


#define CURL_MULTI_HANDLE 0x000bab1e

#define GOOD_MULTI_HANDLE(x) ((x)&&(((struct Curl_multi *)x)->type == CURL_MULTI_HANDLE))
#define GOOD_EASY_HANDLE(x) (x)

/* This is the struct known as CURLM on the outside */
struct Curl_multi {
  /* First a simple identifier to easier detect if a user mix up
     this multi handle with an easy handle. Set this to CURL_MULTI_HANDLE. */
  long type;

  /* We have a linked list with easy handles */
  struct Curl_one_easy easy; 
  /* This is the amount of entries in the linked list above. */
  int num_easy;

  /* this is a linked list of posted messages */
  struct Curl_message *msgs;
  /* amount of messages in the queue */
  int num_msgs;
  /* Hostname cache */
  curl_hash *hostcache;
};


CURLM *curl_multi_init(void)
{
  struct Curl_multi *multi;

  multi = (void *)malloc(sizeof(struct Curl_multi));

  if(multi) {
    memset(multi, 0, sizeof(struct Curl_multi));
    multi->type = CURL_MULTI_HANDLE;
  }
  
  return (CURLM *) multi;
}

CURLMcode curl_multi_add_handle(CURLM *multi_handle,
                                CURL *easy_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;
  
  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(easy_handle))
    return CURLM_BAD_EASY_HANDLE;

  /* Now, time to add an easy handle to the multi stack */
  easy = (struct Curl_one_easy *)malloc(sizeof(struct Curl_one_easy));
  if(!easy)
    return CURLM_OUT_OF_MEMORY;
  
  /* clean it all first (just to be sure) */
  memset(easy, 0, sizeof(struct Curl_one_easy));

  /* set the easy handle */
  easy->easy_handle = easy_handle;
  easy->state = CURLM_STATE_INIT;
  
  /* We add this new entry first in the list. We make our 'next' point to the
     previous next and our 'prev' point back to the 'first' struct */
  easy->next = multi->easy.next;
  easy->prev = &multi->easy; 

  /* make 'easy' the first node in the chain */
  multi->easy.next = easy;

  /* if there was a next node, make sure its 'prev' pointer links back to
     the new node */
  if(easy->next)
    easy->next->prev = easy;

  /* increase the node-counter */
  multi->num_easy++;

  return CURLM_CALL_MULTI_PERFORM;
}

CURLMcode curl_multi_remove_handle(CURLM *multi_handle,
                                   CURL *curl_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;

  /* First, make some basic checks that the CURLM handle is a good handle */
  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;
  
  /* Verify that we got a somewhat good easy handle too */
  if(!GOOD_EASY_HANDLE(curl_handle))
    return CURLM_BAD_EASY_HANDLE;

  /* scan through the list and remove the 'curl_handle' */
  easy = multi->easy.next;
  while(easy) {
    if(easy->easy_handle == curl_handle)
      break;
    easy=easy->next;
  }
  if(easy) {
    /* If the 'state' is not INIT or COMPLETED, we might need to do something
       nice to put the easy_handle in a good known state when this returns. */

    /* make the previous node point to our next */
    if(easy->prev)
      easy->prev->next = easy->next;
    /* make our next point to our previous node */
    if(easy->next)
      easy->next->prev = easy->prev;
    
    /* NOTE NOTE NOTE
       We do not touch the easy handle here! */
    free(easy);

    multi->num_easy--; /* one less to care about now */

    return CURLM_OK;
  }
  else
    return CURLM_BAD_EASY_HANDLE; /* twasn't found */
}

CURLMcode curl_multi_fdset(CURLM *multi_handle,
                           fd_set *read_fd_set, fd_set *write_fd_set,
                           fd_set *exc_fd_set, int *max_fd)
{
  /* Scan through all the easy handles to get the file descriptors set.
     Some easy handles may not have connected to the remote host yet,
     and then we must make sure that is done. */
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;
  int this_max_fd=-1;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  *max_fd = -1; /* so far none! */

  easy=multi->easy.next;
  while(easy) {
    switch(easy->state) {
    default:
      break;
    case CURLM_STATE_PERFORM:
      /* This should have a set of file descriptors for us to set.  */
      /* after the transfer is done, go DONE */

      Curl_single_fdset(easy->easy_conn,
                        read_fd_set, write_fd_set,
                        exc_fd_set, &this_max_fd);

      /* remember the maximum file descriptor */
      if(this_max_fd > *max_fd)
        *max_fd = this_max_fd;

      break;
    }
    easy = easy->next; /* check next handle */
  }

  return CURLM_OK;
}

CURLMcode curl_multi_perform(CURLM *multi_handle, int *running_handles)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;
  bool done;
  CURLMcode result=CURLM_OK;

  *running_handles = 0; /* bump this once for every living handle */

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  easy=multi->easy.next;
  while(easy) {
    switch(easy->state) {
    case CURLM_STATE_INIT:
      /* init this transfer. */
      easy->result=Curl_pretransfer(easy->easy_handle);
      if(CURLE_OK == easy->result) {
        /* after init, go CONNECT */
        easy->state = CURLM_STATE_CONNECT;
        result = CURLM_CALL_MULTI_PERFORM; 
      }
      break;
    case CURLM_STATE_CONNECT:
      if (Curl_global_host_cache_use(easy->easy_handle)) {
        easy->easy_handle->hostcache = Curl_global_host_cache_get();
      }
      else {
        if (multi->hostcache == NULL) {
          multi->hostcache = curl_hash_alloc(7, Curl_freeaddrinfo);
        }

        easy->easy_handle->hostcache = multi->hostcache;
      }

      /* Connect. We get a connection identifier filled in. */
      easy->result = Curl_connect(easy->easy_handle, &easy->easy_conn);

      /* after connect, go DO */
      if(CURLE_OK == easy->result) {
        easy->state = CURLM_STATE_DO;
        result = CURLM_CALL_MULTI_PERFORM; 
      }
      break;
    case CURLM_STATE_DO:
      /* Do the fetch or put request */
      easy->result = Curl_do(&easy->easy_conn);
      /* after do, go PERFORM */
      if(CURLE_OK == easy->result) {
        if(CURLE_OK == Curl_readwrite_init(easy->easy_conn)) {
          easy->state = CURLM_STATE_PERFORM;
          result = CURLM_CALL_MULTI_PERFORM; 
        }
      }
      break;
    case CURLM_STATE_PERFORM:
      /* read/write data if it is ready to do so */
      easy->result = Curl_readwrite(easy->easy_conn, &done);
      /* hm, when we follow redirects, we may need to go back to the CONNECT
         state */
      /* after the transfer is done, go DONE */
      if(TRUE == done) {
        /* call this even if the readwrite function returned error */
        easy->result = Curl_posttransfer(easy->easy_handle);
        easy->state = CURLM_STATE_DONE;
        result = CURLM_CALL_MULTI_PERFORM; 
      }
      break;
    case CURLM_STATE_DONE:
      /* post-transfer command */
      easy->result = Curl_done(easy->easy_conn);
      /* after we have DONE what we're supposed to do, go COMPLETED */
      if(CURLE_OK == easy->result)
        easy->state = CURLM_STATE_COMPLETED;
      break;
    case CURLM_STATE_COMPLETED:
      /* this is a completed transfer, it is likely to still be connected */

      /* This node should be delinked from the list now and we should post
         an information message that we are complete. */
      break;
    default:
      return CURLM_INTERNAL_ERROR;
    }

    if((CURLM_STATE_COMPLETED != easy->state) &&
       (CURLE_OK != easy->result)) {
      /*
       * If an error was returned, and we aren't in completed now,
       * then we go to completed and consider this transfer aborted.
       */
      easy->state = CURLM_STATE_COMPLETED;
    }
    else if(CURLM_STATE_COMPLETED != easy->state)
      /* this one still lives! */
      (*running_handles)++;

    easy = easy->next; /* operate on next handle */
  }
  return result;
}

CURLMcode curl_multi_cleanup(CURLM *multi_handle)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  if(GOOD_MULTI_HANDLE(multi)) {
    multi->type = 0; /* not good anymore */
    curl_hash_destroy(multi->hostcache);
    /* remove all easy handles */

    free(multi);

    return CURLM_OK;
  }
  else
    return CURLM_BAD_HANDLE;
}

CURLMsg *curl_multi_info_read(CURLM *multi_handle, int *msgs_in_queue);

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
