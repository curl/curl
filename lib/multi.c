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

#include "multi.h" /* will become <curl/multi.h> soon */

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
  
  CURL *easy_handle; /* this is the easy handle for this unit */
  CURLMstate state; /* the handle's state */
};


#define CURL_MULTI_HANDLE 0x000bab1e

#define GOOD_MULTI_HANDLE(x) ((x) && ((x)->type == CURL_MULTI_HANDLE))
#define GOOD_EASY_HANDLE(x) (x)

/* This is the struct known as CURLM on the outside */
struct Curl_multi {
  /* First a simple identifier to easier detect if a user mix up
     this multi handle with an easy handle. Set this to CURL_MULTI_HANDLE. */
  long type;

  /* We have a linked list with easy handles */
  struct Curl_one_easy first; 
  /* This is the amount of entries in the linked list above. */
  int num_easy;
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
  easy->next = multi->first.next;
  easy->prev = &multi->first; 

  /* make 'easy' the first node in the chain */
  multi->first.next = easy;

  /* if there was a next node, make sure its 'prev' pointer links back to
     the new node */
  if(easy->next)
    easy->next->prev = easy;

  /* increase the node-counter */
  multi->num_easy++;

  return CURLM_OK;
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
  easy = multi->first.next;
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

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  easy=multi->first.next;
  while(easy) {
    switch(easy->state) {
    case CURLM_STATE_INIT:
    case CURLM_STATE_CONNECT:
    case CURLM_STATE_DO:
    case CURLM_STATE_DONE:
      /* we want curl_multi_perform() to get called, but we don't have any
         file descriptors to set */
      break;
    case CURLM_STATE_PERFORM:
      /* This should have a set of file descriptors for us to set.  */
      /* after the transfer is done, go DONE */
      break;
    }

  }

  return CURLM_OK;
}

CURLMcode curl_multi_perform(CURLM *multi_handle, int *running_handles)
{
  struct Curl_multi *multi=(struct Curl_multi *)multi_handle;
  struct Curl_one_easy *easy;

  if(!GOOD_MULTI_HANDLE(multi))
    return CURLM_BAD_HANDLE;

  easy=multi->first.next;
  while(easy) {
    switch(easy->state) {
    case CURLM_STATE_INIT:
      /* after init, go CONNECT */
      break;
    case CURLM_STATE_CONNECT:
      /* after connect, go DO */
      break;
    case CURLM_STATE_DO:
      /* after do, go PERFORM */
      break;
    case CURLM_STATE_PERFORM:
      /* read/write data if it is ready to do so */
      /* after the transfer is done, go DONE */
      break;
    case CURLM_STATE_DONE:
      /* after we have DONE what we're supposed to do, go COMPLETED */
      break;
    case CURLM_STATE_COMPLETED:
      /* this is a completed transfer */
      break;
    }

  }

}

CURLMcode curl_multi_cleanup(CURLM *multi_handle);

int curl_multi_info_open(CURLM *multi_handle, CURLMinfo *info_handle);

CURLMsg *curl_multi_info_read(CURLMinfo *info_handle);

void curl_multi_info_close(CURLMinfo *info_handle);
