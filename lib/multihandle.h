#ifndef HEADER_CURL_MULTIHANDLE_H
#define HEADER_CURL_MULTIHANDLE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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

struct Curl_message {
  /* the 'CURLMsg' is the part that is visible to the external user */
  struct CURLMsg extmsg;
};

/* NOTE: if you add a state here, add the name to the statename[] array as
   well!
*/
typedef enum {
  CURLM_STATE_INIT,        /* 0 - start in this state */
  CURLM_STATE_CONNECT,     /* 1 - resolve/connect has been sent off */
  CURLM_STATE_WAITRESOLVE, /* 2 - awaiting the resolve to finalize */
  CURLM_STATE_WAITCONNECT, /* 3 - awaiting the connect to finalize */
  CURLM_STATE_WAITPROXYCONNECT, /* 4 - awaiting proxy CONNECT to finalize */
  CURLM_STATE_PROTOCONNECT, /* 5 - completing the protocol-specific connect
                               phase */
  CURLM_STATE_WAITDO,      /* 6 - wait for our turn to send the request */
  CURLM_STATE_DO,          /* 7 - start send off the request (part 1) */
  CURLM_STATE_DOING,       /* 8 - sending off the request (part 1) */
  CURLM_STATE_DO_MORE,     /* 9 - send off the request (part 2) */
  CURLM_STATE_DO_DONE,     /* 10 - done sending off request */
  CURLM_STATE_WAITPERFORM, /* 11 - wait for our turn to read the response */
  CURLM_STATE_PERFORM,     /* 12 - transfer data */
  CURLM_STATE_TOOFAST,     /* 13 - wait because limit-rate exceeded */
  CURLM_STATE_DONE,        /* 14 - post data transfer operation */
  CURLM_STATE_COMPLETED,   /* 15 - operation complete */
  CURLM_STATE_MSGSENT,     /* 16 - the operation complete message is sent */
  CURLM_STATE_LAST         /* 17 - not a true state, never use this */
} CURLMstate;

/* we support N sockets per easy handle. Set the corresponding bit to what
   action we should wait for */
#define MAX_SOCKSPEREASYHANDLE 5
#define GETSOCK_READABLE (0x00ff)
#define GETSOCK_WRITABLE (0xff00)

struct Curl_one_easy {
  /* first, two fields for the linked list of these */
  struct Curl_one_easy *next;
  struct Curl_one_easy *prev;

  struct SessionHandle *easy_handle; /* the easy handle for this unit */
  struct connectdata *easy_conn;     /* the "unit's" connection */

  CURLMstate state;  /* the handle's state */
  CURLcode result;   /* previous result */

  struct Curl_message msg; /* A single posted message. */

  /* Array with the plain socket numbers this handle takes care of, in no
     particular order. Note that all sockets are added to the sockhash, where
     the state etc are also kept. This array is mostly used to detect when a
     socket is to be removed from the hash. See singlesocket(). */
  curl_socket_t sockets[MAX_SOCKSPEREASYHANDLE];
  int numsocks;
};

/* This is the struct known as CURLM on the outside */
struct Curl_multi {
  /* First a simple identifier to easier detect if a user mix up
     this multi handle with an easy handle. Set this to CURL_MULTI_HANDLE. */
  long type;

  /* We have a doubly-linked circular list with easy handles */
  struct Curl_one_easy easy;

  int num_easy; /* amount of entries in the linked list above. */
  int num_alive; /* amount of easy handles that are added but have not yet
                    reached COMPLETE state */

  struct curl_llist *msglist; /* a list of messages from completed transfers */

  /* callback function and user data pointer for the *socket() API */
  curl_socket_callback socket_cb;
  void *socket_userp;

  /* Hostname cache */
  struct curl_hash *hostcache;

  /* timetree points to the splay-tree of time nodes to figure out expire
     times of all currently set timers */
  struct Curl_tree *timetree;

  /* 'sockhash' is the lookup hash for socket descriptor => easy handles (note
     the pluralis form, there can be more than one easy handle waiting on the
     same actual socket) */
  struct curl_hash *sockhash;

  /* Whether pipelining is enabled for this multi handle */
  bool pipelining_enabled;

  /* Shared connection cache (bundles)*/
  struct conncache *conn_cache;

  /* This handle will be used for closing the cached connections in
     curl_multi_cleanup() */
  struct SessionHandle *closure_handle;

  long maxconnects; /* if >0, a fixed limit of the maximum number of entries
                       we're allowed to grow the connection cache to */

  /* timer callback and user data pointer for the *socket() API */
  curl_multi_timer_callback timer_cb;
  void *timer_userp;
  struct timeval timer_lastcall; /* the fixed time for the timeout for the
                                    previous callback */
};

#endif /* HEADER_CURL_MULTIHANDLE_H */

