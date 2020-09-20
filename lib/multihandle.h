#ifndef HEADER_CURL_MULTIHANDLE_H
#define HEADER_CURL_MULTIHANDLE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "conncache.h"
#include "psl.h"
#include "socketpair.h"

struct Curl_message {
  struct Curl_llist_element list;
  /* the 'CURLMsg' is the part that is visible to the external user */
  struct CURLMsg extmsg;
};

/* NOTE: if you add a state here, add the name to the statename[] array as
   well!
*/
typedef enum {
  CURLM_STATE_INIT,         /* 0 - start in this state */
  CURLM_STATE_CONNECT_PEND, /* 1 - no connections, waiting for one */
  CURLM_STATE_CONNECT,      /* 2 - resolve/connect has been sent off */
  CURLM_STATE_WAITRESOLVE,  /* 3 - awaiting the resolve to finalize */
  CURLM_STATE_WAITCONNECT,  /* 4 - awaiting the TCP connect to finalize */
  CURLM_STATE_WAITPROXYCONNECT, /* 5 - awaiting HTTPS proxy SSL initialization
                                   to complete and/or proxy CONNECT to
                                   finalize */
  CURLM_STATE_SENDPROTOCONNECT, /* 6 - initiate protocol connect procedure */
  CURLM_STATE_PROTOCONNECT, /* 7 - completing the protocol-specific connect
                                   phase */
  CURLM_STATE_DO,           /* 8 - start send off the request (part 1) */
  CURLM_STATE_DOING,        /* 9 - sending off the request (part 1) */
  CURLM_STATE_DO_MORE,      /* 10 - send off the request (part 2) */
  CURLM_STATE_DO_DONE,      /* 11 - done sending off request */
  CURLM_STATE_PERFORM,      /* 12 - transfer data */
  CURLM_STATE_TOOFAST,      /* 13 - wait because limit-rate exceeded */
  CURLM_STATE_DONE,         /* 14 - post data transfer operation */
  CURLM_STATE_COMPLETED,    /* 15 - operation complete */
  CURLM_STATE_MSGSENT,      /* 16 - the operation complete message is sent */
  CURLM_STATE_LAST          /* 17 - not a true state, never use this */
} CURLMstate;

/* we support N sockets per easy handle. Set the corresponding bit to what
   action we should wait for */
#define MAX_SOCKSPEREASYHANDLE 5
#define GETSOCK_READABLE (0x00ff)
#define GETSOCK_WRITABLE (0xff00)

#define CURLPIPE_ANY (CURLPIPE_MULTIPLEX)

#if defined(USE_SOCKETPAIR) && !defined(USE_BLOCKING_SOCKETS) &&        \
  !defined(CURL_DISABLE_SOCKETPAIR)
#define ENABLE_WAKEUP
#endif

/* value for MAXIMUM CONCURRENT STREAMS upper limit */
#define INITIAL_MAX_CONCURRENT_STREAMS ((1U << 31) - 1)

/* This is the struct known as CURLM on the outside */
struct Curl_multi {
  /* First a simple identifier to easier detect if a user mix up
     this multi handle with an easy handle. Set this to CURL_MULTI_HANDLE. */
  long type;

  /* We have a doubly-linked list with easy handles */
  struct Curl_easy *easyp;
  struct Curl_easy *easylp; /* last node */

  int num_easy; /* amount of entries in the linked list above. */
  int num_alive; /* amount of easy handles that are added but have not yet
                    reached COMPLETE state */

  struct Curl_llist msglist; /* a list of messages from completed transfers */

  struct Curl_llist pending; /* Curl_easys that are in the
                                CURLM_STATE_CONNECT_PEND state */

  /* callback function and user data pointer for the *socket() API */
  curl_socket_callback socket_cb;
  void *socket_userp;

  /* callback function and user data pointer for server push */
  curl_push_callback push_cb;
  void *push_userp;

  /* Hostname cache */
  struct Curl_hash hostcache;

#ifdef USE_LIBPSL
  /* PSL cache. */
  struct PslCache psl;
#endif

  /* timetree points to the splay-tree of time nodes to figure out expire
     times of all currently set timers */
  struct Curl_tree *timetree;

  /* 'sockhash' is the lookup hash for socket descriptor => easy handles (note
     the pluralis form, there can be more than one easy handle waiting on the
     same actual socket) */
  struct Curl_hash sockhash;

  /* Shared connection cache (bundles)*/
  struct conncache conn_cache;

  long maxconnects; /* if >0, a fixed limit of the maximum number of entries
                       we're allowed to grow the connection cache to */

  long max_host_connections; /* if >0, a fixed limit of the maximum number
                                of connections per host */

  long max_total_connections; /* if >0, a fixed limit of the maximum number
                                 of connections in total */

  /* timer callback and user data pointer for the *socket() API */
  curl_multi_timer_callback timer_cb;
  void *timer_userp;
  struct curltime timer_lastcall; /* the fixed time for the timeout for the
                                    previous callback */
  unsigned int max_concurrent_streams;

#ifdef USE_WINSOCK
  WSAEVENT wsa_event; /* winsock event used for waits */
#else
#ifdef ENABLE_WAKEUP
  curl_socket_t wakeup_pair[2]; /* socketpair() used for wakeup
                                   0 is used for read, 1 is used for write */
#endif
#endif
  /* multiplexing wanted */
  bool multiplexing;
  bool recheckstate; /* see Curl_multi_connchanged */
  bool in_callback;            /* true while executing a callback */
  bool ipv6_works;
};

#endif /* HEADER_CURL_MULTIHANDLE_H */
