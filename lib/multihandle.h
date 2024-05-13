#ifndef HEADER_CURL_MULTIHANDLE_H
#define HEADER_CURL_MULTIHANDLE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
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

#include "llist.h"
#include "hash.h"
#include "conncache.h"
#include "psl.h"
#include "socketpair.h"

struct connectdata;

struct Curl_message {
  struct Curl_llist_element list;
  /* the 'CURLMsg' is the part that is visible to the external user */
  struct CURLMsg extmsg;
};

/* NOTE: if you add a state here, add the name to the statename[] array as
   well!
*/
typedef enum {
  MSTATE_INIT,         /* 0 - start in this state */
  MSTATE_PENDING,      /* 1 - no connections, waiting for one */
  MSTATE_SETUP,        /* 2 - start a new transfer */
  MSTATE_CONNECT,      /* 3 - resolve/connect has been sent off */
  MSTATE_RESOLVING,    /* 4 - awaiting the resolve to finalize */
  MSTATE_CONNECTING,   /* 5 - awaiting the TCP connect to finalize */
  MSTATE_TUNNELING,    /* 6 - awaiting HTTPS proxy SSL initialization to
                          complete and/or proxy CONNECT to finalize */
  MSTATE_PROTOCONNECT, /* 7 - initiate protocol connect procedure */
  MSTATE_PROTOCONNECTING, /* 8 - completing the protocol-specific connect
                             phase */
  MSTATE_DO,           /* 9 - start send off the request (part 1) */
  MSTATE_DOING,        /* 10 - sending off the request (part 1) */
  MSTATE_DOING_MORE,   /* 11 - send off the request (part 2) */
  MSTATE_DID,          /* 12 - done sending off request */
  MSTATE_PERFORMING,   /* 13 - transfer data */
  MSTATE_RATELIMITING, /* 14 - wait because limit-rate exceeded */
  MSTATE_DONE,         /* 15 - post data transfer operation */
  MSTATE_COMPLETED,    /* 16 - operation complete */
  MSTATE_MSGSENT,      /* 17 - the operation complete message is sent */
  MSTATE_LAST          /* 18 - not a true state, never use this */
} CURLMstate;

/* we support N sockets per easy handle. Set the corresponding bit to what
   action we should wait for */
#define MAX_SOCKSPEREASYHANDLE 5
#define GETSOCK_READABLE (0x00ff)
#define GETSOCK_WRITABLE (0xff00)

#define CURLPIPE_ANY (CURLPIPE_MULTIPLEX)

#if !defined(CURL_DISABLE_SOCKETPAIR)
#define ENABLE_WAKEUP
#endif

/* value for MAXIMUM CONCURRENT STREAMS upper limit */
#define INITIAL_MAX_CONCURRENT_STREAMS ((1U << 31) - 1)

/* Curl_multi SSL backend-specific data; declared differently by each SSL
   backend */
struct multi_ssl_backend_data;

/* This is the struct known as CURLM on the outside */
struct Curl_multi {
  /* First a simple identifier to easier detect if a user mix up
     this multi handle with an easy handle. Set this to CURL_MULTI_HANDLE. */
  unsigned int magic;

  /* We have a doubly-linked list with easy handles */
  struct Curl_easy *easyp;
  struct Curl_easy *easylp; /* last node */

  unsigned int num_easy; /* amount of entries in the linked list above. */
  unsigned int num_alive; /* amount of easy handles that are added but have
                             not yet reached COMPLETE state */

  struct Curl_llist msglist; /* a list of messages from completed transfers */

  struct Curl_llist pending; /* Curl_easys that are in the
                                MSTATE_PENDING state */
  struct Curl_llist msgsent; /* Curl_easys that are in the
                                MSTATE_MSGSENT state */

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

  /* buffer used for transfer data, lazy initialized */
  char *xfer_buf; /* the actual buffer */
  size_t xfer_buf_len;      /* the allocated length */
  /* buffer used for upload data, lazy initialized */
  char *xfer_ulbuf; /* the actual buffer */
  size_t xfer_ulbuf_len;      /* the allocated length */

#if defined(USE_SSL)
  struct multi_ssl_backend_data *ssl_backend_data;
#endif

  /* 'sockhash' is the lookup hash for socket descriptor => easy handles (note
     the pluralis form, there can be more than one easy handle waiting on the
     same actual socket) */
  struct Curl_hash sockhash;

  /* Shared connection cache (bundles)*/
  struct conncache conn_cache;

  long max_host_connections; /* if >0, a fixed limit of the maximum number
                                of connections per host */

  long max_total_connections; /* if >0, a fixed limit of the maximum number
                                 of connections in total */

  /* timer callback and user data pointer for the *socket() API */
  curl_multi_timer_callback timer_cb;
  void *timer_userp;
  struct curltime timer_lastcall; /* the fixed time for the timeout for the
                                    previous callback */
#ifdef USE_WINSOCK
  WSAEVENT wsa_event; /* winsock event used for waits */
#else
#ifdef ENABLE_WAKEUP
  curl_socket_t wakeup_pair[2]; /* pipe()/socketpair() used for wakeup
                                   0 is used for read, 1 is used for write */
#endif
#endif
  unsigned int max_concurrent_streams;
  unsigned int maxconnects; /* if >0, a fixed limit of the maximum number of
                               entries we're allowed to grow the connection
                               cache to */
#define IPV6_UNKNOWN 0
#define IPV6_DEAD    1
#define IPV6_WORKS   2
  unsigned char ipv6_up;       /* IPV6_* defined */
  BIT(multiplexing);           /* multiplexing wanted */
  BIT(recheckstate);           /* see Curl_multi_connchanged */
  BIT(in_callback);            /* true while executing a callback */
#ifdef USE_OPENSSL
  BIT(ssl_seeded);
#endif
  BIT(dead); /* a callback returned error, everything needs to crash and
                burn */
  BIT(xfer_buf_borrowed);      /* xfer_buf is currently being borrowed */
  BIT(xfer_ulbuf_borrowed);    /* xfer_ulbuf is currently being borrowed */
#ifdef DEBUGBUILD
  BIT(warned);                 /* true after user warned of DEBUGBUILD */
#endif
};

#endif /* HEADER_CURL_MULTIHANDLE_H */
