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
#include "cshutdn.h"
#include "hostip.h"
#include "multi_ev.h"
#include "multi_ntfy.h"
#include "psl.h"
#include "socketpair.h"
#include "uint-bset.h"
#include "uint-spbset.h"
#include "uint-table.h"

struct connectdata;
struct Curl_easy;

struct Curl_message {
  struct Curl_llist_node list;
  /* the 'CURLMsg' is the part that is visible to the external user */
  struct CURLMsg extmsg;
};

/* NOTE: if you add a state here, add the name to the statenames[] array
 * in curl_trc.c as well!
 */
typedef enum {
  MSTATE_INIT,         /* 0 - start in this state */
  MSTATE_PENDING,      /* no connections, waiting for one */
  MSTATE_SETUP,        /* start a new transfer */
  MSTATE_CONNECT,      /* resolve/connect has been sent off */
  MSTATE_RESOLVING,    /* awaiting the resolve to finalize */
  MSTATE_CONNECTING,   /* awaiting the TCP connect to finalize */
  MSTATE_PROTOCONNECT, /* initiate protocol connect procedure */
  MSTATE_PROTOCONNECTING, /* completing the protocol-specific connect phase */
  MSTATE_DO,           /* start send off the request (part 1) */
  MSTATE_DOING,        /* sending off the request (part 1) */
  MSTATE_DOING_MORE,   /* send off the request (part 2) */
  MSTATE_DID,          /* done sending off request */
  MSTATE_PERFORMING,   /* transfer data */
  MSTATE_RATELIMITING, /* wait because limit-rate exceeded */
  MSTATE_DONE,         /* post data transfer operation */
  MSTATE_COMPLETED,    /* operation complete */
  MSTATE_MSGSENT,      /* the operation complete message is sent */
  MSTATE_LAST          /* not a true state, never use this */
} CURLMstate;

#define CURLPIPE_ANY (CURLPIPE_MULTIPLEX)

#ifndef CURL_DISABLE_SOCKETPAIR
#define ENABLE_WAKEUP
#endif

/* value for MAXIMUM CONCURRENT STREAMS upper limit */
#define INITIAL_MAX_CONCURRENT_STREAMS ((1U << 31) - 1)

/* This is the struct known as CURLM on the outside */
struct Curl_multi {
  /* First a simple identifier to easier detect if a user mix up
     this multi handle with an easy handle. Set this to CURL_MULTI_HANDLE. */
  unsigned int magic;

  unsigned int xfers_alive; /* amount of added transfers that have
                               not yet reached COMPLETE state */
  curl_off_t xfers_total_ever; /* total of added transfers, ever. */
  struct uint32_tbl xfers; /* transfers added to this multi */
  /* Each transfer's mid may be present in at most one of these */
  struct uint32_bset process; /* transfer being processed */
  struct uint32_bset dirty; /* transfer to be run NOW, e.g. ASAP. */
  struct uint32_bset pending; /* transfers in waiting (conn limit etc.) */
  struct uint32_bset msgsent; /* transfers done with message for application */

  struct Curl_llist msglist; /* a list of messages from completed transfers */

  struct Curl_easy *admin; /* internal easy handle for admin operations.
                              gets assigned `mid` 0 on multi init */

  /* callback function and user data pointer for the *socket() API */
  curl_socket_callback socket_cb;
  void *socket_userp;

  /* callback function and user data pointer for server push */
  curl_push_callback push_cb;
  void *push_userp;

  struct Curl_dnscache dnscache; /* DNS cache */
  struct Curl_ssl_scache *ssl_scache; /* TLS session pool */

#ifdef USE_LIBPSL
  /* PSL cache. */
  struct PslCache psl;
#endif

  /* current time for transfers running in this multi handle */
  struct curltime now;
  /* timetree points to the splay-tree of time nodes to figure out expire
     times of all currently set timers */
  struct Curl_tree *timetree;

  /* buffer used for transfer data, lazy initialized */
  char *xfer_buf; /* the actual buffer */
  size_t xfer_buf_len;      /* the allocated length */
  /* buffer used for upload data, lazy initialized */
  char *xfer_ulbuf; /* the actual buffer */
  size_t xfer_ulbuf_len;      /* the allocated length */
  /* buffer used for socket I/O operations, lazy initialized */
  char *xfer_sockbuf; /* the actual buffer */
  size_t xfer_sockbuf_len; /* the allocated length */

  /* multi event related things */
  struct curl_multi_ev ev;
  /* multi notification related things */
  struct curl_multi_ntfy ntfy;

  /* `proto_hash` is a general key-value store for protocol implementations
   * with the lifetime of the multi handle. The number of elements kept here
   * should be in the order of supported protocols (and sub-protocols like
   * TLS), *not* in the order of connections or current transfers!
   * Elements need to be added with their own destructor to be invoked when
   * the multi handle is cleaned up (see Curl_hash_add2()).*/
  struct Curl_hash proto_hash;

  struct cshutdn cshutdn; /* connection shutdown handling */
  struct cpool cpool;     /* connection pool (bundles) */

  size_t max_host_connections; /* if >0, a fixed limit of the maximum number
                                  of connections per host */
  size_t max_total_connections; /* if >0, a fixed limit of the maximum number
                                   of connections in total */

  /* timer callback and user data pointer for the *socket() API */
  curl_multi_timer_callback timer_cb;
  void *timer_userp;
  long last_timeout_ms;        /* the last timeout value set via timer_cb */
  struct curltime last_expire_ts; /* timestamp of last expiry */

#ifdef USE_WINSOCK
  WSAEVENT wsa_event; /* Winsock event used for waits */
#else
#ifdef ENABLE_WAKEUP
  curl_socket_t wakeup_pair[2]; /* eventfd()/pipe()/socketpair() used for
                                   wakeup 0 is used for read, 1 is used
                                   for write */
#endif
#endif
  unsigned int max_concurrent_streams;
  unsigned int maxconnects; /* if >0, a fixed limit of the maximum number of
                               entries we are allowed to grow the connection
                               cache to */
#ifdef DEBUGBUILD
  unsigned int now_access_count;
#endif
#define IPV6_UNKNOWN 0
#define IPV6_DEAD    1
#define IPV6_WORKS   2
  unsigned char ipv6_up;       /* IPV6_* defined */
  BIT(multiplexing);           /* multiplexing wanted */
  BIT(recheckstate);           /* see Curl_multi_connchanged */
  BIT(in_callback);            /* true while executing a callback */
  BIT(in_ntfy_callback);       /* true while dispatching notifications */
#ifdef USE_OPENSSL
  BIT(ssl_seeded);
#endif
  BIT(dead); /* a callback returned error, everything needs to crash and
                burn */
  BIT(xfer_buf_borrowed);      /* xfer_buf is currently being borrowed */
  BIT(xfer_ulbuf_borrowed);    /* xfer_ulbuf is currently being borrowed */
  BIT(xfer_sockbuf_borrowed);  /* xfer_sockbuf is currently being borrowed */
#ifdef DEBUGBUILD
  BIT(warned);                 /* true after user warned of DEBUGBUILD */
#endif
};

#endif /* HEADER_CURL_MULTIHANDLE_H */
