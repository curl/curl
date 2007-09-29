#ifndef __ARES_PRIVATE_H
#define __ARES_PRIVATE_H

/* $Id$ */

/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#include <stdio.h>
#include <sys/types.h>

#if !defined(WIN32) || defined(WATT32)
#include <netinet/in.h>
/* We define closesocket() here so that we can use this function all over
   the source code for closing sockets. */
#define closesocket(x) close(x)
#endif

#ifdef WATT32
#include <tcp.h>
#include <sys/ioctl.h>
#undef  closesocket
#define closesocket(s)    close_s(s)
#define writev(s,v,c)     writev_s(s,v,c)
#endif

#ifdef NETWARE
#include <time.h>
#endif

#define DEFAULT_TIMEOUT         5
#define DEFAULT_TRIES           4
#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#if defined(WIN32) && !defined(WATT32)

#define IS_NT()        ((int)GetVersion() > 0)
#define WIN_NS_9X      "System\\CurrentControlSet\\Services\\VxD\\MSTCP"
#define WIN_NS_NT_KEY  "System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define NAMESERVER     "NameServer"
#define DHCPNAMESERVER "DhcpNameServer"
#define DATABASEPATH   "DatabasePath"
#define WIN_PATH_HOSTS  "\\hosts"

#elif defined(WATT32)

#define PATH_RESOLV_CONF "/dev/ENV/etc/resolv.conf"

#elif defined(NETWARE)

#define PATH_RESOLV_CONF "sys:/etc/resolv.cfg"
#define PATH_HOSTS              "sys:/etc/hosts"

#elif defined(__riscos__)

#define PATH_HOSTS             "InetDBase:Hosts"

#else

#define PATH_RESOLV_CONF        "/etc/resolv.conf"
#ifdef ETC_INET
#define PATH_HOSTS              "/etc/inet/hosts"
#else
#define PATH_HOSTS              "/etc/hosts"
#endif

#endif

#define ARES_ID_KEY_LEN 31

#include "ares_ipv6.h"

struct query;

/* Node definition for circular, doubly-linked list */
struct list_node {
  struct list_node *prev;
  struct list_node *next;
  void* data;
};

struct send_request {
  /* Remaining data to send */
  const unsigned char *data;
  size_t len;

  /* The query for which we're sending this data */
  struct query* owner_query;
  /* The buffer we're using, if we have our own copy of the packet */
  unsigned char *data_storage;

  /* Next request in queue */
  struct send_request *next;
};

struct server_state {
  struct in_addr addr;
  ares_socket_t udp_socket;
  ares_socket_t tcp_socket;

  /* Mini-buffer for reading the length word */
  unsigned char tcp_lenbuf[2];
  int tcp_lenbuf_pos;
  int tcp_length;

  /* Buffer for reading actual TCP data */
  unsigned char *tcp_buffer;
  int tcp_buffer_pos;

  /* TCP output queue */
  struct send_request *qhead;
  struct send_request *qtail;

  /* Which incarnation of this connection is this? We don't want to
   * retransmit requests into the very same socket, but if the server
   * closes on us and we re-open the connection, then we do want to
   * re-send. */
  int tcp_connection_generation;

  /* Circular, doubly-linked list of outstanding queries to this server */
  struct list_node queries_to_server;

  /* Link back to owning channel */
  ares_channel channel;

  /* Is this server broken? We mark connections as broken when a
   * request that is queued for sending times out.
   */
  int is_broken;
};

/* State to represent a DNS query */
struct query {
  /* Query ID from qbuf, for faster lookup, and current timeout */
  unsigned short qid;
  time_t timeout;

  /*
   * Links for the doubly-linked lists in which we insert a query.
   * These circular, doubly-linked lists that are hash-bucketed based
   * the attributes we care about, help making most important
   * operations O(1).
   */
  struct list_node queries_by_qid;    /* hopefully in same cache line as qid */
  struct list_node queries_by_timeout;
  struct list_node queries_to_server;
  struct list_node all_queries;

  /* Query buf with length at beginning, for TCP transmission */
  unsigned char *tcpbuf;
  int tcplen;

  /* Arguments passed to ares_send() (qbuf points into tcpbuf) */
  const unsigned char *qbuf;
  int qlen;
  ares_callback callback;
  void *arg;

  /* Query status */
  int try;
  int server;
  struct query_server_info *server_info;   /* per-server state */
  int using_tcp;
  int error_status;
  int timeouts; /* number of timeouts we saw for this request */
};

/* Per-server state for a query */
struct query_server_info {
  int skip_server;  /* should we skip server, due to errors, etc? */
  int tcp_connection_generation;  /* into which TCP connection did we send? */
};

/* An IP address pattern; matches an IP address X if X & mask == addr */
#define PATTERN_MASK 0x1
#define PATTERN_CIDR 0x2

union ares_addr {
  struct in_addr addr4;
  struct in6_addr addr6;
};

struct apattern {
  union ares_addr addr;
  union
  {
    union ares_addr addr;
    unsigned short bits;
  } mask;
  int family;
  unsigned short type;
};

typedef struct rc4_key
{
  unsigned char state[256];
  unsigned char x;
  unsigned char y;
} rc4_key;

struct ares_channeldata {
  /* Configuration data */
  int flags;
  int timeout;
  int tries;
  int ndots;
  int udp_port;
  int tcp_port;
  int socket_send_buffer_size;
  int socket_receive_buffer_size;
  char **domains;
  int ndomains;
  struct apattern *sortlist;
  int nsort;
  char *lookups;

  /* Server addresses and communications state */
  struct server_state *servers;
  int nservers;

  /* ID to use for next query */
  unsigned short next_id;
  /* key to use when generating new ids */
  rc4_key id_key;

  /* Generation number to use for the next TCP socket open/close */
  int tcp_connection_generation;

  /* The time at which we last called process_timeouts() */
  time_t last_timeout_processed;

  /* Circular, doubly-linked list of queries, bucketed various ways.... */
  /* All active queries in a single list: */
  struct list_node all_queries;
  /* Queries bucketed by qid, for quickly dispatching DNS responses: */
#define ARES_QID_TABLE_SIZE 2048
  struct list_node queries_by_qid[ARES_QID_TABLE_SIZE];
  /* Queries bucketed by timeout, for quickly handling timeouts: */
#define ARES_TIMEOUT_TABLE_SIZE 1024
  struct list_node queries_by_timeout[ARES_TIMEOUT_TABLE_SIZE];

  ares_sock_state_cb sock_state_cb;
  void *sock_state_cb_data;
};

void ares__rc4(rc4_key* key,unsigned char *buffer_ptr, int buffer_len);
void ares__send_query(ares_channel channel, struct query *query, time_t now);
void ares__close_sockets(ares_channel channel, struct server_state *server);
int ares__get_hostent(FILE *fp, int family, struct hostent **host);
int ares__read_line(FILE *fp, char **buf, int *bufsize);
void ares__free_query(struct query *query);
short ares__generate_new_id(rc4_key* key);


/* Routines for managing doubly-linked circular linked lists with a
 * dummy head.
 */

/* Initialize a new head node */
static inline void ares__init_list_head(struct list_node* head) {
  head->prev = head;
  head->next = head;
  head->data = NULL;
}

/* Initialize a list node */
static inline void ares__init_list_node(struct list_node* node, void* d) {
  node->prev = NULL;
  node->next = NULL;
  node->data = d;
}

/* Returns true iff the given list is empty */
static inline int ares__is_list_empty(struct list_node* head) {
  return ((head->next == head) && (head->prev == head));
}

/* Inserts new_node before old_node */
static inline void ares__insert_in_list(struct list_node* new_node,
                                        struct list_node* old_node) {
  new_node->next = old_node;
  new_node->prev = old_node->prev;
  old_node->prev->next = new_node;
  old_node->prev = new_node;
}

/* Removes the node from the list it's in, if any */
static inline void ares__remove_from_list(struct list_node* node) {
  if (node->next != NULL) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = NULL;
    node->next = NULL;
  }
}

/* Swap the contents of two lists */
static inline void ares__swap_lists(struct list_node* head_a,
                                    struct list_node* head_b) {
  int is_a_empty = ares__is_list_empty(head_a);
  int is_b_empty = ares__is_list_empty(head_b);
  struct list_node old_a = *head_a;
  struct list_node old_b = *head_b;

  if (is_a_empty) {
    ares__init_list_head(head_b);
  } else {
    *head_b = old_a;
    old_a.next->prev = head_b;
    old_a.prev->next = head_b;
  }
  if (is_b_empty) {
    ares__init_list_head(head_a);
  } else {
    *head_a = old_b;
    old_b.next->prev = head_a;
    old_b.prev->next = head_a;
  }
}

#define ARES_SWAP_BYTE(a,b) \
  { unsigned char swapByte = *(a);  *(a) = *(b);  *(b) = swapByte; }

#define SOCK_STATE_CALLBACK(c, s, r, w)                                 \
  do {                                                                  \
    if ((c)->sock_state_cb)                                             \
      (c)->sock_state_cb((c)->sock_state_cb_data, (s), (r), (w));       \
  } while (0)

#ifdef CURLDEBUG
/* This is low-level hard-hacking memory leak tracking and similar. Using the
   libcurl lowlevel code from within library is ugly and only works when
   c-ares is built and linked with a similarly debug-build libcurl, but we do
   this anyway for convenience. */
#include "../lib/memdebug.h"
#endif

#endif /* __ARES_PRIVATE_H */
