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

#define	DEFAULT_TIMEOUT		5
#define DEFAULT_TRIES		4
#ifndef INADDR_NONE
#define	INADDR_NONE 0xffffffff
#endif

#if defined(WIN32) && !defined(WATT32)

#define IsNT ((int)GetVersion()>0)
#define WIN_NS_9X      "System\\CurrentControlSet\\Services\\VxD\\MSTCP"
#define WIN_NS_NT_KEY  "System\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define NAMESERVER     "NameServer"
#define DHCPNAMESERVER "DhcpNameServer"
#define PATH_HOSTS_NT  "\\drivers\\etc\\hosts"
#define PATH_HOSTS_9X  "\\hosts"

#elif defined(WATT32)

#define PATH_RESOLV_CONF "/dev/ENV/etc/resolv.conf"

#elif defined(NETWARE)

#define PATH_RESOLV_CONF "sys:/etc/resolv.cfg"
#define PATH_HOSTS		"sys:/etc/hosts"

#else

#define PATH_RESOLV_CONF	"/etc/resolv.conf"
#ifdef ETC_INET
#define PATH_HOSTS		"/etc/inet/hosts"
#else
#define PATH_HOSTS		"/etc/hosts"
#endif

#endif

struct send_request {
  /* Remaining data to send */
  const unsigned char *data;
  size_t len;

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
};

struct query {
  /* Query ID from qbuf, for faster lookup, and current timeout */
  unsigned short qid;
  time_t timeout;

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
  int *skip_server;
  int using_tcp;
  int error_status;

  /* Next query in chain */
  struct query *next;
};

/* An IP address pattern; matches an IP address X if X & mask == addr */
struct apattern {
  struct in_addr addr;
  struct in_addr mask;
};

struct ares_channeldata {
  /* Configuration data */
  int flags;
  int timeout;
  int tries;
  int ndots;
  int udp_port;
  int tcp_port;
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

  /* Active queries */
  struct query *queries;
};

void ares__send_query(ares_channel channel, struct query *query, time_t now);
void ares__close_sockets(struct server_state *server);
int ares__get_hostent(FILE *fp, struct hostent **host);
int ares__read_line(FILE *fp, char **buf, int *bufsize);

#ifdef CURLDEBUG
/* This is low-level hard-hacking memory leak tracking and similar. Using the
   libcurl lowlevel code from within library is ugly and only works when
   c-ares is built and linked with a similarly debug-build libcurl, but we do
   this anyway for convenience. */
#include "../lib/memdebug.h"
#endif
