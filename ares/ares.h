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

#ifndef ARES__H
#define ARES__H

#include <sys/types.h>

#if defined(_AIX) || defined(NETWARE)
/* HP-UX systems version 9, 10 and 11 lack sys/select.h and so does oldish
   libc5-based Linux systems. Only include it on system that are known to
   require it! */
#include <sys/select.h>
#endif

#if defined(WATT32)
  #include <netinet/in.h>
  #include <tcp.h>
#elif defined(WIN32)
  #include <winsock.h>
  #include <windows.h>
#else
  #include <netinet/in.h>
#endif

#define ARES_SUCCESS		0

/* Server error codes (ARES_ENODATA indicates no relevant answer) */
#define ARES_ENODATA		1
#define ARES_EFORMERR		2
#define ARES_ESERVFAIL		3
#define ARES_ENOTFOUND		4
#define ARES_ENOTIMP		5
#define ARES_EREFUSED		6

/* Locally generated error codes */
#define ARES_EBADQUERY		7
#define ARES_EBADNAME		8
#define ARES_EBADFAMILY		9
#define ARES_EBADRESP		10
#define ARES_ECONNREFUSED	11
#define ARES_ETIMEOUT		12
#define ARES_EOF		13
#define ARES_EFILE		14
#define ARES_ENOMEM		15
#define ARES_EDESTRUCTION	16
#define ARES_EBADSTR		17

/* Flag values */
#define ARES_FLAG_USEVC		(1 << 0)
#define ARES_FLAG_PRIMARY	(1 << 1)
#define ARES_FLAG_IGNTC		(1 << 2)
#define ARES_FLAG_NORECURSE	(1 << 3)
#define ARES_FLAG_STAYOPEN	(1 << 4)
#define ARES_FLAG_NOSEARCH	(1 << 5)
#define ARES_FLAG_NOALIASES	(1 << 6)
#define ARES_FLAG_NOCHECKRESP	(1 << 7)

/* Option mask values */
#define ARES_OPT_FLAGS		(1 << 0)
#define ARES_OPT_TIMEOUT	(1 << 1)
#define ARES_OPT_TRIES		(1 << 2)
#define ARES_OPT_NDOTS		(1 << 3)
#define ARES_OPT_UDP_PORT	(1 << 4)
#define ARES_OPT_TCP_PORT	(1 << 5)
#define ARES_OPT_SERVERS	(1 << 6)
#define ARES_OPT_DOMAINS	(1 << 7)
#define ARES_OPT_LOOKUPS	(1 << 8)

struct ares_options {
  int flags;
  int timeout;
  int tries;
  int ndots;
  unsigned short udp_port;
  unsigned short tcp_port;
  struct in_addr *servers;
  int nservers;
  char **domains;
  int ndomains;
  char *lookups;
};

struct hostent;
struct timeval;
struct ares_channeldata;
typedef struct ares_channeldata *ares_channel;
typedef void (*ares_callback)(void *arg, int status, unsigned char *abuf,
			      int alen);
typedef void (*ares_host_callback)(void *arg, int status,
				   struct hostent *hostent);

int ares_init(ares_channel *channelptr);
int ares_init_options(ares_channel *channelptr, struct ares_options *options,
		      int optmask);
void ares_destroy(ares_channel channel);
void ares_cancel(ares_channel channel);
void ares_send(ares_channel channel, const unsigned char *qbuf, int qlen,
	       ares_callback callback, void *arg);
void ares_query(ares_channel channel, const char *name, int dnsclass,
		int type, ares_callback callback, void *arg);
void ares_search(ares_channel channel, const char *name, int dnsclass,
		 int type, ares_callback callback, void *arg);
void ares_gethostbyname(ares_channel channel, const char *name, int family,
			ares_host_callback callback, void *arg);
void ares_gethostbyaddr(ares_channel channel, const void *addr, int addrlen,
			int family, ares_host_callback callback, void *arg);

int ares_fds(ares_channel channel, fd_set *read_fds, fd_set *write_fds);
struct timeval *ares_timeout(ares_channel channel, struct timeval *maxtv,
			     struct timeval *tv);
void ares_process(ares_channel channel, fd_set *read_fds, fd_set *write_fds);

int ares_mkquery(const char *name, int dnsclass, int type, unsigned short id,
		 int rd, unsigned char **buf, int *buflen);
int ares_expand_name(const unsigned char *encoded, const unsigned char *abuf,
		     int alen, char **s, long *enclen);
int ares_expand_string(const unsigned char *encoded, const unsigned char *abuf,
		     int alen, unsigned char **s, long *enclen);
int ares_parse_a_reply(const unsigned char *abuf, int alen,
		       struct hostent **host);
int ares_parse_ptr_reply(const unsigned char *abuf, int alen, const void *addr,
			 int addrlen, int family, struct hostent **host);
void ares_free_string(void *str);
void ares_free_hostent(struct hostent *host);
const char *ares_strerror(int code);
void ares_free_errmem(char *mem);

#endif /* ARES__H */
