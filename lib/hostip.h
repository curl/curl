#ifndef __HOSTIP_H
#define __HOSTIP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include "setup.h"
#include "hash.h"

#if (defined(NETWARE) && defined(__NOVELL_LIBC__))
#undef in_addr_t
#define in_addr_t uint32_t
#endif

/*
 * Setup comfortable CURLRES_* defines to use in the host*.c sources.
 */

#ifdef USE_ARES
#define CURLRES_ASYNCH
#define CURLRES_ARES
#endif

#ifdef USE_THREADING_GETHOSTBYNAME
#define CURLRES_ASYNCH
#define CURLRES_THREADED
#endif

#ifdef USE_THREADING_GETADDRINFO
#define CURLRES_ASYNCH
#define CURLRES_THREADED
#endif

#ifdef ENABLE_IPV6
#define CURLRES_IPV6
#else
#define CURLRES_IPV4
#endif

#if defined(CURLRES_IPV4) || defined(CURLRES_ARES)
#if !defined(HAVE_GETHOSTBYNAME_R) || defined(CURLRES_ASYNCH)
/* If built for ipv4 and missing gethostbyname_r(), or if using async name
   resolve, we need the Curl_addrinfo_copy() function (which itself needs the
   Curl_he2ai() function)) */
#define CURLRES_ADDRINFO_COPY
#endif
#endif /* IPv4/ares-only */

#ifndef CURLRES_ASYNCH
#define CURLRES_SYNCH
#endif

#ifndef USE_LIBIDN
#define CURLRES_IDN
#endif

/* Allocate enough memory to hold the full name information structs and
 * everything. OSF1 is known to require at least 8872 bytes. The buffer
 * required for storing all possible aliases and IP numbers is according to
 * Stevens' Unix Network Programming 2nd edition, p. 304: 8192 bytes!
 */
#define CURL_HOSTENT_SIZE 9000

#define CURL_TIMEOUT_RESOLVE 300 /* when using asynch methods, we allow this
                                    many seconds for a name resolve */

#ifdef CURLRES_ARES
#define CURL_ASYNC_SUCCESS ARES_SUCCESS
#else
#define CURL_ASYNC_SUCCESS CURLE_OK
#define ares_cancel(x) do {} while(0)
#define ares_destroy(x) do {} while(0)
#endif

/*
 * Curl_addrinfo MUST be used for all name resolved info.
 */
#ifdef CURLRES_IPV6
typedef struct addrinfo Curl_addrinfo;
#else
/* OK, so some ipv4-only include tree probably have the addrinfo struct, but
   to work even on those that don't, we provide our own look-alike! */
struct Curl_addrinfo {
  int                   ai_flags;
  int                   ai_family;
  int                   ai_socktype;
  int                   ai_protocol;
  socklen_t             ai_addrlen;   /* Follow rfc3493 struct addrinfo */
  char                 *ai_canonname;
  struct sockaddr      *ai_addr;
  struct Curl_addrinfo *ai_next;
};
typedef struct Curl_addrinfo Curl_addrinfo;
#endif

struct addrinfo;
struct hostent;
struct SessionHandle;
struct connectdata;

void Curl_global_host_cache_init(void);
void Curl_global_host_cache_dtor(void);
struct curl_hash *Curl_global_host_cache_get(void);

#define Curl_global_host_cache_use(__p) ((__p)->set.global_dns_cache)

struct Curl_dns_entry {
  Curl_addrinfo *addr;
  time_t timestamp;
  long inuse;      /* use-counter, make very sure you decrease this
                      when you're done using the address you received */
};

/*
 * Curl_resolv() returns an entry with the info for the specified host
 * and port.
 *
 * The returned data *MUST* be "unlocked" with Curl_resolv_unlock() after
 * use, or we'll leak memory!
 */
/* return codes */
#define CURLRESOLV_ERROR    -1
#define CURLRESOLV_RESOLVED  0
#define CURLRESOLV_PENDING   1
int Curl_resolv(struct connectdata *conn, const char *hostname,
                int port, struct Curl_dns_entry **dnsentry);

/*
 * Curl_ipvalid() checks what CURL_IPRESOLVE_* requirements that might've
 * been set and returns TRUE if they are OK.
 */
bool Curl_ipvalid(struct SessionHandle *data);

/*
 * Curl_getaddrinfo() is the generic low-level name resolve API within this
 * source file. There are several versions of this function - for different
 * name resolve layers (selected at build-time). They all take this same set
 * of arguments
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                const char *hostname,
                                int port,
                                int *waitp);

CURLcode Curl_is_resolved(struct connectdata *conn,
                          struct Curl_dns_entry **dns);
CURLcode Curl_wait_for_resolv(struct connectdata *conn,
                              struct Curl_dns_entry **dnsentry);

/* Curl_resolv_getsock() is a generic function that exists in multiple
   versions depending on what name resolve technology we've built to use. The
   function is called from the multi_getsock() function.  'sock' is a pointer
   to an array to hold the file descriptors, with 'numsock' being the size of
   that array (in number of entries). This function is supposed to return
   bitmask indicating what file descriptors (referring to array indexes in the
   'sock' array) to wait for, read/write. */
int Curl_resolv_getsock(struct connectdata *conn, curl_socket_t *sock,
                        int numsocks);

/* unlock a previously resolved dns entry */
void Curl_resolv_unlock(struct SessionHandle *data,
                        struct Curl_dns_entry *dns);

/* for debugging purposes only: */
void Curl_scan_cache_used(void *user, void *ptr);

/* free name info */
void Curl_freeaddrinfo(Curl_addrinfo *freeaddr);

/* make a new dns cache and return the handle */
struct curl_hash *Curl_mk_dnscache(void);

/* prune old entries from the DNS cache */
void Curl_hostcache_prune(struct SessionHandle *data);

/* Return # of adresses in a Curl_addrinfo struct */
int Curl_num_addresses (const Curl_addrinfo *addr);

#ifdef CURLDEBUG
void curl_dofreeaddrinfo(struct addrinfo *freethis,
                         int line, const char *source);
int curl_dogetaddrinfo(const char *hostname, const char *service,
                       struct addrinfo *hints,
                       struct addrinfo **result,
                       int line, const char *source);
#ifdef HAVE_GETNAMEINFO
int curl_dogetnameinfo(GETNAMEINFO_QUAL_ARG1 GETNAMEINFO_TYPE_ARG1 sa,
                       GETNAMEINFO_TYPE_ARG2 salen,
                       char *host, GETNAMEINFO_TYPE_ARG46 hostlen,
                       char *serv, GETNAMEINFO_TYPE_ARG46 servlen,
                       GETNAMEINFO_TYPE_ARG7 flags,
                       int line, const char *source);
#endif
#endif

/* This is the callback function that is used when we build with asynch
   resolve, ipv4 */
CURLcode Curl_addrinfo4_callback(void *arg,
                                 int status,
                                 struct hostent *hostent);
/* This is the callback function that is used when we build with asynch
   resolve, ipv6 */
CURLcode Curl_addrinfo6_callback(void *arg,
                                 int status,
                                 struct addrinfo *ai);


/* [ipv4/ares only] Creates a Curl_addrinfo struct from a numerical-only IP
   address */
Curl_addrinfo *Curl_ip2addr(in_addr_t num, const char *hostname, int port);

/* [ipv4/ares only] Curl_he2ai() converts a struct hostent to a Curl_addrinfo chain
   and returns it */
Curl_addrinfo *Curl_he2ai(const struct hostent *, int port);

/* Clone a Curl_addrinfo struct, works protocol independently */
Curl_addrinfo *Curl_addrinfo_copy(const void *orig, int port);

/*
 * Curl_printable_address() returns a printable version of the 1st address
 * given in the 'ip' argument. The result will be stored in the buf that is
 * bufsize bytes big.
 */
const char *Curl_printable_address(const Curl_addrinfo *ip,
                                   char *buf, size_t bufsize);

/*
 * Curl_cache_addr() stores a 'Curl_addrinfo' struct in the DNS cache.
 *
 * Returns the Curl_dns_entry entry pointer or NULL if the storage failed.
 */
struct Curl_dns_entry *
Curl_cache_addr(struct SessionHandle *data, Curl_addrinfo *addr,
                const char *hostname, int port);

/*
 * Curl_destroy_thread_data() cleans up async resolver data.
 * Complementary of ares_destroy.
 */
struct Curl_async; /* forward-declaration */
void Curl_destroy_thread_data(struct Curl_async *async);

#ifndef INADDR_NONE
#define CURL_INADDR_NONE (in_addr_t) ~0
#else
#define CURL_INADDR_NONE INADDR_NONE
#endif




#endif
