#ifndef __HOSTIP_H
#define __HOSTIP_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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

struct addrinfo;
struct hostent;
struct SessionHandle;
struct connectdata;

void Curl_global_host_cache_init(void);
void Curl_global_host_cache_dtor(void);
curl_hash *Curl_global_host_cache_get(void);

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

int Curl_resolv(struct connectdata *conn,
                char *hostname,
                int port,
                struct Curl_dns_entry **dnsentry);

CURLcode Curl_is_resolved(struct connectdata *conn,
                          struct Curl_dns_entry **dns);
CURLcode Curl_wait_for_resolv(struct connectdata *conn,
                              struct Curl_dns_entry **dnsentry);
CURLcode Curl_multi_ares_fdset(struct connectdata *conn,
                               fd_set *read_fd_set,
                               fd_set *write_fd_set,
                               int *max_fdp);
/* unlock a previously resolved dns entry */
void Curl_resolv_unlock(struct SessionHandle *data, struct Curl_dns_entry *dns);

/* for debugging purposes only: */
void Curl_scan_cache_used(void *user, void *ptr);

/* free name info */
void Curl_freeaddrinfo(Curl_addrinfo *freeaddr);

/* make a new dns cache and return the handle */
curl_hash *Curl_mk_dnscache(void);

/* prune old entries from the DNS cache */
void Curl_hostcache_prune(struct SessionHandle *data);

#ifdef CURLDEBUG
void curl_freeaddrinfo(struct addrinfo *freethis,
                       int line, const char *source);
int curl_getaddrinfo(char *hostname, char *service,
                     struct addrinfo *hints,
                     struct addrinfo **result,
                     int line, const char *source);
#endif

#ifndef INADDR_NONE
#define CURL_INADDR_NONE (in_addr_t) ~0
#else
#define CURL_INADDR_NONE INADDR_NONE
#endif


#endif
