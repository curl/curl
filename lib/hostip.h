#ifndef __HOSTIP_H
#define __HOSTIP_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

void Curl_global_host_cache_init(void);
void Curl_global_host_cache_dtor(void);
curl_hash *Curl_global_host_cache_get(void);

#define Curl_global_host_cache_use(__p) ((__p)->set.global_dns_cache)

struct Curl_dns_entry {
  Curl_addrinfo *addr;
  time_t timestamp;
  long inuse;      /* use-counter, make very sure you decrease this
                      when you're done using the address you received */
#ifdef MALLOCDEBUG
  char *entry_id;
#endif
};

/*
 * Curl_resolv() returns an entry with the info for the specified host
 * and port.
 *
 * The returned data *MUST* be "unlocked" with Curl_resolv_unlock() after
 * use, or we'll leak memory!
 */

struct Curl_dns_entry *Curl_resolv(struct SessionHandle *data,
                                   char *hostname,
                                   int port);

/* unlock a previously resolved dns entry */
#define Curl_resolv_unlock(dns) dns->inuse--

/* for debugging purposes only: */
void Curl_scan_cache_used(void *user, void *ptr);

/* free name info */
void Curl_freeaddrinfo(void *freethis);

#ifdef MALLOCDEBUG
void curl_freeaddrinfo(struct addrinfo *freethis,
                       int line, const char *source);
int curl_getaddrinfo(char *hostname, char *service,
                     struct addrinfo *hints,
                     struct addrinfo **result,
                     int line, const char *source);
#endif

#endif
