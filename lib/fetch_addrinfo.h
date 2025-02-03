#ifndef HEADER_FETCH_ADDRINFO_H
#define HEADER_FETCH_ADDRINFO_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef __VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
#endif

/*
 * Fetch_addrinfo is our internal struct definition that we use to allow
 * consistent internal handling of this data. We use this even when the system
 * provides an addrinfo structure definition. We use this for all sorts of
 * IPv4 and IPV6 builds.
 */

struct Fetch_addrinfo
{
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  fetch_socklen_t ai_addrlen; /* Follow rfc3493 struct addrinfo */
  char *ai_canonname;
  struct sockaddr *ai_addr;
  struct Fetch_addrinfo *ai_next;
};

void Fetch_freeaddrinfo(struct Fetch_addrinfo *cahead);

#ifdef HAVE_GETADDRINFO
int Fetch_getaddrinfo_ex(const char *nodename,
                        const char *servname,
                        const struct addrinfo *hints,
                        struct Fetch_addrinfo **result);
#endif

#if !(defined(HAVE_GETADDRINFO) && defined(HAVE_GETADDRINFO_THREADSAFE))
struct Fetch_addrinfo *
Fetch_he2ai(const struct hostent *he, int port);
#endif

struct Fetch_addrinfo *
Fetch_ip2addr(int af, const void *inaddr, const char *hostname, int port);

struct Fetch_addrinfo *Fetch_str2addr(char *dotted, int port);

#ifdef USE_UNIX_SOCKETS
struct Fetch_addrinfo *Fetch_unix2addr(const char *path, bool *longpath,
                                     bool abstract);
#endif

#if defined(FETCHDEBUG) && defined(HAVE_GETADDRINFO) && \
    defined(HAVE_FREEADDRINFO)
void fetch_dbg_freeaddrinfo(struct addrinfo *freethis, int line, const char *source);
#endif

#if defined(FETCHDEBUG) && defined(HAVE_GETADDRINFO)
int fetch_dbg_getaddrinfo(const char *hostname, const char *service,
                          const struct addrinfo *hints, struct addrinfo **result,
                          int line, const char *source);
#endif

#ifdef HAVE_GETADDRINFO
#ifdef USE_RESOLVE_ON_IPS
void Fetch_addrinfo_set_port(struct Fetch_addrinfo *addrinfo, int port);
#else
#define Fetch_addrinfo_set_port(x, y)
#endif
#endif

#endif /* HEADER_FETCH_ADDRINFO_H */
