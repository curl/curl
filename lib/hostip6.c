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

/***********************************************************************
 * Only for IPv6-enabled builds
 **********************************************************************/
#ifdef FETCHRES_IPV6

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
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "url.h"
#include "inet_pton.h"
#include "connect.h"
/* The last 3 #include files should be in this order */
#include "fetch_printf.h"
#include "fetch_memory.h"
#include "memdebug.h"

/*
 * Fetch_ipvalid() checks what FETCH_IPRESOLVE_* requirements that might've
 * been set and returns TRUE if they are OK.
 */
bool Fetch_ipvalid(struct Fetch_easy *data, struct connectdata *conn)
{
  if (conn->ip_version == FETCH_IPRESOLVE_V6)
    return Fetch_ipv6works(data);

  return TRUE;
}

#if defined(FETCHRES_SYNCH)

#ifdef DEBUG_ADDRINFO
static void dump_addrinfo(const struct Fetch_addrinfo *ai)
{
  printf("dump_addrinfo:\n");
  for (; ai; ai = ai->ai_next)
  {
    char buf[INET6_ADDRSTRLEN];
    printf("    fam %2d, CNAME %s, ",
           ai->ai_family, ai->ai_canonname ? ai->ai_canonname : "<none>");
    Fetch_printable_address(ai, buf, sizeof(buf));
    printf("%s\n", buf);
  }
}
#else
#define dump_addrinfo(x) Fetch_nop_stmt
#endif

/*
 * Fetch_getaddrinfo() when built IPv6-enabled (non-threading and
 * non-ares version).
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'addrinfo' is returned and the fourth argument will point
 * to memory we need to free after use. That memory *MUST* be freed with
 * Fetch_freeaddrinfo(), nothing else.
 */
struct Fetch_addrinfo *Fetch_getaddrinfo(struct Fetch_easy *data,
                                       const char *hostname,
                                       int port,
                                       int *waitp)
{
  struct addrinfo hints;
  struct Fetch_addrinfo *res;
  int error;
  char sbuf[12];
  char *sbufptr = NULL;
#ifndef USE_RESOLVE_ON_IPS
  char addrbuf[128];
#endif
  int pf = PF_INET;

  *waitp = 0; /* synchronous response only */

  if ((data->conn->ip_version != FETCH_IPRESOLVE_V4) && Fetch_ipv6works(data))
    /* The stack seems to be IPv6-enabled */
    pf = PF_UNSPEC;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  hints.ai_socktype = (data->conn->transport == TRNSPRT_TCP) ? SOCK_STREAM : SOCK_DGRAM;

#ifndef USE_RESOLVE_ON_IPS
  /*
   * The AI_NUMERICHOST must not be set to get synthesized IPv6 address from
   * an IPv4 address on iOS and macOS.
   */
  if ((1 == Fetch_inet_pton(AF_INET, hostname, addrbuf)) ||
      (1 == Fetch_inet_pton(AF_INET6, hostname, addrbuf)))
  {
    /* the given address is numerical only, prevent a reverse lookup */
    hints.ai_flags = AI_NUMERICHOST;
  }
#endif

  if (port)
  {
    msnprintf(sbuf, sizeof(sbuf), "%d", port);
    sbufptr = sbuf;
  }

  error = Fetch_getaddrinfo_ex(hostname, sbufptr, &hints, &res);
  if (error)
  {
    infof(data, "getaddrinfo(3) failed for %s:%d", hostname, port);
    return NULL;
  }

  if (port)
  {
    Fetch_addrinfo_set_port(res, port);
  }

  dump_addrinfo(res);

  return res;
}
#endif /* FETCHRES_SYNCH */

#endif /* FETCHRES_IPV6 */
