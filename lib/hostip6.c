/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

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

#ifdef HAVE_PROCESS_H
#include <process.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "hostip.h"
#include "hash.h"
#include "share.h"
#include "strerror.h"
#include "url.h"
#include "inet_pton.h"
#include "connect.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/***********************************************************************
 * Only for IPv6-enabled builds
 **********************************************************************/
#ifdef CURLRES_IPV6

#if defined(CURLDEBUG) && defined(HAVE_GETNAMEINFO)
/* These are strictly for memory tracing and are using the same style as the
 * family otherwise present in memdebug.c. I put these ones here since they
 * require a bunch of structs I didn't want to include in memdebug.c
 */

/*
 * For CURLRES_ARS, this should be written using ares_gethostbyaddr()
 * (ignoring the fact c-ares doesn't return 'serv').
 */

int curl_dogetnameinfo(GETNAMEINFO_QUAL_ARG1 GETNAMEINFO_TYPE_ARG1 sa,
                       GETNAMEINFO_TYPE_ARG2 salen,
                       char *host, GETNAMEINFO_TYPE_ARG46 hostlen,
                       char *serv, GETNAMEINFO_TYPE_ARG46 servlen,
                       GETNAMEINFO_TYPE_ARG7 flags,
                       int line, const char *source)
{
  int res = (getnameinfo)(sa, salen,
                          host, hostlen,
                          serv, servlen,
                          flags);
  if(0 == res)
    /* success */
    curl_memlog("GETNAME %s:%d getnameinfo()\n",
                source, line);
  else
    curl_memlog("GETNAME %s:%d getnameinfo() failed = %d\n",
                source, line, res);
  return res;
}
#endif /* defined(CURLDEBUG) && defined(HAVE_GETNAMEINFO) */

/*
 * Curl_ipv6works() returns TRUE if IPv6 seems to work.
 */
bool Curl_ipv6works(void)
{
  /* the nature of most system is that IPv6 status doesn't come and go
     during a program's lifetime so we only probe the first time and then we
     have the info kept for fast re-use */
  static int ipv6_works = -1;
  if(-1 == ipv6_works) {
    /* probe to see if we have a working IPv6 stack */
    curl_socket_t s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s == CURL_SOCKET_BAD)
      /* an IPv6 address was requested but we can't get/use one */
      ipv6_works = 0;
    else {
      ipv6_works = 1;
      Curl_closesocket(NULL, s);
    }
  }
  return (ipv6_works>0)?TRUE:FALSE;
}

/*
 * Curl_ipvalid() checks what CURL_IPRESOLVE_* requirements that might've
 * been set and returns TRUE if they are OK.
 */
bool Curl_ipvalid(struct connectdata *conn)
{
  if(conn->ip_version == CURL_IPRESOLVE_V6)
    return Curl_ipv6works();

  return TRUE;
}

#if defined(CURLRES_SYNCH)

#ifdef DEBUG_ADDRINFO
static void dump_addrinfo(struct connectdata *conn, const Curl_addrinfo *ai)
{
  printf("dump_addrinfo:\n");
  for(; ai; ai = ai->ai_next) {
    char  buf[INET6_ADDRSTRLEN];

    printf("    fam %2d, CNAME %s, ",
           ai->ai_family, ai->ai_canonname ? ai->ai_canonname : "<none>");
    if(Curl_printable_address(ai, buf, sizeof(buf)))
      printf("%s\n", buf);
    else
      printf("failed; %s\n", Curl_strerror(conn, SOCKERRNO));
  }
}
#else
#define dump_addrinfo(x,y) Curl_nop_stmt
#endif

/*
 * Curl_getaddrinfo() when built IPv6-enabled (non-threading and
 * non-ares version).
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'addrinfo' is returned and the forth argument will point to
 * memory we need to free after use. That memory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 */
Curl_addrinfo *Curl_getaddrinfo(struct connectdata *conn,
                                const char *hostname,
                                int port,
                                int *waitp)
{
  struct addrinfo hints;
  Curl_addrinfo *res;
  int error;
  char sbuf[12];
  char *sbufptr = NULL;
#ifndef USE_RESOLVE_ON_IPS
  char addrbuf[128];
#endif
  int pf;
#if !defined(CURL_DISABLE_VERBOSE_STRINGS)
  struct Curl_easy *data = conn->data;
#endif

  *waitp = 0; /* synchronous response only */

  /* Check if a limited name resolve has been requested */
  switch(conn->ip_version) {
  case CURL_IPRESOLVE_V4:
    pf = PF_INET;
    break;
  case CURL_IPRESOLVE_V6:
    pf = PF_INET6;
    break;
  default:
    pf = PF_UNSPEC;
    break;
  }

  if((pf != PF_INET) && !Curl_ipv6works())
    /* The stack seems to be a non-IPv6 one */
    pf = PF_INET;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  hints.ai_socktype = conn->socktype;

#ifndef USE_RESOLVE_ON_IPS
  /*
   * The AI_NUMERICHOST must not be set to get synthesized IPv6 address from
   * an IPv4 address on iOS and Mac OS X.
   */
  if((1 == Curl_inet_pton(AF_INET, hostname, addrbuf)) ||
     (1 == Curl_inet_pton(AF_INET6, hostname, addrbuf))) {
    /* the given address is numerical only, prevent a reverse lookup */
    hints.ai_flags = AI_NUMERICHOST;
  }
#endif

  if(port) {
    snprintf(sbuf, sizeof(sbuf), "%d", port);
    sbufptr = sbuf;
  }

  error = Curl_getaddrinfo_ex(hostname, sbufptr, &hints, &res);
  if(error) {
    infof(data, "getaddrinfo(3) failed for %s:%d\n", hostname, port);
    return NULL;
  }

  if(port) {
    Curl_addrinfo_set_port(res, port);
  }

  dump_addrinfo(conn, res);

  return res;
}
#endif /* CURLRES_SYNCH */

#endif /* CURLRES_IPV6 */
