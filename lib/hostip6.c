/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "setup.h"

#include <string.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>     /* required for free() prototypes */
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>     /* for the close() proto */
#endif
#ifdef __VMS
#include <in.h>
#include <inet.h>
#include <stdlib.h>
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

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/***********************************************************************
 * Only for ipv6-enabled builds
 **********************************************************************/
#ifdef CURLRES_IPV6


#if defined(CURLDEBUG) && defined(HAVE_GETNAMEINFO)
/* These are strictly for memory tracing and are using the same style as the
 * family otherwise present in memdebug.c. I put these ones here since they
 * require a bunch of structs I didn't wanna include in memdebug.c
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
 * Curl_ipvalid() checks what CURL_IPRESOLVE_* requirements that might've
 * been set and returns TRUE if they are OK.
 */
bool Curl_ipvalid(struct SessionHandle *data)
{
  if(data->set.ip_version == CURL_IPRESOLVE_V6) {
    /* see if we have an IPv6 stack */
    curl_socket_t s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s == CURL_SOCKET_BAD)
      /* an ipv6 address was requested and we can't get/use one */
      return FALSE;
    sclose(s);
  }
  return TRUE;
}

#if defined(CURLRES_SYNCH)

#ifdef DEBUG_ADDRINFO
static void dump_addrinfo(struct connectdata *conn, const Curl_addrinfo *ai)
{
  printf("dump_addrinfo:\n");
  for ( ; ai; ai = ai->ai_next) {
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
#define dump_addrinfo(x,y)
#endif

/*
 * Curl_getaddrinfo() when built ipv6-enabled (non-threading and
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
  char sbuf[NI_MAXSERV];
  char *sbufptr = NULL;
  char addrbuf[128];
  int pf;
  struct SessionHandle *data = conn->data;

  *waitp = 0; /* synchronous response only */

  /*
   * Check if a limited name resolve has been requested.
   */
  switch(data->set.ip_version) {
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

  if (pf != PF_INET) {
    /* see if we have an IPv6 stack */
    curl_socket_t s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s == CURL_SOCKET_BAD) {
      /* Some non-IPv6 stacks have been found to make very slow name resolves
       * when PF_UNSPEC is used, so thus we switch to a mere PF_INET lookup if
       * the stack seems to be a non-ipv6 one. */

      pf = PF_INET;
    }
    else {
      /* This seems to be an IPv6-capable stack, use PF_UNSPEC for the widest
       * possible checks. And close the socket again.
       */
      sclose(s);
    }
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = pf;
  hints.ai_socktype = conn->socktype;

  if((1 == Curl_inet_pton(AF_INET, hostname, addrbuf)) ||
     (1 == Curl_inet_pton(AF_INET6, hostname, addrbuf))) {
    /* the given address is numerical only, prevent a reverse lookup */
    hints.ai_flags = AI_NUMERICHOST;
  }
#ifdef HAVE_GSSAPI
  if(conn->data->set.krb)
    /* if krb is used, we (might) need the canonical host name */
    hints.ai_flags |= AI_CANONNAME;
#endif

  if(port) {
    snprintf(sbuf, sizeof(sbuf), "%d", port);
    sbufptr=sbuf;
  }
  error = Curl_getaddrinfo_ex(hostname, sbufptr, &hints, &res);
  if(error) {
    infof(data, "getaddrinfo(3) failed for %s:%d\n", hostname, port);
    return NULL;
  }

  dump_addrinfo(conn, res);

  return res;
}
#endif /* CURLRES_SYNCH */
#endif /* CURLRES_IPV6 */

