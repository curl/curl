/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#ifdef HAVE_NET_IF_H
#  include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_SYS_SOCKIO_H
#  include <sys/sockio.h>
#endif
#ifdef HAVE_IFADDRS_H
#  include <ifaddrs.h>
#endif
#ifdef HAVE_STROPTS_H
#  include <stropts.h>
#endif
#ifdef __VMS
#  include <inet.h>
#endif

#include "inet_ntop.h"
#include "strequal.h"
#include "if2ip.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* ------------------------------------------------------------------ */

#if defined(HAVE_GETIFADDRS)

char *Curl_if2ip(int af, const char *interface, char *buf, int buf_size)
{
  struct ifaddrs *iface, *head;
  char *ip=NULL;

  if(getifaddrs(&head) >= 0) {
    for(iface=head; iface != NULL; iface=iface->ifa_next) {
      if((iface->ifa_addr != NULL) &&
         (iface->ifa_addr->sa_family == af) &&
         curl_strequal(iface->ifa_name, interface)) {
        void *addr;
        char scope[12]="";
#ifdef ENABLE_IPV6
        if(af == AF_INET6) {
          unsigned int scopeid = 0;
          addr = &((struct sockaddr_in6 *)iface->ifa_addr)->sin6_addr;
#ifdef HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID
          /* Include the scope of this interface as part of the address */
          scopeid = ((struct sockaddr_in6 *)iface->ifa_addr)->sin6_scope_id;
#endif
          if(scopeid)
            snprintf(scope, sizeof(scope), "%%%u", scopeid);
        }
        else
#endif
          addr = &((struct sockaddr_in *)iface->ifa_addr)->sin_addr;
        ip = (char *) Curl_inet_ntop(af, addr, buf, buf_size);
        strlcat(buf, scope, buf_size);
        break;
      }
    }
    freeifaddrs(head);
  }
  return ip;
}

#elif defined(HAVE_IOCTL_SIOCGIFADDR)

char *Curl_if2ip(int af, const char *interface, char *buf, int buf_size)
{
  struct ifreq req;
  struct in_addr in;
  struct sockaddr_in *s;
  curl_socket_t dummy;
  size_t len;
  char *ip;

  if(!interface || (af != AF_INET))
    return NULL;

  len = strlen(interface);
  if(len >= sizeof(req.ifr_name))
    return NULL;

  dummy = socket(AF_INET, SOCK_STREAM, 0);
  if(CURL_SOCKET_BAD == dummy)
    return NULL;

  memset(&req, 0, sizeof(req));
  memcpy(req.ifr_name, interface, len+1);
  req.ifr_addr.sa_family = AF_INET;

  if(ioctl(dummy, SIOCGIFADDR, &req) < 0) {
    sclose(dummy);
    return NULL;
  }

  s = (struct sockaddr_in *)&req.ifr_addr;
  memcpy(&in, &s->sin_addr, sizeof(in));
  ip = (char *) Curl_inet_ntop(s->sin_family, &in, buf, buf_size);

  sclose(dummy);
  return ip;
}

#else

char *Curl_if2ip(int af, const char *interf, char *buf, int buf_size)
{
    (void) af;
    (void) interf;
    (void) buf;
    (void) buf_size;
    return NULL;
}

#endif
