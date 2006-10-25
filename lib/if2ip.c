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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "if2ip.h"

/*
 * This test can probably be simplified to #if defined(SIOCGIFADDR) and
 * moved after the following includes.
 */
#if !defined(WIN32) && !defined(__BEOS__) && !defined(__CYGWIN__) && \
    !defined(__riscos__) && !defined(__INTERIX) && !defined(NETWARE) && \
    !defined(_AMIGASF) && !defined(__minix)

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_TIME_H
/* This must be before net/if.h for AIX 3.2 to enjoy life */
#include <sys/time.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef VMS
#include <inet.h>
#endif

#include "inet_ntop.h"
#include "memory.h"

/* The last #include file should be: */
#include "memdebug.h"

#define SYS_ERROR -1

char *Curl_if2ip(const char *interface, char *buf, int buf_size)
{
  int dummy;
  char *ip=NULL;

  if(!interface)
    return NULL;

  dummy = socket(AF_INET, SOCK_STREAM, 0);
  if (SYS_ERROR == dummy) {
    return NULL;
  }
  else {
    struct ifreq req;
    size_t len = strlen(interface);
    memset(&req, 0, sizeof(req));
    if(len >= sizeof(req.ifr_name))
      return NULL; /* this can't be a fine interface name */
    memcpy(req.ifr_name, interface, len+1);
    req.ifr_addr.sa_family = AF_INET;
#ifdef IOCTL_3_ARGS
    if (SYS_ERROR == ioctl(dummy, SIOCGIFADDR, &req)) {
#else
    if (SYS_ERROR == ioctl(dummy, SIOCGIFADDR, &req, sizeof(req))) {
#endif
      sclose(dummy);
      return NULL;
    }
    else {
      struct in_addr in;

      struct sockaddr_in *s = (struct sockaddr_in *)&req.ifr_dstaddr;
      memcpy(&in, &s->sin_addr, sizeof(in));
      ip = (char *) Curl_inet_ntop(s->sin_family, &in, buf, buf_size);
    }
    sclose(dummy);
  }
  return ip;
}

/* -- end of if2ip() -- */
#else
char *Curl_if2ip(const char *interf, char *buf, int buf_size)
{
    (void) interf;
    (void) buf;
    (void) buf_size;
    return NULL;
}
#endif
