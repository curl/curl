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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if ! defined(WIN32) && ! defined(__BEOS__) && !defined(__CYGWIN32__)

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
#include <sys/ioctl.h>

/* -- if2ip() -- */
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#if defined(HAVE_INET_NTOA_R) && !defined(HAVE_INET_NTOA_R_DECL) 
#include "inet_ntoa_r.h"
#endif

#ifdef	VMS
#define	IOCTL_3_ARGS
#include <inet.h>
#endif

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#define SYS_ERROR -1

char *Curl_if2ip(char *interface, char *buf, int buf_size)
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
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, interface);
    req.ifr_addr.sa_family = AF_INET;
#ifdef	IOCTL_3_ARGS
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
      memcpy(&in, &(s->sin_addr.s_addr), sizeof(in));
#if defined(HAVE_INET_NTOA_R)
      ip = inet_ntoa_r(in,buf,buf_size);
#else
      ip = strncpy(buf,inet_ntoa(in),buf_size);
      ip[buf_size - 1] = 0;
#endif
    }
    sclose(dummy);
  }
  return ip;
}

/* -- end of if2ip() -- */
#else
#define if2ip(x) NULL
#endif

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
