/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <string.h>
#include <malloc.h>

#include "setup.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#include <winsock.h>
#else
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <netdb.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#endif

#include "urldata.h"
#include "sendf.h"

#ifdef HAVE_INET_NTOA_R
#include "inet_ntoa_r.h"
#endif

/* --- resolve name or IP-number --- */

char *MakeIP(unsigned long num,char *addr, int addr_len)
{
#if defined(HAVE_INET_NTOA) || defined(HAVE_INET_NTOA_R)
  struct in_addr in;
  in.s_addr = htonl(num);

#if defined(HAVE_INET_NTOA_R)
  inet_ntoa_r(in,addr,addr_len);
#else
  strncpy(addr,inet_ntoa(in),addr_len);
#endif
#else
  unsigned char *paddr;

  num = htonl(num);  /* htonl() added to avoid endian probs */
  paddr = (unsigned char *)&num;
  sprintf(addr, "%u.%u.%u.%u", paddr[0], paddr[1], paddr[2], paddr[3]);
#endif
  return (addr);
}

/* The original code to this function was stolen from the Dancer source code,
   written by Bjorn Reese, it has since been patched and modified. */
#ifndef INADDR_NONE
#define INADDR_NONE (unsigned long) ~0
#endif
struct hostent *GetHost(struct UrlData *data,
                        char *hostname,
                        char *buf,
                        int buf_size )
{
  struct hostent *h = NULL;
  unsigned long in;

  if ( (in=inet_addr(hostname)) != INADDR_NONE ) {
    struct in_addr *addrentry;

    h = (struct hostent*)buf;
    h->h_addr_list = (char**)(buf + sizeof(*h));
    addrentry = (struct in_addr*)(h->h_addr_list + 2);
    addrentry->s_addr = in;
    h->h_addr_list[0] = (char*)addrentry;
    h->h_addr_list[1] = NULL;
    h->h_addrtype = AF_INET;
    h->h_length = sizeof(*addrentry);
    h->h_name = (char*)(h->h_addr_list + h->h_length);
    MakeIP(ntohl(in),h->h_name,buf_size - (long)(h->h_name) + (long)buf);
#if defined(HAVE_GETHOSTBYNAME_R)
  }
  else {
    int h_errnop;
    memset(buf,0,buf_size);	/* workaround for gethostbyname_r bug in qnx nto */
    if ((h = gethostbyname_r(hostname,
                             (struct hostent *)buf,buf +
                             sizeof(struct hostent),buf_size -
                             sizeof(struct hostent),&h_errnop)) == NULL ) {
      infof(data, "gethostbyname_r(2) failed for %s\n", hostname);
    }
#else
  }
  else {
    if ((h = gethostbyname(hostname)) == NULL ) {
      infof(data, "gethostbyname(2) failed for %s\n", hostname);
    }
#endif
  }
  return (h);
}
