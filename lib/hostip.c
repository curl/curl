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

/* --- resolve name or IP-number --- */

char *MakeIP(unsigned long num)
{
#ifdef HAVE_INET_NTOA
  struct in_addr in;

  in.s_addr = htonl(num);
  return (inet_ntoa(in));
#else
  static char addr[128];
  unsigned char *paddr;

  num = htonl(num);  /* htonl() added to avoid endian probs */
  paddr = (unsigned char *)&num;
  sprintf(addr, "%u.%u.%u.%u", paddr[0], paddr[1], paddr[2], paddr[3]);
  return (addr);
#endif
}

/* Stolen from Dancer source code, written by
   Bjorn Reese <breese@imada.ou.dk> */
#ifndef INADDR_NONE
#define INADDR_NONE (unsigned long) ~0
#endif
struct hostent *GetHost(struct UrlData *data, char *hostname)
{
  struct hostent *h = NULL;
  unsigned long in;
  static struct hostent he;
  static char name[MAXHOSTNAMELEN];
  static char *addrlist[2];
  static struct in_addr addrentry;

  if ( (in=inet_addr(hostname)) != INADDR_NONE ) {
    addrentry.s_addr = in;
    addrlist[0] = (char *)&addrentry;
    addrlist[1] = NULL;
    he.h_name = strncpy(name, MakeIP(ntohl(in)), MAXHOSTNAMELEN);
    he.h_addrtype = AF_INET;
    he.h_length = sizeof(struct in_addr);
    he.h_addr_list = addrlist;
    h = &he;
  } else if ( (h=gethostbyname(hostname)) == NULL ) {
    infof(data, "gethostbyname(2) failed for %s\n", hostname);
  }
  return (h);
}
