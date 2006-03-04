#ifndef __IF2IP_H
#define __IF2IP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
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

extern char *Curl_if2ip(const char *interf, char *buf, int buf_size);

#ifdef __INTERIX
#include <sys/socket.h>

/* Nedelcho Stanev's work-around for SFU 3.0 */
struct ifreq {
#define IFNAMSIZ 16
#define IFHWADDRLEN 6
  union {
    char ifrn_name[IFNAMSIZ]; /* if name, e.g. "en0" */
  } ifr_ifrn;

 union {
   struct sockaddr ifru_addr;
   struct sockaddr ifru_broadaddr;
   struct sockaddr ifru_netmask;
   struct sockaddr ifru_hwaddr;
   short ifru_flags;
   int ifru_metric;
   int ifru_mtu;
 } ifr_ifru;
};

/* This define was added by Daniel to avoid an extra #ifdef INTERIX in the
   C code. */
#define ifr_dstaddr ifr_addr

#define ifr_name ifr_ifrn.ifrn_name /* interface name */
#define ifr_addr ifr_ifru.ifru_addr /* address */
#define ifr_broadaddr ifr_ifru.ifru_broadaddr /* broadcast address */
#define ifr_netmask ifr_ifru.ifru_netmask /* interface net mask */
#define ifr_flags ifr_ifru.ifru_flags /* flags */
#define ifr_hwaddr ifr_ifru.ifru_hwaddr /* MAC address */
#define ifr_metric ifr_ifru.ifru_metric /* metric */
#define ifr_mtu ifr_ifru.ifru_mtu /* mtu */

#define SIOCGIFADDR _IOW('s', 102, struct ifreq) /* Get if addr */
#endif /* interix */

#endif
