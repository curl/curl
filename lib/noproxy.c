/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifndef CURL_DISABLE_PROXY

#include "inet_pton.h"
#include "strcase.h"
#include "noproxy.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/*
 * Curl_cidr4_match() returns TRUE if the given IPv4 address is within the
 * specified CIDR address range.
 */
UNITTEST bool Curl_cidr4_match(const char *ipv4,    /* 1.2.3.4 address */
                               const char *network, /* 1.2.3.4 address */
                               unsigned int bits)
{
  unsigned int address = 0;
  unsigned int check = 0;

  if(bits > 32)
    /* strange input */
    return FALSE;

  if(1 != Curl_inet_pton(AF_INET, ipv4, &address))
    return FALSE;
  if(1 != Curl_inet_pton(AF_INET, network, &check))
    return FALSE;

  if(bits && (bits != 32)) {
    unsigned int mask = 0xffffffff << (32 - bits);
    unsigned int haddr = htonl(address);
    unsigned int hcheck = htonl(check);
#if 0
    fprintf(stderr, "Host %s (%x) network %s (%x) bits %u mask %x => %x\n",
            ipv4, haddr, network, hcheck, bits, mask,
            (haddr ^ hcheck) & mask);
#endif
    if((haddr ^ hcheck) & mask)
      return FALSE;
    return TRUE;
  }
  return (address == check);
}

UNITTEST bool Curl_cidr6_match(const char *ipv6,
                               const char *network,
                               unsigned int bits)
{
#ifdef ENABLE_IPV6
  int bytes;
  int rest;
  unsigned char address[16];
  unsigned char check[16];

  if(!bits)
    bits = 128;

  bytes = bits/8;
  rest = bits & 0x07;
  if(1 != Curl_inet_pton(AF_INET6, ipv6, address))
    return FALSE;
  if(1 != Curl_inet_pton(AF_INET6, network, check))
    return FALSE;
  if((bytes > 16) || ((bytes == 16) && rest))
    return FALSE;
  if(bytes && memcmp(address, check, bytes))
    return FALSE;
  if(rest && !((address[bytes] ^ check[bytes]) & (0xff << (8 - rest))))
    return FALSE;

  return TRUE;
#else
  (void)ipv6;
  (void)network;
  (void)bits;
  return FALSE;
#endif
}

enum nametype {
  TYPE_HOST,
  TYPE_IPV4,
  TYPE_IPV6
};

/****************************************************************
* Checks if the host is in the noproxy list. returns TRUE if it matches and
* therefore the proxy should NOT be used.
****************************************************************/
bool Curl_check_noproxy(const char *name, const char *no_proxy)
{
  /* no_proxy=domain1.dom,host.domain2.dom
   *   (a comma-separated list of hosts which should
   *   not be proxied, or an asterisk to override
   *   all proxy variables)
   */
  if(no_proxy && no_proxy[0]) {
    const char *p = no_proxy;
    size_t namelen;
    enum nametype type = TYPE_HOST;
    char hostip[128];
    if(!strcmp("*", no_proxy))
      return TRUE;

    /* NO_PROXY was specified and it wasn't just an asterisk */

    if(name[0] == '[') {
      char *endptr;
      /* IPv6 numerical address */
      endptr = strchr(name, ']');
      if(!endptr)
        return FALSE;
      name++;
      namelen = endptr - name;
      if(namelen >= sizeof(hostip))
        return FALSE;
      memcpy(hostip, name, namelen);
      hostip[namelen] = 0;
      name = hostip;
      type = TYPE_IPV6;
    }
    else {
      unsigned int address;
      if(1 == Curl_inet_pton(AF_INET, name, &address))
        type = TYPE_IPV4;
      namelen = strlen(name);
    }

    while(*p) {
      const char *token;
      size_t tokenlen = 0;
      bool match = FALSE;

      /* pass blanks */
      while(*p && ISBLANK(*p))
        p++;

      token = p;
      /* pass over the pattern */
      while(*p && !ISBLANK(*p) && (*p != ',')) {
        p++;
        tokenlen++;
      }

      if(tokenlen) {
        switch(type) {
        case TYPE_HOST:
          if(*token == '.') {
            ++token;
            --tokenlen;
            /* tailmatch */
            match = (tokenlen <= namelen) &&
              strncasecompare(token, name + (namelen - tokenlen), namelen);
          }
          else
            match = (tokenlen == namelen) &&
              strncasecompare(token, name, namelen);
          break;
        case TYPE_IPV4:
          /* FALLTHROUGH */
        case TYPE_IPV6: {
          const char *check = token;
          char *slash = strchr(check, '/');
          unsigned int bits = 0;
          char checkip[128];
          /* if the slash is part of this token, use it */
          if(slash && (slash < &check[tokenlen])) {
            bits = atoi(slash + 1);
            /* copy the check name to a temp buffer */
            if(tokenlen >= sizeof(checkip))
              break;
            memcpy(checkip, check, tokenlen);
            checkip[ slash - check ] = 0;
            check = checkip;
          }
          if(type == TYPE_IPV6)
            match = Curl_cidr6_match(name, check, bits);
          else
            match = Curl_cidr4_match(name, check, bits);
          break;
        }
        }
        if(match)
          return TRUE;
      } /* if(tokenlen) */
      while(*p == ',')
        p++;
    } /* while(*p) */
  } /* NO_PROXY was specified and it wasn't just an asterisk */

  return FALSE;
}

#endif /* CURL_DISABLE_PROXY */
