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

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
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
#ifdef USE_IPV6
  unsigned int bytes;
  unsigned int rest;
  unsigned char address[16];
  unsigned char check[16];

  if(!bits)
    bits = 128;

  bytes = bits / 8;
  rest = bits & 0x07;
  if((bytes > 16) || ((bytes == 16) && rest))
    return FALSE;
  if(1 != Curl_inet_pton(AF_INET6, ipv6, address))
    return FALSE;
  if(1 != Curl_inet_pton(AF_INET6, network, check))
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
  char hostip[128];

  /*
   * If we do not have a hostname at all, like for example with a FILE
   * transfer, we have nothing to interrogate the noproxy list with.
   */
  if(!name || name[0] == '\0')
    return FALSE;

  /* no_proxy=domain1.dom,host.domain2.dom
   *   (a comma-separated list of hosts which should
   *   not be proxied, or an asterisk to override
   *   all proxy variables)
   */
  if(no_proxy && no_proxy[0]) {
    const char *p = no_proxy;
    size_t namelen;
    enum nametype type = TYPE_HOST;
    if(!strcmp("*", no_proxy))
      return TRUE;

    /* NO_PROXY was specified and it was not just an asterisk */

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
      namelen = strlen(name);
      if(1 == Curl_inet_pton(AF_INET, name, &address))
        type = TYPE_IPV4;
      else {
        /* ignore trailing dots in the hostname */
        if(name[namelen - 1] == '.')
          namelen--;
      }
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
          /* ignore trailing dots in the token to check */
          if(token[tokenlen - 1] == '.')
            tokenlen--;

          if(tokenlen && (*token == '.')) {
            /* ignore leading token dot as well */
            token++;
            tokenlen--;
          }
          /* A: example.com matches 'example.com'
             B: www.example.com matches 'example.com'
             C: nonexample.com DOES NOT match 'example.com'
          */
          if(tokenlen == namelen)
            /* case A, exact match */
            match = strncasecompare(token, name, namelen);
          else if(tokenlen < namelen) {
            /* case B, tailmatch domain */
            match = (name[namelen - tokenlen - 1] == '.') &&
              strncasecompare(token, name + (namelen - tokenlen),
                              tokenlen);
          }
          /* case C passes through, not a match */
          break;
        case TYPE_IPV4:
        case TYPE_IPV6: {
          const char *check = token;
          char *slash;
          unsigned int bits = 0;
          char checkip[128];
          if(tokenlen >= sizeof(checkip))
            /* this cannot match */
            break;
          /* copy the check name to a temp buffer */
          memcpy(checkip, check, tokenlen);
          checkip[tokenlen] = 0;
          check = checkip;

          slash = strchr(check, '/');
          /* if the slash is part of this token, use it */
          if(slash) {
            /* if the bits variable gets a crazy value here, that is fine as
               the value will then be rejected in the cidr function */
            bits = (unsigned int)atoi(slash + 1);
            *slash = 0; /* null terminate there */
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
      /* pass blanks after pattern */
      while(ISBLANK(*p))
        p++;
      /* if not a comma, this ends the loop */
      if(*p != ',')
        break;
      /* pass any number of commas */
      while(*p == ',')
        p++;
    } /* while(*p) */
  } /* NO_PROXY was specified and it was not just an asterisk */

  return FALSE;
}

#endif /* CURL_DISABLE_PROXY */
