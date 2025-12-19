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

#include "curlx/inet_pton.h"
#include "noproxy.h"
#include "curlx/strparse.h"

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

  if(curlx_inet_pton(AF_INET, ipv4, &address) != 1)
    return FALSE;
  if(curlx_inet_pton(AF_INET, network, &check) != 1)
    return FALSE;

  if(bits && (bits != 32)) {
    unsigned int mask = 0xffffffff << (32 - bits);
    unsigned int haddr = htonl(address);
    unsigned int hcheck = htonl(check);
#if 0
    curl_mfprintf(stderr, "Host %s (%x) network %s (%x) "
                  "bits %u mask %x => %x\n",
                  ipv4, haddr, network, hcheck, bits, mask,
                  (haddr ^ hcheck) & mask);
#endif
    if((haddr ^ hcheck) & mask)
      return FALSE;
    return TRUE;
  }
  return address == check;
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
  if(curlx_inet_pton(AF_INET6, ipv6, address) != 1)
    return FALSE;
  if(curlx_inet_pton(AF_INET6, network, check) != 1)
    return FALSE;
  if(bytes && memcmp(address, check, bytes))
    return FALSE;
  if(rest && ((address[bytes] ^ check[bytes]) & (0xff << (8 - rest))))
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

static bool match_host(const char *token, size_t tokenlen,
                       const char *name, size_t namelen)
{
  bool match = FALSE;

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
    match = curl_strnequal(token, name, namelen);
  else if(tokenlen < namelen) {
    /* case B, tailmatch domain */
    match = (name[namelen - tokenlen - 1] == '.') &&
            curl_strnequal(token, name + (namelen - tokenlen), tokenlen);
  }
  /* case C passes through, not a match */
  return match;
}

static bool match_ip(int type, const char *token, size_t tokenlen,
                     const char *name)
{
  const char *check = token;
  char *slash;
  unsigned int bits = 0;
  char checkip[128];
  if(tokenlen >= sizeof(checkip))
    /* this cannot match */
    return FALSE;
  /* copy the check name to a temp buffer */
  memcpy(checkip, check, tokenlen);
  checkip[tokenlen] = 0;
  check = checkip;

  slash = strchr(check, '/');
  /* if the slash is part of this token, use it */
  if(slash) {
    curl_off_t value;
    const char *p = &slash[1];
    if(curlx_str_number(&p, &value, 128) || *p)
      return FALSE;
    /* a too large value is rejected in the cidr function below */
    bits = (unsigned int)value;
    *slash = 0; /* null-terminate there */
  }
  if(type == TYPE_IPV6)
    return Curl_cidr6_match(name, check, bits);
  else
    return Curl_cidr4_match(name, check, bits);
}

/****************************************************************
 * Checks if the host is in the noproxy list. returns TRUE if it matches and
 * therefore the proxy should NOT be used.
 ****************************************************************/
bool Curl_check_noproxy(const char *name, const char *no_proxy)
{
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
    char address[16];
    enum nametype type = TYPE_HOST;
    if(!strcmp("*", no_proxy))
      return TRUE;

    /* NO_PROXY was specified and it was not just an asterisk */

    /* Check if name is an IP address; if not, assume it being a hostname. */
    namelen = strlen(name);
    if(curlx_inet_pton(AF_INET, name, &address) == 1)
      type = TYPE_IPV4;
#ifdef USE_IPV6
    else if(curlx_inet_pton(AF_INET6, name, &address) == 1)
      type = TYPE_IPV6;
#endif
    else {
      /* ignore trailing dots in the hostname */
      if(name[namelen - 1] == '.')
        namelen--;
    }

    while(*p) {
      const char *token;
      size_t tokenlen = 0;

      /* pass blanks */
      curlx_str_passblanks(&p);

      token = p;
      /* pass over the pattern */
      while(*p && !ISBLANK(*p) && (*p != ',')) {
        p++;
        tokenlen++;
      }

      if(tokenlen) {
        bool match = FALSE;
        if(type == TYPE_HOST)
          match = match_host(token, tokenlen, name, namelen);
        else
          match = match_ip(type, token, tokenlen, name);

        if(match)
          return TRUE;
      }

      /* pass blanks after pattern */
      curlx_str_passblanks(&p);
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
