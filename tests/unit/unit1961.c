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
#include "unitcheck.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifndef _WIN32
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

/*
 * If USE_IPV6 is disabled, we still want to parse IPv6 addresses, so make
 * sure we have _some_ value for AF_INET6 without polluting our fake value
 * everywhere.
 */
#if !defined(USE_IPV6) && !defined(AF_INET6)
#define AF_INET6 (AF_INET + 1)
#endif

static int test_ntop(void)
{
  char ipv6res[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
  char ipv4res[sizeof("255.255.255.255")];
  unsigned char ipv6a[26];
  unsigned char ipv4a[5];
  const char *ipv6ptr = 0;
  const char *ipv4ptr = 0;

  ipv4res[0] = '\0';
  ipv4a[0] = 0xc0;
  ipv4a[1] = 0xa8;
  ipv4a[2] = 0x64;
  ipv4a[3] = 0x01;
  ipv4a[4] = 0x01;
  ipv4ptr = curlx_inet_ntop(AF_INET, ipv4a, ipv4res, sizeof(ipv4res));
  if(!ipv4ptr)
    return 1; /* fail */
  if(ipv4ptr != ipv4res)
    return 1; /* fail */
  if(!ipv4ptr[0])
    return 1; /* fail */
  if(memcmp(ipv4res, "192.168.100.1", 13))
    return 1; /* fail */

  ipv6res[0] = '\0';
  memset(ipv6a, 0, sizeof(ipv6a));
  ipv6a[0] = 0xfe;
  ipv6a[1] = 0x80;
  ipv6a[8] = 0x02;
  ipv6a[9] = 0x14;
  ipv6a[10] = 0x4f;
  ipv6a[11] = 0xff;
  ipv6a[12] = 0xfe;
  ipv6a[13] = 0x0b;
  ipv6a[14] = 0x76;
  ipv6a[15] = 0xc8;
  ipv6a[25] = 0x01;
  ipv6ptr = curlx_inet_ntop(AF_INET6, ipv6a, ipv6res, sizeof(ipv6res));
  if(!ipv6ptr)
    return 1; /* fail */
  if(ipv6ptr != ipv6res)
    return 1; /* fail */
  if(!ipv6ptr[0])
    return 1; /* fail */
  if(memcmp(ipv6res, "fe80::214:4fff:fe0b:76c8", 24))
    return 1; /* fail */

  /* verify working RFC 4291 zero prefixed IPv4 - mapped format */
  memset(ipv6a, 0, sizeof(ipv6a));
  ipv6a[12] = 0x7f;
  ipv6a[13] = 0x0;
  ipv6a[14] = 0x0;
  ipv6a[15] = 0x01;
  ipv6ptr = curlx_inet_ntop(AF_INET6, ipv6a, ipv6res, sizeof(ipv6res));
  if(!ipv6ptr)
    return 1; /* fail */
  if(ipv6ptr != ipv6res)
    return 1; /* fail */
  if(!ipv6ptr[0])
    return 1; /* fail */
  if(memcmp(ipv6res, "::127.0.0.1", 11))
    return 1; /* fail */

  return 0;
}

static int test_pton(void)
{
  unsigned char ipv6a[16 + 1];
  unsigned char ipv4a[4 + 1];
  const char *ipv6src = "fe80::214:4fff:fe0b:76c8";
  const char *ipv4src = "192.168.100.1";

  memset(ipv4a, 1, sizeof(ipv4a));
  if(curlx_inet_pton(AF_INET, ipv4src, ipv4a) != 1)
    return 1; /* fail */

  if((ipv4a[0] != 0xc0) ||
     (ipv4a[1] != 0xa8) ||
     (ipv4a[2] != 0x64) ||
     (ipv4a[3] != 0x01) ||
     (ipv4a[4] != 0x01))
    return 1; /* fail */

  memset(ipv6a, 1, sizeof(ipv6a));
  if(curlx_inet_pton(AF_INET6, ipv6src, ipv6a) != 1)
    return 1; /* fail */

  if((ipv6a[0]  != 0xfe) ||
     (ipv6a[1]  != 0x80) ||
     (ipv6a[8]  != 0x02) ||
     (ipv6a[9]  != 0x14) ||
     (ipv6a[10] != 0x4f) ||
     (ipv6a[11] != 0xff) ||
     (ipv6a[12] != 0xfe) ||
     (ipv6a[13] != 0x0b) ||
     (ipv6a[14] != 0x76) ||
     (ipv6a[15] != 0xc8) ||
     (ipv6a[16] != 0x01))
    return 1; /* fail */

  if((ipv6a[2] != 0x0) ||
     (ipv6a[3] != 0x0) ||
     (ipv6a[4] != 0x0) ||
     (ipv6a[5] != 0x0) ||
     (ipv6a[6] != 0x0) ||
     (ipv6a[7] != 0x0))
    return 1; /* fail */

  return 0;
}

static CURLcode test_unit1961(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  fail_if(test_ntop(), "curlx_inet_ntop()");
  fail_if(test_pton(), "curlx_inet_pton()");

  UNITTEST_END_SIMPLE
}
