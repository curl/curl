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
#include "first.h"

/* Purpose
 *
 * Resolve the given name, using system name resolve functions (NOT any
 * function provided by libcurl). Used to see if the name exists and thus if
 * we can allow a test case to use it for testing.
 *
 * Like if 'localhost' actual exists etc.
 *
 */

static int test_resolve(int argc, const char *argv[])
{
  int arg = 1;
  const char *host = NULL;
  int rc = 0;

  while(argc > arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("resolve IPv4%s\n",
#ifdef CURLRES_IPV6
             "/IPv6"
#else
             ""
#endif
      );
      return 0;
    }
    else if(!strcmp("--ipv6", argv[arg])) {
#ifdef CURLRES_IPV6
      socket_type = "IPv6";
      socket_domain = AF_INET6;
      arg++;
#else
      puts("IPv6 support has been disabled in this program");
      return 1;
#endif
    }
    else if(!strcmp("--ipv4", argv[arg])) {
      socket_type = "IPv4";
      socket_domain = AF_INET;
      arg++;
    }
    else {
      host = argv[arg++];
    }
  }
  if(!host) {
    puts("Usage: resolve [option] <host>\n"
         " --version\n"
         " --ipv4"
#ifdef CURLRES_IPV6
         "\n --ipv6"
#endif
    );
    return 1;
  }

#ifdef CURLRES_IPV6
  if(socket_domain == AF_INET6) {
    /* Check that the system has IPv6 enabled before checking the resolver */
    curl_socket_t s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s == CURL_SOCKET_BAD)
      /* an IPv6 address was requested and we cannot get/use one */
      rc = -1;
    else {
      sclose(s);
    }
  }

  if(rc == 0) {
    /* getaddrinfo() resolve */
    struct addrinfo *ai;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = socket_domain;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    rc = getaddrinfo(host, "80", &hints, &ai);
    if(rc == 0)
      freeaddrinfo(ai);
  }
#else
  {
    struct hostent *he;  /* gethostbyname() resolve */

#ifdef __AMIGA__
    he = gethostbyname((unsigned char *)CURL_UNCONST(host));
#else
    he = gethostbyname(host);
#endif

    rc = !he;
  }
#endif

  if(rc)
    printf("Resolving %s '%s' did not work\n", socket_type, host);

  return !!rc;
}
