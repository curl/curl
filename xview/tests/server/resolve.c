/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "server_setup.h"

/* Purpose
 *
 * Resolve the given name, using system name resolve functions (NOT any
 * function provided by libcurl). Used to see if the name exists and thus if
 * we can allow a test case to use it for testing.
 *
 * Like if 'localhost' actual exists etc.
 *
 */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _XOPEN_SOURCE_EXTENDED
/* This define is "almost" required to build on HPUX 11 */
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include "curlx.h" /* from the private lib dir */
#include "util.h"

/* include memdebug.h last */
#include "memdebug.h"

static bool use_ipv6 = FALSE;
static const char *ipv_inuse = "IPv4";

const char *serverlogfile=""; /* for a util.c function we don't use */

int main(int argc, char *argv[])
{
  int arg=1;
  const char *host = NULL;
  int rc = 0;

  while(argc>arg) {
    if(!strcmp("--version", argv[arg])) {
      printf("resolve IPv4%s\n",
#ifdef ENABLE_IPV6
             "/IPv6"
#else
             ""
#endif
             );
      return 0;
    }
    else if(!strcmp("--ipv6", argv[arg])) {
      ipv_inuse = "IPv6";
      use_ipv6 = TRUE;
      arg++;
    }
    else if(!strcmp("--ipv4", argv[arg])) {
      /* for completeness, we support this option as well */
      ipv_inuse = "IPv4";
      use_ipv6 = FALSE;
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
#ifdef ENABLE_IPV6
         "\n --ipv6"
#endif
         );
    return 1;
  }

#ifdef WIN32
  win32_init();
  atexit(win32_cleanup);
#endif

  if(!use_ipv6) {
    /* gethostbyname() resolve */
    struct hostent *he;

    he = gethostbyname(host);

    rc = !he;
  }
  else {
#ifdef ENABLE_IPV6
    /* Check that the system has IPv6 enabled before checking the resolver */
    curl_socket_t s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s == CURL_SOCKET_BAD)
      /* an IPv6 address was requested and we can't get/use one */
      rc = -1;
    else {
      sclose(s);
    }

    if (rc == 0) {
      /* getaddrinfo() resolve */
      struct addrinfo *ai;
      struct addrinfo hints;

      memset(&hints, 0, sizeof(hints));
      hints.ai_family = PF_INET6;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_CANONNAME;
      /* Use parenthesis around functions to stop them from being replaced by
         the macro in memdebug.h */
      rc = (getaddrinfo)(host, "80", &hints, &ai);
      if (rc == 0)
        (freeaddrinfo)(ai);
    }

#else
    puts("IPv6 support has been disabled in this program");
    return 1;
#endif
  }
  if(rc)
    printf("Resolving %s '%s' didn't work\n", ipv_inuse, host);

  return !!rc;
}
