#ifndef HEADER_SERVER_FIRST_H
#define HEADER_SERVER_FIRST_H
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

typedef int (*entry_func_t)(int, char **);

struct entry_s {
  const char *name;
  entry_func_t ptr;
};

#ifndef UNDER_CE
#include <signal.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef _XOPEN_SOURCE_EXTENDED
/* This define is "almost" required to build on HP-UX 11 */
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <curlx.h> /* from the private lib dir */

/* adjust for old MSVC */
#if defined(_MSC_VER) && (_MSC_VER < 1900)
#  define snprintf _snprintf
#endif

#ifdef _WIN32
#  define CURL_STRNICMP(p1, p2, n) _strnicmp(p1, p2, n)
#elif defined(HAVE_STRCASECMP)
#  ifdef HAVE_STRINGS_H
#    include <strings.h>
#  endif
#  define CURL_STRNICMP(p1, p2, n) strncasecmp(p1, p2, n)
#elif defined(HAVE_STRCMPI)
#  define CURL_STRNICMP(p1, p2, n) strncmpi(p1, p2, n)
#elif defined(HAVE_STRICMP)
#  define CURL_STRNICMP(p1, p2, n) strnicmp(p1, p2, n)
#else
#  error "missing case insensitive comparison function"
#endif

enum {
  DOCNUMBER_NOTHING    = -7,
  DOCNUMBER_QUIT       = -6,
  DOCNUMBER_BADCONNECT = -5,
  DOCNUMBER_INTERNAL   = -4,
  DOCNUMBER_CONNECT    = -3,
  DOCNUMBER_WERULEZ    = -2,
  DOCNUMBER_404        = -1
};

#define SERVERLOGS_LOCKDIR "lock"  /* within logdir */

#include <curl/curl.h> /* for curl_socket_t */

#ifdef USE_UNIX_SOCKETS
#ifdef HAVE_SYS_UN_H
#include <sys/un.h> /* for sockaddr_un */
#endif
#endif /* USE_UNIX_SOCKETS */

typedef union {
  struct sockaddr      sa;
  struct sockaddr_in   sa4;
#ifdef USE_IPV6
  struct sockaddr_in6  sa6;
#endif
#ifdef USE_UNIX_SOCKETS
  struct sockaddr_un   sau;
#endif
} srvr_sockaddr_union_t;

/* getpart */
#define GPE_NO_BUFFER_SPACE -2
#define GPE_OUT_OF_MEMORY   -1
#define GPE_OK               0
#define GPE_END_OF_FILE      1

static int getpart(char **outbuf, size_t *outlen,
                   const char *main, const char *sub, FILE *stream);

#endif /* HEADER_SERVER_FIRST_H */
