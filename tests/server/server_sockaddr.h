#ifndef HEADER_CURL_SERVER_SOCKADDR_H
#define HEADER_CURL_SERVER_SOCKADDR_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_SYS_UN_H
#include <sys/un.h> /* for sockaddr_un */
#endif

typedef union {
  struct sockaddr      sa;
  struct sockaddr_in   sa4;
#ifdef ENABLE_IPV6
  struct sockaddr_in6  sa6;
#endif
#ifdef USE_UNIX_SOCKETS
  struct sockaddr_un   sau;
#endif
} srvr_sockaddr_union_t;

#endif /* HEADER_CURL_SERVER_SOCKADDR_H */
