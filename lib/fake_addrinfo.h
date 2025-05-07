#ifndef HEADER_FAKE_ADDRINFO_H
#define HEADER_FAKE_ADDRINFO_H
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

#ifdef USE_ARES
#include <ares.h>
#endif

#if defined(CURLDEBUG) && defined(USE_ARES) && defined(HAVE_GETADDRINFO) && \
  (ARES_VERSION >= 0x011a00) /* >= 1.26. 0 */
#define USE_FAKE_GETADDRINFO 1
#endif

#ifdef USE_FAKE_GETADDRINFO

#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

void r_freeaddrinfo(struct addrinfo *res);
int r_getaddrinfo(const char *node,
                  const char *service,
                  const struct addrinfo *hints,
                  struct addrinfo **res);
#endif /* USE_FAKE_GETADDRINFO */

#endif /* HEADER_FAKE_ADDRINFO_H */
