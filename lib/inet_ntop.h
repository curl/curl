#ifndef HEADER_FETCH_INET_NTOP_H
#define HEADER_FETCH_INET_NTOP_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

char *Fetch_inet_ntop(int af, const void *addr, char *buf, size_t size);

#ifdef HAVE_INET_NTOP
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef _WIN32
#if defined(_MSC_VER) && (_MSC_VER <= 1900)
#define Fetch_inet_ntop(af, addr, buf, size) inet_ntop(af, (void *)addr, buf, size)
#else
#define Fetch_inet_ntop(af, addr, buf, size) inet_ntop(af, addr, buf, size)
#endif
#elif defined(__AMIGA__)
#define Fetch_inet_ntop(af, addr, buf, size)                       \
        (char *)inet_ntop(af, (void *)addr, (unsigned char *)buf, \
                          (fetch_socklen_t)(size))
#else
#define Fetch_inet_ntop(af, addr, buf, size) \
        inet_ntop(af, addr, buf, (fetch_socklen_t)(size))
#endif
#endif

#endif /* HEADER_FETCH_INET_NTOP_H */
