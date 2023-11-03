#ifndef HEADER_CURL_SOCKETPAIR_H
#define HEADER_CURL_SOCKETPAIR_H
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

#ifdef HAVE_PIPE

#define wakeup_write  write
#define wakeup_read   read
#define wakeup_close  close
#define wakeup_create pipe

#else /* HAVE_PIPE */

#define wakeup_write     swrite
#define wakeup_read      sread
#define wakeup_close     sclose
#define wakeup_create(p) Curl_socketpair(AF_UNIX, SOCK_STREAM, 0, p)

#endif /* HAVE_PIPE */

#ifndef HAVE_SOCKETPAIR
#include <curl/curl.h>

int Curl_socketpair(int domain, int type, int protocol,
                    curl_socket_t socks[2]);
#else
#define Curl_socketpair(a,b,c,d) socketpair(a,b,c,d)
#endif

#endif /* HEADER_CURL_SOCKETPAIR_H */
