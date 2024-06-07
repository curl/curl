#ifndef HEADER_CURL_NONBLOCK_H
#define HEADER_CURL_NONBLOCK_H
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

#include <curl/curl.h> /* for curl_socket_t */

#if defined(SOCK_NONBLOCK) && !defined(_WIN32)
/* While SOCK_NONBLOCK may be defined on Windows, it does not
 * seem to work reliably on all such platforms. Better pay
 * the price of setting it explicitly via curlx_nonblock(). */
#define USE_SOCK_NONBLOCK
#endif

int curlx_nonblock(curl_socket_t sockfd,    /* operate on this */
                   int nonblock   /* TRUE or FALSE */);

#endif /* HEADER_CURL_NONBLOCK_H */
