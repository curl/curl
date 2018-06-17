#ifndef HEADER_CURL_DOH_H
#define HEADER_CURL_DOH_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "urldata.h"
#include "curl_addrinfo.h"

/*
 * Curl_doh() resolve a name using DOH. It resolves a name and returns a
 * 'Curl_addrinfo *' with the address information.
 */

Curl_addrinfo *Curl_doh(struct connectdata *conn,
                        const char *hostname,
                        int port,
                        int *waitp);

CURLcode Curl_doh_is_resolved(struct connectdata *conn,
                              struct Curl_dns_entry **dns);

int Curl_doh_getsock(struct connectdata *conn, curl_socket_t *socks,
                     int numsocks);

#endif
