#ifndef __CONNECT_H
#define __CONNECT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/

int Curl_nonblock(curl_socket_t sockfd,    /* operate on this */
                  int nonblock   /* TRUE or FALSE */);

CURLcode Curl_is_connected(struct connectdata *conn,
                           int sockindex,
                           bool *connected);

CURLcode Curl_connecthost(struct connectdata *conn,
                          const struct Curl_dns_entry *host, /* connect to this */
                          curl_socket_t *sockconn, /* not set if error */
                          Curl_addrinfo **addr, /* the one we used */
                          bool *connected /* truly connected? */
                          );

int Curl_sockerrno(void);

CURLcode Curl_store_ip_addr(struct connectdata *conn);

#define DEFAULT_CONNECT_TIMEOUT 300000 /* milliseconds == five minutes */

#endif
