#ifndef HEADER_CURL_CONNECT_H
#define HEADER_CURL_CONNECT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "curl_setup.h"

#include "nonblock.h" /* for curlx_nonblock(), formerly Curl_nonblock() */
#include "sockaddr.h"

CURLcode Curl_is_connected(struct connectdata *conn,
                           int sockindex,
                           bool *connected);

CURLcode Curl_connecthost(struct connectdata *conn,
                          const struct Curl_dns_entry *host);

/* generic function that returns how much time there's left to run, according
   to the timeouts set */
long Curl_timeleft(struct SessionHandle *data,
                   struct timeval *nowp,
                   bool duringconnect);

#define DEFAULT_CONNECT_TIMEOUT 300000 /* milliseconds == five minutes */
#define HAPPY_EYEBALLS_TIMEOUT     200 /* milliseconds to wait between
                                          ipv4/ipv6 connection attempts */

/*
 * Used to extract socket and connectdata struct for the most recent
 * transfer on the given SessionHandle.
 *
 * The returned socket will be CURL_SOCKET_BAD in case of failure!
 */
curl_socket_t Curl_getconnectinfo(struct SessionHandle *data,
                                  struct connectdata **connp);

#ifdef USE_WINSOCK
/* When you run a program that uses the Windows Sockets API, you may
   experience slow performance when you copy data to a TCP server.

   http://support.microsoft.com/kb/823764

   Work-around: Make the Socket Send Buffer Size Larger Than the Program Send
   Buffer Size

*/
void Curl_sndbufset(curl_socket_t sockfd);
#else
#define Curl_sndbufset(y) Curl_nop_stmt
#endif

void Curl_updateconninfo(struct connectdata *conn, curl_socket_t sockfd);
void Curl_persistconninfo(struct connectdata *conn);
int Curl_closesocket(struct connectdata *conn, curl_socket_t sock);

/*
 * The Curl_sockaddr_ex structure is basically libcurl's external API
 * curl_sockaddr structure with enough space available to directly hold any
 * protocol-specific address structures. The variable declared here will be
 * used to pass / receive data to/from the fopensocket callback if this has
 * been set, before that, it is initialized from parameters.
 */
struct Curl_sockaddr_ex {
  int family;
  int socktype;
  int protocol;
  unsigned int addrlen;
  union {
    struct sockaddr addr;
    struct Curl_sockaddr_storage buff;
  } _sa_ex_u;
};
#define sa_addr _sa_ex_u.addr

/*
 * Create a socket based on info from 'conn' and 'ai'.
 *
 * Fill in 'addr' and 'sockfd' accordingly if OK is returned. If the open
 * socket callback is set, used that!
 *
 */
CURLcode Curl_socket(struct connectdata *conn,
                     const Curl_addrinfo *ai,
                     struct Curl_sockaddr_ex *addr,
                     curl_socket_t *sockfd);

#endif /* HEADER_CURL_CONNECT_H */
