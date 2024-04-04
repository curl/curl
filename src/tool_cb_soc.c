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
#include "tool_setup.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h> /* IPPROTO_TCP */
#endif

#include "tool_cb_soc.h"

/*
** callback for CURLOPT_OPENSOCKETFUNCTION
**
** Notice that only Linux is supported for the moment.
*/

curl_socket_t tool_socket_open_mptcp_cb(void *clientp,
                                        curlsocktype purpose,
                                        struct curl_sockaddr *addr)
{
  int protocol = addr->protocol;

  (void)clientp;
  (void)purpose;

  if(protocol == IPPROTO_TCP)
#if defined(__linux__)
#  ifndef IPPROTO_MPTCP
#  define IPPROTO_MPTCP 262
#  endif
    protocol = IPPROTO_MPTCP;
#else
    return CURL_SOCKET_BAD;
#endif

  return socket(addr->family, addr->socktype, protocol);
}
