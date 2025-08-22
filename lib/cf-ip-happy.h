#ifndef HEADER_CURL_IP_HAPPY_H
#define HEADER_CURL_IP_HAPPY_H
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

#include "curlx/nonblock.h" /* for curlx_nonblock() */
#include "sockaddr.h"

/**
 * Create a cfilter for making an "ip" connection to the
 * given address, using parameters from `conn`. The "ip" connection
 * can be a TCP socket, a UDP socket or even a QUIC connection.
 *
 * It MUST use only the supplied `ai` for its connection attempt.
 *
 * Such a filter may be used in "happy eyeball" scenarios, and its
 * `connect` implementation needs to support non-blocking. Once connected,
 * it MAY be installed in the connection filter chain to serve transfers.
 */
typedef CURLcode cf_ip_connect_create(struct Curl_cfilter **pcf,
                                      struct Curl_easy *data,
                                      struct connectdata *conn,
                                      const struct Curl_addrinfo *ai,
                                      int transport);

CURLcode cf_ip_happy_insert_after(struct Curl_cfilter *cf_at,
                                  struct Curl_easy *data,
                                  int transport);

extern struct Curl_cftype Curl_cft_ip_happy;

#ifdef UNITTESTS
void Curl_debug_set_transport_provider(int transport,
                                       cf_ip_connect_create *cf_create);
#endif

#endif /* HEADER_CURL_IP_HAPPY_H */
