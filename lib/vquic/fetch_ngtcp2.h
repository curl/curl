#ifndef HEADER_FETCH_VQUIC_FETCH_NGTCP2_H
#define HEADER_FETCH_VQUIC_FETCH_NGTCP2_H
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

#if defined(USE_NGTCP2) && defined(USE_NGHTTP3)

#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif

#include <ngtcp2/ngtcp2_crypto.h>
#include <nghttp3/nghttp3.h>
#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#endif

struct Fetch_cfilter;

#include "urldata.h"

void Fetch_ngtcp2_ver(char *p, size_t len);

FETCHcode Fetch_cf_ngtcp2_create(struct Fetch_cfilter **pcf,
                                struct Fetch_easy *data,
                                struct connectdata *conn,
                                const struct Fetch_addrinfo *ai);

bool Fetch_conn_is_ngtcp2(const struct Fetch_easy *data,
                         const struct connectdata *conn,
                         int sockindex);
#endif

#endif /* HEADER_FETCH_VQUIC_FETCH_NGTCP2_H */
