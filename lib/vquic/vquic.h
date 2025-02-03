#ifndef HEADER_FETCH_VQUIC_QUIC_H
#define HEADER_FETCH_VQUIC_QUIC_H
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

#ifdef USE_HTTP3
struct Fetch_cfilter;
struct Fetch_easy;
struct connectdata;
struct Fetch_addrinfo;

void Fetch_quic_ver(char *p, size_t len);

FETCHcode Fetch_qlogdir(struct Fetch_easy *data,
                       unsigned char *scid,
                       size_t scidlen,
                       int *qlogfdp);

FETCHcode Fetch_cf_quic_create(struct Fetch_cfilter **pcf,
                              struct Fetch_easy *data,
                              struct connectdata *conn,
                              const struct Fetch_addrinfo *ai,
                              int transport);

extern struct Fetch_cftype Fetch_cft_http3;

#endif /* !USE_HTTP3 */

FETCHcode Fetch_conn_may_http3(struct Fetch_easy *data,
                              const struct connectdata *conn);

#endif /* HEADER_FETCH_VQUIC_QUIC_H */
