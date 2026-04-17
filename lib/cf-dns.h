#ifndef HEADER_CURL_CF_DNS_H
#define HEADER_CURL_CF_DNS_H
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

struct Curl_easy;
struct connectdata;
struct Curl_dns_entry;
struct Curl_addrinfo;

CURLcode Curl_cf_dns_add(struct Curl_easy *data,
                         struct connectdata *conn,
                         int sockindex,
                         uint8_t dns_queries,
                         uint8_t transport,
                         struct Curl_dns_entry *dns);

CURLcode Curl_cf_dns_insert_after(struct Curl_cfilter *cf_at,
                                  struct Curl_easy *data,
                                  uint8_t dns_queries,
                                  const char *hostname,
                                  uint16_t port,
                                  uint8_t transport,
                                  bool complete_resolve);

CURLcode Curl_conn_dns_result(struct connectdata *conn, int sockindex);

const struct Curl_addrinfo *Curl_conn_dns_get_ai(struct Curl_easy *data,
                                                 int sockindex,
                                                 int ai_family,
                                                 unsigned int index);

const struct Curl_addrinfo *Curl_cf_dns_get_ai(struct Curl_cfilter *cf,
                                               struct Curl_easy *data,
                                               int ai_family,
                                               unsigned int index);

#ifdef USE_HTTPSRR
const struct Curl_https_rrinfo *Curl_conn_dns_get_https(struct Curl_easy *data,
                                                        int sockindex);
bool Curl_conn_dns_resolved_https(struct Curl_easy *data, int sockindex);
#else
#define Curl_conn_dns_get_https(a, b)        NULL
#define Curl_conn_dns_resolved_https(a, b)   TRUE
#endif

extern struct Curl_cftype Curl_cft_dns;

#endif /* HEADER_CURL_CF_DNS_H */
