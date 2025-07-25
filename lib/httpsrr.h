#ifndef HEADER_CURL_HTTPSRR_H
#define HEADER_CURL_HTTPSRR_H
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

#ifdef USE_ARES
#include <ares.h>
#endif

#ifdef USE_HTTPSRR

#define CURL_MAXLEN_host_name 253
#define MAX_HTTPSRR_ALPNS 4

struct Curl_easy;

struct Curl_https_rrinfo {
  /*
   * Fields from HTTPS RR. The only mandatory fields are priority and target.
   * See https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2
   */
  char *target;
  unsigned char *ipv4hints; /* keytag = 4 */
  size_t ipv4hints_len;
  unsigned char *echconfiglist; /* keytag = 5 */
  size_t echconfiglist_len;
  unsigned char *ipv6hints; /* keytag = 6 */
  size_t ipv6hints_len;
  unsigned char alpns[MAX_HTTPSRR_ALPNS]; /* keytag = 1 */
  /* store parsed alpnid entries in the array, end with ALPN_none */
  int port; /* -1 means not set */
  uint16_t priority;
  BIT(no_def_alpn); /* keytag = 2 */
};

CURLcode Curl_httpsrr_set(struct Curl_easy *data,
                          struct Curl_https_rrinfo *hi,
                          uint16_t rrkey, const uint8_t *val, size_t vlen);

struct Curl_https_rrinfo *
Curl_httpsrr_dup_move(struct Curl_https_rrinfo *rrinfo);

void Curl_httpsrr_cleanup(struct Curl_https_rrinfo *rrinfo);

/*
 * Code points for DNS wire format SvcParams as per RFC 9460
 */
#define HTTPS_RR_CODE_MANDATORY       0x00
#define HTTPS_RR_CODE_ALPN            0x01
#define HTTPS_RR_CODE_NO_DEF_ALPN     0x02
#define HTTPS_RR_CODE_PORT            0x03
#define HTTPS_RR_CODE_IPV4            0x04
#define HTTPS_RR_CODE_ECH             0x05
#define HTTPS_RR_CODE_IPV6            0x06

#ifdef USE_ARES
CURLcode Curl_httpsrr_from_ares(struct Curl_easy *data,
                                const ares_dns_record_t *dnsrec,
                                struct Curl_https_rrinfo *hinfo);
#endif /* USE_ARES */
#endif /* USE_HTTPSRR */

#endif /* HEADER_CURL_HTTPSRR_H */
