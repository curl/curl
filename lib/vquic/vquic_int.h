#ifndef HEADER_CURL_VQUIC_QUIC_INT_H
#define HEADER_CURL_VQUIC_QUIC_INT_H
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

#ifdef ENABLE_QUIC

struct vquic_blocked_pkt {
  const uint8_t *pkt;
  size_t pktlen;
  size_t gsolen;
};

struct cf_quic_ctx {
  curl_socket_t sockfd;
  struct sockaddr_storage local_addr;
  socklen_t local_addrlen;
  struct vquic_blocked_pkt blocked_pkt[2];
  uint8_t *pktbuf;
  /* the number of entries in blocked_pkt */
  size_t num_blocked_pkt;
  size_t num_blocked_pkt_sent;
  /* the packets blocked by sendmsg (EAGAIN or EWOULDBLOCK) */
  size_t pktbuflen;
  /* the number of processed entries in blocked_pkt */
  bool no_gso;
};

CURLcode vquic_ctx_init(struct cf_quic_ctx *qctx, size_t pktbuflen);
void vquic_ctx_free(struct cf_quic_ctx *qctx);

CURLcode vquic_send_packet(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct cf_quic_ctx *qctx,
                           const uint8_t *pkt, size_t pktlen, size_t gsolen,
                           size_t *psent);

void vquic_push_blocked_pkt(struct Curl_cfilter *cf,
                            struct cf_quic_ctx *qctx,
                            const uint8_t *pkt, size_t pktlen, size_t gsolen);

CURLcode vquic_send_blocked_pkt(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                struct cf_quic_ctx *qctx);


#endif /* !ENABLE_QUIC */

#endif /* HEADER_CURL_VQUIC_QUIC_INT_H */
