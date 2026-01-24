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
#include "../curl_setup.h"

#include "../bufq.h"

#ifdef USE_HTTP3

#define MAX_PKT_BURST         10
#define MAX_UDP_PAYLOAD_SIZE  1452

/* definitions from RFC 9114, ch 8.1 */
typedef enum {
  CURL_H3_ERR_NO_ERROR = 0x0100,
  CURL_H3_ERR_GENERAL_PROTOCOL_ERROR = 0x0101,
  CURL_H3_ERR_INTERNAL_ERROR = 0x0102,
  CURL_H3_ERR_STREAM_CREATION_ERROR = 0x0103,
  CURL_H3_ERR_CLOSED_CRITICAL_STREAM = 0x0104,
  CURL_H3_ERR_FRAME_UNEXPECTED = 0x0105,
  CURL_H3_ERR_FRAME_ERROR = 0x0106,
  CURL_H3_ERR_EXCESSIVE_LOAD = 0x0107,
  CURL_H3_ERR_ID_ERROR = 0x0108,
  CURL_H3_ERR_SETTINGS_ERROR = 0x0109,
  CURL_H3_ERR_MISSING_SETTINGS = 0x010a,
  CURL_H3_ERR_REQUEST_REJECTED = 0x010b,
  CURL_H3_ERR_REQUEST_CANCELLED = 0x010c,
  CURL_H3_ERR_REQUEST_INCOMPLETE = 0x010d,
  CURL_H3_ERR_MESSAGE_ERROR = 0x010e,
  CURL_H3_ERR_CONNECT_ERROR = 0x010f,
  CURL_H3_ERR_VERSION_FALLBACK = 0x0110,
} vquic_h3_error;

#ifdef CURLVERBOSE
const char *vquic_h3_err_str(uint64_t error_code);
#else
#define vquic_h3_err_str(x)   ""
#endif /* CURLVERBOSE */

struct cf_quic_ctx {
  curl_socket_t sockfd;               /* connected UDP socket */
  struct sockaddr_storage local_addr; /* address socket is bound to */
  socklen_t local_addrlen;            /* length of local address */

  struct bufq sendbuf;           /* buffer for sending one or more packets */
  struct curltime first_byte_at; /* when first byte was recvd */
  struct curltime last_op;       /* last (attempted) send/recv operation */
  struct curltime last_io;       /* last successful socket IO */
  size_t gsolen;                 /* length of individual packets in send buf */
  size_t split_len;    /* if != 0, buffer length after which GSO differs */
  size_t split_gsolen; /* length of individual packets after split_len */
#ifdef DEBUGBUILD
  int wblock_percent;  /* percent of writes doing EAGAIN */
#endif
  BIT(got_first_byte); /* if first byte was received */
  BIT(no_gso);         /* do not use gso on sending */
};

#define H3_STREAM_CTX(ctx, data)                                        \
  (data ? Curl_uint32_hash_get(&(ctx)->streams, (data)->mid) : NULL)

CURLcode vquic_ctx_init(struct Curl_easy *data,
                        struct cf_quic_ctx *qctx);
void vquic_ctx_free(struct cf_quic_ctx *qctx);

void vquic_ctx_set_time(struct cf_quic_ctx *qctx,
                        const struct curltime *pnow);

void vquic_ctx_update_time(struct cf_quic_ctx *qctx,
                           const struct curltime *pnow);

void vquic_push_blocked_pkt(struct Curl_cfilter *cf,
                            struct cf_quic_ctx *qctx,
                            const uint8_t *pkt, size_t pktlen, size_t gsolen);

CURLcode vquic_send_blocked_pkts(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct cf_quic_ctx *qctx);

CURLcode vquic_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                    struct cf_quic_ctx *qctx, size_t gsolen);

CURLcode vquic_send_tail_split(struct Curl_cfilter *cf, struct Curl_easy *data,
                               struct cf_quic_ctx *qctx, size_t gsolen,
                               size_t tail_len, size_t tail_gsolen);

CURLcode vquic_flush(struct Curl_cfilter *cf, struct Curl_easy *data,
                     struct cf_quic_ctx *qctx);

typedef CURLcode vquic_recv_pkts_cb(const unsigned char *buf, size_t buflen,
                                    size_t gso_size,
                                    struct sockaddr_storage *remote_addr,
                                    socklen_t remote_addrlen, int ecn,
                                    void *userp);

CURLcode vquic_recv_packets(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct cf_quic_ctx *qctx,
                            size_t max_pkts,
                            vquic_recv_pkts_cb *recv_cb, void *userp);

#endif /* !USE_HTTP3 */

#ifdef USE_NGTCP2
struct ngtcp2_mem;
struct ngtcp2_mem *Curl_ngtcp2_mem(void);
#endif
#ifdef USE_NGHTTP3
struct nghttp3_mem;
struct nghttp3_mem *Curl_nghttp3_mem(void);
#endif

#endif /* HEADER_CURL_VQUIC_QUIC_INT_H */
