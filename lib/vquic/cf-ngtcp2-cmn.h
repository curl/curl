#ifndef HEADER_CURL_VQUIC_CF_NGTCP2_CMN_H
#define HEADER_CURL_VQUIC_CF_NGTCP2_CMN_H
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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGTCP2) && defined(USE_NGHTTP3)

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#ifdef USE_OPENSSL
#include <openssl/err.h>
#if defined(OPENSSL_IS_AWSLC) || defined(OPENSSL_IS_BORINGSSL)
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#elif defined(OPENSSL_QUIC_API2)
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#else
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#endif
#include "vtls/openssl.h"
#elif defined(USE_GNUTLS)
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include "vtls/gtls.h"
#elif defined(USE_WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#include "vtls/wolfssl.h"
#endif

#ifdef HAVE_NETINET_UDP_H
#include <netinet/udp.h>
#endif

#include <nghttp3/nghttp3.h>

#include "http1.h"
#include "uint-hash.h"
#include "vtls/vtls.h"
#include "vquic/vquic_int.h"
#include "vquic/vquic-tls.h"

struct Curl_cfilter;
struct Curl_easy;
struct cf_ngtcp2_ctx;
struct cf_quic_ctx;

#define QUIC_MAX_STREAMS       (256 * 1024)
#define QUIC_HANDSHAKE_TIMEOUT (10 * NGTCP2_SECONDS)
#define QUIC_TUNNEL_INBUF_SIZE (64 * 1024)

/* We announce a small window size in transport param to the server,
 * and grow that immediately to max when no rate limit is in place.
 * We need to start small as we are not able to decrease it. */
#define H3_STREAM_WINDOW_SIZE_INITIAL (32 * 1024)
#define H3_STREAM_WINDOW_SIZE_MAX     (10 * 1024 * 1024)
#define H3_CONN_WINDOW_SIZE_MAX       (100 * H3_STREAM_WINDOW_SIZE_MAX)

#define H3_STREAM_CHUNK_SIZE  (64 * 1024)
#if H3_STREAM_CHUNK_SIZE < NGTCP2_MAX_UDP_PAYLOAD_SIZE
#error H3_STREAM_CHUNK_SIZE smaller than NGTCP2_MAX_UDP_PAYLOAD_SIZE
#endif
/* The pool keeps spares around and half of a full stream window
 * seems good. More does not seem to improve performance.
 * The benefit of the pool is that stream buffers do not keep
 * spares. Memory consumption goes down when streams run empty,
 * have a large upload done, etc. */
#define H3_STREAM_POOL_SPARES      2
/* The max amount of un-acked upload data we keep around per stream */
#define H3_STREAM_SEND_BUFFER_MAX      (10 * 1024 * 1024)
#define H3_STREAM_SEND_CHUNKS \
  (H3_STREAM_SEND_BUFFER_MAX / H3_STREAM_CHUNK_SIZE)
#define QUIC_TUNNEL_INGRESS_PKT_LIMIT 1000


void Curl_ngtcp2_ver(char *p, size_t len);

typedef CURLcode cf_ngtcp2_init_h3_conn(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct cf_ngtcp2_ctx *ctx);

struct cf_ngtcp2_ctx {
  struct cf_quic_ctx q;
  struct ssl_peer ssl_peer;
  struct curl_tls_ctx tls;
#ifdef OPENSSL_QUIC_API2
  ngtcp2_crypto_ossl_ctx *ossl_ctx;
#endif
  ngtcp2_path connected_path;
  ngtcp2_conn *qconn;
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  uint32_t version;
  ngtcp2_settings settings;
  ngtcp2_transport_params transport_params;
  ngtcp2_ccerr last_error;
  ngtcp2_crypto_conn_ref conn_ref;
  struct cf_call_data call_data;
  cf_ngtcp2_init_h3_conn *init_h3_conn_cb;
  nghttp3_conn *h3conn;
  nghttp3_settings h3settings;
  struct curltime started_at;       /* time the current attempt started */
  struct curltime handshake_at;     /* time connect handshake finished */
  struct bufc_pool stream_bufcp;    /* chunk pool for streams */
  struct dynbuf scratch;            /* temp buffer for header construction */
  struct uint_hash streams;         /* hash data->mid to h3_stream_ctx */
  uint64_t used_bidi_streams;       /* bidi streams we have opened */
  uint64_t max_bidi_streams;        /* max bidi streams we can open */
  size_t earlydata_max;             /* max amount of early data supported by
                                       server on session reuse */
  size_t earlydata_skip;            /* sending bytes to skip when earlydata
                                       is accepted by peer */
  CURLcode tls_vrfy_result;         /* result of TLS peer verification */
  int qlogfd;
  unsigned char *tunnel_inbuf;      /* ingress buffer for tunneled packets */
  size_t tunnel_inbuf_len;
  BIT(initialized);
  BIT(tls_handshake_complete);      /* TLS handshake is done */
  BIT(use_earlydata);               /* Using 0RTT data */
  BIT(earlydata_accepted);          /* 0RTT was accepted by server */
  BIT(shutdown_started);            /* queued shutdown packets */
};

/* How to access `call_data` from a cf_ngtcp2 filter */
#undef CF_CTX_CALL_DATA
#define CF_CTX_CALL_DATA(cf) ((struct cf_ngtcp2_ctx *)(cf)->ctx)->call_data

CURLcode Curl_cf_ngtcp2_ctx_init(struct cf_ngtcp2_ctx *ctx,
                                 struct Curl_peer *origin,
                                 struct Curl_peer *peer,
                                 struct ssl_primary_config *sslc,
                                 cf_ngtcp2_init_h3_conn *init_h3_conn_cb);
void Curl_cf_ngtcp2_ctx_cleanup(struct cf_ngtcp2_ctx *ctx);
void Curl_cf_ngtcp2_cmn_err_set(struct Curl_cfilter *cf,
                                struct Curl_easy *data, int code);

/**
 * All about the H3 internals of a stream
 */
struct h3_stream_ctx {
  int64_t id;                   /* HTTP/3 stream identifier */
  struct bufq sendbuf;          /* h3 request body */
  struct h1_req_parser h1;      /* h1 request parsing */
  size_t sendbuf_len_in_flight; /* sendbuf amount "in flight" */
  uint64_t error3;              /* HTTP/3 stream error code */
  curl_off_t upload_left;       /* number of request bytes left to upload */
  curl_off_t rx_total;          /* total number of bytes received */
  uint64_t rx_offset;           /* current receive offset */
  uint64_t rx_offset_max;       /* allowed receive offset */
  uint64_t window_size_max;     /* max flow control window set for stream */
  int status_code;              /* HTTP status code */
  CURLcode xfer_result;         /* result from xfer_resp_write(_hd) */
  BIT(resp_hds_complete);       /* we have a complete, final response */
  BIT(closed);                  /* TRUE on stream close */
  BIT(reset);                   /* TRUE on stream reset */
  BIT(send_closed);             /* stream is local closed */
  BIT(quic_flow_blocked);       /* stream is blocked by QUIC flow control */
};

void Curl_cf_ngtcp2_h3_stream_ctx_free(struct h3_stream_ctx *stream);
void Curl_cf_ngtcp2_h3_err_set(struct Curl_cfilter *cf,
                               struct Curl_easy *data, int code);

CURLcode Curl_cf_ngtcp2_h3_init_ctrls(struct cf_ngtcp2_ctx *ctx,
                                      struct Curl_easy *data);

CURLcode Curl_cf_ngtcp2_cmn_connect(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *done);

CURLcode Curl_cf_ngtcp2_cmn_shutdown(struct Curl_cfilter *cf,
                                     struct Curl_easy *data, bool *done);
void Curl_cf_ngtcp2_cmn_conn_close(struct Curl_cfilter *cf,
                                   struct Curl_easy *data);

struct cf_ngtcp2_io_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  ngtcp2_tstamp ts;
  ngtcp2_path_storage ps;
};

void Curl_cf_ngtcp2_io_ctx_init(struct cf_ngtcp2_io_ctx *io_ctx,
                                struct Curl_cfilter *cf,
                                struct Curl_easy *data);
void Curl_cf_ngtcp2_io_ctx_update_time(struct Curl_easy *data,
                                       struct cf_ngtcp2_io_ctx *pktx,
                                       struct Curl_cfilter *cf);

CURLcode Curl_cf_ngtcp2_progress_egress(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct cf_ngtcp2_io_ctx *pktx);

CURLcode Curl_cf_ngtcp2_progress_ingress(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct cf_ngtcp2_io_ctx *pktx);

CURLcode Curl_cf_ngtcp2_cmn_set_expiry(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       struct cf_ngtcp2_io_ctx *pktx);

CURLcode Curl_cf_ngtcp2_h3_stream_setup(struct Curl_cfilter *cf,
                                        struct Curl_easy *data);
void Curl_cf_ngtcp2_h3_stream_close(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct h3_stream_ctx *stream);
void Curl_cf_ngtcp2_h3_stream_done(struct Curl_cfilter *cf,
                                   struct Curl_easy *data);

bool Curl_cf_ngtcp2_cmn_conn_is_alive(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *input_pending);

#endif /* !CURL_DISABLE_HTTP && USE_NGTCP2 && USE_NGHTTP3 */

#endif /* HEADER_CURL_VQUIC_CF_NGTCP2_CMN_H */
