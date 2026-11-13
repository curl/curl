#ifndef HEADER_CURL_NGTCP2_SHIM_H
#define HEADER_CURL_NGTCP2_SHIM_H
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

#ifdef USE_NGTCP2

#include <ngtcp2/ngtcp2.h>

enum curl_ngtcp2_state {
  CURL_NGTCP2_NORMAL,
  CURL_NGTCP2_COALESCING,
  CURL_NGTCP2_CLOSE_ONLY
};

/* ngtcp2 restricts which connection APIs may be called while it is
 * coalescing a packet and after a connection error. This shim records those
 * states and prevents calls which would violate the connection contract. */
struct curl_ngtcp2 {
  ngtcp2_conn *conn;
  const ngtcp2_path *path;
  const ngtcp2_pkt_info *pi;
  const uint8_t *dest;
  size_t destlen;
  ngtcp2_tstamp ts;
  ngtcp2_ssize error_rv;
  enum curl_ngtcp2_state state;
};

/* True if a connection exists and is not restricted to terminal handling. */
bool Curl_ngtcp2_valid(const struct curl_ngtcp2 *ntp2);
/* True while packet coalescing or terminal handling restricts API calls. */
bool Curl_ngtcp2_restricted(const struct curl_ngtcp2 *ntp2);
/* Raw connection access for APIs which require an ngtcp2_conn pointer. */
ngtcp2_conn *Curl_ngtcp2_conn(const struct curl_ngtcp2 *ntp2);

int Curl_ngtcp2_conn_client_new(
  struct curl_ngtcp2 *ntp2, const ngtcp2_cid *dcid,
  const ngtcp2_cid *scid, const ngtcp2_path *path,
  uint32_t client_chosen_version, const ngtcp2_callbacks *callbacks,
  const ngtcp2_settings *settings, const ngtcp2_transport_params *params,
  const ngtcp2_mem *mem, void *user_data);
void Curl_ngtcp2_conn_del(struct curl_ngtcp2 *ntp2);

int Curl_ngtcp2_conn_decode_and_set_0rtt_transport_params(
  struct curl_ngtcp2 *ntp2, const uint8_t *data, size_t datalen);
ngtcp2_ssize Curl_ngtcp2_conn_encode_0rtt_transport_params(
  struct curl_ngtcp2 *ntp2, uint8_t *dest, size_t destlen);
void Curl_ngtcp2_conn_extend_max_offset(struct curl_ngtcp2 *ntp2,
                                        uint64_t datalen);
int Curl_ngtcp2_conn_extend_max_stream_offset(struct curl_ngtcp2 *ntp2,
                                              int64_t stream_id,
                                              uint64_t datalen);
const ngtcp2_ccerr *Curl_ngtcp2_conn_get_ccerr(struct curl_ngtcp2 *ntp2);
uint64_t Curl_ngtcp2_conn_get_cwnd_left(struct curl_ngtcp2 *ntp2);
ngtcp2_tstamp Curl_ngtcp2_conn_get_expiry(struct curl_ngtcp2 *ntp2);
int Curl_ngtcp2_conn_get_handshake_completed(struct curl_ngtcp2 *ntp2);
uint64_t Curl_ngtcp2_conn_get_max_data_left(struct curl_ngtcp2 *ntp2);
size_t Curl_ngtcp2_conn_get_max_tx_udp_payload_size(
  struct curl_ngtcp2 *ntp2);
size_t Curl_ngtcp2_conn_get_path_max_tx_udp_payload_size(
  struct curl_ngtcp2 *ntp2);
const ngtcp2_transport_params *
Curl_ngtcp2_conn_get_remote_transport_params(struct curl_ngtcp2 *ntp2);
size_t Curl_ngtcp2_conn_get_send_quantum(struct curl_ngtcp2 *ntp2);
uint64_t Curl_ngtcp2_conn_get_streams_uni_left(struct curl_ngtcp2 *ntp2);
uint8_t Curl_ngtcp2_conn_get_tls_alert(struct curl_ngtcp2 *ntp2);
#if NGTCP2_VERSION_NUM >= 0x011700
int Curl_ngtcp2_conn_get_tls_early_data_rejected2(
  struct curl_ngtcp2 *ntp2);
#endif
int Curl_ngtcp2_conn_handle_expiry(struct curl_ngtcp2 *ntp2,
                                   ngtcp2_tstamp ts);
int Curl_ngtcp2_conn_in_draining_period(struct curl_ngtcp2 *ntp2);
int Curl_ngtcp2_conn_open_bidi_stream(struct curl_ngtcp2 *ntp2,
                                      int64_t *pstream_id,
                                      void *stream_user_data);
int Curl_ngtcp2_conn_open_uni_stream(struct curl_ngtcp2 *ntp2,
                                     int64_t *pstream_id,
                                     void *stream_user_data);
int Curl_ngtcp2_conn_read_pkt(struct curl_ngtcp2 *ntp2,
                              const ngtcp2_path *path,
                              const ngtcp2_pkt_info *pi, const uint8_t *pkt,
                              size_t pktlen, ngtcp2_tstamp ts);
void Curl_ngtcp2_conn_set_keep_alive_timeout(struct curl_ngtcp2 *ntp2,
                                             ngtcp2_duration timeout);
int Curl_ngtcp2_conn_set_stream_user_data(struct curl_ngtcp2 *ntp2,
                                          int64_t stream_id,
                                          void *stream_user_data);
void Curl_ngtcp2_conn_set_tls_native_handle(struct curl_ngtcp2 *ntp2,
                                            void *tls_native_handle);
int Curl_ngtcp2_conn_shutdown_stream(struct curl_ngtcp2 *ntp2,
                                     uint32_t flags, int64_t stream_id,
                                     uint64_t app_error_code);
int Curl_ngtcp2_conn_shutdown_stream_read(struct curl_ngtcp2 *ntp2,
                                          uint32_t flags, int64_t stream_id,
                                          uint64_t app_error_code);
int Curl_ngtcp2_conn_shutdown_stream_write(struct curl_ngtcp2 *ntp2,
                                           uint32_t flags, int64_t stream_id,
                                           uint64_t app_error_code);
void Curl_ngtcp2_conn_update_pkt_tx_time(struct curl_ngtcp2 *ntp2,
                                         ngtcp2_tstamp ts);
ngtcp2_ssize Curl_ngtcp2_conn_write_connection_close(
  struct curl_ngtcp2 *ntp2, ngtcp2_path *path, ngtcp2_pkt_info *pi,
  uint8_t *dest, size_t destlen, const ngtcp2_ccerr *ccerr,
  ngtcp2_tstamp ts);
ngtcp2_ssize Curl_ngtcp2_conn_writev_stream(
  struct curl_ngtcp2 *ntp2, ngtcp2_path *path, ngtcp2_pkt_info *pi,
  uint8_t *dest, size_t destlen, ngtcp2_ssize *pdatalen, uint32_t flags,
  int64_t stream_id, const ngtcp2_vec *datav, size_t datavcnt,
  ngtcp2_tstamp ts);

#endif /* USE_NGTCP2 */

#endif /* HEADER_CURL_NGTCP2_SHIM_H */
