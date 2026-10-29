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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGTCP2) && \
  defined(USE_NGHTTP3)

#include <ngtcp2/ngtcp2.h>

#include "vquic/ngtcp2_shim.h"

static void ntp2_clear_tuple(struct curl_ngtcp2 *ntp2)
{
  ntp2->path = NULL;
  ntp2->pi = NULL;
  ntp2->dest = NULL;
  ntp2->destlen = 0;
  ntp2->ts = 0;
}

static void ntp2_set_normal(struct curl_ngtcp2 *ntp2)
{
  ntp2_clear_tuple(ntp2);
  ntp2->error_rv = 0;
  ntp2->state = CURL_NGTCP2_NORMAL;
}

static void ntp2_set_close_only(struct curl_ngtcp2 *ntp2, ngtcp2_ssize rv)
{
  ntp2_clear_tuple(ntp2);
  if((ntp2->state != CURL_NGTCP2_CLOSE_ONLY) ||
     (ntp2->error_rv >= 0))
    ntp2->error_rv = (rv < 0) ? rv : NGTCP2_ERR_INVALID_STATE;
  ntp2->state = CURL_NGTCP2_CLOSE_ONLY;
}

static ngtcp2_ssize ntp2_error(const struct curl_ngtcp2 *ntp2)
{
  return (ntp2->error_rv < 0) ? ntp2->error_rv :
    NGTCP2_ERR_INVALID_STATE;
}

static bool ntp2_allow_normal(struct curl_ngtcp2 *ntp2)
{
  if(ntp2->conn && (ntp2->state == CURL_NGTCP2_NORMAL))
    return TRUE;
  if(ntp2->conn && (ntp2->state == CURL_NGTCP2_COALESCING))
    ntp2_set_close_only(ntp2, NGTCP2_ERR_INVALID_STATE);
  return FALSE;
}

static bool ntp2_allow_terminal(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2->conn)
    return FALSE;
  if(ntp2->state == CURL_NGTCP2_COALESCING) {
    ntp2_set_close_only(ntp2, NGTCP2_ERR_INVALID_STATE);
    return FALSE;
  }
  return TRUE;
}

static bool ntp2_allow_shutdown(struct curl_ngtcp2 *ntp2)
{
  return ntp2->conn && (ntp2->state != CURL_NGTCP2_CLOSE_ONLY);
}

static int ntp2_check_int(struct curl_ngtcp2 *ntp2, int rv)
{
  if(rv < NGTCP2_ERR_FATAL)
    ntp2_set_close_only(ntp2, rv);
  return (ntp2->state == CURL_NGTCP2_CLOSE_ONLY) ?
    (int)ntp2_error(ntp2) : rv;
}

static ngtcp2_ssize ntp2_check_ssize(struct curl_ngtcp2 *ntp2,
                                     ngtcp2_ssize rv)
{
  if(rv < NGTCP2_ERR_FATAL)
    ntp2_set_close_only(ntp2, rv);
  return (ntp2->state == CURL_NGTCP2_CLOSE_ONLY) ?
    ntp2_error(ntp2) : rv;
}

static bool ntp2_is_continuation(ngtcp2_ssize rv)
{
  return (rv == NGTCP2_ERR_WRITE_MORE) ||
         (rv == NGTCP2_ERR_STREAM_DATA_BLOCKED) ||
         (rv == NGTCP2_ERR_STREAM_NOT_FOUND) ||
         (rv == NGTCP2_ERR_STREAM_SHUT_WR);
}

bool Curl_ngtcp2_valid(const struct curl_ngtcp2 *ntp2)
{
  return ntp2->conn && (ntp2->state != CURL_NGTCP2_CLOSE_ONLY);
}

bool Curl_ngtcp2_restricted(const struct curl_ngtcp2 *ntp2)
{
  return ntp2->conn && (ntp2->state != CURL_NGTCP2_NORMAL);
}

ngtcp2_conn *Curl_ngtcp2_conn(const struct curl_ngtcp2 *ntp2)
{
  return ntp2->conn;
}

int Curl_ngtcp2_conn_client_new(
  struct curl_ngtcp2 *ntp2, const ngtcp2_cid *dcid,
  const ngtcp2_cid *scid, const ngtcp2_path *path,
  uint32_t client_chosen_version, const ngtcp2_callbacks *callbacks,
  const ngtcp2_settings *settings, const ngtcp2_transport_params *params,
  const ngtcp2_mem *mem, void *user_data)
{
  ngtcp2_conn *conn = NULL;
  int rv;

  if(ntp2->conn)
    return NGTCP2_ERR_INVALID_STATE;
  ntp2_set_normal(ntp2);
  rv = ngtcp2_conn_client_new(&conn, dcid, scid, path,
                              client_chosen_version, callbacks, settings,
                              params, mem, user_data);
  if(!rv)
    ntp2->conn = conn;
  return rv;
}

void Curl_ngtcp2_conn_del(struct curl_ngtcp2 *ntp2)
{
  if(ntp2->conn)
    ngtcp2_conn_del(ntp2->conn);
  memset(ntp2, 0, sizeof(*ntp2));
}

int Curl_ngtcp2_conn_decode_and_set_0rtt_transport_params(
  struct curl_ngtcp2 *ntp2, const uint8_t *data, size_t datalen)
{
  if(!ntp2_allow_normal(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_decode_and_set_0rtt_transport_params(ntp2->conn,
                                                     data, datalen));
}

ngtcp2_ssize Curl_ngtcp2_conn_encode_0rtt_transport_params(
  struct curl_ngtcp2 *ntp2, uint8_t *dest, size_t destlen)
{
  if(!ntp2_allow_normal(ntp2))
    return ntp2_error(ntp2);
  return ntp2_check_ssize(ntp2,
    ngtcp2_conn_encode_0rtt_transport_params(ntp2->conn, dest, destlen));
}

void Curl_ngtcp2_conn_extend_max_offset(struct curl_ngtcp2 *ntp2,
                                        uint64_t datalen)
{
  if(ntp2_allow_normal(ntp2))
    ngtcp2_conn_extend_max_offset(ntp2->conn, datalen);
}

int Curl_ngtcp2_conn_extend_max_stream_offset(struct curl_ngtcp2 *ntp2,
                                              int64_t stream_id,
                                              uint64_t datalen)
{
  if(!ntp2_allow_normal(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_extend_max_stream_offset(ntp2->conn, stream_id, datalen));
}

const ngtcp2_ccerr *Curl_ngtcp2_conn_get_ccerr(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_terminal(ntp2))
    return NULL;
  return ngtcp2_conn_get_ccerr(ntp2->conn);
}

uint64_t Curl_ngtcp2_conn_get_cwnd_left(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return 0;
  return ngtcp2_conn_get_cwnd_left(ntp2->conn);
}

ngtcp2_tstamp Curl_ngtcp2_conn_get_expiry(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return UINT64_MAX;
  return ngtcp2_conn_get_expiry(ntp2->conn);
}

int Curl_ngtcp2_conn_get_handshake_completed(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return 0;
  return ngtcp2_conn_get_handshake_completed(ntp2->conn);
}

uint64_t Curl_ngtcp2_conn_get_max_data_left(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return 0;
  return ngtcp2_conn_get_max_data_left(ntp2->conn);
}

size_t Curl_ngtcp2_conn_get_max_tx_udp_payload_size(
  struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return 0;
  return ngtcp2_conn_get_max_tx_udp_payload_size(ntp2->conn);
}

size_t Curl_ngtcp2_conn_get_path_max_tx_udp_payload_size(
  struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return 0;
  return ngtcp2_conn_get_path_max_tx_udp_payload_size(ntp2->conn);
}

const ngtcp2_transport_params *
Curl_ngtcp2_conn_get_remote_transport_params(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return NULL;
  return ngtcp2_conn_get_remote_transport_params(ntp2->conn);
}

size_t Curl_ngtcp2_conn_get_send_quantum(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return 0;
  return ngtcp2_conn_get_send_quantum(ntp2->conn);
}

uint64_t Curl_ngtcp2_conn_get_streams_uni_left(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return 0;
  return ngtcp2_conn_get_streams_uni_left(ntp2->conn);
}

uint8_t Curl_ngtcp2_conn_get_tls_alert(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_terminal(ntp2))
    return 0;
  return ngtcp2_conn_get_tls_alert(ntp2->conn);
}

#if NGTCP2_VERSION_NUM >= 0x011700
int Curl_ngtcp2_conn_get_tls_early_data_rejected2(
  struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_normal(ntp2))
    return 0;
  return ngtcp2_conn_get_tls_early_data_rejected2(ntp2->conn);
}
#endif

int Curl_ngtcp2_conn_handle_expiry(struct curl_ngtcp2 *ntp2,
                                   ngtcp2_tstamp ts)
{
  if(!ntp2_allow_normal(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_handle_expiry(ntp2->conn, ts));
}

int Curl_ngtcp2_conn_in_draining_period(struct curl_ngtcp2 *ntp2)
{
  if(!ntp2_allow_terminal(ntp2))
    return 0;
  return ngtcp2_conn_in_draining_period(ntp2->conn);
}

int Curl_ngtcp2_conn_open_bidi_stream(struct curl_ngtcp2 *ntp2,
                                      int64_t *pstream_id,
                                      void *stream_user_data)
{
  if(!ntp2_allow_normal(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_open_bidi_stream(ntp2->conn, pstream_id, stream_user_data));
}

int Curl_ngtcp2_conn_open_uni_stream(struct curl_ngtcp2 *ntp2,
                                     int64_t *pstream_id,
                                     void *stream_user_data)
{
  if(!ntp2_allow_normal(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_open_uni_stream(ntp2->conn, pstream_id, stream_user_data));
}

int Curl_ngtcp2_conn_read_pkt(struct curl_ngtcp2 *ntp2,
                              const ngtcp2_path *path,
                              const ngtcp2_pkt_info *pi, const uint8_t *pkt,
                              size_t pktlen, ngtcp2_tstamp ts)
{
  if(!ntp2_allow_normal(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_read_pkt(ntp2->conn, path, pi, pkt, pktlen, ts));
}

void Curl_ngtcp2_conn_set_keep_alive_timeout(struct curl_ngtcp2 *ntp2,
                                             ngtcp2_duration timeout)
{
  if(ntp2_allow_normal(ntp2))
    ngtcp2_conn_set_keep_alive_timeout(ntp2->conn, timeout);
}

int Curl_ngtcp2_conn_set_stream_user_data(struct curl_ngtcp2 *ntp2,
                                          int64_t stream_id,
                                          void *stream_user_data)
{
  if(!ntp2_allow_normal(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_set_stream_user_data(ntp2->conn, stream_id,
                                     stream_user_data));
}

void Curl_ngtcp2_conn_set_tls_native_handle(struct curl_ngtcp2 *ntp2,
                                            void *tls_native_handle)
{
  if(ntp2_allow_normal(ntp2))
    ngtcp2_conn_set_tls_native_handle(ntp2->conn, tls_native_handle);
}

int Curl_ngtcp2_conn_shutdown_stream(struct curl_ngtcp2 *ntp2,
                                     uint32_t flags, int64_t stream_id,
                                     uint64_t app_error_code)
{
  if(!ntp2_allow_shutdown(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_shutdown_stream(ntp2->conn, flags, stream_id,
                                app_error_code));
}

int Curl_ngtcp2_conn_shutdown_stream_read(struct curl_ngtcp2 *ntp2,
                                          uint32_t flags, int64_t stream_id,
                                          uint64_t app_error_code)
{
  if(!ntp2_allow_shutdown(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_shutdown_stream_read(ntp2->conn, flags, stream_id,
                                     app_error_code));
}

int Curl_ngtcp2_conn_shutdown_stream_write(struct curl_ngtcp2 *ntp2,
                                           uint32_t flags, int64_t stream_id,
                                           uint64_t app_error_code)
{
  if(!ntp2_allow_shutdown(ntp2))
    return (int)ntp2_error(ntp2);
  return ntp2_check_int(ntp2,
    ngtcp2_conn_shutdown_stream_write(ntp2->conn, flags, stream_id,
                                      app_error_code));
}

void Curl_ngtcp2_conn_update_pkt_tx_time(struct curl_ngtcp2 *ntp2,
                                         ngtcp2_tstamp ts)
{
  if(ntp2_allow_normal(ntp2))
    ngtcp2_conn_update_pkt_tx_time(ntp2->conn, ts);
}

ngtcp2_ssize Curl_ngtcp2_conn_write_connection_close(
  struct curl_ngtcp2 *ntp2, ngtcp2_path *path, ngtcp2_pkt_info *pi,
  uint8_t *dest, size_t destlen, const ngtcp2_ccerr *ccerr,
  ngtcp2_tstamp ts)
{
  ngtcp2_ssize rv;

  if(!ntp2->conn)
    return ntp2_error(ntp2);
  rv = ngtcp2_conn_write_connection_close(ntp2->conn, path, pi, dest,
                                           destlen, ccerr, ts);
  if(rv < 0)
    ntp2_set_close_only(ntp2, rv);
  else
    ntp2_set_close_only(ntp2, ntp2->error_rv);
  return rv;
}

ngtcp2_ssize Curl_ngtcp2_conn_writev_stream(
  struct curl_ngtcp2 *ntp2, ngtcp2_path *path, ngtcp2_pkt_info *pi,
  uint8_t *dest, size_t destlen, ngtcp2_ssize *pdatalen, uint32_t flags,
  int64_t stream_id, const ngtcp2_vec *datav, size_t datavcnt,
  ngtcp2_tstamp ts)
{
  bool was_coalescing;
  bool may_coalesce;
  ngtcp2_ssize rv;

  if(!ntp2->conn || (ntp2->state == CURL_NGTCP2_CLOSE_ONLY))
    return ntp2_error(ntp2);

  was_coalescing = ntp2->state == CURL_NGTCP2_COALESCING;
  if(was_coalescing && ((ntp2->path != path) || (ntp2->pi != pi) ||
                        (ntp2->dest != dest) ||
                        (ntp2->destlen != destlen) || (ntp2->ts != ts))) {
    ntp2_set_close_only(ntp2, NGTCP2_ERR_INVALID_ARGUMENT);
    return ntp2_error(ntp2);
  }

  rv = ngtcp2_conn_writev_stream(ntp2->conn, path, pi, dest, destlen,
                                  pdatalen, flags, stream_id, datav,
                                  datavcnt, ts);
  if(rv < NGTCP2_ERR_FATAL)
    ntp2_set_close_only(ntp2, rv);
  if(ntp2->state == CURL_NGTCP2_CLOSE_ONLY)
    return ntp2_error(ntp2);

  may_coalesce = was_coalescing ||
    !!(flags & NGTCP2_WRITE_STREAM_FLAG_MORE);
  if((rv < 0) && may_coalesce && !ntp2_is_continuation(rv)) {
    ntp2_set_close_only(ntp2, rv);
    return rv;
  }

  if(may_coalesce && ntp2_is_continuation(rv)) {
    ntp2->path = path;
    ntp2->pi = pi;
    ntp2->dest = dest;
    ntp2->destlen = destlen;
    ntp2->ts = ts;
    ntp2->error_rv = 0;
    ntp2->state = CURL_NGTCP2_COALESCING;
  }
  else
    ntp2_set_normal(ntp2);
  return rv;
}

#endif /* !CURL_DISABLE_HTTP && USE_NGTCP2 && USE_NGHTTP3 */
