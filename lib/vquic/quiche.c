/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_QUICHE
#include <quiche.h>
#include <openssl/err.h>
#include "urldata.h"
#include "sendf.h"
#include "strdup.h"
#include "rand.h"
#include "quic.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_MAX_DATA (1*1024*1024)
#define QUIC_IDLE_TIMEOUT 60 * 1000 /* milliseconds */

static CURLcode process_ingress(struct connectdata *conn,
                                curl_socket_t sockfd);

static CURLcode flush_egress(struct connectdata *conn, curl_socket_t sockfd);

static Curl_recv quic_stream_recv;
static Curl_send quic_stream_send;


CURLcode Curl_quic_connect(struct connectdata *conn, curl_socket_t sockfd,
                           const struct sockaddr *addr, socklen_t addrlen)
{
  CURLcode result;
  struct quicsocket *qs = &conn->quic;
  (void)addr;
  (void)addrlen;

  infof(conn->data, "Connecting socket %d over QUIC\n", sockfd);

  qs->cfg = quiche_config_new(QUICHE_PROTOCOL_VERSION);
  if(!qs->cfg)
    return CURLE_FAILED_INIT; /* TODO: better return code */

  quiche_config_set_idle_timeout(qs->cfg, QUIC_IDLE_TIMEOUT);
  quiche_config_set_initial_max_data(qs->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_bidi_local(qs->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_bidi_remote(qs->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_stream_data_uni(qs->cfg, QUIC_MAX_DATA);
  quiche_config_set_initial_max_streams_bidi(qs->cfg, QUIC_MAX_STREAMS);
  quiche_config_set_initial_max_streams_uni(qs->cfg, QUIC_MAX_STREAMS);
  quiche_config_set_application_protos(qs->cfg, (uint8_t *) "\x05hq-20", 6);

  result = Curl_rand(conn->data, qs->scid, sizeof(qs->scid));
  if(result)
    return result;

  qs->conn = quiche_connect(conn->host.name, (const uint8_t *) qs->scid,
                            sizeof(qs->scid), qs->cfg);
  if(!qs->conn)
    return CURLE_FAILED_INIT; /* TODO: better return code */

  result = flush_egress(conn, sockfd);
  if(result)
    return CURLE_FAILED_INIT; /* TODO: better return code */

  infof(conn->data, "Sent QUIC client Initial\n");

  return CURLE_OK;
}

CURLcode Curl_quic_is_connected(struct connectdata *conn, int sockindex,
                                bool *done)
{
  CURLcode result;
  struct quicsocket *qs = &conn->quic;
  curl_socket_t sockfd = conn->sock[sockindex];

  result = process_ingress(conn, sockfd);
  if(result)
    return result;

  result = flush_egress(conn, sockfd);
  if(result)
    return result;

  if(quiche_conn_is_established(qs->conn)) {
    conn->recv[sockindex] = quic_stream_recv;
    conn->send[sockindex] = quic_stream_send;
    *done = TRUE;
  }

  return CURLE_OK;
}

static CURLcode process_ingress(struct connectdata *conn, int sockfd)
{
  ssize_t recvd;
  struct quicsocket *qs = &conn->quic;
  static uint8_t buf[65535];

  do {
    recvd = recv(sockfd, buf, sizeof(buf), 0);
    if((recvd < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
      break;

    if(recvd < 0)
      return CURLE_RECV_ERROR;

    recvd = quiche_conn_recv(qs->conn, buf, recvd);
    if(recvd == QUICHE_ERR_DONE)
      break;

    if(recvd < 0)
      return CURLE_RECV_ERROR;
  } while(1);

  return CURLE_OK;
}

static CURLcode flush_egress(struct connectdata *conn, int sockfd)
{
  ssize_t sent;
  struct quicsocket *qs = &conn->quic;
  static uint8_t out[1200];

  do {
    sent = quiche_conn_send(qs->conn, out, sizeof(out));
    if(sent == QUICHE_ERR_DONE)
      break;

    if(sent < 0)
      return CURLE_SEND_ERROR;

    sent = send(sockfd, out, sent, 0);
    if(sent < 0)
      return CURLE_SEND_ERROR;
  } while(1);

  return CURLE_OK;
}

static ssize_t quic_stream_recv(struct connectdata *conn,
                                int sockindex,
                                char *buf,
                                size_t buffersize,
                                CURLcode *curlcode)
{
  bool fin;
  ssize_t recvd;
  struct quicsocket *qs = &conn->quic;
  curl_socket_t sockfd = conn->sock[sockindex];

  if(process_ingress(conn, sockfd)) {
    *curlcode = CURLE_RECV_ERROR;
    return -1;
  }

  recvd = quiche_conn_stream_recv(qs->conn, 0, (uint8_t *) buf, buffersize, &fin);
  if(recvd == QUICHE_ERR_DONE) {
    *curlcode = CURLE_AGAIN;
    return -1;
  }

  if(recvd < 0) {
    *curlcode = CURLE_RECV_ERROR;
    return -1;
  }

  *curlcode = CURLE_OK;
  return recvd;
}

static ssize_t quic_stream_send(struct connectdata *conn,
                                int sockindex,
                                const void *mem,
                                size_t len,
                                CURLcode *curlcode)
{
  ssize_t sent;
  struct quicsocket *qs = &conn->quic;
  curl_socket_t sockfd = conn->sock[sockindex];

  sent = quiche_conn_stream_send(qs->conn, 0, mem, len, true);
  if(sent < 0) {
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }

  if(flush_egress(conn, sockfd)) {
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }

  *curlcode = CURLE_OK;
  return sent;
}

/*
 * Store quiche version info in this buffer, Prefix with a space.  Return total
 * length written.
 */
int Curl_quic_ver(char *p, size_t len)
{
  return msnprintf(p, len, " quiche");
}

#endif
