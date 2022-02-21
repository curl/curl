/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_MSH3

#include "urldata.h"

static CURLcode msh3_do_it(struct Curl_easy *data, bool *done);
static int msh3_getsock(struct Curl_easy *data,
                        struct connectdata *conn, curl_socket_t *socks);
static CURLcode msh3_disconnect(struct Curl_easy *data,
                                struct connectdata *conn, bool dead_connection);
static unsigned int msh3_conncheck(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   unsigned int checks_to_perform);
static Curl_recv msh3_stream_recv;
static Curl_send msh3_stream_send;

static const struct Curl_handler msh3_curl_handler_http3 = {
  "HTTPS",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  msh3_do_it,                           /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  msh3_getsock,                         /* proto_getsock */
  msh3_getsock,                         /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  msh3_getsock,                         /* perform_getsock */
  msh3_disconnect,                      /* disconnect */
  ZERO_NULL,                            /* readwrite */
  msh3_conncheck,                       /* connection_check */
  ZERO_NULL,                            /* attach connection */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTPS,                      /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_STREAM          /* flags */
};

void Curl_quic_ver(char *p, size_t len)
{
  (void)msnprintf(p, len, "msh3/%s", "0.0.1");
}

CURLcode Curl_quic_connect(struct Curl_easy *data,
                           struct connectdata *conn,
                           curl_socket_t sockfd,
                           int sockindex,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  CURLcode result;
  struct quicsocket *qs = &conn->hequic[sockindex];
  bool unsecure = !conn->ssl_config.verifypeer;
  memset(qs, 0, sizeof(*qs));

  qs->api = MsH3ApiOpen();
  if(!qs->api) {
    failf(data, "can't create msh3 api");
    return CURLE_FAILED_INIT;
  }

  qs->conn = MsH3ConnectionOpen(qs->api, conn->host.name, unsecure);
  if(!qs->conn) {
    failf(data, "can't create msh3 connection");
    if(qs->api) MsH3ApiClose(qs->api);
    return CURLE_FAILED_INIT;
  }

  return CURLE_OK;
}

CURLcode Curl_quic_is_connected(struct Curl_easy *data,
                                struct connectdata *conn,
                                int sockindex,
                                bool *connected)
{
  struct quicsocket *qs = &conn->hequic[sockindex];

  MSH3_CONNECTION_STATE state = MsH3ConnectionGetState(qs->conn, false);
  *connected = state == MSH3_CONN_CONNECTED;
  if (state == MSH3_CONN_HANDSHAKE_FAILED || state == MSH3_CONN_DISCONNECTED) {
    return CURLE_COULDNT_CONNECT;
  }

  conn->quic = qs;
  conn->recv[sockindex] = h3_stream_recv;
  conn->send[sockindex] = h3_stream_send;
  conn->handler = &msh3_curl_handler_http3;
  conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  conn->httpversion = 30;
  conn->bundle->multiuse = BUNDLE_MULTIPLEX;

  // TODO - Set up function pointers?
  return CURLE_OK;
}

static int msh3_getsock(struct Curl_easy *data,
                        struct connectdata *conn, curl_socket_t *socks)
{
  struct SingleRequest *k = &data->req;
  int bitmap = GETSOCK_BLANK;

  socks[0] = conn->sock[FIRSTSOCKET];

  /* in a HTTP/2 connection we can basically always get a frame so we should
     always be ready for one */
  bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);

  /* we're still uploading or the HTTP/2 layer wants to send data */
  if((k->keepon & (KEEP_SEND|KEEP_SEND_PAUSE)) == KEEP_SEND)
    bitmap |= GETSOCK_WRITESOCK(FIRSTSOCKET);

  return bitmap;
}

static CURLcode msh3_do_it(struct Curl_easy *data, bool *done)
{
  struct HTTP *stream = data->req.p.http;
  stream->h3req = FALSE; /* not sent */
  return Curl_http(data, done);
}

static unsigned int msh3_conncheck(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   unsigned int checks_to_perform)
{
  (void)data;
  (void)conn;
  (void)checks_to_perform;
  return CONNRESULT_NONE;
}

static CURLcode msh3_disconnect(struct Curl_easy *data,
                                struct connectdata *conn, bool dead_connection)
{
  (void)data;
  struct quicsocket *qs = conn->quic;
  (void)dead_connection;
  MsH3ConnectionClose(qs->conn);
  MsH3ApiClose(qs->api);
  return CURLE_OK;
}

void Curl_quic_disconnect(struct Curl_easy *data, struct connectdata *conn,
                          int tempindex)
{
  if(conn->transport == TRNSPRT_QUIC)
    msh3_disconnect(data, &conn->hequic[tempindex], false);
}

static ssize_t msh3_stream_recv(struct Curl_easy *data,
                                int sockindex,
                                char *buf,
                                size_t buffersize,
                                CURLcode *curlcode)
{
}

static ssize_t msh3_stream_send(struct Curl_easy *data,
                                int sockindex,
                                const void *mem,
                                size_t len,
                                CURLcode *curlcode)
{
  struct connectdata *conn = data->conn;
  struct HTTP *stream = data->req.p.http;
  struct quicsocket *qs = conn->quic;

  if(!stream->h3req) {
    stream->h3req = TRUE;
    CURLcode result = http_request(data, mem, len);
    if(result) {
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
    sent = len;
  }
  else {
    H3BUGF(infof(data, "Pass on %zd body bytes to quiche", len));
    sent = quiche_h3_send_body(qs->h3c, qs->conn, stream->stream3_id,
                               (uint8_t *)mem, len, FALSE);
    if(sent < 0) {
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
  }
}

CURLcode Curl_quic_done_sending(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  DEBUGASSERT(conn);
  if(conn->handler == &Curl_handler_http3) {
    // TODO - What now?
  }

  return CURLE_OK;
}

void Curl_quic_done(struct Curl_easy *data, bool premature)
{
  (void)data;
  (void)premature;
}

bool Curl_quic_data_pending(const struct Curl_easy *data)
{
  (void)data;
  return FALSE;
}

#include "msh3.h"

#endif // USE_MSH3
