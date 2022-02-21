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
#include "curl_printf.h"
#include "timeval.h"
#include "multiif.h"
#include "sendf.h"

//#define DEBUG_HTTP3
#ifdef DEBUG_HTTP3
#define H3BUGF(x) x
#else
#define H3BUGF(x) do { } while(0)
#endif

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
static void MSH3_CALL msh3_header_received(MSH3_REQUEST* Request,
                                           void* IfContext,
                                           const MSH3_HEADER* Header);
static void MSH3_CALL msh3_data_received(MSH3_REQUEST* Request, void* IfContext,
                                         uint32_t Length, const uint8_t* Data);
static void MSH3_CALL msh3_complete(MSH3_REQUEST* Request, void* IfContext,
                                    bool Aborted, uint64_t AbortError);
static void MSH3_CALL msh3_shutdown(MSH3_REQUEST* Request, void* IfContext);

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

static const MSH3_REQUEST_IF msh3_request_if = {
  msh3_header_received,
  msh3_data_received,
  msh3_complete,
  msh3_shutdown
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
  struct quicsocket *qs = &conn->hequic[sockindex];
  bool unsecure = !conn->ssl_config.verifypeer;
  memset(qs, 0, sizeof(*qs));

  (void)sockfd;
  (void)addr;
  (void)addrlen;

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
  MSH3_CONNECTION_STATE state;

  (void)data;

  state = MsH3ConnectionGetState(qs->conn, false);
  *connected = state == MSH3_CONN_CONNECTED;
  if (state == MSH3_CONN_HANDSHAKE_FAILED || state == MSH3_CONN_DISCONNECTED) {
    return CURLE_COULDNT_CONNECT;
  }

  conn->quic = qs;
  conn->recv[sockindex] = msh3_stream_recv;
  conn->send[sockindex] = msh3_stream_send;
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
  struct quicsocket *qs = conn->quic;
  (void)data;
  (void)dead_connection;
  MsH3ConnectionClose(qs->conn);
  MsH3ApiClose(qs->api);
  return CURLE_OK;
}

void Curl_quic_disconnect(struct Curl_easy *data, struct connectdata *conn,
                          int tempindex)
{
  (void)data;
  if(conn->transport == TRNSPRT_QUIC) {
    struct quicsocket *qs = &conn->hequic[tempindex];
    MsH3ConnectionClose(qs->conn);
    MsH3ApiClose(qs->api);
  }
}

static ssize_t msh3_stream_recv(struct Curl_easy *data,
                                int sockindex,
                                char *buf,
                                size_t buffersize,
                                CURLcode *curlcode)
{
  (void)data;
  (void)sockindex;
  (void)buf;
  (void)buffersize;
  *curlcode = CURLE_RECV_ERROR;
  return -1;
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
  MSH3_REQUEST* Request;

  (void)sockindex;
  (void)mem;

  if(!stream->h3req) {
    stream->h3req = TRUE;
    Request = MsH3RequestOpen(qs->conn, &msh3_request_if, NULL, NULL);
    if(!Request) {
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
    return len;
  }
  else {
    H3BUGF(infof(data, "Pass on %zd body bytes to quiche", len));
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }
}


static void MSH3_CALL msh3_header_received(MSH3_REQUEST* Request,
                                           void* IfContext,
                                           const MSH3_HEADER* Header)
{
  (void)Request;
  (void)IfContext;
  (void)Header;
}

static void MSH3_CALL msh3_data_received(MSH3_REQUEST* Request, void* IfContext,
                                         uint32_t Length, const uint8_t* Data)
{
  (void)Request;
  (void)IfContext;
  (void)Length;
  (void)Data;
}

static void MSH3_CALL msh3_complete(MSH3_REQUEST* Request, void* IfContext,
                                    bool Aborted, uint64_t AbortError)
{
  (void)Request;
  (void)IfContext;
  (void)Aborted;
  (void)AbortError;
}

static void MSH3_CALL msh3_shutdown(MSH3_REQUEST* Request, void* IfContext)
{
  (void)Request;
  (void)IfContext;
}

CURLcode Curl_quic_done_sending(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  DEBUGASSERT(conn);
  if(conn->handler == &msh3_curl_handler_http3) {
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
