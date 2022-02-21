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

#define MSH3_REQ_INIT_BUF_LEN 8192

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

  /* in a HTTP/3 connection we can basically always get a frame so we should
     always be ready for one */
  bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);

  /* we're still uploading or the HTTP/3 layer wants to send data */
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

struct msh3request* make_msh3request(void)
{
  struct msh3request* req = malloc(sizeof(*req));
  if(req) {
    memset(req, 0, sizeof(*req));
    req->recv_buf_alloc = MSH3_REQ_INIT_BUF_LEN;
    req->recv_buf = malloc(MSH3_REQ_INIT_BUF_LEN);
    if (!req->recv_buf) {
      free(req);
      req = ZERO_NULL;
    }
  }
  return req;
}

void free_msh3request(struct msh3request* req)
{
  if(req->req) MsH3RequestClose(req->req);
  free(req->recv_buf);
  free(req);
}

static void MSH3_CALL msh3_header_received(MSH3_REQUEST* Request,
                                           void* IfContext,
                                           const MSH3_HEADER* Header)
{
  struct msh3request* req = IfContext;
  (void)Request;
  (void)req;
  (void)Header;
}

static void MSH3_CALL msh3_data_received(MSH3_REQUEST* Request, void* IfContext,
                                         uint32_t Length, const uint8_t* Data)
{
  struct msh3request* req = IfContext;
  // TODO - Add locking to synchronize with curl thread
  (void)Request;
  if (req->recv_buf_len + (size_t)Length > req->recv_buf_alloc) {
    size_t new_recv_buf_alloc_len = req->recv_buf_alloc << 1; // TODO - handle overflow
    uint8_t* new_recv_buf = malloc(new_recv_buf_alloc_len);
    if (!new_recv_buf) {
      // TODO - handle error
      return;
    }
    if (req->recv_buf_len) {
      memcpy(new_recv_buf, req->recv_buf, req->recv_buf_len);
    }
    req->recv_buf_alloc = new_recv_buf_alloc_len;
    free(req->recv_buf);
    req->recv_buf = new_recv_buf;
  }
  memcpy(req->recv_buf+req->recv_buf_len, Data, Length);
  req->recv_buf_len += (size_t)Length;
}

static void MSH3_CALL msh3_complete(MSH3_REQUEST* Request, void* IfContext,
                                    bool Aborted, uint64_t AbortError)
{
  struct msh3request* req = IfContext;
  (void)Request;
  if(Aborted) {
    req->recv_error = CURLE_RECV_ERROR;
  }
  req->recv_complete = true;
}

static void MSH3_CALL msh3_shutdown(MSH3_REQUEST* Request, void* IfContext)
{
  struct msh3request* req = IfContext;
  (void)Request;
  (void)req;
}

static ssize_t msh3_stream_recv(struct Curl_easy *data,
                                int sockindex,
                                char *buf,
                                size_t buffersize,
                                CURLcode *curlcode)
{
  struct connectdata *conn = data->conn;
  struct HTTP *stream = data->req.p.http;
  struct quicsocket *qs = conn->quic;
  struct msh3request* req = (void*)stream->stream3_id;
  (void)sockindex;
  if(req->recv_complete && req->recv_error) {
    *curlcode = req->recv_error;
    return -1;
  }
  if (req->recv_buf_len) {
    if(req->recv_buf_len < buffersize) {
      buffersize = req->recv_buf_len;
    }
    memcpy(buf, req->recv_buf, buffersize);
    if (buffersize < req->recv_buf_len) {
      memmove(req->recv_buf, req->recv_buf+buffersize,
              req->recv_buf_len-buffersize);
    }
    req->recv_buf_len -= buffersize;
  } else {
    buffersize = 0;
  }
  // TODO - how to handle complete case?
  return (ssize_t)buffersize;
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
  struct msh3request* req;

  (void)sockindex;
  (void)mem;

  if(!stream->h3req) {
    stream->h3req = TRUE;
    req = make_msh3request();
    if (!req) {
      *curlcode = CURLE_OUT_OF_MEMORY;
      return -1;
    }
    req->req = MsH3RequestOpen(qs->conn, &msh3_request_if, req, NULL);
    if(!req->req) {
      free_msh3request(req);
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
    stream->stream3_id = (int64_t)req;
    return len;
  }
  H3BUGF(infof(data, "send %zd body bytes on request %p", len, (void*)stream->stream3_id));
  *curlcode = CURLE_SEND_ERROR;
  return -1;
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
