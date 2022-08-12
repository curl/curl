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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#ifdef USE_MSH3

#include "urldata.h"
#include "timeval.h"
#include "multiif.h"
#include "sendf.h"
#include "connect.h"
#include "h2h3.h"
#include "msh3.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* #define DEBUG_HTTP3 1 */
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
                                struct connectdata *conn,
                                bool dead_connection);
static unsigned int msh3_conncheck(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   unsigned int checks_to_perform);
static Curl_recv msh3_stream_recv;
static Curl_send msh3_stream_send;
static void MSH3_CALL msh3_header_received(MSH3_REQUEST *Request,
                                           void *IfContext,
                                           const MSH3_HEADER *Header);
static void MSH3_CALL msh3_data_received(MSH3_REQUEST *Request,
                                        void *IfContext, uint32_t Length,
                                        const uint8_t *Data);
static void MSH3_CALL msh3_complete(MSH3_REQUEST *Request, void *IfContext,
                                    bool Aborted, uint64_t AbortError);
static void MSH3_CALL msh3_shutdown(MSH3_REQUEST *Request, void *IfContext);

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
  uint32_t v[4];
  MsH3Version(v);
  (void)msnprintf(p, len, "msh3/%d.%d.%d.%d", v[0], v[1], v[2], v[3]);
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
  (void)addr; /* TODO - Pass address along */
  (void)addrlen;

  H3BUGF(infof(data, "creating new api/connection"));

  qs->api = MsH3ApiOpen();
  if(!qs->api) {
    failf(data, "can't create msh3 api");
    return CURLE_FAILED_INIT;
  }

  qs->conn = MsH3ConnectionOpen(qs->api,
                                conn->host.name,
                                (uint16_t)conn->remote_port,
                                unsecure);
  if(!qs->conn) {
    failf(data, "can't create msh3 connection");
    if(qs->api) {
      MsH3ApiClose(qs->api);
    }
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

  state = MsH3ConnectionGetState(qs->conn, false);
  if(state == MSH3_CONN_HANDSHAKE_FAILED || state == MSH3_CONN_DISCONNECTED) {
    failf(data, "failed to connect, state=%u", (uint32_t)state);
    return CURLE_COULDNT_CONNECT;
  }

  if(state == MSH3_CONN_CONNECTED) {
    H3BUGF(infof(data, "connection connected"));
    *connected = true;
    conn->quic = qs;
    conn->recv[sockindex] = msh3_stream_recv;
    conn->send[sockindex] = msh3_stream_send;
    conn->handler = &msh3_curl_handler_http3;
    conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
    conn->httpversion = 30;
    conn->bundle->multiuse = BUNDLE_MULTIPLEX;
    /* TODO - Clean up other happy-eyeballs connection(s)? */
  }

  return CURLE_OK;
}

static int msh3_getsock(struct Curl_easy *data,
                        struct connectdata *conn, curl_socket_t *socks)
{
  struct HTTP *stream = data->req.p.http;
  int bitmap = GETSOCK_BLANK;

  socks[0] = conn->sock[FIRSTSOCKET];

  if(stream->recv_error) {
    bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);
    data->state.drain++;
  }
  else if(stream->recv_header_len || stream->recv_data_len) {
    bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);
    data->state.drain++;
  }

  H3BUGF(infof(data, "msh3_getsock %u", (uint32_t)data->state.drain));

  return bitmap;
}

static CURLcode msh3_do_it(struct Curl_easy *data, bool *done)
{
  struct HTTP *stream = data->req.p.http;
  H3BUGF(infof(data, "msh3_do_it"));
  stream->recv_buf = malloc(MSH3_REQ_INIT_BUF_LEN);
  if(!stream->recv_buf) {
    return CURLE_OUT_OF_MEMORY;
  }
  stream->req = ZERO_NULL;
  msh3_lock_initialize(&stream->recv_lock);
  stream->recv_buf_alloc = MSH3_REQ_INIT_BUF_LEN;
  stream->recv_header_len = 0;
  stream->recv_header_complete = false;
  stream->recv_data_len = 0;
  stream->recv_data_complete = false;
  stream->recv_error = CURLE_OK;
  return Curl_http(data, done);
}

static unsigned int msh3_conncheck(struct Curl_easy *data,
                                   struct connectdata *conn,
                                   unsigned int checks_to_perform)
{
  (void)data;
  (void)conn;
  (void)checks_to_perform;
  H3BUGF(infof(data, "msh3_conncheck"));
  return CONNRESULT_NONE;
}

static void disconnect(struct quicsocket *qs)
{
  if(qs->conn) {
    MsH3ConnectionClose(qs->conn);
    qs->conn = ZERO_NULL;
  }
  if(qs->api) {
    MsH3ApiClose(qs->api);
    qs->api = ZERO_NULL;
  }
}

static CURLcode msh3_disconnect(struct Curl_easy *data,
                                struct connectdata *conn, bool dead_connection)
{
  (void)data;
  (void)dead_connection;
  H3BUGF(infof(data, "disconnecting (msh3)"));
  disconnect(conn->quic);
  return CURLE_OK;
}

void Curl_quic_disconnect(struct Curl_easy *data, struct connectdata *conn,
                          int tempindex)
{
  (void)data;
  if(conn->transport == TRNSPRT_QUIC) {
    H3BUGF(infof(data, "disconnecting QUIC index %u", tempindex));
    disconnect(&conn->hequic[tempindex]);
  }
}

/* Requires stream->recv_lock to be held */
static bool msh3request_ensure_room(struct HTTP *stream, size_t len)
{
  uint8_t *new_recv_buf;
  const size_t cur_recv_len = stream->recv_header_len + stream->recv_data_len;
  if(cur_recv_len + len > stream->recv_buf_alloc) {
    size_t new_recv_buf_alloc_len = stream->recv_buf_alloc;
    do {
      new_recv_buf_alloc_len <<= 1; /* TODO - handle overflow */
    } while(cur_recv_len + len > new_recv_buf_alloc_len);
    new_recv_buf = malloc(new_recv_buf_alloc_len);
    if(!new_recv_buf) {
      return false;
    }
    if(cur_recv_len) {
      memcpy(new_recv_buf, stream->recv_buf, cur_recv_len);
    }
    stream->recv_buf_alloc = new_recv_buf_alloc_len;
    free(stream->recv_buf);
    stream->recv_buf = new_recv_buf;
  }
  return true;
}

static void MSH3_CALL msh3_header_received(MSH3_REQUEST *Request,
                                           void *IfContext,
                                           const MSH3_HEADER *Header)
{
  struct HTTP *stream = IfContext;
  size_t total_len;
  (void)Request;

  if(stream->recv_header_complete) {
    H3BUGF(printf("* ignoring header after data\n"));
    return;
  }

  msh3_lock_acquire(&stream->recv_lock);

  if((Header->NameLength == 7) &&
     !strncmp(H2H3_PSEUDO_STATUS, (char *)Header->Name, 7)) {
     total_len = 9 + Header->ValueLength;
    if(!msh3request_ensure_room(stream, total_len)) {
      /* TODO - handle error */
      goto release_lock;
    }
    msnprintf((char *)stream->recv_buf + stream->recv_header_len,
              stream->recv_buf_alloc - stream->recv_header_len,
              "HTTP/3 %.*s\n", (int)Header->ValueLength, Header->Value);
  }
  else {
    total_len = Header->NameLength + 4 + Header->ValueLength;
    if(!msh3request_ensure_room(stream, total_len)) {
      /* TODO - handle error */
      goto release_lock;
    }
    msnprintf((char *)stream->recv_buf + stream->recv_header_len,
              stream->recv_buf_alloc - stream->recv_header_len,
              "%.*s: %.*s\n",
              (int)Header->NameLength, Header->Name,
              (int)Header->ValueLength, Header->Value);
  }

  stream->recv_header_len += total_len - 1; /* don't include null-terminator */

release_lock:
  msh3_lock_release(&stream->recv_lock);
}

static void MSH3_CALL msh3_data_received(MSH3_REQUEST *Request,
                                         void *IfContext, uint32_t Length,
                                         const uint8_t *Data)
{
  struct HTTP *stream = IfContext;
  size_t cur_recv_len = stream->recv_header_len + stream->recv_data_len;
  (void)Request;
  H3BUGF(printf("* msh3_data_received %u. %zu buffered, %zu allocated\n",
                Length, cur_recv_len, stream->recv_buf_alloc));
  msh3_lock_acquire(&stream->recv_lock);
  if(!stream->recv_header_complete) {
    H3BUGF(printf("* Headers complete!\n"));
    if(!msh3request_ensure_room(stream, 2)) {
      /* TODO - handle error */
      goto release_lock;
    }
    stream->recv_buf[stream->recv_header_len++] = '\r';
    stream->recv_buf[stream->recv_header_len++] = '\n';
    stream->recv_header_complete = true;
    cur_recv_len += 2;
  }
  if(!msh3request_ensure_room(stream, Length)) {
    /* TODO - handle error */
    goto release_lock;
  }
  memcpy(stream->recv_buf + cur_recv_len, Data, Length);
  stream->recv_data_len += (size_t)Length;
release_lock:
  msh3_lock_release(&stream->recv_lock);
}

static void MSH3_CALL msh3_complete(MSH3_REQUEST *Request, void *IfContext,
                                    bool Aborted, uint64_t AbortError)
{
  struct HTTP *stream = IfContext;
  (void)Request;
  (void)AbortError;
  H3BUGF(printf("* msh3_complete, aborted=%s\n", Aborted ? "true" : "false"));
  msh3_lock_acquire(&stream->recv_lock);
  if(Aborted) {
    stream->recv_error = CURLE_HTTP3; /* TODO - how do we pass AbortError? */
  }
  stream->recv_header_complete = true;
  stream->recv_data_complete = true;
  msh3_lock_release(&stream->recv_lock);
}

static void MSH3_CALL msh3_shutdown(MSH3_REQUEST *Request, void *IfContext)
{
  struct HTTP *stream = IfContext;
  (void)Request;
  (void)stream;
}

static_assert(sizeof(MSH3_HEADER) == sizeof(struct h2h3pseudo),
              "Sizes must match for cast below to work");

static ssize_t msh3_stream_send(struct Curl_easy *data,
                                int sockindex,
                                const void *mem,
                                size_t len,
                                CURLcode *curlcode)
{
  struct connectdata *conn = data->conn;
  struct HTTP *stream = data->req.p.http;
  struct quicsocket *qs = conn->quic;
  struct h2h3req *hreq;

  (void)sockindex;
  H3BUGF(infof(data, "msh3_stream_send %zu", len));

  if(!stream->req) {
    *curlcode = Curl_pseudo_headers(data, mem, len, &hreq);
    if(*curlcode) {
      failf(data, "Curl_pseudo_headers failed");
      return -1;
    }
    H3BUGF(infof(data, "starting request with %zu headers", hreq->entries));
    stream->req = MsH3RequestOpen(qs->conn, &msh3_request_if, stream,
                                 (MSH3_HEADER*)hreq->header, hreq->entries);
    Curl_pseudo_free(hreq);
    if(!stream->req) {
      failf(data, "request open failed");
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
    *curlcode = CURLE_OK;
    return len;
  }
  H3BUGF(infof(data, "send %zd body bytes on request %p", len,
               (void *)stream->req));
  *curlcode = CURLE_SEND_ERROR;
  return -1;
}

static ssize_t msh3_stream_recv(struct Curl_easy *data,
                                int sockindex,
                                char *buf,
                                size_t buffersize,
                                CURLcode *curlcode)
{
  struct HTTP *stream = data->req.p.http;
  size_t outsize = 0;
  (void)sockindex;
  H3BUGF(infof(data, "msh3_stream_recv %zu", buffersize));

  if(stream->recv_error) {
    failf(data, "request aborted");
    *curlcode = stream->recv_error;
    return -1;
  }

  msh3_lock_acquire(&stream->recv_lock);

  if(stream->recv_header_len) {
    outsize = buffersize;
    if(stream->recv_header_len < outsize) {
      outsize = stream->recv_header_len;
    }
    memcpy(buf, stream->recv_buf, outsize);
    if(outsize < stream->recv_header_len + stream->recv_data_len) {
      memmove(stream->recv_buf, stream->recv_buf + outsize,
              stream->recv_header_len + stream->recv_data_len - outsize);
    }
    stream->recv_header_len -= outsize;
    H3BUGF(infof(data, "returned %zu bytes of headers", outsize));
  }
  else if(stream->recv_data_len) {
    outsize = buffersize;
    if(stream->recv_data_len < outsize) {
      outsize = stream->recv_data_len;
    }
    memcpy(buf, stream->recv_buf, outsize);
    if(outsize < stream->recv_data_len) {
      memmove(stream->recv_buf, stream->recv_buf + outsize,
              stream->recv_data_len - outsize);
    }
    stream->recv_data_len -= outsize;
    H3BUGF(infof(data, "returned %zu bytes of data", outsize));
  }
  else if(stream->recv_data_complete) {
    H3BUGF(infof(data, "receive complete"));
  }

  msh3_lock_release(&stream->recv_lock);

  return (ssize_t)outsize;
}

CURLcode Curl_quic_done_sending(struct Curl_easy *data)
{
  struct connectdata *conn = data->conn;
  H3BUGF(infof(data, "Curl_quic_done_sending"));
  if(conn->handler == &msh3_curl_handler_http3) {
    struct HTTP *stream = data->req.p.http;
    stream->upload_done = TRUE;
  }

  return CURLE_OK;
}

void Curl_quic_done(struct Curl_easy *data, bool premature)
{
  struct HTTP *stream = data->req.p.http;
  (void)premature;
  H3BUGF(infof(data, "Curl_quic_done"));
  if(stream) {
    if(stream->recv_buf) {
      Curl_safefree(stream->recv_buf);
      msh3_lock_uninitialize(&stream->recv_lock);
    }
    if(stream->req) {
      MsH3RequestClose(stream->req);
      stream->req = ZERO_NULL;
    }
  }
}

bool Curl_quic_data_pending(const struct Curl_easy *data)
{
  struct HTTP *stream = data->req.p.http;
  H3BUGF(infof((struct Curl_easy *)data, "Curl_quic_data_pending"));
  return stream->recv_header_len || stream->recv_data_len;
}

/*
 * Called from transfer.c:Curl_readwrite when neither HTTP level read
 * nor write is performed. It is a good place to handle timer expiry
 * for QUIC transport.
 */
CURLcode Curl_quic_idle(struct Curl_easy *data)
{
  (void)data;
  H3BUGF(infof(data, "Curl_quic_idle"));
  return CURLE_OK;
}

#endif /* USE_MSH3 */
