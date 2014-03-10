/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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

#ifdef USE_NGHTTP2
#define _MPRINTF_REPLACE
#include <curl/mprintf.h>

#include <nghttp2/nghttp2.h>
#include "urldata.h"
#include "http2.h"
#include "http.h"
#include "sendf.h"
#include "curl_base64.h"
#include "curl_memory.h"
#include "rawstr.h"
#include "multiif.h"

/* include memdebug.h last */
#include "memdebug.h"

#if (NGHTTP2_VERSION_NUM < 0x000300)
#error too old nghttp2 version, upgrade!
#endif

static int http2_perform_getsock(const struct connectdata *conn,
                                 curl_socket_t *sock, /* points to
                                                         numsocks
                                                         number of
                                                         sockets */
                                 int numsocks)
{
  const struct http_conn *httpc = &conn->proto.httpc;
  int bitmap = GETSOCK_BLANK;
  (void)numsocks;

  /* TODO We should check underlying socket state if it is SSL socket
     because of renegotiation. */
  sock[0] = conn->sock[FIRSTSOCKET];

  if(nghttp2_session_want_read(httpc->h2))
    bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);

  if(nghttp2_session_want_write(httpc->h2))
    bitmap |= GETSOCK_WRITESOCK(FIRSTSOCKET);

  return bitmap;
}

static int http2_getsock(struct connectdata *conn,
                         curl_socket_t *sock, /* points to numsocks
                                                 number of sockets */
                         int numsocks)
{
  return http2_perform_getsock(conn, sock, numsocks);
}

static CURLcode http2_disconnect(struct connectdata *conn,
                                 bool dead_connection)
{
  struct http_conn *httpc = &conn->proto.httpc;
  (void)dead_connection;

  infof(conn->data, "HTTP/2 DISCONNECT starts now\n");

  nghttp2_session_del(httpc->h2);

  Curl_safefree(httpc->header_recvbuf->buffer);
  Curl_safefree(httpc->header_recvbuf);

  Curl_safefree(httpc->inbuf);

  infof(conn->data, "HTTP/2 DISCONNECT done\n");

  return CURLE_OK;
}

/*
 * HTTP2 handler interface. This isn't added to the general list of protocols
 * but will be used at run-time when the protocol is dynamically switched from
 * HTTP to HTTP2.
 */
const struct Curl_handler Curl_handler_http2 = {
  "HTTP2",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL     ,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  http2_getsock,                        /* proto_getsock */
  http2_getsock,                        /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  http2_perform_getsock,                /* perform_getsock */
  http2_disconnect,                     /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};

const struct Curl_handler Curl_handler_http2_ssl = {
  "HTTP2",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ZERO_NULL,                            /* do_it */
  ZERO_NULL     ,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  http2_getsock,                        /* proto_getsock */
  http2_getsock,                        /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  http2_perform_getsock,                /* perform_getsock */
  http2_disconnect,                     /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTP | CURLPROTO_HTTPS,     /* protocol */
  PROTOPT_SSL                           /* flags */
};

/*
 * Store nghttp2 version info in this buffer, Prefix with a space.  Return
 * total length written.
 */
int Curl_http2_ver(char *p, size_t len)
{
  nghttp2_info *h2 = nghttp2_version(0);
  return snprintf(p, len, " nghttp2/%s", h2->version_str);
}

/*
 * The implementation of nghttp2_send_callback type. Here we write |data| with
 * size |length| to the network and return the number of bytes actually
 * written. See the documentation of nghttp2_send_callback for the details.
 */
static ssize_t send_callback(nghttp2_session *h2,
                             const uint8_t *data, size_t length, int flags,
                             void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *httpc = &conn->proto.httpc;
  ssize_t written;
  CURLcode rc;
  (void)h2;
  (void)flags;

  rc = 0;
  written = ((Curl_send*)httpc->send_underlying)(conn, FIRSTSOCKET,
                                                 data, length, &rc);

  if(rc == CURLE_AGAIN) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  if(written == -1) {
    failf(conn->data, "Failed sending HTTP2 data");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if(!written)
    return NGHTTP2_ERR_WOULDBLOCK;

  return written;
}

static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *c = &conn->proto.httpc;
  int rv;
  (void)session;
  (void)frame;
  infof(conn->data, "on_frame_recv() was called with header %x\n",
        frame->hd.type);
  switch(frame->hd.type) {
  case NGHTTP2_HEADERS:
    if(frame->headers.cat != NGHTTP2_HCAT_RESPONSE)
      break;
    c->bodystarted = TRUE;
    Curl_add_buffer(c->header_recvbuf, "\r\n", 2);
    c->nread_header_recvbuf = c->len < c->header_recvbuf->size_used ?
      c->len : c->header_recvbuf->size_used;

    memcpy(c->mem, c->header_recvbuf->buffer, c->nread_header_recvbuf);

    c->mem += c->nread_header_recvbuf;
    c->len -= c->nread_header_recvbuf;
    break;
  case NGHTTP2_PUSH_PROMISE:
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                   frame->hd.stream_id, NGHTTP2_CANCEL);
    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
    break;
  }
  return 0;
}

static int on_invalid_frame_recv(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 nghttp2_error_code error_code, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  infof(conn->data, "on_invalid_frame_recv() was called, error_code = %d\n",
        error_code);
  return 0;
}

static int on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              const uint8_t *data, size_t len, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *c = &conn->proto.httpc;
  size_t nread;
  (void)session;
  (void)flags;
  (void)data;
  infof(conn->data, "on_data_chunk_recv() "
        "len = %u, stream = %x\n", len, stream_id);

  if(stream_id != c->stream_id) {
    return 0;
  }

  nread = c->len < len ? c->len : len;
  memcpy(c->mem, data, nread);

  c->mem += nread;
  c->len -= nread;

  infof(conn->data, "%zu data written\n", nread);

  if(nread < len) {
    c->data = data + nread;
    c->datalen = len - nread;
    return NGHTTP2_ERR_PAUSE;
  }
  return 0;
}

static int before_frame_send(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *c = &conn->proto.httpc;
  (void)session;
  (void)frame;
  infof(conn->data, "before_frame_send() was called\n");
  if(frame->hd.type == NGHTTP2_HEADERS &&
     frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    /* Get stream ID of our request */
    c->stream_id = frame->hd.stream_id;
  }
  return 0;
}
static int on_frame_send(nghttp2_session *session,
                         const nghttp2_frame *frame,
                         void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  infof(conn->data, "on_frame_send() was called\n");
  return 0;
}
static int on_frame_not_send(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             int lib_error_code, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  infof(conn->data, "on_frame_not_send() was called, lib_error_code = %d\n",
        lib_error_code);
  return 0;
}
static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           nghttp2_error_code error_code, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *c = &conn->proto.httpc;
  (void)session;
  (void)stream_id;
  infof(conn->data, "on_stream_close() was called, error_code = %d\n",
        error_code);

  if(stream_id != c->stream_id) {
    return 0;
  }

  c->closed = TRUE;

  return 0;
}

static int on_unknown_frame_recv(nghttp2_session *session,
                                 const uint8_t *head, size_t headlen,
                                 const uint8_t *payload, size_t payloadlen,
                                 void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)head;
  (void)headlen;
  (void)payload;
  (void)payloadlen;
  infof(conn->data, "on_unknown_frame_recv() was called\n");
  return 0;
}
static int on_begin_headers(nghttp2_session *session,
                            const nghttp2_frame *frame, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  infof(conn->data, "on_begin_headers() was called\n");
  return 0;
}

static const char STATUS[] = ":status";

/* frame->hd.type is either NGHTTP2_HEADERS or NGHTTP2_PUSH_PROMISE */
static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                      const uint8_t *name, size_t namelen,
                      const uint8_t *value, size_t valuelen,
                      void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *c = &conn->proto.httpc;
  (void)session;
  (void)frame;

  if(frame->hd.stream_id != c->stream_id) {
    return 0;
  }

  if(namelen == sizeof(":status") - 1 &&
     memcmp(STATUS, name, namelen) == 0) {
    snprintf(c->header_recvbuf->buffer, 13, "HTTP/2.0 %s", value);
    c->header_recvbuf->buffer[12] = '\r';
    return 0;
  }
  else {
    /* convert to a HTTP1-style header */
    infof(conn->data, "got header\n");
    Curl_add_buffer(c->header_recvbuf, name, namelen);
    Curl_add_buffer(c->header_recvbuf, ":", 1);
    Curl_add_buffer(c->header_recvbuf, value, valuelen);
    Curl_add_buffer(c->header_recvbuf, "\r\n", 2);
  }

  return 0; /* 0 is successful */
}

/*
 * This is all callbacks nghttp2 calls
 */
static const nghttp2_session_callbacks callbacks = {
  send_callback,         /* nghttp2_send_callback */
  NULL,                  /* nghttp2_recv_callback */
  on_frame_recv,         /* nghttp2_on_frame_recv_callback */
  on_invalid_frame_recv, /* nghttp2_on_invalid_frame_recv_callback */
  on_data_chunk_recv,    /* nghttp2_on_data_chunk_recv_callback */
  before_frame_send,     /* nghttp2_before_frame_send_callback */
  on_frame_send,         /* nghttp2_on_frame_send_callback */
  on_frame_not_send,     /* nghttp2_on_frame_not_send_callback */
  on_stream_close,       /* nghttp2_on_stream_close_callback */
  on_unknown_frame_recv, /* nghttp2_on_unknown_frame_recv_callback */
  on_begin_headers,      /* nghttp2_on_begin_headers_callback */
  on_header              /* nghttp2_on_header_callback */
#if NGHTTP2_VERSION_NUM >= 0x000400
  , NULL                 /* nghttp2_select_padding_callback */
#endif
};

static ssize_t data_source_read_callback(nghttp2_session *session,
                                         int32_t stream_id,
                                         uint8_t *buf, size_t length,
                                         int *eof,
                                         nghttp2_data_source *source,
                                         void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *c = &conn->proto.httpc;
  size_t nread;
  (void)session;
  (void)stream_id;
  (void)eof;
  (void)source;

  nread = c->upload_len < length ? c->upload_len : length;
  if(nread > 0) {
    memcpy(buf, c->upload_mem, nread);
    c->upload_mem += nread;
    c->upload_len -= nread;
    c->upload_left -= nread;
  }

  if(c->upload_left == 0)
    *eof = 1;
  else if(nread == 0)
    return NGHTTP2_ERR_DEFERRED;

  return nread;
}

/*
 * The HTTP2 settings we send in the Upgrade request
 */
static nghttp2_settings_entry settings[] = {
  { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
  { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, NGHTTP2_INITIAL_WINDOW_SIZE },
};

#define H2_BUFSIZE 4096

/*
 * Initialize nghttp2 for a Curl connection
 */
CURLcode Curl_http2_init(struct connectdata *conn)
{
  if(!conn->proto.httpc.h2) {
    int rc;
    conn->proto.httpc.inbuf = malloc(H2_BUFSIZE);
    if(conn->proto.httpc.inbuf == NULL)
      return CURLE_OUT_OF_MEMORY;

    /* The nghttp2 session is not yet setup, do it */
    rc = nghttp2_session_client_new(&conn->proto.httpc.h2,
                                    &callbacks, conn);
    if(rc) {
      failf(conn->data, "Couldn't initialize nghttp2!");
      return CURLE_OUT_OF_MEMORY; /* most likely at least */
    }
  }
  return CURLE_OK;
}

/*
 * Send a request using http2
 */
CURLcode Curl_http2_send_request(struct connectdata *conn)
{
  (void)conn;
  return CURLE_OK;
}

/*
 * Append headers to ask for a HTTP1.1 to HTTP2 upgrade.
 */
CURLcode Curl_http2_request_upgrade(Curl_send_buffer *req,
                                    struct connectdata *conn)
{
  CURLcode result;
  ssize_t binlen;
  char *base64;
  size_t blen;
  struct SingleRequest *k = &conn->data->req;
  uint8_t *binsettings = conn->proto.httpc.binsettings;

  Curl_http2_init(conn);

  /* As long as we have a fixed set of settings, we don't have to dynamically
   * figure out the base64 strings since it'll always be the same. However,
   * the settings will likely not be fixed every time in the future.
   */

  /* this returns number of bytes it wrote */
  binlen = nghttp2_pack_settings_payload(binsettings, H2_BINSETTINGS_LEN,
                                         settings,
                                         sizeof(settings)/sizeof(settings[0]));
  if(!binlen) {
    failf(conn->data, "nghttp2 unexpectedly failed on pack_settings_payload");
    return CURLE_FAILED_INIT;
  }
  conn->proto.httpc.binlen = binlen;

  result = Curl_base64_encode(conn->data, (const char *)binsettings, binlen,
                              &base64, &blen);
  if(result)
    return result;

  result = Curl_add_bufferf(req,
                            "Connection: Upgrade, HTTP2-Settings\r\n"
                            "Upgrade: %s\r\n"
                            "HTTP2-Settings: %s\r\n",
                            NGHTTP2_PROTO_VERSION_ID, base64);
  Curl_safefree(base64);

  k->upgr101 = UPGR101_REQUESTED;

  return result;
}

/*
 * If the read would block (EWOULDBLOCK) we return -1. Otherwise we return
 * a regular CURLcode value.
 */
static ssize_t http2_recv(struct connectdata *conn, int sockindex,
                          char *mem, size_t len, CURLcode *err)
{
  CURLcode rc;
  ssize_t rv;
  ssize_t nread;
  struct http_conn *httpc = &conn->proto.httpc;

  (void)sockindex; /* we always do HTTP2 on sockindex 0 */

  if(httpc->closed) {
    return 0;
  }

  /* Nullify here because we call nghttp2_session_send() and they
     might refer to the old buffer. */
  httpc->upload_mem = NULL;
  httpc->upload_len = 0;

  if(httpc->bodystarted &&
     httpc->nread_header_recvbuf < httpc->header_recvbuf->size_used) {
    size_t left =
      httpc->header_recvbuf->size_used - httpc->nread_header_recvbuf;
    size_t ncopy = len < left ? len : left;
    memcpy(mem, httpc->header_recvbuf->buffer + httpc->nread_header_recvbuf,
           ncopy);
    httpc->nread_header_recvbuf += ncopy;
    return ncopy;
  }

  if(httpc->data) {
    nread = len < httpc->datalen ? len : httpc->datalen;
    memcpy(mem, httpc->data, nread);

    httpc->data += nread;
    httpc->datalen -= nread;

    infof(conn->data, "%zu data written\n", nread);
    if(httpc->datalen == 0) {
      httpc->data = NULL;
      httpc->datalen = 0;
    }
    return nread;
  }

  conn->proto.httpc.mem = mem;
  conn->proto.httpc.len = len;

  infof(conn->data, "http2_recv: %d bytes buffer\n",
        conn->proto.httpc.len);

  rc = 0;
  nread = ((Curl_recv*)httpc->recv_underlying)(conn, FIRSTSOCKET,
                                               httpc->inbuf, H2_BUFSIZE, &rc);

  if(rc == CURLE_AGAIN) {
    *err = rc;
    return -1;
  }

  if(nread == -1) {
    failf(conn->data, "Failed receiving HTTP2 data");
    *err = rc;
    return 0;
  }

  infof(conn->data, "nread=%zd\n", nread);
  rv = nghttp2_session_mem_recv(httpc->h2,
                                (const uint8_t *)httpc->inbuf, nread);

  if(nghttp2_is_fatal((int)rv)) {
    failf(conn->data, "nghttp2_session_mem_recv() returned %d:%s\n",
          rv, nghttp2_strerror((int)rv));
    *err = CURLE_RECV_ERROR;
    return 0;
  }
  infof(conn->data, "nghttp2_session_mem_recv() returns %zd\n", rv);
  /* Always send pending frames in nghttp2 session, because
     nghttp2_session_mem_recv() may queue new frame */
  rv = nghttp2_session_send(httpc->h2);
  if(rv != 0) {
    *err = CURLE_SEND_ERROR;
    return 0;
  }
  if(len != httpc->len) {
    return len - conn->proto.httpc.len;
  }
  /* If stream is closed, return 0 to signal the http routine to close
     the connection */
  if(httpc->closed) {
    return 0;
  }
  *err = CURLE_AGAIN;
  return -1;
}

#define MAKE_NV(k, v)                                           \
  { (uint8_t*)k, (uint8_t*)v, sizeof(k) - 1, sizeof(v) - 1 }

#define MAKE_NV2(k, v, vlen)                            \
  { (uint8_t*)k, (uint8_t*)v, sizeof(k) - 1, vlen }

/* return number of received (decrypted) bytes */
static ssize_t http2_send(struct connectdata *conn, int sockindex,
                          const void *mem, size_t len, CURLcode *err)
{
  /*
   * BIG TODO: Currently, we send request in this function, but this
   * function is also used to send request body. It would be nice to
   * add dedicated function for request.
   */
  int rv;
  struct http_conn *httpc = &conn->proto.httpc;
  nghttp2_nv *nva;
  size_t nheader;
  size_t i;
  char *hdbuf = (char*)mem;
  char *end;
  nghttp2_data_provider data_prd;
  (void)sockindex;

  infof(conn->data, "http2_send len=%zu\n", len);

  if(httpc->stream_id != -1) {
    /* If stream_id != -1, we have dispatched request HEADERS, and now
       are going to send or sending request body in DATA frame */
    httpc->upload_mem = mem;
    httpc->upload_len = len;
    nghttp2_session_resume_data(httpc->h2, httpc->stream_id);
    rv = nghttp2_session_send(httpc->h2);
    if(nghttp2_is_fatal(rv)) {
      *err = CURLE_SEND_ERROR;
      return -1;
    }
    return len - httpc->upload_len;
  }

  /* Calculate number of headers contained in [mem, mem + len) */
  /* Here, we assume the curl http code generate *correct* HTTP header
     field block */
  nheader = 0;
  for(i = 0; i < len; ++i) {
    if(hdbuf[i] == 0x0a) {
      ++nheader;
    }
  }
  /* We counted additional 2 \n in the first and last line. We need 3
     new headers: :method, :path and :scheme. Therefore we need one
     more space. */
  nheader += 1;
  nva = malloc(sizeof(nghttp2_nv) * nheader);
  if(nva == NULL) {
    *err = CURLE_OUT_OF_MEMORY;
    return -1;
  }
  /* Extract :method, :path from request line */
  end = strchr(hdbuf, ' ');
  nva[0].name = (unsigned char *)":method";
  nva[0].namelen = (uint16_t)strlen((char *)nva[0].name);
  nva[0].value = (unsigned char *)hdbuf;
  nva[0].valuelen = (uint16_t)(end - hdbuf);

  hdbuf = end + 1;

  end = strchr(hdbuf, ' ');
  nva[1].name = (unsigned char *)":path";
  nva[1].namelen = (uint16_t)strlen((char *)nva[1].name);
  nva[1].value = (unsigned char *)hdbuf;
  nva[1].valuelen = (uint16_t)(end - hdbuf);

  nva[2].name = (unsigned char *)":scheme";
  nva[2].namelen = (uint16_t)strlen((char *)nva[2].name);
  if(conn->handler->flags & PROTOPT_SSL)
    nva[2].value = (unsigned char *)"https";
  else
    nva[2].value = (unsigned char *)"http";
  nva[2].valuelen = (uint16_t)strlen((char *)nva[2].value);

  hdbuf = strchr(hdbuf, 0x0a);
  ++hdbuf;

  for(i = 3; i < nheader; ++i) {
    end = strchr(hdbuf, ':');
    assert(end);
    if(end - hdbuf == 4 && Curl_raw_nequal("host", hdbuf, 4)) {
      nva[i].name = (unsigned char *)":authority";
      nva[i].namelen = (uint16_t)strlen((char *)nva[i].name);
    }
    else {
      nva[i].name = (unsigned char *)hdbuf;
      nva[i].namelen = (uint16_t)(end - hdbuf);
    }
    hdbuf = end + 1;
    for(; *hdbuf == ' '; ++hdbuf);
    end = strchr(hdbuf, 0x0d);
    assert(end);
    nva[i].value = (unsigned char *)hdbuf;
    nva[i].valuelen = (uint16_t)(end - hdbuf);

    hdbuf = end + 2;
    /* Inspect Content-Length header field and retrieve the request
       entity length so that we can set END_STREAM to the last DATA
       frame. */
    if(nva[i].namelen == 14 &&
       Curl_raw_nequal("content-length", (char*)nva[i].name, 14)) {
      size_t j;
      for(j = 0; j < nva[i].valuelen; ++j) {
        httpc->upload_left *= 10;
        httpc->upload_left += nva[i].value[j] - '0';
      }
      infof(conn->data, "request content-length=%zu\n", httpc->upload_left);
    }
  }

  switch(conn->data->set.httpreq) {
  case HTTPREQ_POST:
  case HTTPREQ_POST_FORM:
  case HTTPREQ_PUT:
    data_prd.read_callback = data_source_read_callback;
    data_prd.source.ptr = NULL;
    rv = nghttp2_submit_request(httpc->h2, 0, nva, nheader, &data_prd, NULL);
    break;
  default:
    rv = nghttp2_submit_request(httpc->h2, 0, nva, nheader, NULL, NULL);
  }

  Curl_safefree(nva);

  if(rv != 0) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  rv = nghttp2_session_send(httpc->h2);

  if(rv != 0) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  if(httpc->stream_id != -1) {
    /* If whole HEADERS frame was sent off to the underlying socket,
       the nghttp2 library calls data_source_read_callback. But only
       it found that no data available, so it deferred the DATA
       transmission. Which means that nghttp2_session_want_write()
       returns 0 on http2_perform_getsock(), which results that no
       writable socket check is performed. To workaround this, we
       issue nghttp2_session_resume_data() here to bring back DATA
       transmission from deferred state. */
    nghttp2_session_resume_data(httpc->h2, httpc->stream_id);
  }

  return len;
}

int Curl_http2_switched(struct connectdata *conn)
{
  int rv;
  CURLcode rc;
  struct http_conn *httpc = &conn->proto.httpc;
  /* we are switched! */
  /* Don't know this is needed here at this moment. Original
     handler->flags is still useful. */
  if(conn->handler->flags & PROTOPT_SSL)
    conn->handler = &Curl_handler_http2_ssl;
  else
    conn->handler = &Curl_handler_http2;

  httpc->recv_underlying = (recving)conn->recv[FIRSTSOCKET];
  httpc->send_underlying = (sending)conn->send[FIRSTSOCKET];
  conn->recv[FIRSTSOCKET] = http2_recv;
  conn->send[FIRSTSOCKET] = http2_send;
  infof(conn->data, "We have switched to HTTP2\n");
  httpc->bodystarted = FALSE;
  httpc->closed = FALSE;
  httpc->header_recvbuf = Curl_add_buffer_init();
  httpc->nread_header_recvbuf = 0;
  httpc->data = NULL;
  httpc->datalen = 0;
  httpc->upload_left = 0;
  httpc->upload_mem = NULL;
  httpc->upload_len = 0;

  conn->httpversion = 20;

  /* Put place holder for status line */
  Curl_add_buffer(httpc->header_recvbuf, "HTTP/2.0 200\r\n", 14);

  /* TODO: May get CURLE_AGAIN */
  rv = (int) ((Curl_send*)httpc->send_underlying)
    (conn, FIRSTSOCKET,
     NGHTTP2_CLIENT_CONNECTION_HEADER,
     NGHTTP2_CLIENT_CONNECTION_HEADER_LEN,
     &rc);
  assert(rv == 24);
  if(conn->data->req.upgr101 == UPGR101_RECEIVED) {
    /* stream 1 is opened implicitly on upgrade */
    httpc->stream_id = 1;
    /* queue SETTINGS frame (again) */
    rv = nghttp2_session_upgrade(httpc->h2, httpc->binsettings,
                                 httpc->binlen, NULL);
    if(rv != 0) {
      failf(conn->data, "nghttp2_session_upgrade() failed: %s(%d)",
            nghttp2_strerror(rv), rv);
      return -1;
    }
  }
  else {
    /* stream ID is unknown at this point */
    httpc->stream_id = -1;
    rv = nghttp2_submit_settings(httpc->h2, NGHTTP2_FLAG_NONE, NULL, 0);
    if(rv != 0) {
      failf(conn->data, "nghttp2_submit_settings() failed: %s(%d)",
            nghttp2_strerror(rv), rv);
      return -1;
    }
  }
  return 0;
}

#endif
