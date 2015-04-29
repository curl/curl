/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "curl_printf.h"
#include <nghttp2/nghttp2.h>
#include "urldata.h"
#include "http2.h"
#include "http.h"
#include "sendf.h"
#include "curl_base64.h"
#include "rawstr.h"
#include "multiif.h"
#include "bundles.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#define MIN(x,y) ((x)<(y)?(x):(y))

#if (NGHTTP2_VERSION_NUM < 0x000600)
#error too old nghttp2 version, upgrade!
#endif

static int http2_perform_getsock(const struct connectdata *conn,
                                 curl_socket_t *sock, /* points to
                                                         numsocks
                                                         number of
                                                         sockets */
                                 int numsocks)
{
  const struct http_conn *c = &conn->proto.httpc;
  int bitmap = GETSOCK_BLANK;
  (void)numsocks;

  /* TODO We should check underlying socket state if it is SSL socket
     because of renegotiation. */
  sock[0] = conn->sock[FIRSTSOCKET];

  if(nghttp2_session_want_read(c->h2))
    bitmap |= GETSOCK_READSOCK(FIRSTSOCKET);

  if(nghttp2_session_want_write(c->h2))
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
  struct http_conn *c = &conn->proto.httpc;
  (void)dead_connection;

  DEBUGF(infof(conn->data, "HTTP/2 DISCONNECT starts now\n"));

  nghttp2_session_del(c->h2);

  Curl_safefree(c->inbuf);

  DEBUGF(infof(conn->data, "HTTP/2 DISCONNECT done\n"));

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
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
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
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
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
  CURLPROTO_HTTPS,                      /* protocol */
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
  struct http_conn *c = &conn->proto.httpc;
  ssize_t written;
  CURLcode result = CURLE_OK;

  (void)h2;
  (void)flags;

  written = ((Curl_send*)c->send_underlying)(conn, FIRSTSOCKET,
                                             data, length, &result);

  if(result == CURLE_AGAIN) {
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
  struct SessionHandle *data_s = NULL;
  struct HTTP *stream = NULL;
  int rv;
  size_t left, ncopy;
  int32_t stream_id = frame->hd.stream_id;

  (void)session;
  (void)frame;
  DEBUGF(infof(conn->data, "on_frame_recv() was called with header %x\n",
               frame->hd.type));

  if(stream_id) {
    /* get the stream from the hash based on Stream ID, stream ID zero is for
       connection-oriented stuff */
    data_s = Curl_hash_pick(&conn->proto.httpc.streamsh, &stream_id,
                            sizeof(stream_id));
    if(!data_s) {
      /* Receiving a Stream ID not in the hash should not happen, this is an
         internal error more than anything else! */
      failf(conn->data, "Received frame on Stream ID: %x not in stream hash!",
            stream_id);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    stream = data_s->req.protop;
  }

  switch(frame->hd.type) {
  case NGHTTP2_DATA:
    /* If body started on this stream, then receiving DATA is illegal. */
    if(!stream->bodystarted) {
      rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                     stream_id, NGHTTP2_PROTOCOL_ERROR);

      if(nghttp2_is_fatal(rv)) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
    break;
  case NGHTTP2_HEADERS:
    if(frame->headers.cat == NGHTTP2_HCAT_REQUEST)
      break;

    if(stream->bodystarted) {
      /* Only valid HEADERS after body started is trailer header,
         which is not fully supported in this code.  If HEADERS is not
         trailer, then it is a PROTOCOL_ERROR. */
      if((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0) {
        rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                       stream_id, NGHTTP2_PROTOCOL_ERROR);

        if(nghttp2_is_fatal(rv)) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
      break;
    }

    if(stream->status_code == -1) {
      /* No :status header field means PROTOCOL_ERROR. */
      rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                     stream_id, NGHTTP2_PROTOCOL_ERROR);

      if(nghttp2_is_fatal(rv)) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }

      break;
    }

    /* Only final status code signals the end of header */
    if(stream->status_code / 100 != 1)
      stream->bodystarted = TRUE;

    stream->status_code = -1;

    Curl_add_buffer(stream->header_recvbuf, "\r\n", 2);

    left = stream->header_recvbuf->size_used - stream->nread_header_recvbuf;
    ncopy = MIN(stream->len, left);

    memcpy(stream->mem, stream->header_recvbuf->buffer +
           stream->nread_header_recvbuf, ncopy);
    stream->nread_header_recvbuf += ncopy;

    stream->mem += ncopy;
    stream->len -= ncopy;
    break;
  case NGHTTP2_PUSH_PROMISE:
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                   frame->push_promise.promised_stream_id,
                                   NGHTTP2_CANCEL);
    if(nghttp2_is_fatal(rv)) {
      return rv;
    }
    break;
  }
  return 0;
}

static int on_invalid_frame_recv(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 uint32_t error_code, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  DEBUGF(infof(conn->data,
               "on_invalid_frame_recv() was called, error_code = %d\n",
               error_code));
  return 0;
}

static int on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              const uint8_t *data, size_t len, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct HTTP *stream;
  struct SessionHandle *data_s;
  size_t nread;
  (void)session;
  (void)flags;
  (void)data;
  DEBUGF(infof(conn->data, "on_data_chunk_recv() "
               "len = %u, stream = %x\n", len, stream_id));

  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */

  /* get the stream from the hash based on Stream ID */
  data_s = Curl_hash_pick(&conn->proto.httpc.streamsh, &stream_id,
                          sizeof(stream_id));
  if(!data_s) {
    /* Receiving a Stream ID not in the hash should not happen, this is an
       internal error more than anything else! */
    failf(conn->data, "Received frame on Stream ID: %x not in stream hash!",
          stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  stream = data_s->req.protop;

  nread = MIN(stream->len, len);
  memcpy(stream->mem, data, nread);

  stream->mem += nread;
  stream->len -= nread;

  DEBUGF(infof(conn->data, "%zu data received for stream %x "
               "(%zu left in buffer)\n",
               nread, stream_id, stream->len));

  if(nread < len) {
    stream->data = data + nread;
    stream->datalen = len - nread;
    return NGHTTP2_ERR_PAUSE;
  }
  return 0;
}

static int before_frame_send(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  DEBUGF(infof(conn->data, "before_frame_send() was called\n"));
  return 0;
}
static int on_frame_send(nghttp2_session *session,
                         const nghttp2_frame *frame,
                         void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  DEBUGF(infof(conn->data, "on_frame_send() was called\n"));
  return 0;
}
static int on_frame_not_send(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             int lib_error_code, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  DEBUGF(infof(conn->data,
               "on_frame_not_send() was called, lib_error_code = %d\n",
               lib_error_code));
  return 0;
}
static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct SessionHandle *data_s;
  struct HTTP *stream;
  (void)session;
  (void)stream_id;
  DEBUGF(infof(conn->data, "on_stream_close(), error_code = %d, stream %x\n",
               error_code, stream_id));

  if(stream_id) {
    /* get the stream from the hash based on Stream ID, stream ID zero is for
       connection-oriented stuff */
    data_s = Curl_hash_pick(&conn->proto.httpc.streamsh, &stream_id,
                            sizeof(stream_id));
    if(!data_s) {
      /* Receiving a Stream ID not in the hash should not happen, this is an
         internal error more than anything else! */
      failf(conn->data, "Received frame on Stream ID: %x not in stream hash!",
            stream_id);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    stream = data_s->req.protop;

    stream->error_code = error_code;
    stream->closed = TRUE;
  }
  return 0;
}

static int on_begin_headers(nghttp2_session *session,
                            const nghttp2_frame *frame, void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  DEBUGF(infof(conn->data, "on_begin_headers() was called\n"));
  return 0;
}

/* Decode HTTP status code.  Returns -1 if no valid status code was
   decoded. */
static int decode_status_code(const uint8_t *value, size_t len)
{
  int i;
  int res;

  if(len != 3) {
    return -1;
  }

  res = 0;

  for(i = 0; i < 3; ++i) {
    char c = value[i];

    if(c < '0' || c > '9') {
      return -1;
    }

    res *= 10;
    res += c - '0';
  }

  return res;
}

static const char STATUS[] = ":status";

/* frame->hd.type is either NGHTTP2_HEADERS or NGHTTP2_PUSH_PROMISE */
static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags,
                     void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct HTTP *stream;
  struct SessionHandle *data_s;
  int rv;
  int goodname;
  int goodheader;
  int32_t stream_id = frame->hd.stream_id;

  (void)session;
  (void)frame;
  (void)flags;

  /* Ignore PUSH_PROMISE for now */
  if(frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */

  /* get the stream from the hash based on Stream ID */
  data_s = Curl_hash_pick(&conn->proto.httpc.streamsh, &stream_id,
                          sizeof(stream_id));
  if(!data_s) {
    /* Receiving a Stream ID not in the hash should not happen, this is an
       internal error more than anything else! */
    failf(conn->data, "Received frame on Stream ID: %x not in stream hash!",
          stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  stream = data_s->req.protop;

  if(stream->bodystarted)
    /* Ignore trailer or HEADERS not mapped to HTTP semantics.  The
       consequence is handled in on_frame_recv(). */
    return 0;

  goodname = nghttp2_check_header_name(name, namelen);
  goodheader = nghttp2_check_header_value(value, valuelen);

  if(!goodname || !goodheader) {

    infof(data_s, "Detected bad incoming header %s%s, reset stream!\n",
          goodname?"":"name",
          goodheader?"":"value");

    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                   stream_id, NGHTTP2_PROTOCOL_ERROR);

    if(nghttp2_is_fatal(rv)) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  if(namelen == sizeof(":status") - 1 &&
     memcmp(STATUS, name, namelen) == 0) {

    /* :status must appear exactly once. */
    if(stream->status_code != -1 ||
       (stream->status_code = decode_status_code(value, valuelen)) == -1) {

      rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                     stream_id, NGHTTP2_PROTOCOL_ERROR);
      if(nghttp2_is_fatal(rv)) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }

      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    Curl_add_buffer(stream->header_recvbuf, "HTTP/2.0 ", 9);
    Curl_add_buffer(stream->header_recvbuf, value, valuelen);
    Curl_add_buffer(stream->header_recvbuf, "\r\n", 2);

    return 0;
  }
  else {
    /* Here we are sure that namelen > 0 because of
       nghttp2_check_header_name().  Pseudo header other than :status
       is illegal. */
    if(stream->status_code == -1 || name[0] == ':') {
      rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                     stream_id, NGHTTP2_PROTOCOL_ERROR);
      if(nghttp2_is_fatal(rv)) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }

      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    /* convert to a HTTP1-style header */
    Curl_add_buffer(stream->header_recvbuf, name, namelen);
    Curl_add_buffer(stream->header_recvbuf, ":", 1);
    Curl_add_buffer(stream->header_recvbuf, value, valuelen);
    Curl_add_buffer(stream->header_recvbuf, "\r\n", 2);

    DEBUGF(infof(data_s, "h2 header: %.*s: %.*s\n",
                 namelen, name, valuelen, value));
  }

  return 0; /* 0 is successful */
}

static ssize_t data_source_read_callback(nghttp2_session *session,
                                         int32_t stream_id,
                                         uint8_t *buf, size_t length,
                                         uint32_t *data_flags,
                                         nghttp2_data_source *source,
                                         void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *c = &conn->proto.httpc;
  size_t nread;
  (void)session;
  (void)stream_id;
  (void)source;

  nread = MIN(c->upload_len, length);
  if(nread > 0) {
    memcpy(buf, c->upload_mem, nread);
    c->upload_mem += nread;
    c->upload_len -= nread;
    c->upload_left -= nread;
  }

  if(c->upload_left == 0)
    *data_flags = 1;
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

#define H2_BUFSIZE (1024)

static void freestreamentry(void *freethis)
{
  (void)freethis;
}

/*
 * Initialize nghttp2 for a Curl connection
 */
CURLcode Curl_http2_init(struct connectdata *conn)
{
  if(!conn->proto.httpc.h2) {
    int rc;
    nghttp2_session_callbacks *callbacks;

    conn->proto.httpc.inbuf = malloc(H2_BUFSIZE);
    if(conn->proto.httpc.inbuf == NULL)
      return CURLE_OUT_OF_MEMORY;

    rc = nghttp2_session_callbacks_new(&callbacks);

    if(rc) {
      failf(conn->data, "Couldn't initialize nghttp2 callbacks!");
      return CURLE_OUT_OF_MEMORY; /* most likely at least */
    }

    /* nghttp2_send_callback */
    nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
    /* nghttp2_on_frame_recv_callback */
    nghttp2_session_callbacks_set_on_frame_recv_callback
      (callbacks, on_frame_recv);
    /* nghttp2_on_invalid_frame_recv_callback */
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback
      (callbacks, on_invalid_frame_recv);
    /* nghttp2_on_data_chunk_recv_callback */
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback
      (callbacks, on_data_chunk_recv);
    /* nghttp2_before_frame_send_callback */
    nghttp2_session_callbacks_set_before_frame_send_callback
      (callbacks, before_frame_send);
    /* nghttp2_on_frame_send_callback */
    nghttp2_session_callbacks_set_on_frame_send_callback
      (callbacks, on_frame_send);
    /* nghttp2_on_frame_not_send_callback */
    nghttp2_session_callbacks_set_on_frame_not_send_callback
      (callbacks, on_frame_not_send);
    /* nghttp2_on_stream_close_callback */
    nghttp2_session_callbacks_set_on_stream_close_callback
      (callbacks, on_stream_close);
    /* nghttp2_on_begin_headers_callback */
    nghttp2_session_callbacks_set_on_begin_headers_callback
      (callbacks, on_begin_headers);
    /* nghttp2_on_header_callback */
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);

    /* The nghttp2 session is not yet setup, do it */
    rc = nghttp2_session_client_new(&conn->proto.httpc.h2, callbacks, conn);

    nghttp2_session_callbacks_del(callbacks);

    if(rc) {
      failf(conn->data, "Couldn't initialize nghttp2!");
      return CURLE_OUT_OF_MEMORY; /* most likely at least */
    }

    rc = Curl_hash_init(&conn->proto.httpc.streamsh, 7, Curl_hash_str,
                        Curl_str_key_compare, freestreamentry);
    if(rc) {
      failf(conn->data, "Couldn't init stream hash!");
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

  result = Curl_base64url_encode(conn->data, (const char *)binsettings, binlen,
                                 &base64, &blen);
  if(result)
    return result;

  result = Curl_add_bufferf(req,
                            "Connection: Upgrade, HTTP2-Settings\r\n"
                            "Upgrade: %s\r\n"
                            "HTTP2-Settings: %s\r\n",
                            NGHTTP2_CLEARTEXT_PROTO_VERSION_ID, base64);
  free(base64);

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
  CURLcode result = CURLE_OK;
  ssize_t rv;
  ssize_t nread;
  struct http_conn *httpc = &conn->proto.httpc;
  struct HTTP *stream = conn->data->req.protop;

  (void)sockindex; /* we always do HTTP2 on sockindex 0 */

  if(stream->closed) {
    /* Reset to FALSE to prevent infinite loop in readwrite_data
       function. */
    stream->closed = FALSE;
    return 0;
  }

  /* Nullify here because we call nghttp2_session_send() and they
     might refer to the old buffer. */
  httpc->upload_mem = NULL;
  httpc->upload_len = 0;

  /*
   * At this point 'stream' is just in the SessionHandle the connection
   * identifies as its owner at this time.
   */

  if(stream->bodystarted &&
     stream->nread_header_recvbuf < stream->header_recvbuf->size_used) {
    /* If there is body data pending for this stream to return, do that */
    size_t left =
      stream->header_recvbuf->size_used - stream->nread_header_recvbuf;
    size_t ncopy = MIN(len, left);
    memcpy(mem, stream->header_recvbuf->buffer + stream->nread_header_recvbuf,
           ncopy);
    stream->nread_header_recvbuf += ncopy;

    infof(conn->data, "http2_recv: Got %d bytes from header_recvbuf\n",
          (int)ncopy);
    return ncopy;
  }

  if(stream->data) {
    nread = MIN(len, stream->datalen);
    memcpy(mem, stream->data, nread);

    stream->data += nread;
    stream->datalen -= nread;

    infof(conn->data, "%zu data bytes written\n", nread);
    if(stream->datalen == 0) {
      stream->data = NULL;
      stream->datalen = 0;
    }
    infof(conn->data, "http2_recv: Got %d bytes from stream->data\n",
          (int)nread);
    return nread;
  }

  /* remember where to store incoming data for this stream and how big the
     buffer is */
  stream->mem = mem;
  stream->len = len;

  infof(conn->data, "http2_recv: %d bytes buffer\n", stream->len);

  nread = ((Curl_recv*)httpc->recv_underlying)(conn, FIRSTSOCKET,
                                               httpc->inbuf, H2_BUFSIZE,
                                               &result);
  if(result == CURLE_AGAIN) {
    *err = result;
    return -1;
  }

  if(nread == -1) {
    failf(conn->data, "Failed receiving HTTP2 data");
    *err = result;
    return 0;
  }

  if(nread == 0) {
    failf(conn->data, "Unexpected EOF");
    *err = CURLE_RECV_ERROR;
    return -1;
  }

  DEBUGF(infof(conn->data, "nread=%zd\n", nread));

  rv = nghttp2_session_mem_recv(httpc->h2,
                                (const uint8_t *)httpc->inbuf, nread);

  if(nghttp2_is_fatal((int)rv)) {
    failf(conn->data, "nghttp2_session_mem_recv() returned %d:%s\n",
          rv, nghttp2_strerror((int)rv));
    *err = CURLE_RECV_ERROR;
    return 0;
  }
  DEBUGF(infof(conn->data, "nghttp2_session_mem_recv() returns %zd\n", rv));
  /* Always send pending frames in nghttp2 session, because
     nghttp2_session_mem_recv() may queue new frame */
  rv = nghttp2_session_send(httpc->h2);
  if(rv != 0) {
    *err = CURLE_SEND_ERROR;
    return 0;
  }
  if(len != stream->len) {
    infof(conn->data, "http2_recv: returns %d for stream %x (%zu/%zu)\n",
          len - stream->len, stream->stream_id,
          len, stream->len);
    return len - stream->len;
  }
  /* If stream is closed, return 0 to signal the http routine to close
     the connection */
  if(stream->closed) {
    /* Reset to FALSE to prevent infinite loop in readwrite_data
       function. */
    stream->closed = FALSE;
    if(stream->error_code != NGHTTP2_NO_ERROR) {
      failf(conn->data,
            "HTTP/2 stream = %x was not closed cleanly: error_code = %d",
            stream->stream_id, stream->error_code);
      *err = CURLE_HTTP2;
      return -1;
    }
    DEBUGF(infof(conn->data, "http2_recv returns 0\n"));
    return 0;
  }
  *err = CURLE_AGAIN;
  DEBUGF(infof(conn->data, "http2_recv returns -1, AGAIN\n"));
  return -1;
}

/* Index where :authority header field will appear in request header
   field list. */
#define AUTHORITY_DST_IDX 3

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
  struct HTTP *stream = conn->data->req.protop;
  nghttp2_nv *nva;
  size_t nheader;
  size_t i;
  size_t authority_idx;
  char *hdbuf = (char*)mem;
  char *end;
  nghttp2_data_provider data_prd;
  int32_t stream_id;

  (void)sockindex;

  DEBUGF(infof(conn->data, "http2_send len=%zu\n", len));

  if(stream->stream_id != -1) {
    /* If stream_id != -1, we have dispatched request HEADERS, and now
       are going to send or sending request body in DATA frame */
    httpc->upload_mem = mem;
    httpc->upload_len = len;
    nghttp2_session_resume_data(httpc->h2, stream->stream_id);
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
  nva[0].flags = NGHTTP2_NV_FLAG_NONE;

  hdbuf = end + 1;

  end = strchr(hdbuf, ' ');
  nva[1].name = (unsigned char *)":path";
  nva[1].namelen = (uint16_t)strlen((char *)nva[1].name);
  nva[1].value = (unsigned char *)hdbuf;
  nva[1].valuelen = (uint16_t)(end - hdbuf);
  nva[1].flags = NGHTTP2_NV_FLAG_NONE;

  nva[2].name = (unsigned char *)":scheme";
  nva[2].namelen = (uint16_t)strlen((char *)nva[2].name);
  if(conn->handler->flags & PROTOPT_SSL)
    nva[2].value = (unsigned char *)"https";
  else
    nva[2].value = (unsigned char *)"http";
  nva[2].valuelen = (uint16_t)strlen((char *)nva[2].value);
  nva[2].flags = NGHTTP2_NV_FLAG_NONE;

  hdbuf = strchr(hdbuf, 0x0a);
  ++hdbuf;

  authority_idx = 0;

  for(i = 3; i < nheader; ++i) {
    end = strchr(hdbuf, ':');
    assert(end);
    if(end - hdbuf == 4 && Curl_raw_nequal("host", hdbuf, 4)) {
      authority_idx = i;
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
    nva[i].flags = NGHTTP2_NV_FLAG_NONE;

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
      DEBUGF(infof(conn->data,
                   "request content-length=%zu\n", httpc->upload_left));
    }
  }

  /* :authority must come before non-pseudo header fields */
  if(authority_idx != 0 && authority_idx != AUTHORITY_DST_IDX) {
    nghttp2_nv authority = nva[authority_idx];
    for(i = authority_idx; i > AUTHORITY_DST_IDX; --i) {
      nva[i] = nva[i - 1];
    }
    nva[i] = authority;
  }

  switch(conn->data->set.httpreq) {
  case HTTPREQ_POST:
  case HTTPREQ_POST_FORM:
  case HTTPREQ_PUT:
    data_prd.read_callback = data_source_read_callback;
    data_prd.source.ptr = NULL;
    stream_id = nghttp2_submit_request(httpc->h2, NULL, nva, nheader,
                                       &data_prd, NULL);
    break;
  default:
    stream_id = nghttp2_submit_request(httpc->h2, NULL, nva, nheader,
                                       NULL, NULL);
  }

  free(nva);

  if(stream_id < 0) {
    DEBUGF(infof(conn->data, "http2_send() send error\n"));
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  infof(conn->data, "Using Stream ID: %x (easy handle %p)\n",
        stream_id, conn->data);
  stream->stream_id = stream_id;

  /* put the SessionHandle in the hash with the stream_id as key */
  if(!Curl_hash_add(&httpc->streamsh, &stream->stream_id, sizeof(stream_id),
                    conn->data)) {
    failf(conn->data, "Couldn't add stream to hash!");
    *err = CURLE_OUT_OF_MEMORY;
    return -1;
  }

  rv = nghttp2_session_send(httpc->h2);

  if(rv != 0) {
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  if(stream->stream_id != -1) {
    /* If whole HEADERS frame was sent off to the underlying socket,
       the nghttp2 library calls data_source_read_callback. But only
       it found that no data available, so it deferred the DATA
       transmission. Which means that nghttp2_session_want_write()
       returns 0 on http2_perform_getsock(), which results that no
       writable socket check is performed. To workaround this, we
       issue nghttp2_session_resume_data() here to bring back DATA
       transmission from deferred state. */
    nghttp2_session_resume_data(httpc->h2, stream->stream_id);
  }

  return len;
}

CURLcode Curl_http2_setup(struct connectdata *conn)
{
  CURLcode result;
  struct http_conn *httpc = &conn->proto.httpc;
  struct HTTP *stream = conn->data->req.protop;

  stream->stream_id = -1;

  if((conn->handler == &Curl_handler_http2_ssl) ||
     (conn->handler == &Curl_handler_http2))
    return CURLE_OK; /* already done */

  if(conn->handler->flags & PROTOPT_SSL)
    conn->handler = &Curl_handler_http2_ssl;
  else
    conn->handler = &Curl_handler_http2;

  result = Curl_http2_init(conn);
  if(result)
    return result;

  infof(conn->data, "Using HTTP2, server supports multi-use\n");
  httpc->upload_left = 0;
  httpc->upload_mem = NULL;
  httpc->upload_len = 0;

  conn->httpversion = 20;
  conn->bundle->server_supports_pipelining = TRUE;

  return CURLE_OK;
}

CURLcode Curl_http2_switched(struct connectdata *conn,
                             const char *mem, size_t nread)
{
  CURLcode result;
  struct http_conn *httpc = &conn->proto.httpc;
  int rv;
  struct SessionHandle *data = conn->data;
  struct HTTP *stream = conn->data->req.protop;

  result = Curl_http2_setup(conn);
  if(result)
    return result;

  httpc->recv_underlying = (recving)conn->recv[FIRSTSOCKET];
  httpc->send_underlying = (sending)conn->send[FIRSTSOCKET];
  conn->recv[FIRSTSOCKET] = http2_recv;
  conn->send[FIRSTSOCKET] = http2_send;

  rv = (int) ((Curl_send*)httpc->send_underlying)
    (conn, FIRSTSOCKET,
     NGHTTP2_CLIENT_CONNECTION_PREFACE,
     NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN,
     &result);
  if(result)
    /* TODO: This may get CURLE_AGAIN */
    return result;

  if(rv != 24) {
    failf(data, "Only sent partial HTTP2 packet");
    return CURLE_SEND_ERROR;
  }

  if(conn->data->req.upgr101 == UPGR101_RECEIVED) {
    /* stream 1 is opened implicitly on upgrade */
    stream->stream_id = 1;
    /* queue SETTINGS frame (again) */
    rv = nghttp2_session_upgrade(httpc->h2, httpc->binsettings,
                                 httpc->binlen, NULL);
    if(rv != 0) {
      failf(data, "nghttp2_session_upgrade() failed: %s(%d)",
            nghttp2_strerror(rv), rv);
      return CURLE_HTTP2;
    }
  }
  else {
    /* stream ID is unknown at this point */
    stream->stream_id = -1;
    rv = nghttp2_submit_settings(httpc->h2, NGHTTP2_FLAG_NONE, NULL, 0);
    if(rv != 0) {
      failf(data, "nghttp2_submit_settings() failed: %s(%d)",
            nghttp2_strerror(rv), rv);
      return CURLE_HTTP2;
    }
  }

  rv = (int)nghttp2_session_mem_recv(httpc->h2, (const uint8_t*)mem, nread);

  if(rv != (int)nread) {
    failf(data, "nghttp2_session_mem_recv() failed: %s(%d)",
          nghttp2_strerror(rv), rv);
    return CURLE_HTTP2;
  }

  /* Try to send some frames since we may read SETTINGS already. */
  rv = nghttp2_session_send(httpc->h2);

  if(rv != 0) {
    failf(data, "nghttp2_session_send() failed: %s(%d)",
          nghttp2_strerror(rv), rv);
    return CURLE_HTTP2;
  }

  return CURLE_OK;
}

#endif
