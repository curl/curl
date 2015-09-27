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
#include "conncache.h"
#include "url.h"
#include "connect.h"

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
  struct HTTP *http = conn->data->req.protop;
  struct http_conn *c = &conn->proto.httpc;
  (void)dead_connection;

  DEBUGF(infof(conn->data, "HTTP/2 DISCONNECT starts now\n"));

  nghttp2_session_del(c->h2);
  Curl_safefree(c->inbuf);

  if(http) {
    Curl_add_buffer_free(http->header_recvbuf);
    http->header_recvbuf = NULL; /* clear the pointer */
    for(; http->push_headers_used > 0; --http->push_headers_used) {
      free(http->push_headers[http->push_headers_used - 1]);
    }
    free(http->push_headers);
    http->push_headers = NULL;
  }

  DEBUGF(infof(conn->data, "HTTP/2 DISCONNECT done\n"));

  return CURLE_OK;
}

/* called from Curl_http_setup_conn */
void Curl_http2_setup_req(struct SessionHandle *data)
{
  struct HTTP *http = data->req.protop;

  http->nread_header_recvbuf = 0;
  http->bodystarted = FALSE;
  http->status_code = -1;
  http->pausedata = NULL;
  http->pauselen = 0;
  http->error_code = NGHTTP2_NO_ERROR;
  http->closed = FALSE;
  http->mem = data->state.buffer;
  http->len = BUFSIZE;
  http->memlen = 0;
}

/* called from Curl_http_setup_conn */
void Curl_http2_setup_conn(struct connectdata *conn)
{
  conn->proto.httpc.settings.max_concurrent_streams =
    DEFAULT_MAX_CONCURRENT_STREAMS;
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


/* We pass a pointer to this struct in the push callback, but the contents of
   the struct are hidden from the user. */
struct curl_pushheaders {
  struct SessionHandle *data;
  const nghttp2_push_promise *frame;
};

/*
 * push header access function. Only to be used from within the push callback
 */
char *curl_pushheader_bynum(struct curl_pushheaders *h, size_t num)
{
  /* Verify that we got a good easy handle in the push header struct, mostly to
     detect rubbish input fast(er). */
  if(!h || !GOOD_EASY_HANDLE(h->data))
    return NULL;
  else {
    struct HTTP *stream = h->data->req.protop;
    if(num < stream->push_headers_used)
      return stream->push_headers[num];
  }
  return NULL;
}

/*
 * push header access function. Only to be used from within the push callback
 */
char *curl_pushheader_byname(struct curl_pushheaders *h, const char *header)
{
  /* Verify that we got a good easy handle in the push header struct,
     mostly to detect rubbish input fast(er). Also empty header name
     is just a rubbish too. We have to allow ":" at the beginning of
     the header, but header == ":" must be rejected. If we have ':' in
     the middle of header, it could be matched in middle of the value,
     this is because we do prefix match.*/
  if(!h || !GOOD_EASY_HANDLE(h->data) || !header || !header[0] ||
     Curl_raw_equal(header, ":") || strchr(header + 1, ':'))
    return NULL;
  else {
    struct HTTP *stream = h->data->req.protop;
    size_t len = strlen(header);
    size_t i;
    for(i=0; i<stream->push_headers_used; i++) {
      if(!strncmp(header, stream->push_headers[i], len)) {
        /* sub-match, make sure that it us followed by a colon */
        if(stream->push_headers[i][len] != ':')
          continue;
        return &stream->push_headers[i][len+1];
      }
    }
  }
  return NULL;
}

static CURL *duphandle(struct SessionHandle *data)
{
  struct SessionHandle *second = curl_easy_duphandle(data);
  if(second) {
    /* setup the request struct */
    struct HTTP *http = calloc(1, sizeof(struct HTTP));
    if(!http) {
      (void)Curl_close(second);
      second = NULL;
    }
    else {
      second->req.protop = http;
      http->header_recvbuf = Curl_add_buffer_init();
      if(!http->header_recvbuf) {
        free(http);
        (void)Curl_close(second);
        second = NULL;
      }
      else
        Curl_http2_setup_req(second);
    }
  }
  return second;
}


static int push_promise(struct SessionHandle *data,
                        struct connectdata *conn,
                        const nghttp2_push_promise *frame)
{
  int rv;
  DEBUGF(infof(data, "PUSH_PROMISE received, stream %u!\n",
               frame->promised_stream_id));
  if(data->multi->push_cb) {
    struct HTTP *stream;
    struct curl_pushheaders heads;
    CURLMcode rc;
    struct http_conn *httpc;
    size_t i;
    /* clone the parent */
    CURL *newhandle = duphandle(data);
    if(!newhandle) {
      infof(data, "failed to duplicate handle\n");
      rv = 1; /* FAIL HARD */
      goto fail;
    }

    heads.data = data;
    heads.frame = frame;
    /* ask the application */
    DEBUGF(infof(data, "Got PUSH_PROMISE, ask application!\n"));

    stream = data->req.protop;
    if(!stream) {
      failf(data, "Internal NULL stream!\n");
      rv = 1;
      goto fail;
    }

    rv = data->multi->push_cb(data, newhandle,
                              stream->push_headers_used, &heads,
                              data->multi->push_userp);

    /* free the headers again */
    for(i=0; i<stream->push_headers_used; i++)
      free(stream->push_headers[i]);
    free(stream->push_headers);
    stream->push_headers = NULL;

    if(rv) {
      /* denied, kill off the new handle again */
      (void)Curl_close(newhandle);
      goto fail;
    }

    /* approved, add to the multi handle and immediately switch to PERFORM
       state with the given connection !*/
    rc = Curl_multi_add_perform(data->multi, newhandle, conn);
    if(rc) {
      infof(data, "failed to add handle to multi\n");
      Curl_close(newhandle);
      rv = 1;
      goto fail;
    }

    httpc = &conn->proto.httpc;
    nghttp2_session_set_stream_user_data(httpc->h2,
                                         frame->promised_stream_id, newhandle);
  }
  else {
    DEBUGF(infof(data, "Got PUSH_PROMISE, ignore it!\n"));
    rv = 1;
  }
  fail:
  return rv;
}

static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *httpc = NULL;
  struct SessionHandle *data_s = NULL;
  struct HTTP *stream = NULL;
  static int lastStream = -1;
  int rv;
  size_t left, ncopy;
  int32_t stream_id = frame->hd.stream_id;

  if(!stream_id) {
    /* stream ID zero is for connection-oriented stuff */
    return 0;
  }
  data_s = nghttp2_session_get_stream_user_data(session,
                                                frame->hd.stream_id);
  if(lastStream != frame->hd.stream_id) {
    lastStream = frame->hd.stream_id;
  }
  if(!data_s) {
    DEBUGF(infof(conn->data,
                 "No SessionHandle associated with stream: %x\n",
                 stream_id));
    return 0;
  }

  stream = data_s->req.protop;
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  DEBUGF(infof(data_s, "on_frame_recv() header %x stream %x\n",
               frame->hd.type, stream_id));

  conn = data_s->easy_conn;
  assert(conn);
  assert(conn->data == data_s);
  httpc = &conn->proto.httpc;
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
      /* Only valid HEADERS after body started is trailer HEADERS.  We
         ignores trailer HEADERS for now.  nghttp2 guarantees that it
         has END_STREAM flag set. */
      break;
    }

    /* nghttp2 guarantees that :status is received, and we store it to
       stream->status_code */
    DEBUGASSERT(stream->status_code != -1);

    /* Only final status code signals the end of header */
    if(stream->status_code / 100 != 1) {
      stream->bodystarted = TRUE;
      stream->status_code = -1;
    }

    Curl_add_buffer(stream->header_recvbuf, "\r\n", 2);

    left = stream->header_recvbuf->size_used - stream->nread_header_recvbuf;
    ncopy = MIN(stream->len, left);

    memcpy(&stream->mem[stream->memlen],
           stream->header_recvbuf->buffer + stream->nread_header_recvbuf,
           ncopy);
    stream->nread_header_recvbuf += ncopy;

    DEBUGF(infof(data_s, "Store %zu bytes headers from stream %u at %p\n",
                 ncopy, stream_id, stream->mem));

    stream->len -= ncopy;
    stream->memlen += ncopy;

    data_s->state.drain++;
    {
      /* get the pointer from userp again since it was re-assigned above */
      struct connectdata *conn_s = (struct connectdata *)userp;

      /* if we receive data for another handle, wake that up */
      if(conn_s->data != data_s)
        Curl_expire(data_s, 1);
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    rv = push_promise(data_s, conn, &frame->push_promise);
    if(rv) { /* deny! */
      rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                     frame->push_promise.promised_stream_id,
                                     NGHTTP2_CANCEL);
      if(nghttp2_is_fatal(rv)) {
        return rv;
      }
    }
    break;
  case NGHTTP2_SETTINGS:
  {
    uint32_t max_conn = httpc->settings.max_concurrent_streams;
    DEBUGF(infof(conn->data, "Got SETTINGS for stream %u!\n", stream_id));
    httpc->settings.max_concurrent_streams =
      nghttp2_session_get_remote_settings(
        session, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
    httpc->settings.enable_push =
      nghttp2_session_get_remote_settings(
        session, NGHTTP2_SETTINGS_ENABLE_PUSH);
    DEBUGF(infof(conn->data, "MAX_CONCURRENT_STREAMS == %d\n",
                 httpc->settings.max_concurrent_streams));
    DEBUGF(infof(conn->data, "ENABLE_PUSH == %s\n",
                 httpc->settings.enable_push?"TRUE":"false"));
    if(max_conn != httpc->settings.max_concurrent_streams) {
      /* only signal change if the value actually changed */
      infof(conn->data,
            "Connection state changed (MAX_CONCURRENT_STREAMS updated)!\n");
      Curl_multi_connchanged(conn->data->multi);
    }
  }
  break;
  default:
    DEBUGF(infof(conn->data, "Got frame type %x for stream %u!\n",
                 frame->hd.type, stream_id));
    break;
  }
  return 0;
}

static int on_invalid_frame_recv(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 int lib_error_code, void *userp)
{
  struct SessionHandle *data_s = NULL;
  (void)userp;

  data_s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(data_s) {
    DEBUGF(infof(data_s,
                 "on_invalid_frame_recv() was called, error=%d:%s\n",
                 lib_error_code, nghttp2_strerror(lib_error_code)));
  }
  return 0;
}

static int on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                              int32_t stream_id,
                              const uint8_t *data, size_t len, void *userp)
{
  struct HTTP *stream;
  struct SessionHandle *data_s;
  size_t nread;
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)flags;
  (void)data;

  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */

  /* get the stream from the hash based on Stream ID */
  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!data_s)
    /* Receiving a Stream ID not in the hash should not happen, this is an
       internal error more than anything else! */
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  stream = data_s->req.protop;
  if(!stream)
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  nread = MIN(stream->len, len);
  memcpy(&stream->mem[stream->memlen], data, nread);

  stream->len -= nread;
  stream->memlen += nread;

  data_s->state.drain++;

  /* if we receive data for another handle, wake that up */
  if(conn->data != data_s)
    Curl_expire(data_s, 1); /* TODO: fix so that this can be set to 0 for
                               immediately? */

  DEBUGF(infof(data_s, "%zu data received for stream %u "
               "(%zu left in buffer %p, total %zu)\n",
               nread, stream_id,
               stream->len, stream->mem,
               stream->memlen));

  if(nread < len) {
    stream->pausedata = data + nread;
    stream->pauselen = len - nread;
    DEBUGF(infof(data_s, "NGHTTP2_ERR_PAUSE - %zu bytes out of buffer"
                 ", stream %u\n",
                 len - nread, stream_id));
    data_s->easy_conn->proto.httpc.pause_stream_id = stream_id;
    return NGHTTP2_ERR_PAUSE;
  }
  return 0;
}

static int before_frame_send(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             void *userp)
{
  struct SessionHandle *data_s;
  (void)userp;

  data_s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(data_s) {
    DEBUGF(infof(data_s, "before_frame_send() was called\n"));
  }

  return 0;
}
static int on_frame_send(nghttp2_session *session,
                         const nghttp2_frame *frame,
                         void *userp)
{
  struct SessionHandle *data_s;
  (void)userp;

  data_s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(data_s) {
    DEBUGF(infof(data_s, "on_frame_send() was called, length = %zd\n",
                 frame->hd.length));
  }
  return 0;
}
static int on_frame_not_send(nghttp2_session *session,
                             const nghttp2_frame *frame,
                             int lib_error_code, void *userp)
{
  struct SessionHandle *data_s;
  (void)userp;

  data_s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(data_s) {
    DEBUGF(infof(data_s,
                 "on_frame_not_send() was called, lib_error_code = %d\n",
                 lib_error_code));
  }
  return 0;
}
static int on_stream_close(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *userp)
{
  struct SessionHandle *data_s;
  struct HTTP *stream;
  (void)session;
  (void)stream_id;
  (void)userp;

  if(stream_id) {
    /* get the stream from the hash based on Stream ID, stream ID zero is for
       connection-oriented stuff */
    data_s = nghttp2_session_get_stream_user_data(session, stream_id);
    if(!data_s) {
      /* We could get stream ID not in the hash.  For example, if we
         decided to reject stream (e.g., PUSH_PROMISE). */
      return 0;
    }
    DEBUGF(infof(data_s, "on_stream_close(), error_code = %d, stream %u\n",
                 error_code, stream_id));
    stream = data_s->req.protop;
    if(!stream)
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    stream->error_code = error_code;
    stream->closed = TRUE;

    /* remove the entry from the hash as the stream is now gone */
    nghttp2_session_set_stream_user_data(session, stream_id, 0);
    DEBUGF(infof(data_s, "Removed stream %u hash!\n", stream_id));
  }
  return 0;
}

static int on_begin_headers(nghttp2_session *session,
                            const nghttp2_frame *frame, void *userp)
{
  struct SessionHandle *data_s = NULL;
  (void)userp;

  data_s = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
  if(data_s) {
    DEBUGF(infof(data_s, "on_begin_headers() was called\n"));
  }
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

/* frame->hd.type is either NGHTTP2_HEADERS or NGHTTP2_PUSH_PROMISE */
static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags,
                     void *userp)
{
  struct HTTP *stream;
  struct SessionHandle *data_s;
  int32_t stream_id = frame->hd.stream_id;
  struct connectdata *conn = (struct connectdata *)userp;
  (void)flags;

  DEBUGASSERT(stream_id); /* should never be a zero stream ID here */

  /* get the stream from the hash based on Stream ID */
  data_s = nghttp2_session_get_stream_user_data(session, stream_id);
  if(!data_s)
    /* Receiving a Stream ID not in the hash should not happen, this is an
       internal error more than anything else! */
    return NGHTTP2_ERR_CALLBACK_FAILURE;

  stream = data_s->req.protop;
  if(!stream) {
    failf(data_s, "Internal NULL stream! 5\n");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if(stream->bodystarted)
    /* Ignore trailer or HEADERS not mapped to HTTP semantics.  The
       consequence is handled in on_frame_recv(). */
    return 0;

  /* Store received PUSH_PROMISE headers to be used when the subsequent
     PUSH_PROMISE callback comes */
  if(frame->hd.type == NGHTTP2_PUSH_PROMISE) {
    char *h;

    if(!stream->push_headers) {
      stream->push_headers_alloc = 10;
      stream->push_headers = malloc(stream->push_headers_alloc *
                                    sizeof(char *));
      stream->push_headers_used = 0;
    }
    else if(stream->push_headers_used ==
            stream->push_headers_alloc) {
      char **headp;
      stream->push_headers_alloc *= 2;
      headp = realloc(stream->push_headers,
                      stream->push_headers_alloc * sizeof(char *));
      if(!headp) {
        free(stream->push_headers);
        stream->push_headers = NULL;
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      stream->push_headers = headp;
    }
    h = aprintf("%s:%s", name, value);
    if(h)
      stream->push_headers[stream->push_headers_used++] = h;
    return 0;
  }

  if(namelen == sizeof(":status") - 1 &&
     memcmp(":status", name, namelen) == 0) {
    /* nghttp2 guarantees :status is received first and only once, and
       value is 3 digits status code, and decode_status_code always
       succeeds. */
    stream->status_code = decode_status_code(value, valuelen);
    DEBUGASSERT(stream->status_code != -1);

    Curl_add_buffer(stream->header_recvbuf, "HTTP/2.0 ", 9);
    Curl_add_buffer(stream->header_recvbuf, value, valuelen);
    Curl_add_buffer(stream->header_recvbuf, "\r\n", 2);
    data_s->state.drain++;
    /* if we receive data for another handle, wake that up */
    if(conn->data != data_s)
      Curl_expire(data_s, 1);

    DEBUGF(infof(data_s, "h2 status: HTTP/2 %03d\n",
                 stream->status_code));
    return 0;
  }

  /* nghttp2 guarantees that namelen > 0, and :status was already
     received, and this is not pseudo-header field . */
  /* convert to a HTTP1-style header */
  Curl_add_buffer(stream->header_recvbuf, name, namelen);
  Curl_add_buffer(stream->header_recvbuf, ":", 1);
  Curl_add_buffer(stream->header_recvbuf, value, valuelen);
  Curl_add_buffer(stream->header_recvbuf, "\r\n", 2);
  data_s->state.drain++;
  /* if we receive data for another handle, wake that up */
  if(conn->data != data_s)
    Curl_expire(data_s, 1);

  DEBUGF(infof(data_s, "h2 header: %.*s: %.*s\n", namelen, name, valuelen,
               value));

  return 0; /* 0 is successful */
}

static ssize_t data_source_read_callback(nghttp2_session *session,
                                         int32_t stream_id,
                                         uint8_t *buf, size_t length,
                                         uint32_t *data_flags,
                                         nghttp2_data_source *source,
                                         void *userp)
{
  struct SessionHandle *data_s;
  struct HTTP *stream = NULL;
  size_t nread;
  (void)source;
  (void)userp;

  if(stream_id) {
    /* get the stream from the hash based on Stream ID, stream ID zero is for
       connection-oriented stuff */
    data_s = nghttp2_session_get_stream_user_data(session, stream_id);
    if(!data_s)
      /* Receiving a Stream ID not in the hash should not happen, this is an
         internal error more than anything else! */
      return NGHTTP2_ERR_CALLBACK_FAILURE;

    stream = data_s->req.protop;
    if(!stream)
      return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  else
    return NGHTTP2_ERR_INVALID_ARGUMENT;

  nread = MIN(stream->upload_len, length);
  if(nread > 0) {
    memcpy(buf, stream->upload_mem, nread);
    stream->upload_mem += nread;
    stream->upload_len -= nread;
    stream->upload_left -= nread;
  }

  if(stream->upload_left == 0)
    *data_flags = 1;
  else if(nread == 0)
    return NGHTTP2_ERR_DEFERRED;

  DEBUGF(infof(data_s, "data_source_read_callback: "
               "returns %zu bytes stream %u\n",
               nread, stream_id));

  return nread;
}

/*
 * The HTTP2 settings we send in the Upgrade request
 */
static nghttp2_settings_entry settings[] = {
  { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
  { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, NGHTTP2_INITIAL_WINDOW_SIZE },
};

#define H2_BUFSIZE 32768

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
  }
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

static ssize_t http2_handle_stream_close(struct http_conn *httpc,
                                         struct SessionHandle *data,
                                         struct HTTP *stream, CURLcode *err) {
  if(httpc->pause_stream_id == stream->stream_id) {
    httpc->pause_stream_id = 0;
  }
  /* Reset to FALSE to prevent infinite loop in readwrite_data
   function. */
  stream->closed = FALSE;
  if(stream->error_code != NGHTTP2_NO_ERROR) {
    failf(data, "HTTP/2 stream %u was not closed cleanly: error_code = %d",
          stream->stream_id, stream->error_code);
    *err = CURLE_HTTP2;
    return -1;
  }
  DEBUGF(infof(data, "http2_recv returns 0, http2_handle_stream_close\n"));
  return 0;
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
  struct SessionHandle *data = conn->data;
  struct HTTP *stream = data->req.protop;

  (void)sockindex; /* we always do HTTP2 on sockindex 0 */

  /* If stream is closed, return 0 to signal the http routine to close
     the connection.  We need to handle stream closure here,
     otherwise, we may be going to read from underlying connection,
     and gets EAGAIN, and we will get stuck there. */
  if(stream->memlen == 0 && stream->closed) {
    return http2_handle_stream_close(httpc, data, stream, err);
  }

  /* Nullify here because we call nghttp2_session_send() and they
     might refer to the old buffer. */
  stream->upload_mem = NULL;
  stream->upload_len = 0;

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

    infof(data, "http2_recv: Got %d bytes from header_recvbuf\n",
          (int)ncopy);
    return ncopy;
  }

  infof(data, "http2_recv: %d bytes buffer at %p (stream %u)\n",
        len, mem, stream->stream_id);

  if((data->state.drain) && stream->memlen) {
    DEBUGF(infof(data, "http2_recv: DRAIN %zu bytes stream %u!! (%p => %p)\n",
                 stream->memlen, stream->stream_id,
                 stream->mem, mem));
    if(mem != stream->mem) {
      /* if we didn't get the same buffer this time, we must move the data to
         the beginning */
      memmove(mem, stream->mem, stream->memlen);
      stream->len = len - stream->memlen;
      stream->mem = mem;
    }
  }
  else if(stream->pausedata) {
    nread = MIN(len, stream->pauselen);
    memcpy(mem, stream->pausedata, nread);

    stream->pausedata += nread;
    stream->pauselen -= nread;

    infof(data, "%zu data bytes written\n", nread);
    if(stream->pauselen == 0) {
      DEBUGF(infof(data, "Unpaused by stream %u\n", stream->stream_id));
      assert(httpc->pause_stream_id == stream->stream_id);
      httpc->pause_stream_id = 0;

      stream->pausedata = NULL;
      stream->pauselen = 0;
    }
    infof(data, "http2_recv: returns unpaused %zd bytes on stream %u\n",
          nread, stream->stream_id);
    return nread;
  }
  else if(httpc->pause_stream_id) {
    /* If a stream paused nghttp2_session_mem_recv previously, and has
       not processed all data, it still refers to the buffer in
       nghttp2_session.  If we call nghttp2_session_mem_recv(), we may
       overwrite that buffer.  To avoid that situation, just return
       here with CURLE_AGAIN.  This could be busy loop since data in
       socket is not read.  But it seems that usually streams are
       notified with its drain property, and socket is read again
       quickly. */
    *err = CURLE_AGAIN;
    return -1;
  }
  else {
    char *inbuf;
    /* remember where to store incoming data for this stream and how big the
       buffer is */
    stream->mem = mem;
    stream->len = len;
    stream->memlen = 0;

    if(httpc->inbuflen == 0) {
      nread = ((Curl_recv *)httpc->recv_underlying)(
          conn, FIRSTSOCKET, httpc->inbuf, H2_BUFSIZE, &result);

      if(result == CURLE_AGAIN) {
        *err = result;
        return -1;
      }

      if(nread == -1) {
        failf(data, "Failed receiving HTTP2 data");
        *err = result;
        return 0;
      }

      if(nread == 0) {
        failf(data, "Unexpected EOF");
        *err = CURLE_RECV_ERROR;
        return -1;
      }

      DEBUGF(infof(data, "nread=%zd\n", nread));

      httpc->inbuflen = nread;
      inbuf = httpc->inbuf;
    }
    else {
      nread = httpc->inbuflen - httpc->nread_inbuf;
      inbuf = httpc->inbuf + httpc->nread_inbuf;

      DEBUGF(infof(data, "Use data left in connection buffer, nread=%zd\n",
                   nread));
    }
    rv = nghttp2_session_mem_recv(httpc->h2, (const uint8_t *)inbuf, nread);

    if(nghttp2_is_fatal((int)rv)) {
      failf(data, "nghttp2_session_mem_recv() returned %d:%s\n",
            rv, nghttp2_strerror((int)rv));
      *err = CURLE_RECV_ERROR;
      return 0;
    }
    DEBUGF(infof(data, "nghttp2_session_mem_recv() returns %zd\n", rv));
    if(nread == rv) {
      DEBUGF(infof(data, "All data in connection buffer processed\n"));
      httpc->inbuflen = 0;
      httpc->nread_inbuf = 0;
    }
    else {
      httpc->nread_inbuf += rv;
      DEBUGF(infof(data, "%zu bytes left in connection buffer\n",
                   httpc->inbuflen - httpc->nread_inbuf));
    }
    /* Always send pending frames in nghttp2 session, because
       nghttp2_session_mem_recv() may queue new frame */
    rv = nghttp2_session_send(httpc->h2);
    if(rv != 0) {
      *err = CURLE_SEND_ERROR;
      return 0;
    }
  }
  if(stream->memlen) {
    ssize_t retlen = stream->memlen;
    infof(data, "http2_recv: returns %zd for stream %u\n",
          retlen, stream->stream_id);
    stream->memlen = 0;

    if(httpc->pause_stream_id == stream->stream_id) {
      /* data for this stream is returned now, but this stream caused a pause
         already so we need it called again asap */
      DEBUGF(infof(data, "Data returned for PAUSED stream %u\n",
                   stream->stream_id));
    }
    else
      data->state.drain = 0; /* this stream is hereby drained */

    return retlen;
  }
  /* If stream is closed, return 0 to signal the http routine to close
     the connection */
  if(stream->closed) {
    return http2_handle_stream_close(httpc, data, stream, err);
  }
  *err = CURLE_AGAIN;
  DEBUGF(infof(data, "http2_recv returns AGAIN for stream %u\n",
               stream->stream_id));
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
  nghttp2_session *h2 = httpc->h2;

  (void)sockindex;

  DEBUGF(infof(conn->data, "http2_send len=%zu\n", len));

  if(stream->stream_id != -1) {
    /* If stream_id != -1, we have dispatched request HEADERS, and now
       are going to send or sending request body in DATA frame */
    stream->upload_mem = mem;
    stream->upload_len = len;
    nghttp2_session_resume_data(h2, stream->stream_id);
    rv = nghttp2_session_send(h2);
    if(nghttp2_is_fatal(rv)) {
      *err = CURLE_SEND_ERROR;
      return -1;
    }
    len -= stream->upload_len;

    /* Nullify here because we call nghttp2_session_send() and they
       might refer to the old buffer. */
    stream->upload_mem = NULL;
    stream->upload_len = 0;

    if(stream->upload_left) {
      /* we are sure that we have more data to send here.  Calling the
         following API will make nghttp2_session_want_write() return
         nonzero if remote window allows it, which then libcurl checks
         socket is writable or not.  See http2_perform_getsock(). */
      nghttp2_session_resume_data(h2, stream->stream_id);
    }

    DEBUGF(infof(conn->data, "http2_send returns %zu for stream %u\n", len,
                 stream->stream_id));
    return len;
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
  if(!end)
    goto fail;
  nva[0].name = (unsigned char *)":method";
  nva[0].namelen = (uint16_t)strlen((char *)nva[0].name);
  nva[0].value = (unsigned char *)hdbuf;
  nva[0].valuelen = (uint16_t)(end - hdbuf);
  nva[0].flags = NGHTTP2_NV_FLAG_NONE;

  hdbuf = end + 1;

  end = strchr(hdbuf, ' ');
  if(!end)
    goto fail;
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
  if(!hdbuf)
    goto fail;
  ++hdbuf;

  authority_idx = 0;

  for(i = 3; i < nheader; ++i) {
    size_t hlen;
    end = strchr(hdbuf, ':');
    if(!end)
      goto fail;
    hlen = end - hdbuf;
    if(hlen == 10 && Curl_raw_nequal("connection", hdbuf, 10))
      ; /* skip Connection: headers! */
    else if(hlen == 4 && Curl_raw_nequal("host", hdbuf, 4)) {
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
    if(!end)
      goto fail;
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
      stream->upload_left = 0;
      for(j = 0; j < nva[i].valuelen; ++j) {
        stream->upload_left *= 10;
        stream->upload_left += nva[i].value[j] - '0';
      }
      DEBUGF(infof(conn->data,
                   "request content-length=%"
                   CURL_FORMAT_CURL_OFF_T
                   "\n", stream->upload_left));
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
    stream_id = nghttp2_submit_request(h2, NULL, nva, nheader,
                                       &data_prd, conn->data);
    break;
  default:
    stream_id = nghttp2_submit_request(h2, NULL, nva, nheader,
                                       NULL, conn->data);
  }

  Curl_safefree(nva);

  if(stream_id < 0) {
    DEBUGF(infof(conn->data, "http2_send() send error\n"));
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  infof(conn->data, "Using Stream ID: %x (easy handle %p)\n",
        stream_id, conn->data);
  stream->stream_id = stream_id;

  rv = nghttp2_session_send(h2);

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
    nghttp2_session_resume_data(h2, stream->stream_id);
  }

  return len;

  fail:
  free(nva);
  *err = CURLE_SEND_ERROR;
  return -1;
}

CURLcode Curl_http2_setup(struct connectdata *conn)
{
  CURLcode result;
  struct http_conn *httpc = &conn->proto.httpc;
  struct HTTP *stream = conn->data->req.protop;

  stream->stream_id = -1;

  if(!stream->header_recvbuf)
    stream->header_recvbuf = Curl_add_buffer_init();

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
  stream->upload_left = 0;
  stream->upload_mem = NULL;
  stream->upload_len = 0;

  httpc->inbuflen = 0;
  httpc->nread_inbuf = 0;

  httpc->pause_stream_id = 0;

  conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  conn->httpversion = 20;
  conn->bundle->multiuse = BUNDLE_MULTIPLEX;

  infof(conn->data, "Connection state changed (HTTP/2 confirmed)\n");
  Curl_multi_connchanged(conn->data->multi);

  /* switch on TCP_NODELAY as we need to send off packets without delay for
     maximum throughput */
  Curl_tcpnodelay(conn, conn->sock[FIRSTSOCKET]);

  return CURLE_OK;
}

CURLcode Curl_http2_switched(struct connectdata *conn,
                             const char *mem, size_t nread)
{
  CURLcode result;
  struct http_conn *httpc = &conn->proto.httpc;
  int rv;
  ssize_t nproc;
  struct SessionHandle *data = conn->data;
  struct HTTP *stream = conn->data->req.protop;

  result = Curl_http2_setup(conn);
  if(result)
    return result;

  httpc->recv_underlying = (recving)conn->recv[FIRSTSOCKET];
  httpc->send_underlying = (sending)conn->send[FIRSTSOCKET];
  conn->recv[FIRSTSOCKET] = http2_recv;
  conn->send[FIRSTSOCKET] = http2_send;

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

    nghttp2_session_set_stream_user_data(httpc->h2,
                                         stream->stream_id,
                                         conn->data);
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

  /* we are going to copy mem to httpc->inbuf.  This is required since
     mem is part of buffer pointed by stream->mem, and callbacks
     called by nghttp2_session_mem_recv() will write stream specific
     data into stream->mem, overwriting data already there. */
  if(H2_BUFSIZE < nread) {
    failf(data, "connection buffer size is too small to store data following "
                "HTTP Upgrade response header: buflen=%zu, datalen=%zu",
          H2_BUFSIZE, nread);
    return CURLE_HTTP2;
  }

  infof(conn->data, "Copying HTTP/2 data in stream buffer to connection buffer"
                    " after upgrade: len=%zu\n",
        nread);

  memcpy(httpc->inbuf, mem, nread);
  httpc->inbuflen = nread;

  nproc = nghttp2_session_mem_recv(httpc->h2, (const uint8_t *)httpc->inbuf,
                                   httpc->inbuflen);

  if(nghttp2_is_fatal((int)nproc)) {
    failf(data, "nghttp2_session_mem_recv() failed: %s(%d)",
          nghttp2_strerror((int)nproc), (int)nproc);
    return CURLE_HTTP2;
  }

  DEBUGF(infof(data, "nghttp2_session_mem_recv() returns %zd\n", nproc));

  if((ssize_t)nread == nproc) {
    httpc->inbuflen = 0;
    httpc->nread_inbuf = 0;
  }
  else {
    httpc->nread_inbuf += nproc;
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

#else /* !USE_NGHTTP2 */

/* Satisfy external references even if http2 is not compiled in. */

#define CURL_DISABLE_TYPECHECK
#include <curl/curl.h>

char *curl_pushheader_bynum(struct curl_pushheaders *h, size_t num)
{
  (void) h;
  (void) num;
  return NULL;
}

char *curl_pushheader_byname(struct curl_pushheaders *h, const char *header)
{
  (void) h;
  (void) header;
  return NULL;
}

#endif /* USE_NGHTTP2 */
