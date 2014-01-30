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

/* include memdebug.h last */
#include "memdebug.h"

#if (NGHTTP2_VERSION_NUM < 0x000300)
#error too old nghttp2 version, upgrade!
#endif

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
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* readwrite */
  PORT_HTTP,                            /* defport */
  CURLPROTO_HTTP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
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
  ssize_t written;
  CURLcode rc =
    Curl_write(conn, conn->sock[FIRSTSOCKET], data, length, &written);
  (void)h2;
  (void)flags;

  if(rc) {
    failf(conn->data, "Failed sending HTTP2 data");
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  else if(!written)
    return NGHTTP2_ERR_WOULDBLOCK;

  return written;
}

static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                         void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  (void)session;
  (void)frame;
  infof(conn->data, "on_frame_recv() was called with header %x\n",
        frame->hd.type);
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
  (void)session;
  (void)flags;
  (void)data;
  infof(conn->data, "on_data_chunk_recv() "
        "len = %u, stream = %x\n", len, stream_id);

  if(len < c->len) {
    memcpy(c->mem, data, len);
    c->mem += len;
    c->len -= len;
  }
  else {
    infof(conn->data, "EEEEEEK\n");
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
  infof(conn->data, "before_frame_send() was called\n");
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
  (void)session;
  (void)stream_id;
  infof(conn->data, "on_stream_close() was called, error_code = %d\n",
        error_code);
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

/* frame->hd.type is either NGHTTP2_HEADERS or NGHTTP2_PUSH_PROMISE */
static int on_header(nghttp2_session *session, const nghttp2_frame *frame,
                      const uint8_t *name, size_t namelen,
                      const uint8_t *value, size_t valuelen,
                      void *userp)
{
  struct connectdata *conn = (struct connectdata *)userp;
  struct http_conn *c = &conn->proto.httpc;
  size_t hlen = namelen + valuelen + 3; /* colon + CRLF == 3 bytes */

  (void)session;
  (void)frame;

  if(namelen && (name[0] == ':')) {
    /* special case */
    hlen = snprintf(c->mem, c->len, "HTTP/2.0 %s\r\n", value);
  }
  else if(hlen + 1 < c->len) { /* hlen + a zero byte */
    /* convert to a HTTP1-style header */
    memcpy(c->mem, name, namelen);
    c->mem[namelen]=':';
    memcpy(&c->mem[namelen+1], value, valuelen);
    c->mem[namelen + valuelen + 1]='\r';
    c->mem[namelen + valuelen + 2]='\n';
    c->mem[namelen + valuelen + 3]=0; /* to display this easier */
  }
  infof(conn->data, "Got %s", c->mem);
  c->mem += hlen;
  c->len -= hlen;

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
};

/*
 * The HTTP2 settings we send in the Upgrade request
 */
static nghttp2_settings_entry settings[] = {
  { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 },
  { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, NGHTTP2_INITIAL_WINDOW_SIZE },
};

/*
 * Initialize nghttp2 for a Curl connection
 */
CURLcode Curl_http2_init(struct connectdata *conn) {
  if(!conn->proto.httpc.h2) {
    /* The nghttp2 session is not yet setup, do it */
    int rc = nghttp2_session_client_new(&conn->proto.httpc.h2,
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
  free(base64);

  k->upgr101 = UPGR101_REQUESTED;

  return result;
}

#define H2_BUFSIZE 4096

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
  char inbuf[H2_BUFSIZE];

  (void)sockindex; /* we always do HTTP2 on sockindex 0 */

  conn->proto.httpc.mem = mem;
  conn->proto.httpc.len = len;

  infof(conn->data, "http2_recv\n");

  for(;;) {
    rc = Curl_read_plain(conn->sock[FIRSTSOCKET], inbuf, H2_BUFSIZE, &nread);

    if(rc == CURLE_AGAIN) {
      if(len == conn->proto.httpc.len) {
        *err = rc;
        return 0;
      }
      return len - conn->proto.httpc.len;
    }
    if(rc) {
      failf(conn->data, "Failed receiving HTTP2 data");
      *err = CURLE_RECV_ERROR;
      return 0;
    }
    infof(conn->data, "nread=%zd\n", nread);
    if(!nread) {
      *err = CURLE_RECV_ERROR;
      return 0; /* TODO EOF? */
    }
    rv = nghttp2_session_mem_recv(conn->proto.httpc.h2,
                                  (const uint8_t *)inbuf, nread);

    if(nghttp2_is_fatal((int)rv)) {
      failf(conn->data, "nghttp2_session_mem_recv() returned %d:%s\n",
            rv, nghttp2_strerror((int)rv));
      *err = CURLE_RECV_ERROR;
      return 0;
    }
    if(rv < nread) {
      /* Happens when NGHTTP2_ERR_PAUSE is returned from user callback */
      break;
    }
  }
  return len - conn->proto.httpc.len;
}

/* return number of received (decrypted) bytes */
static ssize_t http2_send(struct connectdata *conn, int sockindex,
                          const void *mem, size_t len, CURLcode *err)
{
  /* TODO: proper implementation */
  (void)conn;
  (void)sockindex;
  (void)mem;
  (void)len;
  (void)err;
  return 0;
}

int Curl_http2_switched(struct connectdata *conn)
{
  int rc;
  struct http_conn *httpc = &conn->proto.httpc;
  /* we are switched! */
  conn->handler = &Curl_handler_http2;
  conn->recv[FIRSTSOCKET] = http2_recv;
  conn->send[FIRSTSOCKET] = http2_send;
  infof(conn->data, "We have switched to HTTP2\n");

  /* send the SETTINGS frame (again) */
  rc = nghttp2_session_upgrade(httpc->h2, httpc->binsettings, httpc->binlen,
                               conn);
  return rc;
}

#endif
