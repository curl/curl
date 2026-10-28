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
#include "urldata.h"
#include "ws.h"

#ifndef CURL_DISABLE_WEBSOCKETS

#include "url.h"
#include "bufq.h"
#include "curlx/dynbuf.h"
#include "rand.h"
#include "curlx/base64.h"
#include "cfilters.h"
#include "cf-recvbuf.h"
#include "cf-ws.h"
#include "connect.h"
#include "sendf.h"
#include "curl_trc.h"
#include "multiif.h"
#include "easyif.h"
#include "transfer.h"
#include "select.h"
#include "curlx/strparse.h"
#include "curlx/strcopy.h"


static CURLcode ws_cw_write(struct Curl_easy *data,
                            struct Curl_cwriter *writer, int type,
                            const char *buf, size_t nbytes)
{
  struct cf_ws_ctx *ws;

  CURL_TRC_WRITE(data, "[WS] write(len=%zu, type=%d)", nbytes, type);
  if(!(type & CLIENTWRITE_BODY) || data->set.ws_raw_mode)
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  ws = Curl_cf_ws_get_ctx(data);
  if(!ws) {
    failf(data, "[WS] not a websocket transfer");
    return CURLE_FAILED_INIT;
  }

  if((nbytes == 1) && ws->recvframe_0_len) {
    nbytes = 0;
    type |= CLIENTWRITE_0LEN;
  }
  return Curl_cwriter_write(data, writer->next, type, buf, nbytes);
}

/* WebSocket payload decoding client writer. */
static const struct Curl_cwtype ws_cw_raw = {
  "ws-raw",
  NULL,
  0,
  Curl_cwriter_def_init,
  ws_cw_write,
  Curl_cwriter_def_flush,
  Curl_cwriter_def_close,
  sizeof(struct Curl_cwriter)
};

struct cr_ws_ctx {
  struct Curl_creader super;
  BIT(read_eos);  /* we read an EOS from the next reader */
  BIT(eos);       /* we have returned an EOS */
};

static CURLcode cr_ws_init(struct Curl_easy *data, struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return CURLE_OK;
}

static void cr_ws_close(struct Curl_easy *data, struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
}

static CURLcode cr_ws_read(struct Curl_easy *data,
                           struct Curl_creader *reader,
                           char *buf, size_t blen,
                           size_t *pnread, bool *peos)
{
  struct cr_ws_ctx *ctx = reader->ctx;
  CURLcode result = CURLE_OK;
  size_t nread = 0;
  struct cf_ws_ctx *ws;
  bool eos;

  *pnread = 0;
  *peos = FALSE;
  if(ctx->eos) {
    *peos = TRUE;
    return CURLE_OK;
  }

  ws = Curl_cf_ws_get_ctx(data);
  if(!ws) {
    failf(data, "[WS] not a websocket transfer");
    return CURLE_FAILED_INIT;
  }

  if(!ctx->read_eos) {
    result = Curl_creader_read(data, reader->next, buf, blen, &nread, &eos);
    if(result)
      return result;
    ctx->read_eos = eos;
  }

  if(!Curl_bufq_is_empty(&ws->sendbuf)) {
    /* client_read started a new frame, we disregard any eos reported */
    ctx->read_eos = FALSE;
    Curl_creader_clear_eos(data, reader->next);
  }
  else if(!nread) {
    /* nothing to convert, return this right away */
    if(ctx->read_eos)
      ctx->eos = TRUE;
  }
  *pnread = nread;
  *peos = (bool)ctx->eos;

  CURL_TRC_READ(data, "cr_ws_read(len=%zu) -> %d, nread=%zu, eos=%d",
                blen, (int)result, *pnread, *peos);
  return result;
}

static curl_off_t cr_ws_total_length(struct Curl_easy *data,
                                     struct Curl_creader *reader)
{
  /* this reader changes length depending on input */
  (void)data;
  (void)reader;
  return -1;
}

static const struct Curl_crtype ws_cr_0len = {
  "ws-0len-guard",
  cr_ws_init,
  cr_ws_read,
  cr_ws_close,
  Curl_creader_def_needs_rewind,
  cr_ws_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_cntrl,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_ws_ctx)
};

struct wsfield {
  const char *name;
  const char *val;
};

CURLcode Curl_ws_request(struct Curl_easy *data, struct dynbuf *req)
{
  unsigned int i;
  CURLcode result = CURLE_OK;
  uint8_t rand[16];
  char *randstr;
  size_t randlen;
  char keyval[40];
  struct SingleRequest *k = &data->req;
  struct wsfield heads[] = {
    {
      /* The request MUST contain an |Upgrade| header field whose value
         MUST include the "websocket" keyword. */
      "Upgrade", "websocket"
    },
    {
      /* The request MUST include a header field with the name
         |Sec-WebSocket-Version|. The value of this header field MUST be
         13. */
      "Sec-WebSocket-Version", "13",
    },
    {
      /* The request MUST include a header field with the name
         |Sec-WebSocket-Key|. The value of this header field MUST be a nonce
         consisting of a randomly selected 16-byte value that has been
         base64-encoded (see Section 4 of [RFC4648]). The nonce MUST be
         selected randomly for each connection. */
      "Sec-WebSocket-Key", NULL,
    }
  };
  heads[2].val = &keyval[0];

  /* 16 bytes random */
  result = Curl_rand(data, rand, sizeof(rand));
  if(result)
    return result;
  result = curlx_base64_encode(rand, sizeof(rand), &randstr, &randlen);
  if(result)
    return result;
  DEBUGASSERT(randlen < sizeof(keyval));
  if(randlen >= sizeof(keyval)) {
    curlx_free(randstr);
    return CURLE_FAILED_INIT;
  }
  curlx_strcopy(keyval, sizeof(keyval), randstr, randlen);
  curlx_free(randstr);
  for(i = 0; !result && (i < CURL_ARRAYSIZE(heads)); i++) {
    if(!Curl_checkheaders(data, heads[i].name, strlen(heads[i].name))) {
      result = curlx_dyn_addf(req, "%s: %s\r\n", heads[i].name, heads[i].val);
    }
  }
  data->state.http_hd_upgrade = TRUE;
  k->upgr101 = UPGR101_WS;
  data->conn->bits.upgrade_in_progress = TRUE;
  return result;
}

/*
 * 'nread' is number of bytes of websocket data already in the buffer at
 * 'mem'.
 */
CURLcode Curl_ws_accept(struct Curl_easy *data,
                        const char *mem, size_t nread)
{
  struct SingleRequest *k = &data->req;
  struct Curl_cwriter *ws_dec_writer = NULL;
  struct Curl_creader *ws_enc_reader = NULL;
  CURLcode result;

  DEBUGASSERT(data->conn);

  result = Curl_cf_ws_add(data, mem, nread);
  if(result)
    goto out;

  /* Install our client writer that watches 0-length output */
  result = Curl_cwriter_create(&ws_dec_writer, data, &ws_cw_raw,
                               CURL_CW_RAW);
  if(result)
    goto out;
  result = Curl_cwriter_add(data, ws_dec_writer);
  if(result)
    goto out;
  ws_dec_writer = NULL; /* owned by transfer now */

  k->header = FALSE; /* we will not get more response headers */
  if((data->set.method == HTTPREQ_PUT) && !data->set.connect_only) {
    CURL_TRC_WS(data, "prepare for upload");
    result = Curl_creader_set_fread(data, -1);
    if(result)
      goto out;

    if(!data->set.ws_raw_mode) {
      /* Add our client reader, watching 0-length frames input */
      result = Curl_creader_create(&ws_enc_reader, data, &ws_cr_0len,
                                   CURL_CR_CONTENT_ENCODE);
      if(result)
        goto out;
      result = Curl_creader_add(data, ws_enc_reader);
      if(result)
        goto out;
      ws_enc_reader = NULL; /* owned by transfer now */
    }
    /* start over with sending */
    data->req.eos_read = FALSE;
    data->req.eos_sent = FALSE;
    data->req.upload_done = FALSE;
    data->req.send_no_merge = TRUE;
    CURL_REQ_SET_SEND(data);
  }

  k->upgr101 = UPGR101_RECEIVED;
  k->header = FALSE; /* we will not get more responses */


  if(data->set.connect_only)
    CURL_REQ_CLEAR_RECV(data); /* read no more content in multi loop */

out:
  if(ws_dec_writer)
    Curl_cwriter_free(data, ws_dec_writer);
  if(ws_enc_reader)
    Curl_creader_free(data, ws_enc_reader);
  if(result)
    CURL_TRC_WS(data, "Curl_ws_accept() failed -> %d", (int)result);
  else
    CURL_TRC_WS(data, "websocket established, %s mode",
                data->set.connect_only ? "connect-only" : "callback");
  return result;
}

CURLcode curl_ws_recv(CURL *curl, void *buffer,
                      size_t buflen, size_t *recv,
                      const struct curl_ws_frame **metap)
{
  struct Curl_eapi_guard guard;
  CURLcode result = CURLE_OK;

  if(CURL_EAPI_ENTER(&guard, curl, ws_recv, &result)) {
    struct Curl_easy *data = curl;
    struct connectdata *conn;
    struct cf_ws_ctx *ws;

    if(!recv || !metap || (buflen && !buffer)) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    *recv = 0;
    *metap = NULL;

    conn = data->conn;
    if(!conn) {
      /* Unhappy hack with lifetimes of transfers and connection */
      if(!data->set.connect_only) {
        failf(data, "[WS] CONNECT_ONLY is required");
        result = CURLE_UNSUPPORTED_PROTOCOL;
        goto out;
      }

      Curl_getconnectinfo(data, &conn);
      if(!conn) {
        failf(data, "[WS] connection not found");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
    }
    ws = Curl_cf_ws_conn_get_ctx(conn);
    if(!ws) {
      failf(data, "[WS] connection is not setup for websocket");
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    result = Curl_easy_recv(data, buffer, buflen, recv);
    if(!result) {
      *metap = &ws->recvframe;
      if((*recv == 0) && buflen) {
        /* end of connection */
        result = CURLE_GOT_NOTHING;
      }
      else if((*recv == 1) && ws->recvframe_0_len) {
        /* fake byte for a 0-length frame */
        *recv = 0;
      }
    }
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

static CURLcode ws_send_raw_blocking(struct Curl_easy *data,
                                     struct cf_ws_ctx *ws,
                                     const char *buffer, size_t buflen)
{
  CURLcode result = CURLE_OK;
  size_t nwritten;

  if(!data)
    return result;

  (void)ws;
  while(buflen || Curl_xfer_needs_flush(data)) {
    if(!buflen) {
      result = Curl_xfer_flush(data);
      if(result && (result != CURLE_AGAIN))
        return result;
    }
    else {
      result = Curl_xfer_send(data, buffer, buflen, FALSE, &nwritten);
      if(result)
        return result;
      DEBUGASSERT(nwritten <= buflen);
      buffer += nwritten;
      buflen -= nwritten;
    }

    if(buflen || Curl_xfer_needs_flush(data)) {
      curl_socket_t sock = data->conn->sock[FIRSTSOCKET];
      timediff_t left_ms;
      int ev;

      CURL_TRC_WS(data, "ws_send_raw_blocking() partial, %zu left to send",
                  buflen);
      left_ms = Curl_timeleft_ms(data);
      if(left_ms < 0) {
        failf(data, "[WS] Timeout waiting for socket becoming writable");
        return CURLE_SEND_ERROR;
      }

      /* POLLOUT socket */
      if(sock == CURL_SOCKET_BAD)
        return CURLE_SEND_ERROR;
      ev = SOCKET_WRITABLE(sock, left_ms ? left_ms : 500);
      if(ev < 0) {
        failf(data, "[WS] Error while waiting for socket becoming writable");
        return CURLE_SEND_ERROR;
      }
    }
  }
  return result;
}

static CURLcode ws_send_raw(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            const void *buffer, size_t buflen,
                            size_t *pnwritten)
{
  struct cf_ws_ctx *ws = cf->ctx;
  CURLcode result;
  char b;

  if(!buffer)
    buffer = &b;

  result = ws_send_raw_blocking(data, ws, buffer, buflen);
  if(!result)
    *pnwritten = buflen;
  CURL_TRC_WS(data, "ws_send_raw(len=%zu) -> %d, %zu",
              buflen, (int)result, *pnwritten);
  return result;
}

CURLcode curl_ws_send(CURL *curl, const void *buffer_arg,
                      size_t buflen, size_t *sent,
                      curl_off_t fragsize,
                      unsigned int flags)
{
  struct Curl_eapi_guard guard;
  CURLcode result = CURLE_OK;

  if(CURL_EAPI_ENTER(&guard, curl, ws_send, &result)) {
    struct Curl_cfilter *cf;
    const uint8_t *buffer = buffer_arg;
    struct Curl_easy *data = curl;
    size_t ndummy;
    size_t *pnsent = sent ? sent : &ndummy;

    CURL_TRC_WS(data, "curl_ws_send(len=%zu, fragsize=%" FMT_OFF_T
                ", flags=%x), raw=%d",
                buflen, fragsize, flags, data->set.ws_raw_mode);

    *pnsent = 0;

    if(!buffer && buflen) {
      failf(data, "[WS] buffer is NULL when buflen is not");
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    if(!data->conn && data->set.connect_only) {
      result = Curl_connect_only_attach(data);
      if(result)
        goto out;
    }
    if(!data->conn) {
      failf(data, "[WS] No associated connection");
      result = CURLE_SEND_ERROR;
      goto out;
    }

    cf = Curl_cf_ws_get(data);
    if(!cf) {
      failf(data, "[WS] Not a websocket connection");
      result = CURLE_SEND_ERROR;
      goto out;
    }

    if(data->set.ws_raw_mode) {
      if(!buffer) {
        failf(data, "[WS] buffer is NULL in raw mode");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      if(!sent) {
        failf(data, "[WS] sent is NULL in raw mode");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      if(fragsize || flags) {
        failf(data, "[WS] fragsize and flags must be zero in raw mode");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
    }
    else if(!Curl_cf_ws_in_send_frame(cf, data)) {
      /* start a new frame */
      curl_off_t frame_len = fragsize ? fragsize : (curl_off_t)buflen;
      result = Curl_cf_ws_start_frame(cf, data, flags, frame_len);
      if(result)
        goto out;
    }

    result = ws_send_raw(cf, data, buffer, buflen, pnsent);
    CURL_TRC_WS(data, "curl_ws_send(len=%zu, fragsize=%" FMT_OFF_T
                ", flags=%x, raw=%d) -> %d, %zu",
                buflen, fragsize, flags, data->set.ws_raw_mode, (int)result,
                *pnsent);
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

static CURLcode ws_setup_conn(struct Curl_easy *data,
                              struct connectdata *conn)
{
  (void)conn;
  /* WebSocket is 1.1 only (for now) */
  data->state.http_neg.accept_09 = FALSE;
  data->state.http_neg.only_10 = FALSE;
  data->state.http_neg.wanted = CURL_HTTP_V1x;
  data->state.http_neg.allowed = CURL_HTTP_V1x;
  return Curl_http_setup_conn(data, conn);
}

const struct curl_ws_frame *curl_ws_meta(CURL *curl)
{
  /* we only return something for websocket, called from within the callback
     when not using raw mode */
  struct Curl_easy *data = curl;
  if(GOOD_EASY_HANDLE(data) && Curl_api_is_in_callback(data) &&
     data->conn && !data->set.ws_raw_mode) {
    struct cf_ws_ctx *ws;
    ws = Curl_cf_ws_get_ctx(data);
    if(ws)
      return &ws->recvframe;
  }
  return NULL;
}

CURL_EXTERN CURLcode curl_ws_start_frame(CURL *curl,
                                         unsigned int flags,
                                         curl_off_t frame_len)
{
  struct Curl_eapi_guard guard;
  CURLcode result = CURLE_OK;

  if(CURL_EAPI_ENTER(&guard, curl, ws_start_frame, &result)) {
    struct Curl_easy *data = curl;
    struct Curl_cfilter *cf;

    if(data->set.ws_raw_mode) {
      failf(data, "cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled");
      result = CURLE_FAILED_INIT;
      goto out;
    }

    CURL_TRC_WS(data, "curl_ws_start_frame(flags=%x, frame_len=%" FMT_OFF_T,
                flags, frame_len);

    cf = Curl_cf_ws_get(data);
    if(!cf) {
      failf(data, "[WS] No websocket connection");
      result = CURLE_SEND_ERROR;
      goto out;
    }

    result = Curl_cf_ws_start_frame(cf, data, flags, frame_len);
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

static CURLcode ws_setup_filters(struct Curl_easy *data,
                                 struct Curl_cfilter *cf)
{
  CURLcode result;

  result = Curl_http_setup_filters(data, cf);
  if(result)
    return result;

  if(Curl_conn_cf_http_version(data, cf) >= 20) {
    failf(data, "websocket over HTTP later than 1.1 not implemented");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }
  return CURLE_OK;
}

const struct Curl_protocol Curl_protocol_ws = {
  ws_setup_conn,                        /* setup_connection */
  ws_setup_filters,                     /* setup_filters */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_pollset */
  Curl_http_doing_pollset,              /* doing_pollset */
  ZERO_NULL,                            /* domore_pollset */
  Curl_http_perform_pollset,            /* perform_pollset */
  ZERO_NULL,                            /* disconnect */
  Curl_http_write_resp,                 /* write_resp */
  Curl_http_write_resp_hd,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_is_dead */
  ZERO_NULL,                            /* attach connection */
  Curl_http_follow,                     /* follow */
};

#else

CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen,
                      size_t *recv,
                      const struct curl_ws_frame **metap)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)recv;
  (void)metap;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_ws_send(CURL *curl, const void *buffer,
                      size_t buflen, size_t *sent,
                      curl_off_t fragsize,
                      unsigned int flags)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)sent;
  (void)fragsize;
  (void)flags;
  return CURLE_NOT_BUILT_IN;
}

const struct curl_ws_frame *curl_ws_meta(CURL *data)
{
  (void)data;
  return NULL;
}

CURL_EXTERN CURLcode curl_ws_start_frame(CURL *curl,
                                         unsigned int flags,
                                         curl_off_t frame_len)
{
  (void)curl;
  (void)flags;
  (void)frame_len;
  return CURLE_NOT_BUILT_IN;
}

#endif /* !CURL_DISABLE_WEBSOCKETS */
