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
#include <curl/curl.h>

#if !defined(CURL_DISABLE_WEBSOCKETS) && !defined(CURL_DISABLE_HTTP)

#include "urldata.h"
#include "url.h"
#include "bufq.h"
#include "curlx/dynbuf.h"
#include "rand.h"
#include "curlx/base64.h"
#include "connect.h"
#include "sendf.h"
#include "multiif.h"
#include "ws.h"
#include "easyif.h"
#include "transfer.h"
#include "select.h"
#include "curlx/nonblock.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


/***
    RFC 6455 Section 5.2

      0 1 2 3 4 5 6 7
     +-+-+-+-+-------+
     |F|R|R|R| opcode|
     |I|S|S|S|  (4)  |
     |N|V|V|V|       |
     | |1|2|3|       |
*/
#define WSBIT_FIN  (0x80)
#define WSBIT_RSV1 (0x40)
#define WSBIT_RSV2 (0x20)
#define WSBIT_RSV3 (0x10)
#define WSBIT_RSV_MASK (WSBIT_RSV1 | WSBIT_RSV2 | WSBIT_RSV3)
#define WSBIT_OPCODE_CONT  (0x0)
#define WSBIT_OPCODE_TEXT  (0x1)
#define WSBIT_OPCODE_BIN   (0x2)
#define WSBIT_OPCODE_CLOSE (0x8)
#define WSBIT_OPCODE_PING  (0x9)
#define WSBIT_OPCODE_PONG  (0xa)
#define WSBIT_OPCODE_MASK  (0xf)

#define WSBIT_MASK 0x80

/* buffer dimensioning */
#define WS_CHUNK_SIZE 65535
#define WS_CHUNK_COUNT 2


/* a client-side WS frame decoder, parsing frame headers and
 * payload, keeping track of current position and stats */
enum ws_dec_state {
  WS_DEC_INIT,
  WS_DEC_HEAD,
  WS_DEC_PAYLOAD
};

struct ws_decoder {
  int frame_age;        /* zero */
  int frame_flags;      /* See the CURLWS_* defines */
  curl_off_t payload_offset;   /* the offset parsing is at */
  curl_off_t payload_len;
  unsigned char head[10];
  int head_len, head_total;
  enum ws_dec_state state;
  int cont_flags;
};

/* a client-side WS frame encoder, generating frame headers and
 * converting payloads, tracking remaining data in current frame */
struct ws_encoder {
  curl_off_t payload_len;  /* payload length of current frame */
  curl_off_t payload_remain;  /* remaining payload of current */
  unsigned int xori; /* xor index */
  unsigned char mask[4]; /* 32-bit mask for this connection */
  unsigned char firstbyte; /* first byte of frame we encode */
  BIT(contfragment); /* set TRUE if the previous fragment sent was not final */
};

/* Control frames are allowed up to 125 characters, rfc6455, ch. 5.5 */
#define WS_MAX_CNTRL_LEN    125

struct ws_cntrl_frame {
  unsigned int type;
  size_t payload_len;
  unsigned char payload[WS_MAX_CNTRL_LEN];
};

/* A websocket connection with en- and decoder that treat frames
 * and keep track of boundaries. */
struct websocket {
  struct Curl_easy *data; /* used for write callback handling */
  struct ws_decoder dec;  /* decode of we frames */
  struct ws_encoder enc;  /* decode of we frames */
  struct bufq recvbuf;    /* raw data from the server */
  struct bufq sendbuf;    /* raw data to be sent to the server */
  struct curl_ws_frame recvframe;  /* the current WS FRAME received */
  struct ws_cntrl_frame pending; /* a control frame pending to be sent */
  size_t sendbuf_payload; /* number of payload bytes in sendbuf */
};


static const char *ws_frame_name_of_op(unsigned char firstbyte)
{
  switch(firstbyte & WSBIT_OPCODE_MASK) {
    case WSBIT_OPCODE_CONT:
      return "CONT";
    case WSBIT_OPCODE_TEXT:
      return "TEXT";
    case WSBIT_OPCODE_BIN:
      return "BIN";
    case WSBIT_OPCODE_CLOSE:
      return "CLOSE";
    case WSBIT_OPCODE_PING:
      return "PING";
    case WSBIT_OPCODE_PONG:
      return "PONG";
    default:
      return "???";
  }
}

static int ws_frame_firstbyte2flags(struct Curl_easy *data,
                                    unsigned char firstbyte, int cont_flags)
{
  switch(firstbyte) {
    /* 0x00 - intermediate TEXT/BINARY fragment */
    case WSBIT_OPCODE_CONT:
      if(!(cont_flags & CURLWS_CONT)) {
        failf(data, "[WS] no ongoing fragmented message to resume");
        return 0;
      }
      return cont_flags | CURLWS_CONT;
    /* 0x80 - final TEXT/BIN fragment */
    case (WSBIT_OPCODE_CONT | WSBIT_FIN):
      if(!(cont_flags & CURLWS_CONT)) {
        failf(data, "[WS] no ongoing fragmented message to resume");
        return 0;
      }
      return cont_flags & ~CURLWS_CONT;
    /* 0x01 - first TEXT fragment */
    case WSBIT_OPCODE_TEXT:
      if(cont_flags & CURLWS_CONT) {
        failf(data, "[WS] fragmented message interrupted by new TEXT msg");
        return 0;
      }
      return CURLWS_TEXT | CURLWS_CONT;
    /* 0x81 - unfragmented TEXT msg */
    case (WSBIT_OPCODE_TEXT | WSBIT_FIN):
      if(cont_flags & CURLWS_CONT) {
        failf(data, "[WS] fragmented message interrupted by new TEXT msg");
        return 0;
      }
      return CURLWS_TEXT;
    /* 0x02 - first BINARY fragment */
    case WSBIT_OPCODE_BIN:
      if(cont_flags & CURLWS_CONT) {
        failf(data, "[WS] fragmented message interrupted by new BINARY msg");
        return 0;
      }
      return CURLWS_BINARY | CURLWS_CONT;
    /* 0x82 - unfragmented BINARY msg */
    case (WSBIT_OPCODE_BIN | WSBIT_FIN):
      if(cont_flags & CURLWS_CONT) {
        failf(data, "[WS] fragmented message interrupted by new BINARY msg");
        return 0;
      }
      return CURLWS_BINARY;
    /* 0x08 - first CLOSE fragment */
    case WSBIT_OPCODE_CLOSE:
      failf(data, "[WS] invalid fragmented CLOSE frame");
      return 0;
    /* 0x88 - unfragmented CLOSE */
    case (WSBIT_OPCODE_CLOSE | WSBIT_FIN):
      return CURLWS_CLOSE;
    /* 0x09 - first PING fragment */
    case WSBIT_OPCODE_PING:
      failf(data, "[WS] invalid fragmented PING frame");
      return 0;
    /* 0x89 - unfragmented PING */
    case (WSBIT_OPCODE_PING | WSBIT_FIN):
      return CURLWS_PING;
    /* 0x0a - first PONG fragment */
    case WSBIT_OPCODE_PONG:
      failf(data, "[WS] invalid fragmented PONG frame");
      return 0;
    /* 0x8a - unfragmented PONG */
    case (WSBIT_OPCODE_PONG | WSBIT_FIN):
      return CURLWS_PONG;
    /* invalid first byte */
    default:
      if(firstbyte & WSBIT_RSV_MASK)
        /* any of the reserved bits 0x40/0x20/0x10 are set */
        failf(data, "[WS] invalid reserved bits: %02x", firstbyte);
      else
        /* any of the reserved opcodes 0x3-0x7 or 0xb-0xf is used */
        failf(data, "[WS] invalid opcode: %02x", firstbyte);
      return 0;
  }
}

static CURLcode ws_frame_flags2firstbyte(struct Curl_easy *data,
                                         unsigned int flags,
                                         bool contfragment,
                                         unsigned char *pfirstbyte)
{
  *pfirstbyte = 0;
  switch(flags & ~CURLWS_OFFSET) {
    case 0:
      if(contfragment) {
        CURL_TRC_WS(data, "no flags given; interpreting as continuation "
                    "fragment for compatibility");
        *pfirstbyte = (WSBIT_OPCODE_CONT | WSBIT_FIN);
        return CURLE_OK;
      }
      failf(data, "[WS] no flags given");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    case CURLWS_CONT:
      if(contfragment) {
        infof(data, "[WS] setting CURLWS_CONT flag without message type is "
                    "supported for compatibility but highly discouraged");
        *pfirstbyte = WSBIT_OPCODE_CONT;
        return CURLE_OK;
      }
      failf(data, "[WS] No ongoing fragmented message to continue");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    case CURLWS_TEXT:
      *pfirstbyte = contfragment ? (WSBIT_OPCODE_CONT | WSBIT_FIN)
                                 : (WSBIT_OPCODE_TEXT | WSBIT_FIN);
      return CURLE_OK;
    case (CURLWS_TEXT | CURLWS_CONT):
      *pfirstbyte = contfragment ? WSBIT_OPCODE_CONT : WSBIT_OPCODE_TEXT;
      return CURLE_OK;
    case CURLWS_BINARY:
      *pfirstbyte = contfragment ? (WSBIT_OPCODE_CONT | WSBIT_FIN)
                                 : (WSBIT_OPCODE_BIN | WSBIT_FIN);
      return CURLE_OK;
    case (CURLWS_BINARY | CURLWS_CONT):
      *pfirstbyte = contfragment ? WSBIT_OPCODE_CONT : WSBIT_OPCODE_BIN;
      return CURLE_OK;
    case CURLWS_CLOSE:
      *pfirstbyte = WSBIT_OPCODE_CLOSE | WSBIT_FIN;
      return CURLE_OK;
    case (CURLWS_CLOSE | CURLWS_CONT):
      failf(data, "[WS] CLOSE frame must not be fragmented");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    case CURLWS_PING:
      *pfirstbyte = WSBIT_OPCODE_PING | WSBIT_FIN;
      return CURLE_OK;
    case (CURLWS_PING | CURLWS_CONT):
      failf(data, "[WS] PING frame must not be fragmented");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    case CURLWS_PONG:
      *pfirstbyte = WSBIT_OPCODE_PONG | WSBIT_FIN;
      return CURLE_OK;
    case (CURLWS_PONG | CURLWS_CONT):
      failf(data, "[WS] PONG frame must not be fragmented");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    default:
      failf(data, "[WS] unknown flags: %x", flags);
      return CURLE_BAD_FUNCTION_ARGUMENT;
  }
}

static void ws_dec_info(struct ws_decoder *dec, struct Curl_easy *data,
                        const char *msg)
{
  switch(dec->head_len) {
  case 0:
    break;
  case 1:
    CURL_TRC_WS(data, "decoded %s [%s%s]", msg,
                ws_frame_name_of_op(dec->head[0]),
                (dec->head[0] & WSBIT_FIN) ? "" : " NON-FINAL");
    break;
  default:
    if(dec->head_len < dec->head_total) {
      CURL_TRC_WS(data, "decoded %s [%s%s](%d/%d)", msg,
                  ws_frame_name_of_op(dec->head[0]),
                  (dec->head[0] & WSBIT_FIN) ? "" : " NON-FINAL",
                  dec->head_len, dec->head_total);
    }
    else {
      CURL_TRC_WS(data, "decoded %s [%s%s payload=%"
                  FMT_OFF_T "/%" FMT_OFF_T "]",
                  msg, ws_frame_name_of_op(dec->head[0]),
                  (dec->head[0] & WSBIT_FIN) ? "" : " NON-FINAL",
                  dec->payload_offset, dec->payload_len);
    }
    break;
  }
}

static CURLcode ws_send_raw_blocking(struct Curl_easy *data,
                                     struct websocket *ws,
                                     const char *buffer, size_t buflen);

typedef CURLcode ws_write_payload(const unsigned char *buf, size_t buflen,
                                  int frame_age, int frame_flags,
                                  curl_off_t payload_offset,
                                  curl_off_t payload_len,
                                  void *userp,
                                  size_t *pnwritten);

static void ws_dec_next_frame(struct ws_decoder *dec)
{
  dec->frame_age = 0;
  dec->frame_flags = 0;
  dec->payload_offset = 0;
  dec->payload_len = 0;
  dec->head_len = dec->head_total = 0;
  dec->state = WS_DEC_INIT;
  /* dec->cont_flags must be carried over to next frame */
}

static void ws_dec_reset(struct ws_decoder *dec)
{
  dec->frame_age = 0;
  dec->frame_flags = 0;
  dec->payload_offset = 0;
  dec->payload_len = 0;
  dec->head_len = dec->head_total = 0;
  dec->state = WS_DEC_INIT;
  dec->cont_flags = 0;
}

static void ws_dec_init(struct ws_decoder *dec)
{
  ws_dec_reset(dec);
}

static CURLcode ws_dec_read_head(struct ws_decoder *dec,
                                 struct Curl_easy *data,
                                 struct bufq *inraw)
{
  const unsigned char *inbuf;
  size_t inlen;

  while(Curl_bufq_peek(inraw, &inbuf, &inlen)) {
    if(dec->head_len == 0) {
      dec->head[0] = *inbuf;
      Curl_bufq_skip(inraw, 1);

      dec->frame_flags = ws_frame_firstbyte2flags(data, dec->head[0],
                                                  dec->cont_flags);
      if(!dec->frame_flags) {
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }

      /* fragmentation only applies to data frames (text/binary);
       * control frames (close/ping/pong) do not affect the CONT status */
      if(dec->frame_flags & (CURLWS_TEXT | CURLWS_BINARY)) {
        dec->cont_flags = dec->frame_flags;
      }

      dec->head_len = 1;
      /* ws_dec_info(dec, data, "seeing opcode"); */
      continue;
    }
    else if(dec->head_len == 1) {
      dec->head[1] = *inbuf;
      Curl_bufq_skip(inraw, 1);
      dec->head_len = 2;

      if(dec->head[1] & WSBIT_MASK) {
        /* A client MUST close a connection if it detects a masked frame. */
        failf(data, "[WS] masked input frame");
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }
      if(dec->frame_flags & CURLWS_PING && dec->head[1] > WS_MAX_CNTRL_LEN) {
        /* The maximum valid size of PING frames is 125 bytes.
           Accepting overlong pings would mean sending equivalent pongs! */
        failf(data, "[WS] received PING frame is too big");
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }
      if(dec->frame_flags & CURLWS_PONG && dec->head[1] > WS_MAX_CNTRL_LEN) {
        /* The maximum valid size of PONG frames is 125 bytes. */
        failf(data, "[WS] received PONG frame is too big");
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }
      if(dec->frame_flags & CURLWS_CLOSE && dec->head[1] > WS_MAX_CNTRL_LEN) {
        failf(data, "[WS] received CLOSE frame is too big");
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }

      /* How long is the frame head? */
      if(dec->head[1] == 126) {
        dec->head_total = 4;
        continue;
      }
      else if(dec->head[1] == 127) {
        dec->head_total = 10;
        continue;
      }
      else {
        dec->head_total = 2;
      }
    }

    if(dec->head_len < dec->head_total) {
      dec->head[dec->head_len] = *inbuf;
      Curl_bufq_skip(inraw, 1);
      ++dec->head_len;
      if(dec->head_len < dec->head_total) {
        /* ws_dec_info(dec, data, "decoding head"); */
        continue;
      }
    }
    /* got the complete frame head */
    DEBUGASSERT(dec->head_len == dec->head_total);
    switch(dec->head_total) {
    case 2:
      dec->payload_len = dec->head[1];
      break;
    case 4:
      dec->payload_len = (dec->head[2] << 8) | dec->head[3];
      break;
    case 10:
      if(dec->head[2] > 127) {
        failf(data, "[WS] frame length longer than 64 signed not supported");
        return CURLE_RECV_ERROR;
      }
      dec->payload_len = ((curl_off_t)dec->head[2] << 56) |
        (curl_off_t)dec->head[3] << 48 |
        (curl_off_t)dec->head[4] << 40 |
        (curl_off_t)dec->head[5] << 32 |
        (curl_off_t)dec->head[6] << 24 |
        (curl_off_t)dec->head[7] << 16 |
        (curl_off_t)dec->head[8] << 8 |
        dec->head[9];
      break;
    default:
      /* this should never happen */
      DEBUGASSERT(0);
      failf(data, "[WS] unexpected frame header length");
      return CURLE_RECV_ERROR;
    }

    dec->frame_age = 0;
    dec->payload_offset = 0;
    ws_dec_info(dec, data, "decoded");
    return CURLE_OK;
  }
  return CURLE_AGAIN;
}

static CURLcode ws_dec_pass_payload(struct ws_decoder *dec,
                                    struct Curl_easy *data,
                                    struct bufq *inraw,
                                    ws_write_payload *write_cb,
                                    void *write_ctx)
{
  const unsigned char *inbuf;
  size_t inlen;
  size_t nwritten;
  CURLcode result;
  curl_off_t remain = dec->payload_len - dec->payload_offset;

  (void)data;
  while(remain && Curl_bufq_peek(inraw, &inbuf, &inlen)) {
    if((curl_off_t)inlen > remain)
      inlen = (size_t)remain;
    result = write_cb(inbuf, inlen, dec->frame_age, dec->frame_flags,
                      dec->payload_offset, dec->payload_len,
                      write_ctx, &nwritten);
    if(result)
      return result;
    Curl_bufq_skip(inraw, nwritten);
    dec->payload_offset += nwritten;
    remain = dec->payload_len - dec->payload_offset;
    CURL_TRC_WS(data, "passed %zu bytes payload, %"
                FMT_OFF_T " remain", nwritten, remain);
  }

  return remain ? CURLE_AGAIN : CURLE_OK;
}

static CURLcode ws_dec_pass(struct ws_decoder *dec,
                            struct Curl_easy *data,
                            struct bufq *inraw,
                            ws_write_payload *write_cb,
                            void *write_ctx)
{
  CURLcode result;

  if(Curl_bufq_is_empty(inraw))
    return CURLE_AGAIN;

  switch(dec->state) {
  case WS_DEC_INIT:
    ws_dec_next_frame(dec);
    dec->state = WS_DEC_HEAD;
    FALLTHROUGH();
  case WS_DEC_HEAD:
    result = ws_dec_read_head(dec, data, inraw);
    if(result) {
      if(result != CURLE_AGAIN) {
        failf(data, "[WS] decode frame error %d", (int)result);
        break;  /* real error */
      }
      /* incomplete ws frame head */
      DEBUGASSERT(Curl_bufq_is_empty(inraw));
      break;
    }
    /* head parsing done */
    dec->state = WS_DEC_PAYLOAD;
    if(dec->payload_len == 0) {
      size_t nwritten;
      const unsigned char tmp = '\0';
      /* special case of a 0 length frame, need to write once */
      result = write_cb(&tmp, 0, dec->frame_age, dec->frame_flags,
                          0, 0, write_ctx, &nwritten);
      if(result)
        return result;
      dec->state = WS_DEC_INIT;
      break;
    }
    FALLTHROUGH();
  case WS_DEC_PAYLOAD:
    result = ws_dec_pass_payload(dec, data, inraw, write_cb, write_ctx);
    ws_dec_info(dec, data, "passing");
    if(result)
      return result;
    /* payload parsing done */
    dec->state = WS_DEC_INIT;
    break;
  default:
    /* we covered all enums above, but some code analyzers are whimps */
    result = CURLE_FAILED_INIT;
  }
  return result;
}

static void update_meta(struct websocket *ws,
                        int frame_age, int frame_flags,
                        curl_off_t payload_offset,
                        curl_off_t payload_len,
                        size_t cur_len)
{
  curl_off_t bytesleft = (payload_len - payload_offset - cur_len);

  ws->recvframe.age = frame_age;
  ws->recvframe.flags = frame_flags;
  ws->recvframe.offset = payload_offset;
  ws->recvframe.len = cur_len;
  ws->recvframe.bytesleft = bytesleft;
}

/* WebSockets decoding client writer */
struct ws_cw_ctx {
  struct Curl_cwriter super;
  struct bufq buf;
};

static CURLcode ws_cw_init(struct Curl_easy *data,
                           struct Curl_cwriter *writer)
{
  struct ws_cw_ctx *ctx = writer->ctx;
  (void)data;
  Curl_bufq_init2(&ctx->buf, WS_CHUNK_SIZE, 1, BUFQ_OPT_SOFT_LIMIT);
  return CURLE_OK;
}

static void ws_cw_close(struct Curl_easy *data, struct Curl_cwriter *writer)
{
  struct ws_cw_ctx *ctx = writer->ctx;
  (void)data;
  Curl_bufq_free(&ctx->buf);
}

struct ws_cw_dec_ctx {
  struct Curl_easy *data;
  struct websocket *ws;
  struct Curl_cwriter *next_writer;
  int cw_type;
};

static CURLcode ws_flush(struct Curl_easy *data, struct websocket *ws,
                         bool blocking);
static CURLcode ws_enc_send(struct Curl_easy *data,
                            struct websocket *ws,
                            const unsigned char *buffer,
                            size_t buflen,
                            curl_off_t fragsize,
                            unsigned int flags,
                            size_t *sent);
static CURLcode ws_enc_add_pending(struct Curl_easy *data,
                                   struct websocket *ws);

static CURLcode ws_enc_add_cntrl(struct Curl_easy *data,
                                 struct websocket *ws,
                                 const unsigned char *payload,
                                 size_t plen,
                                 unsigned int frame_type)
{
  DEBUGASSERT(plen <= WS_MAX_CNTRL_LEN);
  if(plen > WS_MAX_CNTRL_LEN)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* Overwrite any pending frame with the new one, we keep
   * only one. */
  ws->pending.type = frame_type;
  ws->pending.payload_len = plen;
  memcpy(ws->pending.payload, payload, plen);

  if(!ws->enc.payload_remain) { /* not in the middle of another frame */
    CURLcode result = ws_enc_add_pending(data, ws);
    if(!result)
      (void)ws_flush(data, ws, Curl_is_in_callback(data));
    return result;
  }
  return CURLE_OK;
}

static CURLcode ws_cw_dec_next(const unsigned char *buf, size_t buflen,
                               int frame_age, int frame_flags,
                               curl_off_t payload_offset,
                               curl_off_t payload_len,
                               void *user_data,
                               size_t *pnwritten)
{
  struct ws_cw_dec_ctx *ctx = user_data;
  struct Curl_easy *data = ctx->data;
  struct websocket *ws = ctx->ws;
  bool auto_pong = !data->set.ws_no_auto_pong;
  curl_off_t remain = (payload_len - (payload_offset + buflen));
  CURLcode result;

  (void)frame_age;
  *pnwritten = 0;

  if(auto_pong && (frame_flags & CURLWS_PING) && !remain) {
    /* auto-respond to PINGs, only works for single-frame payloads atm */
    CURL_TRC_WS(data, "auto PONG to [PING payload=%" FMT_OFF_T
                "/%" FMT_OFF_T "]", payload_offset, payload_len);
    /* send back the exact same content as a PONG */
    result = ws_enc_add_cntrl(data, ws, buf, buflen, CURLWS_PONG);
    if(result)
      return result;
  }
  else if(buflen || !remain) {
    /* forward the decoded frame to the next client writer. */
    update_meta(ws, frame_age, frame_flags, payload_offset,
                payload_len, buflen);

    result = Curl_cwriter_write(data, ctx->next_writer,
                              (ctx->cw_type | CLIENTWRITE_0LEN),
                              (const char *)buf, buflen);
    if(result)
      return result;
  }
  *pnwritten = buflen;
  return CURLE_OK;
}

static CURLcode ws_cw_write(struct Curl_easy *data,
                            struct Curl_cwriter *writer, int type,
                            const char *buf, size_t nbytes)
{
  struct ws_cw_ctx *ctx = writer->ctx;
  struct websocket *ws;
  CURLcode result;

  CURL_TRC_WRITE(data, "ws_cw_write(len=%zu, type=%d)", nbytes, type);
  if(!(type & CLIENTWRITE_BODY) || data->set.ws_raw_mode)
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] not a websocket transfer");
    return CURLE_FAILED_INIT;
  }

  if(nbytes) {
    size_t nwritten;
    result = Curl_bufq_write(&ctx->buf, (const unsigned char *)buf,
                             nbytes, &nwritten);
    if(result) {
      infof(data, "[WS] error adding data to buffer %d", result);
      return result;
    }
  }

  while(!Curl_bufq_is_empty(&ctx->buf)) {
    struct ws_cw_dec_ctx pass_ctx;
    pass_ctx.data = data;
    pass_ctx.ws = ws;
    pass_ctx.next_writer = writer->next;
    pass_ctx.cw_type = type;
    result = ws_dec_pass(&ws->dec, data, &ctx->buf,
                         ws_cw_dec_next, &pass_ctx);
    if(result == CURLE_AGAIN) {
      /* insufficient amount of data, keep it for later.
       * we pretend to have written all since we have a copy */
      return CURLE_OK;
    }
    else if(result) {
      failf(data, "[WS] decode payload error %d", (int)result);
      return result;
    }
  }

  if((type & CLIENTWRITE_EOS) && !Curl_bufq_is_empty(&ctx->buf)) {
    failf(data, "[WS] decode ending with %zd frame bytes remaining",
          Curl_bufq_len(&ctx->buf));
    return CURLE_RECV_ERROR;
  }

  return CURLE_OK;
}

/* WebSocket payload decoding client writer. */
static const struct Curl_cwtype ws_cw_decode = {
  "ws-decode",
  NULL,
  ws_cw_init,
  ws_cw_write,
  ws_cw_close,
  sizeof(struct ws_cw_ctx)
};


static void ws_enc_info(struct ws_encoder *enc, struct Curl_easy *data,
                        const char *msg)
{
  CURL_TRC_WS(data, "WS-ENC: %s [%s%s payload=%"
              FMT_OFF_T "/%" FMT_OFF_T "]",
              msg, ws_frame_name_of_op(enc->firstbyte),
              (enc->firstbyte & WSBIT_FIN) ? "" : " NON-FIN",
              enc->payload_len - enc->payload_remain, enc->payload_len);
}

static void ws_enc_reset(struct ws_encoder *enc)
{
  enc->payload_remain = 0;
  enc->xori = 0;
  enc->contfragment = FALSE;
}

static void ws_enc_init(struct ws_encoder *enc)
{
  ws_enc_reset(enc);
}

/***
    RFC 6455 Section 5.2

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
*/

static CURLcode ws_enc_add_frame(struct Curl_easy *data,
                                 struct ws_encoder *enc,
                                 unsigned int flags,
                                 curl_off_t payload_len,
                                 struct bufq *out)
{
  unsigned char firstb = 0;
  unsigned char head[14];
  CURLcode result;
  size_t hlen, nwritten;

  if(payload_len < 0) {
    failf(data, "[WS] starting new frame with negative payload length %"
                FMT_OFF_T, payload_len);
    return CURLE_SEND_ERROR;
  }

  if(enc->payload_remain > 0) {
    /* trying to write a new frame before the previous one is finished */
    failf(data, "[WS] starting new frame with %zd bytes from last one "
                "remaining to be sent", (ssize_t)enc->payload_remain);
    return CURLE_SEND_ERROR;
  }

  result = ws_frame_flags2firstbyte(data, flags, enc->contfragment, &firstb);
  if(result)
    return result;

  /* fragmentation only applies to data frames (text/binary);
   * control frames (close/ping/pong) do not affect the CONT status */
  if(flags & (CURLWS_TEXT | CURLWS_BINARY)) {
    enc->contfragment = (flags & CURLWS_CONT) ? (bit)TRUE : (bit)FALSE;
  }

  if(flags & CURLWS_PING && payload_len > WS_MAX_CNTRL_LEN) {
    failf(data, "[WS] given PING frame is too big");
    return CURLE_TOO_LARGE;
  }
  if(flags & CURLWS_PONG && payload_len > WS_MAX_CNTRL_LEN) {
    failf(data, "[WS] given PONG frame is too big");
    return CURLE_TOO_LARGE;
  }
  if(flags & CURLWS_CLOSE && payload_len > WS_MAX_CNTRL_LEN) {
    failf(data, "[WS] given CLOSE frame is too big");
    return CURLE_TOO_LARGE;
  }

  head[0] = enc->firstbyte = firstb;
  if(payload_len > 65535) {
    head[1] = 127 | WSBIT_MASK;
    head[2] = (unsigned char)((payload_len >> 56) & 0xff);
    head[3] = (unsigned char)((payload_len >> 48) & 0xff);
    head[4] = (unsigned char)((payload_len >> 40) & 0xff);
    head[5] = (unsigned char)((payload_len >> 32) & 0xff);
    head[6] = (unsigned char)((payload_len >> 24) & 0xff);
    head[7] = (unsigned char)((payload_len >> 16) & 0xff);
    head[8] = (unsigned char)((payload_len >> 8) & 0xff);
    head[9] = (unsigned char)(payload_len & 0xff);
    hlen = 10;
  }
  else if(payload_len >= 126) {
    head[1] = 126 | WSBIT_MASK;
    head[2] = (unsigned char)((payload_len >> 8) & 0xff);
    head[3] = (unsigned char)(payload_len & 0xff);
    hlen = 4;
  }
  else {
    head[1] = (unsigned char)payload_len | WSBIT_MASK;
    hlen = 2;
  }

  enc->payload_remain = enc->payload_len = payload_len;
  ws_enc_info(enc, data, "sending");

  /* 4 bytes random */

  result = Curl_rand(data, (unsigned char *)&enc->mask, sizeof(enc->mask));
  if(result)
    return result;

#ifdef DEBUGBUILD
  if(getenv("CURL_WS_FORCE_ZERO_MASK"))
    /* force the bit mask to 0x00000000, effectively disabling masking */
    memset(&enc->mask, 0, sizeof(enc->mask));
#endif

  /* add 4 bytes mask */
  memcpy(&head[hlen], &enc->mask, 4);
  hlen += 4;
  /* reset for payload to come */
  enc->xori = 0;

  result = Curl_bufq_write(out, head, hlen, &nwritten);
  if(result)
    return result;
  if(nwritten != hlen) {
    /* We use a bufq with SOFT_LIMIT, writing should always succeed */
    DEBUGASSERT(0);
    return CURLE_SEND_ERROR;
  }
  return CURLE_OK;
}

static CURLcode ws_enc_write_head(struct Curl_easy *data,
                                  struct websocket *ws,
                                  struct ws_encoder *enc,
                                  unsigned int flags,
                                  curl_off_t payload_len,
                                  struct bufq *out)
{
  /* starting a new frame, we want a clean sendbuf.
   * Any pending control frame we can add now as part of the flush. */
  if(ws->pending.type) {
    CURLcode result = ws_enc_add_pending(data, ws);
    if(result)
      return result;
  }
  return ws_enc_add_frame(data, enc, flags, payload_len, out);
}

static CURLcode ws_enc_write_payload(struct ws_encoder *enc,
                                     struct Curl_easy *data,
                                     const unsigned char *buf, size_t buflen,
                                     struct bufq *out, size_t *pnwritten)
{
  CURLcode result;
  size_t i, len, n;

  *pnwritten = 0;
  if(Curl_bufq_is_full(out))
    return CURLE_AGAIN;

  /* not the most performant way to do this */
  len = buflen;
  if((curl_off_t)len > enc->payload_remain)
    len = (size_t)enc->payload_remain;

  for(i = 0; i < len; ++i) {
    unsigned char c = buf[i] ^ enc->mask[enc->xori];
    result = Curl_bufq_write(out, &c, 1, &n);
    if(result) {
      if((result != CURLE_AGAIN) || !i)
        return result;
      break;
    }
    enc->xori++;
    enc->xori &= 3;
  }
  *pnwritten = i;
  enc->payload_remain -= (curl_off_t)i;
  ws_enc_info(enc, data, "buffered");
  return CURLE_OK;
}

static CURLcode ws_enc_add_pending(struct Curl_easy *data,
                                   struct websocket *ws)
{
  CURLcode result;
  size_t n;

  if(!ws->pending.type) /* no pending frame here */
    return CURLE_OK;
  if(ws->enc.payload_remain) /* in the middle of another frame */
    return CURLE_AGAIN;

  result = ws_enc_add_frame(data, &ws->enc, ws->pending.type,
                            (curl_off_t)ws->pending.payload_len,
                            &ws->sendbuf);
  if(result) {
    CURL_TRC_WS(data, "ws_enc_cntrl(), error addiong head: %d",
                result);
    goto out;
  }
  result = ws_enc_write_payload(&ws->enc, data, ws->pending.payload,
                                ws->pending.payload_len,
                                &ws->sendbuf, &n);
  if(result) {
    CURL_TRC_WS(data, "ws_enc_cntrl(), error adding payload: %d",
                result);
    goto out;
  }
  /* our buffer should always be able to take in a control frame */
  DEBUGASSERT(n == ws->pending.payload_len);
  DEBUGASSERT(!ws->enc.payload_remain);

out:
  memset(&ws->pending, 0, sizeof(ws->pending));
  return result;
}

static CURLcode ws_enc_send(struct Curl_easy *data,
                            struct websocket *ws,
                            const unsigned char *buffer,
                            size_t buflen,
                            curl_off_t fragsize,
                            unsigned int flags,
                            size_t *pnsent)
{
  size_t n;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(!data->set.ws_raw_mode);
  *pnsent = 0;

  if(ws->enc.payload_remain || !Curl_bufq_is_empty(&ws->sendbuf)) {
    /* a frame is ongoing with payload buffered or more payload
     * that needs to be encoded into the buffer */
    if(buflen < ws->sendbuf_payload) {
      /* We have been called with LESS buffer data than before. This
       * is not how it's supposed too work. */
      failf(data, "[WS] curl_ws_send() called with smaller 'buflen' than "
            "bytes already buffered in previous call, %zu vs %zu",
            buflen, ws->sendbuf_payload);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if((curl_off_t)buflen >
       (ws->enc.payload_remain + (curl_off_t)ws->sendbuf_payload)) {
      /* too large buflen beyond payload length of frame */
      failf(data, "[WS] unaligned frame size (sending %zu instead of %"
                  FMT_OFF_T ")",
            buflen, ws->enc.payload_remain + ws->sendbuf_payload);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }
  else {
    result = ws_flush(data, ws, Curl_is_in_callback(data));
    if(result)
      return result;

    result = ws_enc_write_head(data, ws, &ws->enc, flags,
                               (flags & CURLWS_OFFSET) ?
                               fragsize : (curl_off_t)buflen,
                               &ws->sendbuf);
    if(result) {
      CURL_TRC_WS(data, "curl_ws_send(), error writing frame head %d", result);
      return result;
    }
  }

  /* While there is either sendbuf to flush OR more payload to encode... */
  while(!Curl_bufq_is_empty(&ws->sendbuf) || (buflen > ws->sendbuf_payload)) {
    /* Try to add more payload to sendbuf */
    if(buflen > ws->sendbuf_payload) {
      size_t prev_len = Curl_bufq_len(&ws->sendbuf);
      result = ws_enc_write_payload(&ws->enc, data,
                                    buffer + ws->sendbuf_payload,
                                    buflen - ws->sendbuf_payload,
                                    &ws->sendbuf, &n);
      if(result && (result != CURLE_AGAIN))
        return result;
      ws->sendbuf_payload += Curl_bufq_len(&ws->sendbuf) - prev_len;
      if(!ws->sendbuf_payload) {
        return CURLE_AGAIN;
      }
    }

    /* flush, blocking when in callback */
    result = ws_flush(data, ws, Curl_is_in_callback(data));
    if(!result && ws->sendbuf_payload > 0) {
      *pnsent += ws->sendbuf_payload;
      buffer += ws->sendbuf_payload;
      buflen -= ws->sendbuf_payload;
      ws->sendbuf_payload = 0;
    }
    else if(result == CURLE_AGAIN) {
      if(ws->sendbuf_payload > Curl_bufq_len(&ws->sendbuf)) {
        /* blocked, part of payload bytes remain, report length
         * that we managed to send. */
        size_t flushed = (ws->sendbuf_payload - Curl_bufq_len(&ws->sendbuf));
        *pnsent += flushed;
        ws->sendbuf_payload -= flushed;
        return CURLE_OK;
      }
      else {
        /* blocked before sending headers or 1st payload byte. We cannot report
         * OK on 0-length send (caller counts only payload) and EAGAIN */
        CURL_TRC_WS(data, "EAGAIN flushing sendbuf, payload_encoded: %zu/%zu",
                    ws->sendbuf_payload, buflen);
        DEBUGASSERT(*pnsent == 0);
        return CURLE_AGAIN;
      }
    }
    else
      return result;  /* real error sending the data */
  }
  return CURLE_OK;
}

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
  size_t nread, n;
  struct websocket *ws;
  bool eos;

  *pnread = 0;
  if(ctx->eos) {
    *peos = TRUE;
    return CURLE_OK;
  }

  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] not a websocket transfer");
    return CURLE_FAILED_INIT;
  }

  if(Curl_bufq_is_empty(&ws->sendbuf)) {
    if(ctx->read_eos) {
      ctx->eos = TRUE;
      *peos = TRUE;
      return CURLE_OK;
    }

    if(ws->enc.payload_remain) {
      CURL_TRC_WS(data, "current frame, %" FMT_OFF_T " remaining",
                  ws->enc.payload_remain);
      if(ws->enc.payload_remain < (curl_off_t)blen)
        blen = (size_t)ws->enc.payload_remain;
    }

    result = Curl_creader_read(data, reader->next, buf, blen, &nread, &eos);
    if(result)
      return result;
    ctx->read_eos = eos;

    if(!Curl_bufq_is_empty(&ws->sendbuf)) {
      /* client_read started a new frame, we disregard any eos reported */
      ctx->read_eos = FALSE;
      Curl_creader_clear_eos(data, reader->next);
    }
    else if(!nread) {
      /* nothing to convert, return this right away */
      if(ctx->read_eos)
        ctx->eos = TRUE;
      *pnread = nread;
      *peos = ctx->eos;
      goto out;
    }

    if(!ws->enc.payload_remain && Curl_bufq_is_empty(&ws->sendbuf)) {
      /* encode the data as a new BINARY frame */
      result = ws_enc_write_head(data, ws, &ws->enc, CURLWS_BINARY, nread,
                                 &ws->sendbuf);
      if(result)
        goto out;
    }

    result = ws_enc_write_payload(&ws->enc, data, (unsigned char *)buf,
                                  nread, &ws->sendbuf, &n);
    if(result)
      goto out;
    CURL_TRC_READ(data, "cr_ws_read, added %zu payload, len=%zu", nread, n);
  }

  DEBUGASSERT(!Curl_bufq_is_empty(&ws->sendbuf));
  *peos = FALSE;
  result = Curl_bufq_cread(&ws->sendbuf, buf, blen, pnread);
  if(!result && ctx->read_eos && Curl_bufq_is_empty(&ws->sendbuf)) {
    /* no more data, read all, done. */
    ctx->eos = TRUE;
    *peos = TRUE;
  }

out:
  CURL_TRC_READ(data, "cr_ws_read(len=%zu) -> %d, nread=%zu, eos=%d",
                blen, result, *pnread, *peos);
  return result;
}

static const struct Curl_crtype ws_cr_encode = {
  "ws-encode",
  cr_ws_init,
  cr_ws_read,
  cr_ws_close,
  Curl_creader_def_needs_rewind,
  Curl_creader_def_total_length,
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
  unsigned char rand[16];
  char *randstr;
  size_t randlen;
  char keyval[40];
  struct SingleRequest *k = &data->req;
  struct wsfield heads[]= {
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
  result = Curl_rand(data, (unsigned char *)rand, sizeof(rand));
  if(result)
    return result;
  result = curlx_base64_encode((char *)rand, sizeof(rand), &randstr, &randlen);
  if(result)
    return result;
  DEBUGASSERT(randlen < sizeof(keyval));
  if(randlen >= sizeof(keyval)) {
    free(randstr);
    return CURLE_FAILED_INIT;
  }
  strcpy(keyval, randstr);
  free(randstr);
  for(i = 0; !result && (i < CURL_ARRAYSIZE(heads)); i++) {
    if(!Curl_checkheaders(data, heads[i].name, strlen(heads[i].name))) {
      result = curlx_dyn_addf(req, "%s: %s\r\n", heads[i].name,
                              heads[i].val);
    }
  }
  data->state.http_hd_upgrade = TRUE;
  k->upgr101 = UPGR101_WS;
  return result;
}

static void ws_conn_dtor(void *key, size_t klen, void *entry)
{
  struct websocket *ws = entry;
  (void)key;
  (void)klen;
  Curl_bufq_free(&ws->recvbuf);
  Curl_bufq_free(&ws->sendbuf);
  free(ws);
}

/*
 * 'nread' is number of bytes of websocket data already in the buffer at
 * 'mem'.
 */
CURLcode Curl_ws_accept(struct Curl_easy *data,
                        const char *mem, size_t nread)
{
  struct SingleRequest *k = &data->req;
  struct websocket *ws;
  struct Curl_cwriter *ws_dec_writer = NULL;
  struct Curl_creader *ws_enc_reader = NULL;
  CURLcode result;

  DEBUGASSERT(data->conn);
  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    size_t chunk_size = WS_CHUNK_SIZE;
    ws = calloc(1, sizeof(*ws));
    if(!ws)
      return CURLE_OUT_OF_MEMORY;
#ifdef DEBUGBUILD
    {
      const char *p = getenv("CURL_WS_CHUNK_SIZE");
      if(p) {
        curl_off_t l;
        if(!curlx_str_number(&p, &l, 1*1024*1024))
          chunk_size = (size_t)l;
      }
    }
#endif
    CURL_TRC_WS(data, "WS, using chunk size %zu", chunk_size);
    Curl_bufq_init2(&ws->recvbuf, chunk_size, WS_CHUNK_COUNT,
                    BUFQ_OPT_SOFT_LIMIT);
    Curl_bufq_init2(&ws->sendbuf, chunk_size, WS_CHUNK_COUNT,
                    BUFQ_OPT_SOFT_LIMIT);
    ws_dec_init(&ws->dec);
    ws_enc_init(&ws->enc);
    result = Curl_conn_meta_set(data->conn, CURL_META_PROTO_WS_CONN,
                                ws, ws_conn_dtor);
    if(result)
      return result;
  }
  else {
    Curl_bufq_reset(&ws->recvbuf);
    ws_dec_reset(&ws->dec);
    ws_enc_reset(&ws->enc);
  }
  /* Verify the Sec-WebSocket-Accept response.

     The sent value is the base64 encoded version of a SHA-1 hash done on the
     |Sec-WebSocket-Key| header field concatenated with
     the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".
  */

  /* If the response includes a |Sec-WebSocket-Extensions| header field and
     this header field indicates the use of an extension that was not present
     in the client's handshake (the server has indicated an extension not
     requested by the client), the client MUST Fail the WebSocket Connection.
  */

  /* If the response includes a |Sec-WebSocket-Protocol| header field
     and this header field indicates the use of a subprotocol that was
     not present in the client's handshake (the server has indicated a
     subprotocol not requested by the client), the client MUST Fail
     the WebSocket Connection. */

  infof(data, "[WS] Received 101, switch to WebSocket");

  /* Install our client writer that decodes WS frames payload */
  result = Curl_cwriter_create(&ws_dec_writer, data, &ws_cw_decode,
                               CURL_CW_CONTENT_DECODE);
  if(result)
    goto out;
  result = Curl_cwriter_add(data, ws_dec_writer);
  if(result)
    goto out;
  ws_dec_writer = NULL; /* owned by transfer now */

  if(data->set.connect_only) {
    size_t nwritten;
    /* In CONNECT_ONLY setup, the payloads from `mem` need to be received
     * when using `curl_ws_recv` later on after this transfer is already
     * marked as DONE. */
    result = Curl_bufq_write(&ws->recvbuf, (const unsigned char *)mem,
                             nread, &nwritten);
    if(result)
      goto out;
    DEBUGASSERT(nread == nwritten);
    k->keepon &= ~KEEP_RECV; /* read no more content */
  }
  else { /* !connect_only */
    if(data->set.method == HTTPREQ_PUT) {
      CURL_TRC_WS(data, "UPLOAD set, add ws-encode reader");
      result = Curl_creader_set_fread(data, -1);
      if(result)
        goto out;

      if(!data->set.ws_raw_mode) {
        /* Add our client readerr encoding WS BINARY frames */
        result = Curl_creader_create(&ws_enc_reader, data, &ws_cr_encode,
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
      data->req.upload_done = FALSE;
      k->keepon |= KEEP_SEND;
    }

    /* And pass any additional data to the writers */
    if(nread) {
      result = Curl_client_write(data, CLIENTWRITE_BODY, mem, nread);
      if(result)
        goto out;
    }
  }

  k->upgr101 = UPGR101_RECEIVED;
  k->header = FALSE; /* we will not get more responses */

out:
  if(ws_dec_writer)
    Curl_cwriter_free(data, ws_dec_writer);
  if(ws_enc_reader)
    Curl_creader_free(data, ws_enc_reader);
  if(result)
    CURL_TRC_WS(data, "Curl_ws_accept() failed -> %d", result);
  else
    CURL_TRC_WS(data, "websocket established, %s mode",
                data->set.connect_only ? "connect-only" : "callback");
  return result;
}

struct ws_collect {
  struct Curl_easy *data;
  struct websocket *ws;
  unsigned char *buffer;
  size_t buflen;
  size_t bufidx;
  int frame_age;
  int frame_flags;
  curl_off_t payload_offset;
  curl_off_t payload_len;
  bool written;
};

static CURLcode ws_client_collect(const unsigned char *buf, size_t buflen,
                                  int frame_age, int frame_flags,
                                  curl_off_t payload_offset,
                                  curl_off_t payload_len,
                                  void *userp,
                                  size_t *pnwritten)
{
  struct ws_collect *ctx = userp;
  struct Curl_easy *data = ctx->data;
  bool auto_pong = !data->set.ws_no_auto_pong;
  curl_off_t remain = (payload_len - (payload_offset + buflen));
  CURLcode result = CURLE_OK;

  *pnwritten = 0;
  if(!ctx->bufidx) {
    /* first write */
    ctx->frame_age = frame_age;
    ctx->frame_flags = frame_flags;
    ctx->payload_offset = payload_offset;
    ctx->payload_len = payload_len;
  }

  if(auto_pong && (frame_flags & CURLWS_PING) && !remain) {
    /* auto-respond to PINGs, only works for single-frame payloads atm */
    CURL_TRC_WS(data, "auto PONG to [PING payload=%" FMT_OFF_T
                "/%" FMT_OFF_T "]", payload_offset, payload_len);
    /* send back the exact same content as a PONG */
    result = ws_enc_add_cntrl(ctx->data, ctx->ws, buf, buflen, CURLWS_PONG);
    if(result)
      return result;
    *pnwritten = buflen;
  }
  else {
    size_t write_len;

    ctx->written = TRUE;
    DEBUGASSERT(ctx->buflen >= ctx->bufidx);
    write_len = CURLMIN(buflen, ctx->buflen - ctx->bufidx);
    if(!write_len) {
      if(!buflen)  /* 0 length write, we accept that */
        return CURLE_OK;
      return CURLE_AGAIN;  /* no more space */
    }
    memcpy(ctx->buffer + ctx->bufidx, buf, write_len);
    ctx->bufidx += write_len;
    *pnwritten = write_len;
  }
  return result;
}

static CURLcode nw_in_recv(void *reader_ctx,
                           unsigned char *buf, size_t buflen,
                           size_t *pnread)
{
  struct Curl_easy *data = reader_ctx;
  return curl_easy_recv(data, buf, buflen, pnread);
}

CURLcode curl_ws_recv(CURL *d, void *buffer,
                      size_t buflen, size_t *nread,
                      const struct curl_ws_frame **metap)
{
  struct Curl_easy *data = d;
  struct connectdata *conn;
  struct websocket *ws;
  struct ws_collect ctx;

  *nread = 0;
  *metap = NULL;
  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  conn = data->conn;
  if(!conn) {
    /* Unhappy hack with lifetimes of transfers and connection */
    if(!data->set.connect_only) {
      failf(data, "[WS] CONNECT_ONLY is required");
      return CURLE_UNSUPPORTED_PROTOCOL;
    }

    Curl_getconnectinfo(data, &conn);
    if(!conn) {
      failf(data, "[WS] connection not found");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }
  ws = Curl_conn_meta_get(conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] connection is not setup for websocket");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }


  memset(&ctx, 0, sizeof(ctx));
  ctx.data = data;
  ctx.ws = ws;
  ctx.buffer = buffer;
  ctx.buflen = buflen;

  while(1) {
    CURLcode result;

    /* receive more when our buffer is empty */
    if(Curl_bufq_is_empty(&ws->recvbuf)) {
      size_t n;
      result = Curl_bufq_slurp(&ws->recvbuf, nw_in_recv, data, &n);
      if(result)
        return result;
      else if(n == 0) {
        /* connection closed */
        infof(data, "[WS] connection expectedly closed?");
        return CURLE_GOT_NOTHING;
      }
      CURL_TRC_WS(data, "curl_ws_recv, added %zu bytes from network",
                  Curl_bufq_len(&ws->recvbuf));
    }

    result = ws_dec_pass(&ws->dec, data, &ws->recvbuf,
                         ws_client_collect, &ctx);
    if(result == CURLE_AGAIN) {
      if(!ctx.written) {
        ws_dec_info(&ws->dec, data, "need more input");
        continue;  /* nothing written, try more input */
      }
      break;
    }
    else if(result) {
      return result;
    }
    else if(ctx.written) {
      /* The decoded frame is passed back to our caller.
       * There are frames like PING were we auto-respond to and
       * that we do not return. For these `ctx.written` is not set. */
      break;
    }
  }

  /* update frame information to be passed back */
  update_meta(ws, ctx.frame_age, ctx.frame_flags, ctx.payload_offset,
              ctx.payload_len, ctx.bufidx);
  *metap = &ws->recvframe;
  *nread = ws->recvframe.len;
  CURL_TRC_WS(data, "curl_ws_recv(len=%zu) -> %zu bytes (frame at %"
               FMT_OFF_T ", %" FMT_OFF_T " left)",
               buflen, *nread, ws->recvframe.offset,
               ws->recvframe.bytesleft);
  /* all's well, try to send any pending control. we do not know
   * when the application will call `curl_ws_send()` again. */
  if(!data->set.ws_raw_mode && ws->pending.type) {
    CURLcode r2 = ws_enc_add_pending(data, ws);
    if(!r2)
      (void)ws_flush(data, ws, Curl_is_in_callback(data));
  }
  return CURLE_OK;
}

static CURLcode ws_flush(struct Curl_easy *data, struct websocket *ws,
                         bool blocking)
{
  if(!Curl_bufq_is_empty(&ws->sendbuf)) {
    CURLcode result;
    const unsigned char *out;
    size_t outlen, n;
#ifdef DEBUGBUILD
    /* Simulate a blocking send after this chunk has been sent */
    bool eagain_next = FALSE;
    size_t chunk_egain = 0;
    const char *p = getenv("CURL_WS_CHUNK_EAGAIN");
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, 1*1024*1024))
        chunk_egain = (size_t)l;
    }
#endif

    while(Curl_bufq_peek(&ws->sendbuf, &out, &outlen)) {
#ifdef DEBUGBUILD
      if(eagain_next)
        return CURLE_AGAIN;
      if(chunk_egain && (outlen > chunk_egain)) {
        outlen = chunk_egain;
        eagain_next = TRUE;
      }
#endif
      if(blocking) {
        result = ws_send_raw_blocking(data, ws, (const char *)out, outlen);
        n = result ? 0 : outlen;
      }
      else if(data->set.connect_only || Curl_is_in_callback(data))
        result = Curl_senddata(data, out, outlen, &n);
      else {
        result = Curl_xfer_send(data, out, outlen, FALSE, &n);
        if(!result && !n && outlen)
          result = CURLE_AGAIN;
      }

      if(result == CURLE_AGAIN) {
        CURL_TRC_WS(data, "flush EAGAIN, %zu bytes remain in buffer",
                    Curl_bufq_len(&ws->sendbuf));
        return result;
      }
      else if(result) {
        failf(data, "[WS] flush, write error %d", result);
        return result;
      }
      else {
        CURL_TRC_WS(data, "flushed %zu bytes", n);
        Curl_bufq_skip(&ws->sendbuf, n);
      }
    }
  }
  return CURLE_OK;
}

static CURLcode ws_send_raw_blocking(struct Curl_easy *data,
                                     struct websocket *ws,
                                     const char *buffer, size_t buflen)
{
  CURLcode result = CURLE_OK;
  size_t nwritten;

  (void)ws;
  while(buflen) {
    result = Curl_xfer_send(data, buffer, buflen, FALSE, &nwritten);
    if(result)
      return result;
    DEBUGASSERT(nwritten <= buflen);
    buffer += nwritten;
    buflen -= nwritten;
    if(buflen) {
      curl_socket_t sock = data->conn->sock[FIRSTSOCKET];
      timediff_t left_ms;
      int ev;

      CURL_TRC_WS(data, "ws_send_raw_blocking() partial, %zu left to send",
                  buflen);
      left_ms = Curl_timeleft(data, NULL, FALSE);
      if(left_ms < 0) {
        failf(data, "[WS] Timeout waiting for socket becoming writable");
        return CURLE_SEND_ERROR;
      }

      /* POLLOUT socket */
      if(sock == CURL_SOCKET_BAD)
        return CURLE_SEND_ERROR;
      ev = Curl_socket_check(CURL_SOCKET_BAD, CURL_SOCKET_BAD, sock,
                             left_ms ? left_ms : 500);
      if(ev < 0) {
        failf(data, "[WS] Error while waiting for socket becoming writable");
        return CURLE_SEND_ERROR;
      }
    }
  }
  return result;
}

static CURLcode ws_send_raw(struct Curl_easy *data, const void *buffer,
                            size_t buflen, size_t *pnwritten)
{
  struct websocket *ws;
  CURLcode result;

  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] Not a websocket transfer");
    return CURLE_SEND_ERROR;
  }
  if(!buflen)
    return CURLE_OK;

  if(Curl_is_in_callback(data)) {
    /* When invoked from inside callbacks, we do a blocking send as the
     * callback will probably not implement partial writes that may then
     * mess up the ws framing subsequently.
     * We need any pending data to be flushed before sending. */
    result = ws_flush(data, ws, TRUE);
    if(result)
      return result;
    result = ws_send_raw_blocking(data, ws, buffer, buflen);
  }
  else {
    /* We need any pending data to be sent or EAGAIN this call. */
    result = ws_flush(data, ws, FALSE);
    if(result)
      return result;
    result = Curl_senddata(data, buffer, buflen, pnwritten);
  }

  CURL_TRC_WS(data, "ws_send_raw(len=%zu) -> %d, %zu",
              buflen, result, *pnwritten);
  return result;
}

CURLcode curl_ws_send(CURL *d, const void *buffer_arg,
                      size_t buflen, size_t *sent,
                      curl_off_t fragsize,
                      unsigned int flags)
{
  struct websocket *ws;
  const unsigned char *buffer = buffer_arg;
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = d;
  size_t ndummy;
  size_t *pnsent = sent ? sent : &ndummy;

  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;
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
  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] Not a websocket transfer");
    result = CURLE_SEND_ERROR;
    goto out;
  }

  if(data->set.ws_raw_mode) {
    /* In raw mode, we write directly to the connection */
    /* try flushing any content still waiting to be sent. */
    result = ws_flush(data, ws, FALSE);
    if(result)
      goto out;

    if(!buffer) {
      failf(data, "[WS] buffer is NULL in raw mode");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!sent) {
      failf(data, "[WS] sent is NULL in raw mode");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(fragsize || flags) {
      failf(data, "[WS] fragsize and flags must be zero in raw mode");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    result = ws_send_raw(data, buffer, buflen, pnsent);
    goto out;
  }

  /* Not RAW mode, we do the frame encoding */
  result = ws_enc_send(data, ws, buffer, buflen, fragsize, flags, pnsent);

out:
  CURL_TRC_WS(data, "curl_ws_send(len=%zu, fragsize=%" FMT_OFF_T
              ", flags=%x, raw=%d) -> %d, %zu",
              buflen, fragsize, flags, data->set.ws_raw_mode, result,
              *pnsent);
  return result;
}

static CURLcode ws_setup_conn(struct Curl_easy *data,
                              struct connectdata *conn)
{
  /* WebSockets is 1.1 only (for now) */
  data->state.http_neg.accept_09 = FALSE;
  data->state.http_neg.only_10 = FALSE;
  data->state.http_neg.wanted = CURL_HTTP_V1x;
  data->state.http_neg.allowed = CURL_HTTP_V1x;
  return Curl_http_setup_conn(data, conn);
}


const struct curl_ws_frame *curl_ws_meta(CURL *d)
{
  /* we only return something for websocket, called from within the callback
     when not using raw mode */
  struct Curl_easy *data = d;
  if(GOOD_EASY_HANDLE(data) && Curl_is_in_callback(data) &&
     data->conn && !data->set.ws_raw_mode) {
    struct websocket *ws;
    ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
    if(ws)
      return &ws->recvframe;

  }
  return NULL;
}

CURL_EXTERN CURLcode curl_ws_start_frame(CURL *d,
                                         unsigned int flags,
                                         curl_off_t frame_len)
{
  struct websocket *ws;
  CURLcode result = CURLE_OK;
  struct Curl_easy *data = d;

  if(!GOOD_EASY_HANDLE(data))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(data->set.ws_raw_mode) {
    failf(data, "cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled");
    return CURLE_FAILED_INIT;
  }

  CURL_TRC_WS(data, "curl_ws_start_frame(flags=%x, frame_len=%" FMT_OFF_T,
              flags, frame_len);

  if(!data->conn) {
    failf(data, "[WS] No associated connection");
    result = CURLE_SEND_ERROR;
    goto out;
  }
  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] Not a websocket transfer");
    result = CURLE_SEND_ERROR;
    goto out;
  }

  if(data->set.ws_raw_mode) {
    failf(data, "[WS] cannot start frame in raw mode");
    result = CURLE_SEND_ERROR;
    goto out;
  }

  if(ws->enc.payload_remain) {
    failf(data, "[WS] previous frame not finished");
    result = CURLE_SEND_ERROR;
    goto out;
  }

  result = ws_enc_write_head(data, ws, &ws->enc, flags, frame_len,
                             &ws->sendbuf);
  if(result)
    CURL_TRC_WS(data, "curl_start_frame(), error  adding frame head %d",
                result);

out:
  return result;
}

const struct Curl_handler Curl_handler_ws = {
  "WS",                                 /* scheme */
  ws_setup_conn,                        /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  Curl_http_connect,                    /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_pollset */
  Curl_http_do_pollset,                 /* doing_pollset */
  ZERO_NULL,                            /* domore_pollset */
  ZERO_NULL,                            /* perform_pollset */
  ZERO_NULL,                            /* disconnect */
  Curl_http_write_resp,                 /* write_resp */
  Curl_http_write_resp_hd,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  Curl_http_follow,                     /* follow */
  PORT_HTTP,                            /* defport */
  CURLPROTO_WS,                         /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_CREDSPERREQUEST |             /* flags */
  PROTOPT_USERPWDCTRL
};

#ifdef USE_SSL
const struct Curl_handler Curl_handler_wss = {
  "WSS",                                /* scheme */
  ws_setup_conn,                        /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  Curl_http_connect,                    /* connect_it */
  NULL,                                 /* connecting */
  ZERO_NULL,                            /* doing */
  NULL,                                 /* proto_pollset */
  Curl_http_do_pollset,                 /* doing_pollset */
  ZERO_NULL,                            /* domore_pollset */
  ZERO_NULL,                            /* perform_pollset */
  ZERO_NULL,                            /* disconnect */
  Curl_http_write_resp,                 /* write_resp */
  Curl_http_write_resp_hd,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  Curl_http_follow,                     /* follow */
  PORT_HTTPS,                           /* defport */
  CURLPROTO_WSS,                        /* protocol */
  CURLPROTO_HTTP,                       /* family */
  PROTOPT_SSL | PROTOPT_CREDSPERREQUEST | /* flags */
  PROTOPT_USERPWDCTRL
};
#endif


#else

CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen,
                      size_t *nread,
                      const struct curl_ws_frame **metap)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)nread;
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
