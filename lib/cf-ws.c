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
#include "cfilters.h"
#include "cf-ws.h"
#include "curl_trc.h"
#include "rand.h"
#include "select.h"

#ifndef CURL_DISABLE_WEBSOCKETS

/* RFC 6455 Section 5.2

    0 1 2 3 4 5 6 7
   +-+-+-+-+-------+
   |F|R|R|R| opcode|
   |I|S|S|S|  (4)  |
   |N|V|V|V|       |
   | |1|2|3|       |
 */
#define WSBIT_FIN          0x80
#define WSBIT_RSV1         0x40
#define WSBIT_RSV2         0x20
#define WSBIT_RSV3         0x10
#define WSBIT_RSV_MASK     (WSBIT_RSV1 | WSBIT_RSV2 | WSBIT_RSV3)
#define WSBIT_OPCODE_CONT  0x0
#define WSBIT_OPCODE_TEXT  0x1
#define WSBIT_OPCODE_BIN   0x2
#define WSBIT_OPCODE_CLOSE 0x8
#define WSBIT_OPCODE_PING  0x9
#define WSBIT_OPCODE_PONG  0xa
#ifdef CURLVERBOSE
#define WSBIT_OPCODE_MASK  0xf
#endif

#define WSBIT_MASK 0x80

/* buffer dimensioning */
#define WS_CHUNK_SIZE  65535
#define WS_CHUNK_COUNT 2

#ifdef CURLVERBOSE
static const char *ws_frame_name_of_op(uint8_t firstbyte)
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
#endif

static CURLcode cf_ws_frame_1st_byte(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     unsigned int flags,
                                     bool contfragment,
                                     uint8_t *pfirstbyte)
{
  NOVERBOSE((void)cf);
  *pfirstbyte = 0;
  switch(flags & ~CURLWS_OFFSET) {
  case 0:
    if(contfragment) {
      CURL_TRC_CF(data, cf, "no flags given; interpreting as continuation "
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

#ifdef CURLVERBOSE
static void ws_dec_info(struct Curl_cfilter *cf,
                        struct Curl_easy *data,
                        const char *msg)
{
  if(Curl_trc_cf_is_verbose(cf, data)) {
    struct cf_ws_ctx *ctx = cf->ctx;
    switch(ctx->dec.head_len) {
    case 0:
      break;
    case 1:
      CURL_TRC_CF(data, cf, "decoded %s [%s%s]", msg,
                  ws_frame_name_of_op(ctx->dec.head[0]),
                  (ctx->dec.head[0] & WSBIT_FIN) ? "" : " NON-FINAL");
      break;
    default:
      if(ctx->dec.head_len < ctx->dec.head_total) {
        CURL_TRC_CF(data, cf, "decoded %s [%s%s](%d/%d)", msg,
                    ws_frame_name_of_op(ctx->dec.head[0]),
                    (ctx->dec.head[0] & WSBIT_FIN) ? "" : " NON-FINAL",
                    ctx->dec.head_len, ctx->dec.head_total);
      }
      else {
        CURL_TRC_CF(data, cf, "decoded %s [%s%s payload=%"
                    FMT_OFF_T "/%" FMT_OFF_T "]",
                    msg, ws_frame_name_of_op(ctx->dec.head[0]),
                    (ctx->dec.head[0] & WSBIT_FIN) ? "" : " NON-FINAL",
                    ctx->dec.payload_offset, ctx->dec.payload_len);
      }
      break;
    }
  }
}
static void ws_enc_info(struct Curl_cfilter *cf,
                        struct Curl_easy *data,
                        const char *msg)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  CURL_TRC_CF(data, cf, "WS-ENC: %s [%s%s payload=%"
              FMT_OFF_T "/%" FMT_OFF_T "]",
              msg, ws_frame_name_of_op(ctx->enc.firstbyte),
              (ctx->enc.firstbyte & WSBIT_FIN) ? "" : " NON-FIN",
              ctx->enc.payload_len - ctx->enc.payload_remain,
              ctx->enc.payload_len);
}
#else /* CURLVERBOSE */
#define ws_dec_info(a,b,c)        Curl_nop_stmt
#define ws_enc_info(a,b,c)     Curl_nop_stmt
#endif /* CURLVERBOSE */

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
  dec->seen_close = FALSE;
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
  enc->maskpool_left = 0;
}

/* RFC 6455 Section 5.2

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

static CURLcode cf_ws_enc_add_frame(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    unsigned int flags,
                                    curl_off_t payload_len)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  uint8_t firstb = 0;
  uint8_t head[14];
  CURLcode result;
  size_t hlen, nwritten;

  if(payload_len < 0) {
    failf(data, "[WS] starting new frame with negative payload length %"
                FMT_OFF_T, payload_len);
    return CURLE_SEND_ERROR;
  }

  if(ctx->enc.payload_remain > 0) {
    /* trying to write a new frame before the previous one is finished */
    failf(data, "[WS] starting new frame with %" FMT_OFF_T " bytes "
                "from last one remaining to be sent", ctx->enc.payload_remain);
    return CURLE_SEND_ERROR;
  }

  result = cf_ws_frame_1st_byte(cf, data, flags, (bool)ctx->enc.contfragment,
                                &firstb);
  if(result)
    return result;

  /* fragmentation only applies to data frames (text/binary);
   * control frames (close/ping/pong) do not affect the CONT status */
  if(flags & (CURLWS_TEXT | CURLWS_BINARY)) {
    ctx->enc.contfragment = (curl_bit)((flags & CURLWS_CONT) ? TRUE : FALSE);
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

  head[0] = ctx->enc.firstbyte = firstb;
  if(payload_len > 65535) {
    head[1] = 127 | WSBIT_MASK;
    head[2] = (uint8_t)((payload_len >> 56) & 0xff);
    head[3] = (uint8_t)((payload_len >> 48) & 0xff);
    head[4] = (uint8_t)((payload_len >> 40) & 0xff);
    head[5] = (uint8_t)((payload_len >> 32) & 0xff);
    head[6] = (uint8_t)((payload_len >> 24) & 0xff);
    head[7] = (uint8_t)((payload_len >> 16) & 0xff);
    head[8] = (uint8_t)((payload_len >> 8) & 0xff);
    head[9] = (uint8_t)(payload_len & 0xff);
    hlen = 10;
  }
  else if(payload_len >= 126) {
    head[1] = 126 | WSBIT_MASK;
    head[2] = (uint8_t)((payload_len >> 8) & 0xff);
    head[3] = (uint8_t)(payload_len & 0xff);
    hlen = 4;
  }
  else {
    head[1] = (uint8_t)payload_len | WSBIT_MASK;
    hlen = 2;
  }

  ctx->enc.payload_remain = ctx->enc.payload_len = payload_len;
  ws_enc_info(cf, data, "sending");

  /* 4 bytes random */

  if(ctx->enc.maskpool_left < sizeof(ctx->enc.mask)) {
    result = Curl_rand(data, ctx->enc.maskpool, sizeof(ctx->enc.maskpool));
    if(result)
      return result;
    ctx->enc.maskpool_left = sizeof(ctx->enc.maskpool);
  }
  memcpy(ctx->enc.mask, &ctx->enc.maskpool[sizeof(ctx->enc.maskpool) -
                        ctx->enc.maskpool_left], sizeof(ctx->enc.mask));
  ctx->enc.maskpool_left -= (unsigned int)sizeof(ctx->enc.mask);

#ifdef DEBUGBUILD
  if(getenv("CURL_WS_FORCE_ZERO_MASK"))
    /* force the bit mask to 0x00000000, effectively disabling masking */
    memset(&ctx->enc.mask, 0, sizeof(ctx->enc.mask));
#endif

  /* add 4 bytes mask */
  memcpy(&head[hlen], &ctx->enc.mask, 4);
  hlen += 4;
  /* reset for payload to come */
  ctx->enc.xori = 0;

  result = Curl_bufq_write(&ctx->sendbuf, head, hlen, &nwritten);
  if(result)
    return result;
  if(nwritten != hlen) {
    /* We use a bufq with SOFT_LIMIT, writing should always succeed */
    DEBUGASSERT(0);
    return CURLE_SEND_ERROR;
  }
  return CURLE_OK;
}

/*
 * Mask and append payload to the bufq in chunks.
 *
 * @unittest 2607
 */
UNITTEST CURLcode ws_enc_mask_write(const uint8_t *mask, unsigned int *pxori,
                                    const uint8_t *buf, size_t len,
                                    struct bufq *out, size_t *pnwritten);
UNITTEST CURLcode ws_enc_mask_write(const uint8_t *mask, unsigned int *pxori,
                                    const uint8_t *buf, size_t len,
                                    struct bufq *out, size_t *pnwritten)
{
  CURLcode result;
  size_t i, done = 0;

  *pnwritten = 0;
  while(done < len) {
    uint8_t tmp[1024];
    uint8_t mask8[8];
    uint64_t m;
    size_t n = CURLMIN(len - done, sizeof(tmp));
    size_t nwritten;

    for(i = 0; i < 8; i++)
      mask8[i] = mask[(*pxori + i) & 3];
    memcpy(&m, mask8, 8);
    for(i = 0; i + 8 <= n; i += 8) {
      uint64_t v;
      memcpy(&v, &buf[done + i], 8);
      v ^= m;
      memcpy(&tmp[i], &v, 8);
    }
    for(; i < n; i++)
      tmp[i] = buf[done + i] ^ mask8[i & 7];

    result = Curl_bufq_write(out, tmp, n, &nwritten);
    if(result) {
      if((result != CURLE_AGAIN) || !done)
        return result;
      break;
    }
    done += nwritten;
    *pxori = (*pxori + (unsigned int)nwritten) & 3;
    if(nwritten < n)
      break;
  }
  *pnwritten = done;
  return CURLE_OK;
}

static CURLcode cf_ws_enc_add_payload(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      const uint8_t *buf, size_t blen,
                                      size_t *pnwritten)
{
  struct cf_ws_ctx *ctx = cf->ctx;

  NOVERBOSE((void)data);
  *pnwritten = 0;
  if(Curl_bufq_is_full(&ctx->sendbuf))
    return CURLE_AGAIN;
  else if(!ctx->enc.payload_remain)
    return CURLE_OK;
  else {
    CURLcode result;
    size_t len, remain;

    len = blen;
    remain = curlx_sotouz_range(ctx->enc.payload_remain, 0, SIZE_MAX);
    if(remain < len)
      len = remain;

    result = ws_enc_mask_write(ctx->enc.mask, &ctx->enc.xori, buf, len,
                               &ctx->sendbuf, pnwritten);
    if(!result) {
      ctx->enc.payload_remain -= (curl_off_t)*pnwritten;
      ws_enc_info(cf, data, "buffered");
    }
    return result;
  }
}

static CURLcode cf_ws_enc_write_payload(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        const uint8_t *buf, size_t buflen,
                                        size_t *pnwritten)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  struct ws_encoder *enc = &ctx->enc;
  CURLcode result;
  size_t len, remain;

  NOVERBOSE((void)data);
  *pnwritten = 0;
  if(Curl_bufq_is_full(&ctx->sendbuf))
    return CURLE_AGAIN;

  len = buflen;
  remain = curlx_sotouz_range(enc->payload_remain, 0, SIZE_MAX);
  if(remain < len)
    len = remain;

  result = ws_enc_mask_write(enc->mask, &enc->xori, buf, len,
                             &ctx->sendbuf, pnwritten);
  if(result)
    return result;
  enc->payload_remain -= (curl_off_t)*pnwritten;
  ws_enc_info(cf, data, "buffered");
  return CURLE_OK;
}

static CURLcode cf_ws_enc_add_pending(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  CURLcode result;
  size_t n;

  if(!ctx->pending.type) /* no pending frame here */
    return CURLE_OK;
  if(ctx->enc.payload_remain) /* in the middle of another frame */
    return CURLE_AGAIN;

  result = cf_ws_enc_add_frame(cf, data, ctx->pending.type,
                               (curl_off_t)ctx->pending.payload_len);
  if(result) {
    CURL_TRC_CF(data, cf, "ws_enc_cntrl(), error adding head: %d",
                (int)result);
    goto out;
  }
  result = cf_ws_enc_write_payload(cf, data, ctx->pending.payload,
                                   ctx->pending.payload_len, &n);
  if(result) {
    CURL_TRC_CF(data, cf, "ws_enc_cntrl(), error adding payload: %d",
                (int)result);
    goto out;
  }
  if(n != ctx->pending.payload_len) {
    DEBUGASSERT(0); /* buffer should always be able to take all */
    CURL_TRC_CF(data, cf, "ws_enc_cntrl(), error added only %zu/%zu payload,",
                n, ctx->pending.payload_len);
    result = CURLE_SEND_ERROR;
    goto out;
  }
  /* the frame should be complete now */
  DEBUGASSERT(!ctx->enc.payload_remain);
  memset(&ctx->pending, 0, sizeof(ctx->pending));

out:
  return result;
}

static CURLcode cf_ws_enc_write_head(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     unsigned int flags,
                                     curl_off_t payload_len)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  /* starting a new frame, we want a clean sendbuf.
   * Any pending control frame we can add now as part of the flush. */
  if(ctx->pending.type) {
    CURLcode result = cf_ws_enc_add_pending(cf, data);
    if(result)
      return result;
  }
  return cf_ws_enc_add_frame(cf, data, flags, payload_len);
}

static int ws_frame_firstbyte2flags(struct Curl_easy *data,
                                    uint8_t firstbyte, int cont_flags)
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

static CURLcode cf_ws_dec_read_head(struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  struct ws_decoder *dec = &ctx->dec;
  const uint8_t *inbuf;
  size_t inlen;

  while(Curl_bufq_peek(&ctx->recvbuf, &inbuf, &inlen)) {
    if(dec->head_len == 0) {
      dec->head[0] = *inbuf;
      Curl_bufq_skip(&ctx->recvbuf, 1);

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
      continue;
    }
    else if(dec->head_len == 1) {
      dec->head[1] = *inbuf;
      Curl_bufq_skip(&ctx->recvbuf, 1);
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
      if((dec->frame_flags & CURLWS_CLOSE) &&
         (dec->head[1] > WS_MAX_CNTRL_LEN)) {
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
      Curl_bufq_skip(&ctx->recvbuf, 1);
      ++dec->head_len;
      if(dec->head_len < dec->head_total) {
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
        failf(data, "[WS] frame length longer than 63 bits not supported");
        return CURLE_RECV_ERROR;
      }
      dec->payload_len =
        (curl_off_t)dec->head[2] << 56 |
        (curl_off_t)dec->head[3] << 48 |
        (curl_off_t)dec->head[4] << 40 |
        (curl_off_t)dec->head[5] << 32 |
        (curl_off_t)dec->head[6] << 24 |
        (curl_off_t)dec->head[7] << 16 |
        (curl_off_t)dec->head[8] <<  8 |
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
    ws_dec_info(cf, data, "head");
    return CURLE_OK;
  }
  return CURLE_AGAIN;
}

static CURLcode cf_ws_enc_add_cntrl(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    const uint8_t *payload,
                                    size_t plen,
                                    unsigned int frame_type)
{
  struct cf_ws_ctx *ctx = cf->ctx;

  (void)data;
  DEBUGASSERT(plen <= WS_MAX_CNTRL_LEN);
  if(plen > WS_MAX_CNTRL_LEN)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* Overwrite any pending frame with the new one, we keep
   * only one. */
  ctx->pending.type = frame_type;
  ctx->pending.payload_len = plen;
  memcpy(ctx->pending.payload, payload, plen);
  return CURLE_OK;
}

struct ws_collect {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  struct cf_ws_ctx *ws;
  char *buffer;
  size_t buflen;
  size_t bufidx;
  int frame_age;
  int frame_flags;
  curl_off_t payload_offset;
  curl_off_t payload_len;
  bool written;
};

static curl_off_t ws_payload_remain(curl_off_t payload_total,
                                    curl_off_t payload_offset,
                                    size_t payload_buffered)
{
  curl_off_t buffered, remain = payload_total - payload_offset;
  if((payload_total < 0) || (payload_offset < 0) || (remain < 0))
    return -1;
  buffered = curlx_uztoso(payload_buffered);
  if(remain < buffered)
    return -1;
  return remain - buffered;
}

static CURLcode cf_ws_dec_collect(const uint8_t *buf, size_t buflen,
                                  int frame_age, int frame_flags,
                                  curl_off_t payload_offset,
                                  curl_off_t payload_len,
                                  struct ws_collect *wsc,
                                  size_t *pnwritten)
{
  struct Curl_cfilter *cf = wsc->cf;
  struct Curl_easy *data = wsc->data;
  bool auto_pong = !data->set.ws_raw_mode && !data->set.ws_no_auto_pong;
  curl_off_t remain;
  size_t write_len;
  CURLcode result = CURLE_OK;

  *pnwritten = 0;
  remain = ws_payload_remain(payload_len, payload_offset, buflen);
  if(remain < 0) {
    DEBUGASSERT(0); /* parameter mismatch */
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(!wsc->bufidx) {
    /* first write */
    wsc->frame_age = frame_age;
    wsc->frame_flags = frame_flags;
    wsc->payload_offset = payload_offset;
    wsc->payload_len = payload_len;
  }

  if(auto_pong && (frame_flags & CURLWS_PING) && !remain) {
    /* auto-respond to PINGs, only works for single-frame payloads atm */
    CURL_TRC_CF(data, cf, "auto PONG to [PING payload=%" FMT_OFF_T
                "/%" FMT_OFF_T "]", payload_offset, payload_len);
    /* send back the exact same content as a PONG */
    result = cf_ws_enc_add_cntrl(cf, wsc->data, buf, buflen, CURLWS_PONG);
    if(result)
      return result;
    *pnwritten = buflen;
  }
  else {
    wsc->written = TRUE;
    if(wsc->buflen < wsc->bufidx) {
      DEBUGASSERT(0);
      return CURLE_FAILED_INIT;
    }
    write_len = CURLMIN(buflen, wsc->buflen - wsc->bufidx);
    if(!write_len) {
      if(!buflen)  /* 0 length write, we accept that */
        return CURLE_OK;
      return CURLE_AGAIN;  /* no more space */
    }
    memcpy(wsc->buffer + wsc->bufidx, buf, write_len);
    wsc->bufidx += write_len;
    *pnwritten = write_len;
  }
  return result;
}

static CURLcode cf_ws_dec_pass_payload(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       struct ws_collect *wsc)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  struct ws_decoder *dec = &ctx->dec;
  const uint8_t *inbuf;
  size_t inlen;
  size_t nwritten;
  CURLcode result;
  size_t remain = curlx_sotouz_range(dec->payload_len - dec->payload_offset,
                                     0, SIZE_MAX);

  while(remain && Curl_bufq_peek(&ctx->recvbuf, &inbuf, &inlen)) {
    if(inlen > remain)
      inlen = remain;
    result = cf_ws_dec_collect(inbuf, inlen, dec->frame_age, dec->frame_flags,
                               dec->payload_offset, dec->payload_len,
                               wsc, &nwritten);
    if(result)
      return result;
    Curl_bufq_skip(&ctx->recvbuf, nwritten);
    dec->payload_offset += nwritten;
    remain = curlx_sotouz_range(dec->payload_len - dec->payload_offset,
                                0, SIZE_MAX);
    CURL_TRC_CF(data, cf, "passed %zu bytes payload, %zu remain",
                nwritten, remain);
  }

  return remain ? CURLE_AGAIN : CURLE_OK;
}

static CURLcode cf_ws_dec_pass(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct ws_collect *wsc)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  struct ws_decoder *dec = &ctx->dec;
  CURLcode result;

  if(Curl_bufq_is_empty(&ctx->recvbuf))
    return CURLE_AGAIN;

  switch(dec->state) {
  case WS_DEC_INIT:
    ws_dec_next_frame(dec);
    dec->state = WS_DEC_HEAD;
    FALLTHROUGH();
  case WS_DEC_HEAD:
    result = cf_ws_dec_read_head(cf, data);
    if(result) {
      if(result != CURLE_AGAIN) {
        failf(data, "[WS] decode frame error %d", (int)result);
        break;  /* real error */
      }
      /* incomplete ws frame head */
      DEBUGASSERT(Curl_bufq_is_empty(&ctx->recvbuf));
      break;
    }
    /* head parsing done */
    dec->state = WS_DEC_PAYLOAD;
    if(dec->payload_len == 0) {
      size_t nwritten;
      const uint8_t tmp = '\0';
      /* special case of a 0 length frame, need to write once */
      result = cf_ws_dec_collect(&tmp, 0, dec->frame_age, dec->frame_flags,
                                 0, 0, wsc, &nwritten);
      if(result)
        return result;
      dec->state = WS_DEC_INIT;
      break;
    }
    FALLTHROUGH();
  case WS_DEC_PAYLOAD:
    result = cf_ws_dec_pass_payload(cf, data, wsc);
    ws_dec_info(cf, data, "passing");
    if(result)
      return result;
    /* payload parsing done */
    dec->state = WS_DEC_INIT;
    break;
  default:
    /* we covered all enums above, but some code analyzers are wimps */
    result = CURLE_FAILED_INIT;
  }
  if(!result && (dec->state == WS_DEC_INIT) &&
     (dec->frame_flags & CURLWS_CLOSE))
    dec->seen_close = TRUE;
  return result;
}

static struct cf_ws_ctx *cf_ws_ctx_create(void)
{
  struct cf_ws_ctx *ctx;
  size_t chunk_size = WS_CHUNK_SIZE;

  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx)
    return NULL;
#ifdef DEBUGBUILD
  {
    const char *p = getenv("CURL_WS_CHUNK_SIZE");
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, 1 * 1024 * 1024))
        chunk_size = (size_t)l;
    }
  }
#endif
  Curl_bufq_init2(&ctx->recvbuf, chunk_size, WS_CHUNK_COUNT,
                  BUFQ_OPT_SOFT_LIMIT);
  Curl_bufq_init2(&ctx->sendbuf, chunk_size, WS_CHUNK_COUNT,
                  BUFQ_OPT_SOFT_LIMIT);
  ws_dec_init(&ctx->dec);
  ws_enc_init(&ctx->enc);
  return ctx;
}

static void cf_ws_ctx_destroy(struct cf_ws_ctx *ctx)
{
  if(ctx) {
    Curl_bufq_free(&ctx->recvbuf);
    Curl_bufq_free(&ctx->sendbuf);
    curlx_free(ctx);
  }
}

static void cf_ws_destroy(struct Curl_cfilter *cf,
                          struct Curl_easy *data)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  CURL_TRC_CF(data, cf, "destroy");
  cf_ws_ctx_destroy(ctx);
  cf->ctx = NULL;
}

static CURLcode cf_ws_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool *done)
{
  CURLcode result;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the lower filters first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  CURL_TRC_CF(data, cf, "connect");
  *done = TRUE;
  cf->connected = TRUE;
  return CURLE_OK;
}

static CURLcode cf_ws_flush(struct Curl_cfilter *cf,
                            struct Curl_easy *data)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  /* If there is space, add any pending control frame */
  if(Curl_bufq_len(&ctx->sendbuf) < ctx->sendbuf.chunk_size) {
    result = cf_ws_enc_add_pending(cf, data);
    if(result && (result != CURLE_AGAIN))
      return result;
    result = CURLE_OK;
  }

  if(!Curl_bufq_is_empty(&ctx->sendbuf)) {
    const uint8_t *out;
    size_t outlen, n;

    while(Curl_bufq_peek(&ctx->sendbuf, &out, &outlen)) {
      result = cf->next->cft->do_send(cf->next, data, out, outlen, FALSE, &n);
      if(result == CURLE_AGAIN) {
        CURL_TRC_CF(data, cf, "flush EAGAIN, %zu bytes remain in buffer",
                    Curl_bufq_len(&ctx->sendbuf));
        return result;
      }
      else if(result) {
        failf(data, "[WS] flush, write error %d", (int)result);
        return result;
      }
      else {
        CURL_TRC_CF(data, cf, "flushed %zu bytes", n);
        Curl_bufq_skip(&ctx->sendbuf, n);
      }
    }
  }

  if(ctx->send_eos_seen && !ctx->sent_eos &&
     Curl_bufq_is_empty(&ctx->sendbuf)) {
    /* Tell lower filters that this is the end of send for this transfer */
    size_t n;
    result = cf->next->cft->do_send(cf->next, data, NULL, 0, TRUE, &n);
    if(!result)
      ctx->sent_eos = TRUE;
  }
  return result;
}

static CURLcode cf_ws_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                           const uint8_t *buf, size_t blen, bool eos,
                           size_t *pnwritten)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  *pnwritten = 0;
  if(!buf && blen) {
    failf(data, "[WS] buffer is NULL when buflen is not");
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  if(data->set.ws_raw_mode) {
    if(!buf) {
      failf(data, "[WS] buffer is NULL in raw mode");
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
    result = cf_ws_flush(cf, data);
    if(result)
      goto out;
    result = cf->next->cft->do_send(cf->next, data, buf, blen, eos, pnwritten);
  }
  else {
    result = cf_ws_flush(cf, data);
    if(result && (result != CURLE_AGAIN))
      goto out;
    if(Curl_bufq_is_full(&ctx->sendbuf)) {
      /* We need to back-pressure this send. The problem is that
       * calling Curl_cf_ws_start_frame() nefore the re-send will
       * de-sync the send data with its frame meta setting.
       * We set `data->req.send_no_merge` to prevent request
       * uploads from send more than one Curl_client_read() at a time. */
      result = CURLE_AGAIN;
      goto out;
    }

    if(!ctx->enc.payload_remain && blen) {
      /* encode the data as a new BINARY frame */
      result = cf_ws_enc_write_head(cf, data, CURLWS_BINARY, blen);
      if(result) {
        CURL_TRC_CF(data, cf, "send(), error writing frame head %d",
                    (int)result);
        goto out;
      }
    }
    result = cf_ws_enc_add_payload(cf, data, buf, blen, pnwritten);
  }

  if(!result) {
    if(eos && !ctx->send_eos_seen)
      ctx->send_eos_seen = TRUE;

    result = cf_ws_flush(cf, data);
    if((result == CURLE_AGAIN) && *pnwritten) {
      result = CURLE_OK;
    }
  }

out:
  CURL_TRC_CF(data, cf, "send(len=%zu, raw=%d) -> %d, %zu",
              blen, data->set.ws_raw_mode, (int)result, *pnwritten);
  return result;
}

static void ws_update_meta(struct cf_ws_ctx *ctx,
                           int frame_age, int frame_flags,
                           curl_off_t payload_offset,
                           curl_off_t payload_len,
                           size_t cur_len)
{
  curl_off_t bytesleft = (payload_len - payload_offset - cur_len);

  ctx->recvframe.age = frame_age;
  ctx->recvframe.flags = frame_flags;
  ctx->recvframe.offset = payload_offset;
  ctx->recvframe.len = cur_len;
  ctx->recvframe.bytesleft = bytesleft;
  ctx->recvframe_0_len = !payload_len;
}

static CURLcode cf_ws_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           char *buf, size_t blen, size_t *pnread)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  struct ws_collect wsc;
  CURLcode result;

  *pnread = 0;
  result = cf_ws_flush(cf, data);
  if(result && (result != CURLE_AGAIN))
    goto out;

  if(data->set.ws_raw_mode) {
    if(!Curl_bufq_is_empty(&ctx->recvbuf))
      result = Curl_bufq_cread(&ctx->recvbuf, buf, blen, pnread);
    else
      result = Curl_conn_cf_recv(cf->next, data, buf, blen, pnread);
    goto out;
  }

  /* Collecting the decoded frame data */
  memset(&wsc, 0, sizeof(wsc));
  wsc.cf = cf;
  wsc.data = data;
  wsc.ws = ctx;
  wsc.buffer = buf;
  wsc.buflen = blen;

  while(1) {
    /* receive more when our buffer is empty */
    if(Curl_bufq_is_empty(&ctx->recvbuf)) {
      size_t n;
      result = Curl_cf_recv_bufq(cf->next, data, &ctx->recvbuf, 0, &n);
      if(result) {
        if(result == CURLE_AGAIN) {
          /* Not a real error, try a flush before leaving */
          CURLcode r2 = cf_ws_flush(cf, data);
          if(r2 && (r2 != CURLE_AGAIN))
            result = r2;
          else if(ctx->dec.seen_close) {
            /* This looks like the EOS on this ws connection. */
            *pnread = 0;
            result = CURLE_OK;
          }
        }
        goto out;
      }
      else if(n == 0) {
        /* connection closed */
        if(ctx->dec.state != WS_DEC_INIT) {
          infof(data, "[WS] connection expectedly closed");
          result = CURLE_RECV_ERROR;
        }
        goto out;
      }
      CURL_TRC_CF(data, cf, "recv, added %zu bytes from network",
                  Curl_bufq_len(&ctx->recvbuf));
    }

    result = cf_ws_dec_pass(cf, data, &wsc);
    if(result == CURLE_AGAIN) {
      if(!wsc.written) {
        ws_dec_info(cf, data, "need more input");
        continue;  /* nothing written, try more input */
      }
      break;
    }
    else if(result) {
      goto out;
    }
    else if(wsc.written) {
      /* The decoded frame is passed back to our caller.
       * There are frames like PING were we auto-respond to and
       * that we do not return. For these `ctx.written` is not set. */
      break;
    }
  }

  /* update frame information to be passed back */
  ws_update_meta(ctx, wsc.frame_age, wsc.frame_flags, wsc.payload_offset,
                 wsc.payload_len, wsc.bufidx);
  if(ctx->recvframe.len) {
    *pnread = ctx->recvframe.len;
    result = CURLE_OK;
  }
  else {
    /* 0-length frame data, if we return this, the transfer loop
     * will think this is an EOS */
    if(!buf || !blen) {
      /* someone just taking a peek at the frame meta data */
      *pnread = 0;
      result = CURLE_OK;
    }
    else if(ctx->recvframe.bytesleft) {
      /* more data is coming, stall */
      *pnread = 0;
      result = CURLE_AGAIN;
    }
    else {
      /* This really is a 0-length frame. */
      DEBUGASSERT(ctx->recvframe_0_len);
      buf[0] = 0;
      *pnread = 1;
      result = CURLE_OK;
    }
  }
  CURL_TRC_CF(data, cf, "recv(len=%zu) -> %zu bytes (frame at %"
              FMT_OFF_T ", %" FMT_OFF_T " left)",
              blen, *pnread, ctx->recvframe.offset,
              ctx->recvframe.bytesleft);
  if(!result) {
    CURLcode r2 = cf_ws_flush(cf, data);
    if(r2 && (r2 != CURLE_AGAIN))
      result = r2;
  }

out:
  CURL_TRC_CF(data, cf, "recv(len=%zu, raw=%d) -> %d, %zu",
              blen, data->set.ws_raw_mode, (int)result, *pnread);
  return result;
}

static CURLcode cf_ws_cntrl(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            int event, int arg1, void *arg2)
{
  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_FLUSH:
    return cf_ws_flush(cf, data);
  default:
    break;
  }
  return CURLE_OK;
}

static CURLcode cf_ws_query(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            int query, int *pres1, void *pres2)
{
  struct cf_ws_ctx *ctx = cf->ctx;

  switch(query) {
  case CF_QUERY_NEED_FLUSH:
    if(!Curl_bufq_is_empty(&ctx->sendbuf)) {
      *pres1 = TRUE;
      return CURLE_OK;
    }
    break;
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_ws_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data)
{
  struct cf_ws_ctx *ctx = cf->ctx;

  if(ctx && !Curl_bufq_is_empty(&ctx->recvbuf))
    return TRUE;
  return cf->next ? cf->next->cft->has_data_pending(cf->next, data) : FALSE;
}

static CURLcode cf_ws_shutdown(struct Curl_cfilter *cf,
                               struct Curl_easy *data, bool *done)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(!ctx->added_close_frame && ctx->dec.seen_close) {
    /* Server sent a CLOSE frame, we have not yet. Do it. */
    result = cf_ws_enc_write_head(cf, data, CURLWS_CLOSE, 0);
    if(result)
      goto out;
    ctx->added_close_frame = TRUE;
  }

  result = cf_ws_flush(cf, data);

out:
  *done = !result;
  if(result == CURLE_AGAIN)
    result = CURLE_OK;
  CURL_TRC_CF(data, cf, "shutdown() -> %d, done=%d", (int)result, *done);
  return result;
}

static CURLcode cf_ws_adjust_pollset(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct easy_pollset *ps)
{
  struct cf_ws_ctx *ctx = cf->ctx;

  if(!Curl_bufq_is_empty(&ctx->sendbuf)) {
    curl_socket_t sock = Curl_conn_cf_get_socket(cf, data);
    return Curl_pollset_add_out(data, ps, sock);
  }
  return CURLE_OK;
}

struct Curl_cftype Curl_cft_ws = {
  "WS",
  0,
  CURL_LOG_LVL_NONE,
  cf_ws_destroy,
  cf_ws_connect,
  cf_ws_shutdown,
  cf_ws_adjust_pollset,
  cf_ws_data_pending,
  cf_ws_send,
  cf_ws_recv,
  cf_ws_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_ws_query,
};

static CURLcode cf_ws_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_ws_ctx *ctx;
  CURLcode result = CURLE_OK;

  (void)data;
  ctx = cf_ws_ctx_create();
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = Curl_cf_create(&cf, &Curl_cft_ws, ctx);
  if(result)
    goto out;
  ctx = NULL;

out:
  *pcf = result ? NULL : cf;
  if(ctx) {
    curlx_free(ctx);
  }
  return result;
}

CURLcode Curl_cf_ws_add(struct Curl_easy *data,
                        const char *buf, size_t blen)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  DEBUGASSERT(data);
  result = cf_ws_create(&cf, data);
  if(result)
    goto out;
  Curl_conn_cf_add(data, data->conn, FIRSTSOCKET, cf);

  if(cf->next && cf->next->connected)
    cf->connected = TRUE;

  if(blen) {
    struct cf_ws_ctx *ctx = cf->ctx;
    size_t nwritten;
    result = Curl_bufq_write(&ctx->recvbuf, (const uint8_t *)buf, blen,
                             &nwritten);
    if(!result && (nwritten != blen)) {
      result = CURLE_FAILED_INIT;
      goto out;
    }
    CURL_TRC_CF(data, cf, "added with %zu bytes in recvbuf", blen);
  }
out:
  return result;
}

struct Curl_cfilter *Curl_cf_ws_get(struct Curl_easy *data)
{
  return Curl_conn_get_first_cf(data->conn, &Curl_cft_ws);
}

struct cf_ws_ctx *Curl_cf_ws_conn_get_ctx(struct connectdata *conn)
{
  struct Curl_cfilter *cf = Curl_conn_get_first_cf(conn, &Curl_cft_ws);
  return cf ? cf->ctx : NULL;
}

struct cf_ws_ctx *Curl_cf_ws_get_ctx(struct Curl_easy *data)
{
  return Curl_cf_ws_conn_get_ctx(data->conn);
}

bool Curl_cf_ws_in_send_frame(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  (void)data;
  return ctx->enc.payload_remain;
}

CURLcode Curl_cf_ws_start_frame(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                unsigned int flags,
                                curl_off_t frame_len)
{
  struct cf_ws_ctx *ctx = cf->ctx;
  CURLcode result;

  if(ctx->enc.payload_remain) {
    CURL_TRC_CF(data, cf, "start_frame denied, previous frame not finished");
    return CURLE_AGAIN;
  }
  result = cf_ws_enc_write_head(cf, data, flags, frame_len);
  CURL_TRC_CF(data, cf, "start_frame(flags=%x, len=%" FMT_OFF_T " -> %d, %zu",
              flags, frame_len, (int)result, Curl_bufq_len(&ctx->sendbuf));
  if(!result && (flags & CURLWS_CLOSE))
    ctx->added_close_frame = TRUE;
  return result;
}

#endif /* !CURL_DISABLE_WEBSOCKETS */
