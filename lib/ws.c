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

#ifdef USE_WEBSOCKETS

#include "urldata.h"
#include "bufq.h"
#include "dynbuf.h"
#include "rand.h"
#include "curl_base64.h"
#include "connect.h"
#include "sendf.h"
#include "multiif.h"
#include "ws.h"
#include "easyif.h"
#include "transfer.h"
#include "nonblock.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#define WSBIT_FIN 0x80
#define WSBIT_OPCODE_CONT  0
#define WSBIT_OPCODE_TEXT  (1)
#define WSBIT_OPCODE_BIN   (2)
#define WSBIT_OPCODE_CLOSE (8)
#define WSBIT_OPCODE_PING  (9)
#define WSBIT_OPCODE_PONG  (0xa)
#define WSBIT_OPCODE_MASK  (0xf)

#define WSBIT_MASK 0x80

/* buffer dimensioning */
#define WS_CHUNK_SIZE 65535
#define WS_CHUNK_COUNT 2

typedef ssize_t ws_write_payload(const unsigned char *buf, size_t buflen,
                                 int frame_age, int frame_flags,
                                 curl_off_t payload_offset,
                                 curl_off_t payload_len,
                                 void *userp,
                                 CURLcode *err);

static void ws_dec_reset(struct ws_decoder *dec)
{
  dec->frame_age = 0;
  dec->frame_flags = 0;
  dec->payload_offset = 0;
  dec->payload_len = 0;
  dec->head_len = dec->head_total = 0;
  dec->state = WS_DEC_INIT;
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
      unsigned char opcode;
      bool fin;

      dec->head[0] = *inbuf;
      Curl_bufq_skip(inraw, 1);

      fin = dec->head[0] & WSBIT_FIN;
      opcode = dec->head[0] & WSBIT_OPCODE_MASK;
      infof(data, "WS:%d received FIN bit %u", __LINE__, (int)fin);
      dec->frame_flags = 0;
      switch(opcode) {
      case WSBIT_OPCODE_CONT:
        if(!fin)
          dec->frame_flags |= CURLWS_CONT;
        infof(data, "WS: received OPCODE CONT");
        break;
      case WSBIT_OPCODE_TEXT:
        infof(data, "WS: received OPCODE TEXT");
        dec->frame_flags |= CURLWS_TEXT;
        break;
      case WSBIT_OPCODE_BIN:
        infof(data, "WS: received OPCODE BINARY");
        dec->frame_flags |= CURLWS_BINARY;
        break;
      case WSBIT_OPCODE_CLOSE:
        infof(data, "WS: received OPCODE CLOSE");
        dec->frame_flags |= CURLWS_CLOSE;
        break;
      case WSBIT_OPCODE_PING:
        infof(data, "WS: received OPCODE PING");
        dec->frame_flags |= CURLWS_PING;
        break;
      case WSBIT_OPCODE_PONG:
        infof(data, "WS: received OPCODE PONG");
        dec->frame_flags |= CURLWS_PONG;
        break;
      default:
        failf(data, "WS: unknown opcode: %x", opcode);
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }
      dec->head_len = 1;
      continue;
    }
    else if(dec->head_len == 1) {
      dec->head[1] = *inbuf;
      Curl_bufq_skip(inraw, 1);
      dec->head_len = 2;

      if(dec->head[1] & WSBIT_MASK) {
        /* A client MUST close a connection if it detects a masked frame. */
        failf(data, "WS: masked input frame");
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
      infof(data, "WS: frame head has %d bytes", dec->head_total);
    }

    if(dec->head_len < dec->head_total) {
      dec->head[dec->head_len] = *inbuf;
      Curl_bufq_skip(inraw, 1);
      ++dec->head_len;
      if(dec->head_len < dec->head_total)
        continue;
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
      failf(data, "WS: unexpected frame header length");
      return CURLE_RECV_ERROR;
    }
    dec->frame_age = 0;
    dec->payload_offset = 0;
    infof(data, "WS: frame payload has %zu bytes", dec->payload_len);
    return CURLE_OK;
  }
  return CURLE_AGAIN;
}

static CURLcode ws_dec_pass_payload(struct ws_decoder *dec,
                                    struct bufq *inraw,
                                    ws_write_payload *write_payload,
                                    void *write_ctx)
{
  const unsigned char *inbuf;
  size_t inlen;
  ssize_t nwritten;
  CURLcode result;
  curl_off_t remain = dec->payload_len - dec->payload_offset;

  while(remain && Curl_bufq_peek(inraw, &inbuf, &inlen)) {
    if((curl_off_t)inlen > remain)
      inlen = (size_t)remain;
    nwritten = write_payload(inbuf, inlen, dec->frame_age, dec->frame_flags,
                             dec->payload_offset, dec->payload_len,
                             write_ctx, &result);
    if(nwritten < 0)
      return result;
    Curl_bufq_skip(inraw, (size_t)nwritten);
    dec->payload_offset += (curl_off_t)nwritten;
    remain = dec->payload_len - dec->payload_offset;
  }

  return remain? CURLE_AGAIN : CURLE_OK;
}

static CURLcode ws_dec_pass(struct ws_decoder *dec,
                            struct Curl_easy *data,
                            struct bufq *inraw,
                            ws_write_payload *write_payload,
                            void *write_ctx)
{
  CURLcode result;

  if(Curl_bufq_is_empty(inraw))
    return CURLE_AGAIN;

  switch(dec->state) {
  case WS_DEC_INIT:
    ws_dec_reset(dec);
    dec->state = WS_DEC_HEAD;
    /* FALLTHROUGH */
  case WS_DEC_HEAD:
    result = ws_dec_read_head(dec, data, inraw);
    if(result) {
      if(result != CURLE_AGAIN) {
        infof(data, "WS: decode error %d", (int)result);
        break;  /* real error */
      }
      /* incomplete ws frame head */
      DEBUGASSERT(Curl_bufq_is_empty(inraw));
      break;
    }
    /* head parsing done */
    dec->state = WS_DEC_PAYLOAD;
    if(dec->payload_len == 0) {
      ssize_t nwritten;
      const unsigned char tmp;
      /* special case of a 0 length frame, need to write once */
      nwritten = write_payload(&tmp, 0, dec->frame_age, dec->frame_flags,
                               0, 0, write_ctx, &result);
      if(nwritten < 0)
        return result;
      dec->state = WS_DEC_INIT;
      break;
    }
    /* FALLTHROUGH */
  case WS_DEC_PAYLOAD:
    result = ws_dec_pass_payload(dec, inraw, write_payload, write_ctx);
    if(result)
      return result;
    /* paylod parsing done */
    dec->state = WS_DEC_INIT;
    break;
  }
  return result;
}

static void update_meta(struct websocket *ws,
                        int frame_age, int frame_flags,
                        curl_off_t payload_offset,
                        curl_off_t payload_len,
                        size_t cur_len)
{
  ws->frame.age = frame_age;
  ws->frame.flags = frame_flags;
  ws->frame.offset = payload_offset;
  ws->frame.len = cur_len;
  ws->frame.bytesleft = (payload_len - payload_offset - cur_len);
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

static ssize_t ws_enc_write_head(struct Curl_easy *data,
                                 struct ws_encoder *enc,
                                 size_t len, unsigned int flags,
                                 struct bufq *out,
                                 CURLcode *err)
{
  unsigned char firstbyte = 0;
  unsigned char opcode;
  unsigned char head[14];
  size_t hlen;
  ssize_t n;

  if(enc->payload_remain > 0) {
    /* trying to write a new frame before the previous one is finished */
    failf(data, "WS: starting new frame with %zd bytes from last one"
                "remaining to be sent", (ssize_t)enc->payload_remain);
    *err = CURLE_SEND_ERROR;
    return -1;
  }

  if(flags & CURLWS_TEXT) {
    opcode = WSBIT_OPCODE_TEXT;
    infof(data, "WS: send OPCODE TEXT");
  }
  else if(flags & CURLWS_CLOSE) {
    opcode = WSBIT_OPCODE_CLOSE;
    infof(data, "WS: send OPCODE CLOSE");
  }
  else if(flags & CURLWS_PING) {
    opcode = WSBIT_OPCODE_PING;
    infof(data, "WS: send OPCODE PING");
  }
  else if(flags & CURLWS_PONG) {
    opcode = WSBIT_OPCODE_PONG;
    infof(data, "WS: send OPCODE PONG");
  }
  else {
    opcode = WSBIT_OPCODE_BIN;
    infof(data, "WS: send OPCODE BINARY");
  }

  if(!(flags & CURLWS_CONT)) {
    if(!enc->contfragment)
      /* not marked as continuing, this is the final fragment */
      firstbyte |= WSBIT_FIN | opcode;
    else
      /* marked as continuing, this is the final fragment; set CONT
         opcode and FIN bit */
      firstbyte |= WSBIT_FIN | WSBIT_OPCODE_CONT;

    enc->contfragment = FALSE;
    infof(data, "WS: set FIN");
  }
  else if(enc->contfragment) {
    /* the previous fragment was not a final one and this isn't either, keep a
       CONT opcode and no FIN bit */
    firstbyte |= WSBIT_OPCODE_CONT;
    infof(data, "WS: keep CONT, no FIN");
  }
  else {
    firstbyte = opcode;
    enc->contfragment = TRUE;
    infof(data, "WS: set CONT, no FIN");
  }

  head[0] = firstbyte;
  if(len > 65535) {
    head[1] = 127 | WSBIT_MASK;
    head[2] = (len >> 8) & 0xff;
    head[3] = len & 0xff;
    hlen = 10;
  }
  else if(len > 126) {
    head[1] = 126 | WSBIT_MASK;
    head[2] = (len >> 8) & 0xff;
    head[3] = len & 0xff;
    hlen = 4;
  }
  else {
    head[1] = (unsigned char)len | WSBIT_MASK;
    hlen = 2;
  }

  infof(data, "WS: send FIN bit %u (byte %02x), payload len=%zu",
        firstbyte & WSBIT_FIN ? 1 : 0,
        firstbyte, len);

  /* add 4 bytes mask */
  memcpy(&head[hlen], &enc->mask, 4);
  hlen += 4;
  /* reset for payload to come */
  enc->xori = 0;

  n = Curl_bufq_write(out, head, hlen, err);
  if(n < 0)
    return -1;
  if((size_t)n != hlen) {
    /* We use a bufq with SOFT_LIMIT, writing should always succeed */
    DEBUGASSERT(0);
    *err = CURLE_SEND_ERROR;
    return -1;
  }
  enc->payload_remain = len;
  return n;
}

static ssize_t ws_enc_write_payload(struct ws_encoder *enc,
                                    const unsigned char *buf, size_t buflen,
                                    struct bufq *out, CURLcode *err)
{
  ssize_t n;
  size_t i, len;

  if(Curl_bufq_is_full(out)) {
    *err = CURLE_AGAIN;
    return -1;
  }

  /* not the most performant way to do this */
  len = buflen;
  if((curl_off_t)len > enc->payload_remain)
    len = (size_t)enc->payload_remain;

  for(i = 0; i < len; ++i) {
    unsigned char c = buf[i] ^ enc->mask[enc->xori];
    n = Curl_bufq_write(out, &c, 1, err);
    if(n < 0) {
      if((*err != CURLE_AGAIN) || !i)
        return -1;
      break;
    }
    enc->xori++;
    enc->xori &= 3;
  }
  enc->payload_remain -= (curl_off_t)i;
  return (ssize_t)i;
}


struct wsfield {
  const char *name;
  const char *val;
};

CURLcode Curl_ws_request(struct Curl_easy *data, REQTYPE *req)
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
      "Upgrade:", "websocket"
    },
    {
      /* The request MUST contain a |Connection| header field whose value
         MUST include the "Upgrade" token. */
      "Connection:", "Upgrade",
    },
    {
      /* The request MUST include a header field with the name
         |Sec-WebSocket-Version|. The value of this header field MUST be
         13. */
      "Sec-WebSocket-Version:", "13",
    },
    {
      /* The request MUST include a header field with the name
         |Sec-WebSocket-Key|. The value of this header field MUST be a nonce
         consisting of a randomly selected 16-byte value that has been
         base64-encoded (see Section 4 of [RFC4648]). The nonce MUST be
         selected randomly for each connection. */
      "Sec-WebSocket-Key:", NULL,
    }
  };
  heads[3].val = &keyval[0];

  /* 16 bytes random */
  result = Curl_rand(data, (unsigned char *)rand, sizeof(rand));
  if(result)
    return result;
  result = Curl_base64_encode((char *)rand, sizeof(rand), &randstr, &randlen);
  if(result)
    return result;
  DEBUGASSERT(randlen < sizeof(keyval));
  if(randlen >= sizeof(keyval))
    return CURLE_FAILED_INIT;
  strcpy(keyval, randstr);
  free(randstr);
  for(i = 0; !result && (i < sizeof(heads)/sizeof(heads[0])); i++) {
    if(!Curl_checkheaders(data, STRCONST(heads[i].name))) {
#ifdef USE_HYPER
      char field[128];
      msnprintf(field, sizeof(field), "%s %s", heads[i].name,
                heads[i].val);
      result = Curl_hyper_header(data, req, field);
#else
      (void)data;
      result = Curl_dyn_addf(req, "%s %s\r\n", heads[i].name,
                             heads[i].val);
#endif
    }
  }
  k->upgr101 = UPGR101_WS;
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
  struct websocket *ws;
  CURLcode result;

  DEBUGASSERT(data->conn);
  ws = data->conn->proto.ws;
  if(!ws) {
    ws = calloc(1, sizeof(*ws));
    if(!ws)
      return CURLE_OUT_OF_MEMORY;
    data->conn->proto.ws = ws;
    Curl_bufq_init(&ws->recvbuf, WS_CHUNK_SIZE, WS_CHUNK_COUNT);
    Curl_bufq_init2(&ws->sendbuf, WS_CHUNK_SIZE, WS_CHUNK_COUNT,
                    BUFQ_OPT_SOFT_LIMIT);
    ws_dec_init(&ws->dec);
    ws_enc_init(&ws->enc);
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

  /* 4 bytes random */

  result = Curl_rand(data, (unsigned char *)&ws->enc.mask,
                     sizeof(ws->enc.mask));
  if(result)
    return result;
  infof(data, "Received 101, switch to WebSocket; mask %02x%02x%02x%02x",
        ws->enc.mask[0], ws->enc.mask[1], ws->enc.mask[2], ws->enc.mask[3]);

  if(data->set.connect_only) {
    ssize_t nwritten;
    /* In CONNECT_ONLY setup, the payloads from `mem` need to be received
     * when using `curl_ws_recv` later on after this transfer is already
     * marked as DONE. */
    nwritten = Curl_bufq_write(&ws->recvbuf, (const unsigned char *)mem,
                               nread, &result);
    if(nwritten < 0)
      return result;
    infof(data, "%zu bytes websocket payload", nread);
  }
  k->upgr101 = UPGR101_RECEIVED;

  return result;
}

static ssize_t ws_client_write(const unsigned char *buf, size_t buflen,
                               int frame_age, int frame_flags,
                               curl_off_t payload_offset,
                               curl_off_t payload_len,
                               void *userp,
                               CURLcode *err)
{
  struct Curl_easy *data = userp;
  struct websocket *ws;
  size_t wrote;
  curl_off_t remain = (payload_len - (payload_offset + buflen));

  (void)frame_age;
  if(!data->conn || !data->conn->proto.ws) {
    *err = CURLE_FAILED_INIT;
    return -1;
  }
  ws = data->conn->proto.ws;

  if((frame_flags & CURLWS_PING) && !remain) {
    /* auto-respond to PINGs, only works for single-frame payloads atm */
    size_t bytes;
    infof(data, "WS: auto-respond to PING with a PONG");
    /* send back the exact same content as a PONG */
    *err = curl_ws_send(data, buf, buflen, &bytes, 0, CURLWS_PONG);
    if(*err)
      return -1;
  }
  else if(buflen || !remain) {
    /* deliver the decoded frame to the user callback. The application
     * may invoke curl_ws_meta() to access frame information. */
    update_meta(ws, frame_age, frame_flags, payload_offset,
                payload_len, buflen);
    Curl_set_in_callback(data, true);
    wrote = data->set.fwrite_func((char *)buf, 1,
                                  buflen, data->set.out);
    Curl_set_in_callback(data, false);
    if(wrote != buflen) {
      *err = CURLE_RECV_ERROR;
      return -1;
    }
  }
  *err = CURLE_OK;
  return (ssize_t)buflen;
}

/* Curl_ws_writecb() is the write callback for websocket traffic. The
   websocket data is provided to this raw, in chunks. This function should
   handle/decode the data and call the "real" underlying callback accordingly.
*/
size_t Curl_ws_writecb(char *buffer, size_t size /* 1 */,
                       size_t nitems, void *userp)
{
  struct Curl_easy *data = userp;

  if(data->set.ws_raw_mode)
    return data->set.fwrite_func(buffer, size, nitems, data->set.out);
  else if(nitems) {
    struct websocket *ws;
    CURLcode result;

    if(!data->conn || !data->conn->proto.ws) {
      failf(data, "WS: not a websocket transfer");
      return nitems - 1;
    }
    ws = data->conn->proto.ws;

    if(buffer) {
      ssize_t nwritten;

      nwritten = Curl_bufq_write(&ws->recvbuf, (const unsigned char *)buffer,
                                 nitems, &result);
      if(nwritten < 0) {
        infof(data, "WS: error adding data to buffer %d", (int)result);
        return nitems - 1;
      }
      buffer = NULL;
    }

    while(!Curl_bufq_is_empty(&ws->recvbuf)) {

      result = ws_dec_pass(&ws->dec, data, &ws->recvbuf,
                           ws_client_write, data);
      if(result == CURLE_AGAIN)
        /* insufficient amount of data, keep it for later.
         * we pretend to have written all since we have a copy */
        return nitems;
      else if(result) {
        infof(data, "WS: decode error %d", (int)result);
        return nitems - 1;
      }
    }
  }
  return nitems;
}

struct ws_collect {
  struct Curl_easy *data;
  void *buffer;
  size_t buflen;
  size_t bufidx;
  int frame_age;
  int frame_flags;
  curl_off_t payload_offset;
  curl_off_t payload_len;
  bool written;
};

static ssize_t ws_client_collect(const unsigned char *buf, size_t buflen,
                                 int frame_age, int frame_flags,
                                 curl_off_t payload_offset,
                                 curl_off_t payload_len,
                                 void *userp,
                                 CURLcode *err)
{
  struct ws_collect *ctx = userp;
  size_t nwritten;
  curl_off_t remain = (payload_len - (payload_offset + buflen));

  if((frame_flags & CURLWS_PING) && !remain) {
    /* auto-respond to PINGs, only works for single-frame payloads atm */
    size_t bytes;
    infof(ctx->data, "WS: auto-respond to PING with a PONG");
    /* send back the exact same content as a PONG */
    *err = curl_ws_send(ctx->data, buf, buflen, &bytes, 0, CURLWS_PONG);
    if(*err)
      return -1;
    nwritten = bytes;
  }
  else {
    ctx->written = TRUE;
    DEBUGASSERT(ctx->buflen >= ctx->bufidx);
    nwritten = CURLMIN(buflen, ctx->buflen - ctx->bufidx);
    if(!nwritten) {
      if(!buflen) {  /* 0 length write, we accept that */
        *err = CURLE_OK;
        return 0;
      }
      *err = CURLE_AGAIN;  /* no more space */
      return -1;
    }
    *err = CURLE_OK;
    memcpy(ctx->buffer, buf, nwritten);
    if(!ctx->bufidx) {
      /* first write */
      ctx->frame_age = frame_age;
      ctx->frame_flags = frame_flags;
      ctx->payload_offset = payload_offset;
      ctx->payload_len = payload_len;
    }
    ctx->bufidx += nwritten;
  }
  return nwritten;
}

static ssize_t nw_in_recv(void *reader_ctx,
                          unsigned char *buf, size_t buflen,
                          CURLcode *err)
{
  struct Curl_easy *data = reader_ctx;
  size_t nread;

  *err = curl_easy_recv(data, buf, buflen, &nread);
  if(*err)
    return *err;
  return (ssize_t)nread;
}

CURL_EXTERN CURLcode curl_ws_recv(struct Curl_easy *data, void *buffer,
                                  size_t buflen, size_t *nread,
                                  struct curl_ws_frame **metap)
{
  struct connectdata *conn = data->conn;
  struct websocket *ws;
  bool done = FALSE; /* not filled passed buffer yet */
  struct ws_collect ctx;
  CURLcode result;

  if(!conn) {
    /* Unhappy hack with lifetimes of transfers and connection */
    if(!data->set.connect_only) {
      failf(data, "CONNECT_ONLY is required");
      return CURLE_UNSUPPORTED_PROTOCOL;
    }

    Curl_getconnectinfo(data, &conn);
    if(!conn) {
      failf(data, "connection not found");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }
  ws = conn->proto.ws;
  if(!ws) {
    failf(data, "connection is not setup for websocket");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  *nread = 0;
  *metap = NULL;
  /* get a download buffer */
  result = Curl_preconnect(data);
  if(result)
    return result;

  memset(&ctx, 0, sizeof(ctx));
  ctx.data = data;
  ctx.buffer = buffer;
  ctx.buflen = buflen;

  while(!done) {
    /* receive more when our buffer is empty */
    if(Curl_bufq_is_empty(&ws->recvbuf)) {
      ssize_t n = Curl_bufq_slurp(&ws->recvbuf, nw_in_recv, data, &result);
      if(n < 0) {
        return result;
      }
      else if(n == 0) {
        /* connection closed */
        infof(data, "connection expectedly closed?");
        return CURLE_GOT_NOTHING;
      }
    }

    infof(data, "WS: %zu bytes left to decode", Curl_bufq_len(&ws->recvbuf));
    result = ws_dec_pass(&ws->dec, data, &ws->recvbuf,
                         ws_client_collect, &ctx);
    if(result == CURLE_AGAIN) {
      if(!ctx.written)
        continue;  /* nothing written, try more input */
    }
    else if(result) {
      return result;
    }

    DEBUGASSERT(ctx.written);
    done = TRUE;
    break;
  }

  /* update frame information to be passed back */
  update_meta(ws, ctx.frame_age, ctx.frame_flags, ctx.payload_offset,
              ctx.payload_len, ctx.bufidx);
  *metap = &ws->frame;
  *nread = ws->frame.len;
  infof(data, "curl_ws_recv(len=%zu) -> %zu bytes (frame at %zd, %zd left)",
        buflen, *nread, ws->frame.offset, ws->frame.bytesleft);
  return CURLE_OK;
}

static CURLcode ws_flush(struct Curl_easy *data, struct websocket *ws,
                         bool complete)
{
  if(!Curl_bufq_is_empty(&ws->sendbuf)) {
    CURLcode result;
    const unsigned char *out;
    size_t outlen;
    ssize_t n;

    while(Curl_bufq_peek(&ws->sendbuf, &out, &outlen)) {
      if(data->set.connect_only)
        result = Curl_senddata(data, out, outlen, &n);
      else
        result = Curl_write(data, data->conn->writesockfd, out, outlen, &n);
      if(result) {
        if(!complete || (result != CURLE_AGAIN))
          return result;
        /* TODO: the current design does not allow for buffered writes.
         * We need to flush the buffer now. There is no ws_flush() later */
        n = 0;
      }
      else {
        Curl_bufq_skip(&ws->sendbuf, (size_t)n);
      }
    }
  }
  return CURLE_OK;
}

CURL_EXTERN CURLcode curl_ws_send(struct Curl_easy *data, const void *buffer,
                                  size_t buflen, size_t *sent,
                                  curl_off_t totalsize,
                                  unsigned int sendflags)
{
  struct websocket *ws;
  ssize_t nwritten, n;
  size_t space;
  CURLcode result;

  *sent = 0;
  if(!data->conn && data->set.connect_only) {
    result = Curl_connect_only_attach(data);
    if(result)
      return result;
  }
  if(!data->conn) {
    failf(data, "No associated connection");
    return CURLE_SEND_ERROR;
  }
  if(!data->conn->proto.ws) {
    failf(data, "Not a websocket transfer on connection #%ld",
          data->conn->connection_id);
    return CURLE_SEND_ERROR;
  }
  ws = data->conn->proto.ws;

  if(data->set.ws_raw_mode) {
    if(totalsize || sendflags)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(!buflen)
      /* nothing to do */
      return CURLE_OK;
    /* raw mode sends exactly what was requested, and this is from within
       the write callback */
    if(Curl_is_in_callback(data)) {
      result = Curl_write(data, data->conn->writesockfd, buffer, buflen,
                          &nwritten);
    }
    else
      result = Curl_senddata(data, buffer, buflen, &nwritten);

    infof(data, "WS: wanted to send %zu bytes, sent %zu bytes",
          buflen, nwritten);
    *sent = (nwritten >= 0)? (size_t)nwritten : 0;
    return result;
  }

  /* Not RAW mode, buf we do the frame encoding */
  result = ws_flush(data, ws, FALSE);
  if(result)
    return result;

  /* Limit what we are willing to buffer */
  space = Curl_bufq_space(&ws->sendbuf);
  if(space < 14)
    return CURLE_AGAIN;
  if(buflen > space)
    buflen = space;

  if(sendflags & CURLWS_OFFSET) {
    if(totalsize) {
      /* a frame series 'totalsize' bytes big, this is the first */
      n = ws_enc_write_head(data, &ws->enc, totalsize, sendflags,
                            &ws->sendbuf, &result);
      if(n < 0)
        return result;
    }
    else {
      if((curl_off_t)buflen > ws->enc.payload_remain) {
        infof(data, "WS: unaligned frame size (sending %zu instead of %zd)",
              buflen, ws->enc.payload_remain);
      }
    }
  }
  else if(!ws->enc.payload_remain) {
    n = ws_enc_write_head(data, &ws->enc, buflen, sendflags,
                          &ws->sendbuf, &result);
    if(n < 0)
      return result;
  }

  n = ws_enc_write_payload(&ws->enc, buffer, buflen, &ws->sendbuf, &result);
  if(n < 0)
    return result;

  *sent = (size_t)n;
  infof(data, "WS: wanted to send %zu bytes, buffered %zu bytes",
        buflen, *sent);
  return ws_flush(data, ws, TRUE);
}

static void ws_free(struct connectdata *conn)
{
  if(conn && conn->proto.ws) {
    Curl_bufq_free(&conn->proto.ws->recvbuf);
    Curl_bufq_free(&conn->proto.ws->sendbuf);
    Curl_safefree(conn->proto.ws);
  }
}

void Curl_ws_done(struct Curl_easy *data)
{
  (void)data;
}

CURLcode Curl_ws_disconnect(struct Curl_easy *data,
                            struct connectdata *conn,
                            bool dead_connection)
{
  (void)data;
  (void)dead_connection;
  ws_free(conn);
  return CURLE_OK;
}

CURL_EXTERN struct curl_ws_frame *curl_ws_meta(struct Curl_easy *data)
{
  /* we only return something for websocket, called from within the callback
     when not using raw mode */
  if(GOOD_EASY_HANDLE(data) && Curl_is_in_callback(data) && data->conn &&
     data->conn->proto.ws && !data->set.ws_raw_mode)
    return &data->conn->proto.ws->frame;
  return NULL;
}

#else

CURL_EXTERN CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen,
                                  size_t *nread,
                                  struct curl_ws_frame **metap)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)nread;
  (void)metap;
  return CURLE_NOT_BUILT_IN;
}

CURL_EXTERN CURLcode curl_ws_send(CURL *curl, const void *buffer,
                                  size_t buflen, size_t *sent,
                                  curl_off_t framesize,
                                  unsigned int sendflags)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)sent;
  (void)framesize;
  (void)sendflags;
  return CURLE_NOT_BUILT_IN;
}

CURL_EXTERN struct curl_ws_frame *curl_ws_meta(struct Curl_easy *data)
{
  (void)data;
  return NULL;
}
#endif /* USE_WEBSOCKETS */
