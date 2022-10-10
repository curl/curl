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
#include <curl/curl.h>

#ifdef USE_WEBSOCKETS

#include "urldata.h"
#include "dynbuf.h"
#include "rand.h"
#include "curl_base64.h"
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
  Curl_dyn_init(&data->req.p.http->ws.buf, MAX_WS_SIZE * 2);
  return result;
}

CURLcode Curl_ws_accept(struct Curl_easy *data)
{
  struct SingleRequest *k = &data->req;
  struct HTTP *ws = data->req.p.http;
  struct connectdata *conn = data->conn;
  struct websocket *wsp = &data->req.p.http->ws;
  CURLcode result;

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
  result = Curl_rand(data, (unsigned char *)&ws->ws.mask, sizeof(ws->ws.mask));
  if(result)
    return result;

  infof(data, "Received 101, switch to WebSocket; mask %02x%02x%02x%02x",
        ws->ws.mask[0], ws->ws.mask[1], ws->ws.mask[2], ws->ws.mask[3]);
  k->upgr101 = UPGR101_RECEIVED;

  if(data->set.connect_only)
    /* switch off non-blocking sockets */
    (void)curlx_nonblock(conn->sock[FIRSTSOCKET], FALSE);

  wsp->oleft = 0;
  return result;
}

#define WSBIT_FIN 0x80
#define WSBIT_OPCODE_CONT  0
#define WSBIT_OPCODE_TEXT  (1)
#define WSBIT_OPCODE_BIN   (2)
#define WSBIT_OPCODE_CLOSE (8)
#define WSBIT_OPCODE_PING  (9)
#define WSBIT_OPCODE_PONG  (0xa)
#define WSBIT_OPCODE_MASK  (0xf)

#define WSBIT_MASK 0x80

/* remove the spent bytes from the beginning of the buffer as that part has
   now been delivered to the application */
static void ws_decode_clear(struct Curl_easy *data)
{
  struct websocket *wsp = &data->req.p.http->ws;
  size_t spent = wsp->usedbuf;
  size_t len = Curl_dyn_len(&wsp->buf);
  size_t keep = len - spent;
  DEBUGASSERT(len >= spent);
  Curl_dyn_tail(&wsp->buf, keep);
}

/* ws_decode() decodes a binary frame into structured WebSocket data,

   wpkt - the incoming raw data. If NULL, work on the already buffered data.
   ilen - the size of the provided data, perhaps too little, perhaps too much
   out - stored pointed to extracted data
   olen - stored length of the extracted data
   oleft - number of unread bytes pending to that belongs to this frame
   more - if there is more data in there
   flags - stored bitmask about the frame

   Returns CURLE_AGAIN if there is only a partial frame in the buffer. Then it
   stores the first part in the ->extra buffer to be used in the next call
   when more data is provided.
*/

static CURLcode ws_decode(struct Curl_easy *data,
                          unsigned char *wpkt, size_t ilen,
                          unsigned char **out, size_t *olen,
                          curl_off_t *oleft,
                          bool *more,
                          unsigned int *flags)
{
  bool fin;
  unsigned char opcode;
  curl_off_t total;
  size_t dataindex = 2;
  curl_off_t plen; /* size of data in the buffer */
  curl_off_t payloadsize;
  struct websocket *wsp = &data->req.p.http->ws;
  unsigned char *p;
  CURLcode result;

  *olen = 0;

  /* add the incoming bytes, if any */
  if(wpkt) {
    result = Curl_dyn_addn(&wsp->buf, wpkt, ilen);
    if(result)
      return result;
  }

  plen = Curl_dyn_len(&wsp->buf);
  if(plen < 2) {
    /* the smallest possible frame is two bytes */
    infof(data, "WS: plen == %u, EAGAIN", (int)plen);
    return CURLE_AGAIN;
  }

  p = Curl_dyn_uptr(&wsp->buf);

  fin = p[0] & WSBIT_FIN;
  opcode = p[0] & WSBIT_OPCODE_MASK;
  infof(data, "WS:%d received FIN bit %u", __LINE__, (int)fin);
  *flags = 0;
  switch(opcode) {
  case WSBIT_OPCODE_CONT:
    if(!fin)
      *flags |= CURLWS_CONT;
    infof(data, "WS: received OPCODE CONT");
    break;
  case WSBIT_OPCODE_TEXT:
    infof(data, "WS: received OPCODE TEXT");
    *flags |= CURLWS_TEXT;
    break;
  case WSBIT_OPCODE_BIN:
    infof(data, "WS: received OPCODE BINARY");
    *flags |= CURLWS_BINARY;
    break;
  case WSBIT_OPCODE_CLOSE:
    infof(data, "WS: received OPCODE CLOSE");
    *flags |= CURLWS_CLOSE;
    break;
  case WSBIT_OPCODE_PING:
    infof(data, "WS: received OPCODE PING");
    *flags |= CURLWS_PING;
    break;
  case WSBIT_OPCODE_PONG:
    infof(data, "WS: received OPCODE PONG");
    *flags |= CURLWS_PONG;
    break;
  }

  if(p[1] & WSBIT_MASK) {
    /* A client MUST close a connection if it detects a masked frame. */
    failf(data, "WS: masked input frame");
    return CURLE_RECV_ERROR;
  }
  payloadsize = p[1];
  if(payloadsize == 126) {
    if(plen < 4) {
      infof(data, "WS:%d plen == %u, EAGAIN", __LINE__, (int)plen);
      return CURLE_AGAIN; /* not enough data available */
    }
    payloadsize = (p[2] << 8) | p[3];
    dataindex += 2;
  }
  else if(payloadsize == 127) {
    /* 64 bit payload size */
    if(plen < 10)
      return CURLE_AGAIN;
    if(p[2] & 80) {
      failf(data, "WS: too large frame");
      return CURLE_RECV_ERROR;
    }
    dataindex += 8;
    payloadsize = ((curl_off_t)p[2] << 56) |
      (curl_off_t)p[3] << 48 |
      (curl_off_t)p[4] << 40 |
      (curl_off_t)p[5] << 32 |
      (curl_off_t)p[6] << 24 |
      (curl_off_t)p[7] << 16 |
      (curl_off_t)p[8] << 8 |
      p[9];
  }

  total = dataindex + payloadsize;
  if(total > plen) {
    /* deliver a partial frame */
    *oleft = total - dataindex;
    payloadsize = total - dataindex;
  }
  else {
    *oleft = 0;
    if(plen > total)
      /* there is another fragment after */
      *more = TRUE;
  }

  /* point to the payload */
  *out = &p[dataindex];

  /* return the payload length */
  *olen = payloadsize;

  /* number of bytes "used" from the buffer */
  wsp->usedbuf = dataindex + payloadsize;
  infof(data, "WS: received %zu bytes payload (%zu left)",
        payloadsize, *oleft);
  return CURLE_OK;
}

/* Curl_ws_writecb() is the write callback for websocket traffic. The
   websocket data is provided to this raw, in chunks. This function should
   handle/decode the data and call the "real" underlying callback accordingly.
*/
size_t Curl_ws_writecb(char *buffer, size_t size /* 1 */,
                       size_t nitems, void *userp)
{
  struct HTTP *ws = (struct HTTP *)userp;
  struct Curl_easy *data = ws->ws.data;
  void *writebody_ptr = data->set.out;
  if(data->set.ws_raw_mode)
    return data->set.fwrite_func(buffer, size, nitems, writebody_ptr);
  else if(nitems) {
    unsigned char *frame = NULL;
    size_t flen = 0;
    size_t wrote = 0;
    CURLcode result;
    bool more; /* there's is more to parse in the buffer */
    curl_off_t oleft;

    decode:
    more = FALSE;
    oleft = ws->ws.frame.bytesleft;
    if(!oleft) {
      unsigned int recvflags;
      result = ws_decode(data, (unsigned char *)buffer, nitems,
                         &frame, &flen, &oleft, &more, &recvflags);
      if(result == CURLE_AGAIN)
        /* insufficient amount of data, keep it for later */
        return nitems;
      else if(result) {
        infof(data, "WS: decode error %d", (int)result);
        return nitems - 1;
      }
      /* Store details about the frame to be reachable with curl_ws_meta()
         from within the write callback */
      ws->ws.frame.age = 0;
      ws->ws.frame.offset = 0;
      ws->ws.frame.flags = recvflags;
      ws->ws.frame.bytesleft = oleft;
    }
    else {
      if(nitems > (size_t)ws->ws.frame.bytesleft) {
        nitems = ws->ws.frame.bytesleft;
        more = TRUE;
      }
      else
        more = FALSE;
      ws->ws.frame.offset += nitems;
      ws->ws.frame.bytesleft -= nitems;
      frame = (unsigned char *)buffer;
      flen = nitems;
    }
    if((ws->ws.frame.flags & CURLWS_PING) && !oleft) {
      /* auto-respond to PINGs, only works for single-frame payloads atm */
      size_t bytes;
      infof(data, "WS: auto-respond to PING with a PONG");
      DEBUGASSERT(frame);
      /* send back the exact same content as a PONG */
      result = curl_ws_send(data, frame, flen, &bytes, 0, CURLWS_PONG);
      if(result)
        return result;
    }
    else {
      /* deliver the decoded frame to the user callback */
      Curl_set_in_callback(data, true);
      wrote = data->set.fwrite_func((char *)frame, 1, flen, writebody_ptr);
      Curl_set_in_callback(data, false);
      if(wrote != flen)
        return 0;
    }
    if(oleft)
      ws->ws.frame.offset += flen;
    /* the websocket frame has been delivered */
    ws_decode_clear(data);
    if(more) {
      /* there's more websocket data to deal with in the buffer */
      buffer = NULL; /* the buffer as been drained already */
      goto decode;
    }
  }
  return nitems;
}


CURL_EXTERN CURLcode curl_ws_recv(struct Curl_easy *data, void *buffer,
                                  size_t buflen, size_t *nread,
                                  struct curl_ws_frame **metap)
{
  size_t bytes;
  CURLcode result;
  struct websocket *wsp = &data->req.p.http->ws;

  *nread = 0;
  *metap = NULL;
  /* get a download buffer */
  result = Curl_preconnect(data);
  if(result)
    return result;

  do {
    bool drain = FALSE; /* if there is pending buffered data to drain */
    char *inbuf = data->state.buffer;
    bytes = wsp->stillbuffer;
    if(!bytes) {
      result = curl_easy_recv(data, data->state.buffer,
                              data->set.buffer_size, &bytes);
      if(result)
        return result;
    }
    else {
      /* the pending bytes can be found here */
      inbuf = wsp->stillb;
      drain = TRUE;
    }
    if(bytes) {
      unsigned char *out;
      size_t olen;
      bool more;
      unsigned int recvflags;
      curl_off_t oleft = wsp->frame.bytesleft;

      infof(data, "WS: got %u websocket bytes to decode", (int)bytes);
      if(!oleft && !drain) {
        result = ws_decode(data, (unsigned char *)inbuf, bytes,
                           &out, &olen, &oleft, &more, &recvflags);
        if(result == CURLE_AGAIN)
          /* a packet fragment only */
          break;
        else if(result)
          return result;
        wsp->frame.offset = 0;
        wsp->frame.bytesleft = oleft;
        wsp->frame.flags = recvflags;
      }
      else {
        olen = oleft;
        out = (unsigned char *)wsp->stillb;
        recvflags = wsp->frame.flags;
        if((curl_off_t)buflen < oleft)
          /* there is still data left after this */
          wsp->frame.bytesleft -= buflen;
        else
          wsp->frame.bytesleft = 0;
      }

      /* auto-respond to PINGs */
      if((recvflags & CURLWS_PING) && !oleft) {
        infof(data, "WS: auto-respond to PING with a PONG");
        /* send back the exact same content as a PONG */
        result = curl_ws_send(data, out, olen, &bytes, 0, CURLWS_PONG);
        if(result)
          return result;
      }
      else {
        if(olen < buflen) {
          /* copy the payload to the user buffer */
          memcpy(buffer, out, olen);
          *nread = olen;
          if(!oleft)
            /*  websocket frame has been delivered */
            ws_decode_clear(data);
        }
        else {
          /* copy a partial payload */
          memcpy(buffer, out, buflen);
          *nread = buflen;
          /* remember what is left and where */
          wsp->stillbuffer = olen - buflen;
          wsp->stillb = (char *)buffer + buflen;
        }
        wsp->frame.offset += *nread;
      }
    }
    else
      *nread = bytes;
    break;
  } while(1);
  *metap = &wsp->frame;
  return CURLE_OK;
}

static void ws_xor(struct Curl_easy *data,
                   const unsigned char *source,
                   unsigned char *dest,
                   size_t len)
{
  struct websocket *wsp = &data->req.p.http->ws;
  size_t i;
  /* append payload after the mask, XOR appropriately */
  for(i = 0; i < len; i++) {
    dest[i] = source[i] ^ wsp->mask[wsp->xori];
    wsp->xori++;
    wsp->xori &= 3;
  }
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

static size_t ws_packethead(struct Curl_easy *data,
                            size_t len, unsigned int flags)
{
  struct HTTP *ws = data->req.p.http;
  unsigned char *out = (unsigned char *)data->state.ulbuf;
  unsigned char firstbyte = 0;
  int outi;
  unsigned char opcode;
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
    /* if not marked as continuing, assume this is the final fragment */
    firstbyte |= WSBIT_FIN | opcode;
    ws->ws.contfragment = FALSE;
  }
  else if(ws->ws.contfragment) {
    /* the previous fragment was not a final one and this isn't either, keep a
       CONT opcode and no FIN bit */
    firstbyte |= WSBIT_OPCODE_CONT;
  }
  else {
    ws->ws.contfragment = TRUE;
  }
  out[0] = firstbyte;
  if(len > 65535) {
    out[1] = 127 | WSBIT_MASK;
    out[2] = (len >> 8) & 0xff;
    out[3] = len & 0xff;
    outi = 10;
  }
  else if(len > 126) {
    out[1] = 126 | WSBIT_MASK;
    out[2] = (len >> 8) & 0xff;
    out[3] = len & 0xff;
    outi = 4;
  }
  else {
    out[1] = (unsigned char)len | WSBIT_MASK;
    outi = 2;
  }

  infof(data, "WS: send FIN bit %u (byte %02x)",
        firstbyte & WSBIT_FIN ? 1 : 0,
        firstbyte);
  infof(data, "WS: send payload len %u", (int)len);

  /* 4 bytes mask */
  memcpy(&out[outi], &ws->ws.mask, 4);

  if(data->set.upload_buffer_size < (len + 10))
    return 0;

  /* pass over the mask */
  outi += 4;

  ws->ws.xori = 0;
  /* return packet size */
  return outi;
}

CURL_EXTERN CURLcode curl_ws_send(struct Curl_easy *data, const void *buffer,
                                  size_t buflen, size_t *sent,
                                  curl_off_t totalsize,
                                  unsigned int sendflags)
{
  CURLcode result;
  size_t headlen;
  char *out;
  ssize_t written;
  struct websocket *wsp = &data->req.p.http->ws;

  if(!data->set.ws_raw_mode) {
    result = Curl_get_upload_buffer(data);
    if(result)
      return result;
  }
  else {
    if(totalsize || sendflags)
      return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(data->set.ws_raw_mode) {
    if(!buflen)
      /* nothing to do */
      return CURLE_OK;
    /* raw mode sends exactly what was requested, and this is from within
       the write callback */
    if(Curl_is_in_callback(data))
      result = Curl_write(data, data->conn->writesockfd, buffer, buflen,
                          &written);
    else
      result = Curl_senddata(data, buffer, buflen, &written);

    infof(data, "WS: wanted to send %zu bytes, sent %zu bytes",
          buflen, written);
    *sent = written;
    return result;
  }

  if(buflen > (data->set.upload_buffer_size - 10))
    /* don't do more than this in one go */
    buflen = data->set.upload_buffer_size - 10;

  if(sendflags & CURLWS_OFFSET) {
    if(totalsize) {
      /* a frame series 'totalsize' bytes big, this is the first */
      headlen = ws_packethead(data, totalsize, sendflags);
      wsp->sleft = totalsize - buflen;
    }
    else {
      headlen = 0;
      if((curl_off_t)buflen > wsp->sleft) {
        infof(data, "WS: unaligned frame size (sending %zu instead of %zu)",
              buflen, wsp->sleft);
        wsp->sleft = 0;
      }
      else
        wsp->sleft -= buflen;
    }
  }
  else
    headlen = ws_packethead(data, buflen, sendflags);

  /* headlen is the size of the frame header */
  out = data->state.ulbuf;
  if(buflen)
    /* for PING and PONG etc there might not be a payload */
    ws_xor(data, buffer, (unsigned char *)out + headlen, buflen);

  if(data->set.connect_only)
    result = Curl_senddata(data, out, buflen + headlen, &written);
  else
    result = Curl_write(data, data->conn->writesockfd, out,
                        buflen + headlen, &written);

  infof(data, "WS: wanted to send %zu bytes, sent %zu bytes",
        headlen + buflen, written);
  *sent = written;

  return result;
}

void Curl_ws_done(struct Curl_easy *data)
{
  struct websocket *wsp = &data->req.p.http->ws;
  DEBUGASSERT(wsp);
  Curl_dyn_free(&wsp->buf);
}

CURL_EXTERN struct curl_ws_frame *curl_ws_meta(struct Curl_easy *data)
{
  /* we only return something for websocket, called from within the callback
     when not using raw mode */
  if(GOOD_EASY_HANDLE(data) && Curl_is_in_callback(data) && data->req.p.http &&
     !data->set.ws_raw_mode)
    return &data->req.p.http->ws.frame;
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
  return CURLE_OK;
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
  return CURLE_OK;
}

CURL_EXTERN struct curl_ws_frame *curl_ws_meta(struct Curl_easy *data)
{
  (void)data;
  return NULL;
}
#endif /* USE_WEBSOCKETS */
