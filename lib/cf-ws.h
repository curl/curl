#ifndef HEADER_CURL_CF_WS_H
#define HEADER_CURL_CF_WS_H
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
#include "bufq.h"

#ifndef CURL_DISABLE_WEBSOCKETS

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
  uint8_t head[10];
  int head_len, head_total;
  enum ws_dec_state state;
  int cont_flags;
  BIT(seen_close);      /* decoded a CLOSE frame */
};

/* a client-side WS frame encoder, generating frame headers and
 * converting payloads, tracking remaining data in current frame */
struct ws_encoder {
  curl_off_t payload_len;  /* payload length of current frame */
  curl_off_t payload_remain;  /* remaining payload of current */
  unsigned int xori; /* xor index */
  unsigned int maskpool_left; /* bytes not yet used at the end of maskpool */
  uint8_t mask[4]; /* 32-bit mask for this connection */
  uint8_t firstbyte; /* first byte of frame we encode */
  BIT(contfragment); /* set TRUE if the previous fragment sent was not final */
  uint8_t maskpool[256]; /* random bytes for the masks of coming frames */
};

/* Control frames are allowed up to 125 characters, rfc6455, ch. 5.5 */
#define WS_MAX_CNTRL_LEN    125

struct ws_cntrl_frame {
  unsigned int type;
  size_t payload_len;
  uint8_t payload[WS_MAX_CNTRL_LEN];
};

struct cf_ws_ctx {
  struct Curl_easy *data; /* used for write callback handling */
  struct ws_decoder dec;  /* decode of ws frames */
  struct ws_encoder enc;  /* encode of ws frames */
  struct bufq recvbuf;    /* raw data from the server */
  struct bufq sendbuf;    /* raw data to be sent to the server */
  struct curl_ws_frame recvframe;  /* the current WS FRAME received */
  struct ws_cntrl_frame pending; /* a control frame pending to be sent */
  size_t sendbuf_payload;
  BIT(send_eos_seen);
  BIT(sent_eos);
  BIT(added_close_frame);
  BIT(recvframe_0_len);  /* recvframe is really 0-length */
};


struct Curl_cfilter *Curl_cf_ws_get(struct Curl_easy *data);
struct cf_ws_ctx *Curl_cf_ws_get_ctx(struct Curl_easy *data);
struct cf_ws_ctx *Curl_cf_ws_conn_get_ctx(struct connectdata *conn);

bool Curl_cf_ws_in_send_frame(struct Curl_cfilter *cf,
                              struct Curl_easy *data);

CURLcode Curl_cf_ws_start_frame(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                unsigned int flags,
                                curl_off_t frame_len);

CURLcode Curl_cf_ws_add(struct Curl_easy *data,
                        const char *buf, size_t blen);

extern struct Curl_cftype Curl_cft_ws;

#endif /* !CURL_DISABLE_WEBSOCKETS */

#endif /* HEADER_CURL_CF_WS_H */
