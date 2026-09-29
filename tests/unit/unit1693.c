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
#include "unitcheck.h"
#include "urldata.h"
#include "mqtt.h"
#include "select.h"
#include "url.h"

#ifndef CURL_DISABLE_MQTT

enum {
  T1693_CONNECT_LEN = 26,
  T1693_PUBLISH_LEN = 15,
  T1693_DISCONNECT_LEN = 2,
  T1693_PUBLISH_END = T1693_CONNECT_LEN + T1693_PUBLISH_LEN,
  T1693_WIRE_LEN = T1693_PUBLISH_END + T1693_DISCONNECT_LEN
};

struct t1693_send {
  size_t n;
  CURLcode result;
};

struct t1693_ctx {
  const struct t1693_send *sends;
  size_t nsends;
  size_t send_index;
  size_t recv_index;
  size_t written;
  size_t pending;
  unsigned char expected[T1693_WIRE_LEN];
  unsigned char output[T1693_WIRE_LEN];
};

static CURLcode t1693_send(struct Curl_easy *data, int8_t sockindex,
                          const uint8_t *buf, size_t len, bool eos,
                          size_t *pnwritten)
{
  struct t1693_ctx *ctx = data->set.private_data;
  const struct t1693_send *send;
  size_t remaining;
  (void)sockindex;
  (void)eos;
  *pnwritten = 0;

  abort_unless(ctx->send_index < ctx->nsends, "unexpected send");
  send = &ctx->sends[ctx->send_index++];
  if(ctx->send_index == 1) {
    /* The CONNECT client ID is random. Save the packet for retry checks. */
    abort_unless(len == T1693_CONNECT_LEN, "unexpected CONNECT size");
    memcpy(ctx->expected, buf, len);
    fail_unless(buf[0] == 0x10 && buf[1] == 0x18,
                "unexpected CONNECT header");
  }

  if(ctx->written < T1693_CONNECT_LEN)
    remaining = T1693_CONNECT_LEN - ctx->written;
  else if(ctx->written < T1693_PUBLISH_END)
    remaining = T1693_PUBLISH_END - ctx->written;
  else
    remaining = sizeof(ctx->expected) - ctx->written;
  abort_unless(len == remaining, "packet sent before previous packet drained");
  fail_unless(!memcmp(buf, ctx->expected + ctx->written, len),
              "queued packet bytes changed");
  ctx->pending = len;
  if(send->result)
    return send->result;

  abort_unless(send->n <= len, "send script exceeds packet size");
  memcpy(ctx->output + ctx->written, buf, send->n);
  ctx->written += send->n;
  ctx->pending -= send->n;
  *pnwritten = send->n;
  return CURLE_OK;

unit_test_abort:
  return CURLE_SEND_ERROR;
}

static CURLcode t1693_recv(struct Curl_easy *data, int8_t sockindex,
                          char *buf, size_t len, size_t *pnread)
{
  static const unsigned char connack[] = { 0x20, 0x02, 0x00, 0x00 };
  struct t1693_ctx *ctx = data->set.private_data;
  size_t n = sizeof(connack) - ctx->recv_index;
  (void)sockindex;
  *pnread = 0;
  abort_unless(ctx->written == T1693_CONNECT_LEN,
               "read while an outgoing packet is queued");
  abort_unless(n, "unexpected read after CONNACK");
  if(n > len)
    n = len;
  memcpy(buf, connack + ctx->recv_index, n);
  ctx->recv_index += n;
  *pnread = n;
  return CURLE_OK;

unit_test_abort:
  return CURLE_RECV_ERROR;
}

static void t1693_meta_dtor(void *p)
{
  /* MQTT metadata supplies its own destructor. */
  (void)p;
}

static void t1693_run(const struct t1693_send *sends, size_t nsends,
                     CURLcode expected_result)
{
  static const unsigned char post[] = {
    0x30, 0x0d, 0x00, 0x04, 't', 'e', 's', 't',
    'p', 'a', 'y', 'l', 'o', 'a', 'd', 0xe0, 0x00
  };
  struct t1693_ctx ctx;
  struct Curl_easy *data = NULL;
  struct connectdata *conn = NULL;
  struct easy_pollset ps;
  CURLcode result;
  bool done = FALSE;
  size_t i;

  Curl_pollset_init(&ps);
  memset(&ctx, 0, sizeof(ctx));
  ctx.sends = sends;
  ctx.nsends = nsends;
  memcpy(ctx.expected + T1693_CONNECT_LEN, post, sizeof(post));

  data = curl_easy_init();
  abort_unless(data, "easy handle allocation failed");
  conn = curlx_calloc(1, sizeof(*conn));
  abort_unless(conn, "connection allocation failed");
  Curl_hash_init(&conn->meta_hash, 23, CURL_HASH_TYPE_BYTES, t1693_meta_dtor);
  data->conn = conn;
  conn->sock[FIRSTSOCKET] = 42;
  conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;
  conn->send[FIRSTSOCKET] = t1693_send;
  conn->recv[FIRSTSOCKET] = t1693_recv;
  data->set.private_data = &ctx;
  data->set.postfields = CURL_UNCONST("payload");
  data->state.httpreq = HTTPREQ_POST;
  data->state.up.path = curlx_strdup("/test");
  abort_unless(data->state.up.path, "path allocation failed");
  result = Curl_protocol_mqtt.setup_connection(data, conn);
  abort_unless(!result, "MQTT setup failed");

  result = Curl_protocol_mqtt.do_it(data, &done);
  for(i = 0; !result && !done && i < nsends + 4; ++i) {
    Curl_pollset_reset(&ps);
    result = Curl_protocol_mqtt.doing_pollset(data, &ps);
    abort_unless(!result, "MQTT pollset failed");
    abort_unless(ps.n == 1 && ps.sockets[0] == 42,
                 "unexpected pollset socket");
    fail_unless(ps.actions[0] == (ctx.pending ? CURL_POLL_OUT : CURL_POLL_IN),
                "polling the wrong direction for queued output");
    result = Curl_protocol_mqtt.doing(data, &done);
    fail_unless(!done || ctx.written == sizeof(ctx.output),
                "transfer completed with unsent packet bytes");
  }
  fail_unless(result == expected_result, "unexpected transfer result");
  fail_unless(ctx.send_index == nsends, "not all scripted sends were used");
  fail_unless(!memcmp(ctx.output, ctx.expected, ctx.written),
              "packets were not sent in order");
  if(!expected_result) {
    fail_unless(done, "transfer did not complete");
    fail_unless(ctx.written == sizeof(ctx.output), "missing packet bytes");
  }
  else
    fail_unless(!done, "send failure marked the transfer complete");

unit_test_abort:
  Curl_pollset_cleanup(&ps);
  if(conn)
    Curl_conn_free(data, conn);
  if(data) {
    data->conn = NULL;
    curl_easy_cleanup(data);
  }
}

#endif /* CURL_DISABLE_MQTT */

static CURLcode test_unit1693(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifndef CURL_DISABLE_MQTT
  static const struct t1693_send full[] = {
    { T1693_CONNECT_LEN, CURLE_OK }, { T1693_PUBLISH_LEN, CURLE_OK },
    { T1693_DISCONNECT_LEN, CURLE_OK }
  };
  static const struct t1693_send partial[] = {
    { 3, CURLE_OK }, { 0, CURLE_AGAIN }, { 4, CURLE_OK }, { 19, CURLE_OK },
    { 3, CURLE_OK }, { 4, CURLE_OK }, { 0, CURLE_AGAIN }, { 8, CURLE_OK },
    { 0, CURLE_AGAIN }, { 1, CURLE_OK }, { 0, CURLE_AGAIN }, { 1, CURLE_OK }
  };
  static const struct t1693_send zero[] = {
    { 0, CURLE_OK }, { T1693_CONNECT_LEN, CURLE_OK },
    { 0, CURLE_OK }, { T1693_PUBLISH_LEN, CURLE_OK },
    { 0, CURLE_OK }, { T1693_DISCONNECT_LEN, CURLE_OK }
  };
  static const struct t1693_send send_error[] = {
    { T1693_CONNECT_LEN, CURLE_OK }, { 4, CURLE_OK }, { 0, CURLE_SEND_ERROR }
  };

  abort_unless(!curl_global_init(CURL_GLOBAL_ALL), "global init failed");
  t1693_run(full, CURL_ARRAYSIZE(full), CURLE_OK);
  t1693_run(partial, CURL_ARRAYSIZE(partial), CURLE_OK);
  t1693_run(zero, CURL_ARRAYSIZE(zero), CURLE_OK);
  t1693_run(send_error, CURL_ARRAYSIZE(send_error), CURLE_SEND_ERROR);
  curl_global_cleanup();
#endif

  UNITTEST_END_SIMPLE
}
