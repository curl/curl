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

#ifndef CURL_DISABLE_MQTT
#include "urldata.h"
#include "mqtt.h"
#include "hash.h"

struct t4998_chunk {
  const unsigned char *data;
  size_t len;
};

struct t4998_io {
  const struct t4998_chunk *chunks;
  size_t nchunks;
  size_t chunk_idx;
  size_t chunk_off;
  bool blocked;
  unsigned char out[64];
  size_t out_len;
};

static struct t4998_io t4998;

static CURLcode t4998_send(struct Curl_easy *data,
                           const uint8_t *buffer, size_t length, bool eos,
                           size_t *written)
{
  (void)data;
  (void)buffer;
  (void)eos;
  *written = length;
  return CURLE_OK;
}

static CURLcode t4998_recv(struct Curl_easy *data,
                           char *buffer, size_t length, size_t *received)
{
  const struct t4998_chunk *cur;
  size_t avail;

  (void)data;
  *received = 0;

  if(t4998.chunk_idx >= t4998.nchunks)
    return CURLE_AGAIN;

  if(t4998.blocked) {
    t4998.blocked = FALSE;
    return CURLE_AGAIN;
  }

  cur = &t4998.chunks[t4998.chunk_idx];
  avail = cur->len - t4998.chunk_off;
  if(length > avail)
    length = avail;
  memcpy(buffer, cur->data + t4998.chunk_off, length);
  t4998.chunk_off += length;
  *received = length;

  if(t4998.chunk_off == cur->len) {
    t4998.chunk_idx++;
    t4998.chunk_off = 0;
    t4998.blocked = TRUE;
  }
  return CURLE_OK;
}

static void t4998_hash_dtor(void *p)
{
  (void)p;
  fail("unexpected MQTT connection metadata destructor");
}

static size_t t4998_write_cb(char *ptr, size_t size, size_t nmemb,
                             void *userdata)
{
  struct t4998_io *io = userdata;
  size_t total = size * nmemb;
  if(io->out_len + total <= sizeof(io->out)) {
    memcpy(io->out + io->out_len, ptr, total);
    io->out_len += total;
  }
  return total;
}

static CURLcode t4998_setup(CURL **easy)
{
  CURLcode result = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return result;
}

static void t4998_stop(CURL *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}
#endif

static CURLcode test_unit4998(const char *arg)
{
#ifndef CURL_DISABLE_MQTT
  static const unsigned char connack[] = { 0x20, 0x02, 0x00, 0x00 };
  static const unsigned char suback_part1[] = { 0x90, 0x03, 0x00 };
  static const unsigned char suback_part2[] = { 0x01, 0x00 };
  static const unsigned char publish[] = {
    0x30, 0x0c,
    0x00, 0x05, 't', 'o', 'p', 'i', 'c',
    'h', 'e', 'l', 'l', 'o'
  };
  static const unsigned char disconnect[] = { 0xe0, 0x00 };
  static const struct t4998_chunk chunks[] = {
    { connack, sizeof(connack) },
    { suback_part1, sizeof(suback_part1) },
    { suback_part2, sizeof(suback_part2) },
    { publish, sizeof(publish) },
    { disconnect, sizeof(disconnect) }
  };
  static const unsigned char expected_body[] = {
    0x00, 0x05, 't', 'o', 'p', 'i', 'c',
    'h', 'e', 'l', 'l', 'o'
  };
  static char topic_path[] = "/topic";
  CURL *easy = NULL;
  struct Curl_easy *data;
  struct connectdata conn;
  CURLcode result;
  bool done = FALSE;
  unsigned int steps;

  UNITTEST_BEGIN(t4998_setup(&easy))

  data = easy;
  memset(&conn, 0, sizeof(conn));
  memset(&t4998, 0, sizeof(t4998));
  t4998.chunks = chunks;
  t4998.nchunks = CURL_ARRAYSIZE(chunks);

  Curl_hash_init(&conn.meta_hash, 23, CURL_HASH_TYPE_BYTES, t4998_hash_dtor);
  conn.do_send = t4998_send;
  conn.do_recv = t4998_recv;

  data->conn = &conn;
  data->state.up.path = topic_path;
  data->req.maxdownload = -1;
  result = curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, t4998_write_cb);
  if(!result)
    result = curl_easy_setopt(easy, CURLOPT_WRITEDATA, &t4998);

  if(!result)
    result = Curl_protocol_mqtt.setup_connection(data, &conn);
  if(!result)
    result = Curl_protocol_mqtt.do_it(data, &done);

  for(steps = 0; !result && !done && steps < 64; steps++) {
    result = Curl_protocol_mqtt.doing(data, &done);
  }

  fail_unless(!result, "MQTT transfer should succeed");
  if(!result) {
    fail_unless(done, "MQTT transfer should complete after DISCONNECT");
    fail_unless(t4998.chunk_idx == t4998.nchunks,
                "all MQTT response chunks should be consumed");
    fail_unless(t4998.out_len == sizeof(expected_body),
                "PUBLISH payload length should match");
    if(t4998.out_len == sizeof(expected_body))
      verify_memory(t4998.out, expected_body, (int)sizeof(expected_body));
  }

  Curl_protocol_mqtt.done(data, result, FALSE);
  Curl_hash_destroy(&conn.meta_hash);
  data->conn = NULL;
  data->state.up.path = NULL;

  UNITTEST_END(t4998_stop(easy))
#else
  (void)arg;
  return CURLE_OK;
#endif
}
