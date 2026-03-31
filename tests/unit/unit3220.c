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

#include "bufq.h"
#include "capsule.h"

#if defined(USE_PROXY_HTTP3) && defined(USE_NGTCP2) && \
  !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)
static void queue_bytes(struct bufq *q, const unsigned char *src, size_t len)
{
  size_t nwritten = 0;
  CURLcode result = Curl_bufq_write(q, src, len, &nwritten);
  fail_unless(result == CURLE_OK, "queue failed");
  fail_unless(nwritten == len, "queue short write");
}
#endif

#if defined(USE_PROXY_HTTP3) && \
  !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)
static void check_capsule_hdr(size_t payload_len,
                              const unsigned char *expected,
                              size_t expected_len)
{
  unsigned char hdr[HTTP_CAPSULE_HEADER_MAX_SIZE];
  size_t hdr_len;

  memset(hdr, 0xA5, sizeof(hdr));
  hdr_len = Curl_capsule_encap_udp_hdr(hdr, sizeof(hdr), payload_len);
  fail_unless(hdr_len == expected_len, "capsule header length mismatch");
  fail_unless(!memcmp(hdr, expected, expected_len),
              "capsule header bytes mismatch");
}

static void test_capsule_encap_udp_hdr_boundaries(void)
{
  const unsigned char p0[] = { 0x00, 0x01, 0x00 };
  const unsigned char p62[] = { 0x00, 0x3F, 0x00 };
  const unsigned char p63[] = { 0x00, 0x40, 0x40, 0x00 };
  const unsigned char p64[] = { 0x00, 0x40, 0x41, 0x00 };
  const unsigned char p16382[] = { 0x00, 0x7F, 0xFF, 0x00 };
  const unsigned char p16383[] = { 0x00, 0x80, 0x00, 0x40, 0x00, 0x00 };
  const unsigned char p16384[] = { 0x00, 0x80, 0x00, 0x40, 0x01, 0x00 };

  check_capsule_hdr(0, p0, sizeof(p0));
  check_capsule_hdr(62, p62, sizeof(p62));
  check_capsule_hdr(63, p63, sizeof(p63));
  check_capsule_hdr(64, p64, sizeof(p64));
  check_capsule_hdr(16382, p16382, sizeof(p16382));
  check_capsule_hdr(16383, p16383, sizeof(p16383));
  check_capsule_hdr(16384, p16384, sizeof(p16384));
}

static void check_payload_written_accounting(size_t payload_len)
{
  unsigned char hdr[HTTP_CAPSULE_HEADER_MAX_SIZE];
  size_t hdr_len, capsule_bytes, expected;

  hdr_len = Curl_capsule_encap_udp_hdr(hdr, sizeof(hdr), payload_len);
  fail_unless(hdr_len, "failed to encode capsule header");

  for(capsule_bytes = 0; capsule_bytes <= (hdr_len + payload_len + 2);
      ++capsule_bytes) {
    expected = 0;
    if(capsule_bytes > hdr_len) {
      expected = capsule_bytes - hdr_len;
      if(expected > payload_len)
        expected = payload_len;
    }
    fail_unless(Curl_capsule_udp_payload_written(payload_len, capsule_bytes) ==
                expected, "capsule payload accounting mismatch");
  }
}

static void test_capsule_udp_payload_written(void)
{
  check_payload_written_accounting(0);
  check_payload_written_accounting(3);
  check_payload_written_accounting(63);
  check_payload_written_accounting(64);
  check_payload_written_accounting(16383);
  check_payload_written_accounting(16384);
}
#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */

#if defined(USE_PROXY_HTTP3) && defined(USE_NGTCP2) && \
  !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)
static void check_capsule_result(struct bufq *q,
                                 const unsigned char *capsule, size_t capslen,
                                 size_t outlen, CURLcode expect_err,
                                 size_t expect_nread)
{
  unsigned char out[32];
  CURLcode err = CURLE_OK;
  size_t nread;

  memset(out, 0, sizeof(out));
  Curl_bufq_reset(q);
  if(capsule && capslen)
    queue_bytes(q, capsule, capslen);

  nread = Curl_capsule_process_udp_raw(NULL, NULL, q, out, outlen, &err);
  fail_unless(err == expect_err, "unexpected capsule error");
  fail_unless(nread == expect_nread, "unexpected capsule read size");
}

static void test_capsule_encode_decode_roundtrip(void)
{
  struct dynbuf dyn;
  struct bufq q;
  unsigned char payload[128];
  unsigned char out[128];
  CURLcode result, err;
  size_t payload_len;
  size_t i, nread;

  for(i = 0; i < sizeof(payload); ++i)
    payload[i] = (unsigned char)i;

  for(i = 0; i < 2; ++i) {
    payload_len = i ? 64 : 7;
    memset(out, 0, sizeof(out));

    result = Curl_capsule_encap_udp_datagram(&dyn, payload, payload_len);
    fail_unless(result == CURLE_OK, "failed to encapsulate UDP datagram");

    Curl_bufq_init2(&q, 32, 8, BUFQ_OPT_NONE);
    queue_bytes(&q, (const unsigned char *)curlx_dyn_ptr(&dyn),
                curlx_dyn_len(&dyn));

    err = CURLE_OK;
    nread = Curl_capsule_process_udp_raw(NULL, NULL, &q, out, sizeof(out),
                                         &err);
    fail_unless(err == CURLE_OK, "failed to decode UDP datagram");
    fail_unless(nread == payload_len, "decoded payload length mismatch");
    fail_unless(!memcmp(out, payload, payload_len),
                "decoded payload bytes mismatch");
    fail_unless(Curl_bufq_is_empty(&q), "decoded capsule must be consumed");

    Curl_bufq_free(&q);
    curlx_dyn_free(&dyn);
  }
}

static void test_capsule_decode_paths(void)
{
  struct bufq q;
  unsigned char out[8];
  CURLcode err = CURLE_OK;
  size_t nread;
  const unsigned char invalid_type[] = { 0x01 };
  const unsigned char partial_len[] = { 0x00, 0x40 };
  const unsigned char invalid_context[] = { 0x00, 0x01, 0x01 };
  const unsigned char invalid_caps_len[] = { 0x00, 0x00, 0x00 };
  const unsigned char partial_payload[] = { 0x00, 0x04, 0x00, 0x11, 0x22 };
  const unsigned char payload_3b[] = { 0x00, 0x04, 0x00, 0x11, 0x22, 0x33 };
  const unsigned char payload_empty[] = { 0x00, 0x01, 0x00 };

  Curl_bufq_init2(&q, 32, 4, BUFQ_OPT_NONE);

  check_capsule_result(&q, NULL, 0, 0, CURLE_BAD_FUNCTION_ARGUMENT, 0);
  check_capsule_result(&q, NULL, 0, sizeof(out), CURLE_AGAIN, 0);
  check_capsule_result(&q, invalid_type, sizeof(invalid_type), sizeof(out),
                       CURLE_RECV_ERROR, 0);
  check_capsule_result(&q, partial_len, sizeof(partial_len), sizeof(out),
                       CURLE_AGAIN, 0);
  check_capsule_result(&q, invalid_context, sizeof(invalid_context),
                       sizeof(out), CURLE_RECV_ERROR, 0);
  check_capsule_result(&q, invalid_caps_len, sizeof(invalid_caps_len),
                       sizeof(out), CURLE_RECV_ERROR, 0);
  check_capsule_result(&q, partial_payload, sizeof(partial_payload),
                       sizeof(out), CURLE_AGAIN, 0);

  /* payload does not fit output buffer -> AGAIN and no consumption */
  Curl_bufq_reset(&q);
  queue_bytes(&q, payload_3b, sizeof(payload_3b));
  nread = Curl_capsule_process_udp_raw(NULL, NULL, &q, out, 2, &err);
  fail_unless(err == CURLE_AGAIN, "expected AGAIN for short output buffer");
  fail_unless(nread == 0, "expected zero read on short output buffer");
  fail_unless(Curl_bufq_len(&q) == sizeof(payload_3b),
              "capsule must remain buffered on short output");

  /* zero-length UDP payload is accepted and consumed */
  Curl_bufq_reset(&q);
  queue_bytes(&q, payload_empty, sizeof(payload_empty));
  nread = Curl_capsule_process_udp_raw(NULL, NULL, &q, out, sizeof(out), &err);
  fail_unless(err == CURLE_OK, "zero-length UDP payload should succeed");
  fail_unless(nread == 0, "zero-length UDP payload should read zero");
  fail_unless(Curl_bufq_is_empty(&q), "zero-length capsule must be consumed");

  /* normal payload decode */
  Curl_bufq_reset(&q);
  queue_bytes(&q, payload_3b, sizeof(payload_3b));
  memset(out, 0, sizeof(out));
  nread = Curl_capsule_process_udp_raw(NULL, NULL, &q, out, sizeof(out), &err);
  fail_unless(err == CURLE_OK, "payload decode should succeed");
  fail_unless(nread == 3, "payload decode size mismatch");
  fail_unless(out[0] == 0x11 && out[1] == 0x22 && out[2] == 0x33,
              "payload decode bytes mismatch");
  fail_unless(Curl_bufq_is_empty(&q), "payload capsule must be consumed");

  Curl_bufq_free(&q);
}
#endif /* USE_NGTCP2 && !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP */

static CURLcode test_unit3220(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  (void)arg;

#if defined(USE_PROXY_HTTP3) && \
  !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)
  test_capsule_encap_udp_hdr_boundaries();
  test_capsule_udp_payload_written();
#endif

#if defined(USE_PROXY_HTTP3) && defined(USE_NGTCP2) && \
  !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)
  test_capsule_encode_decode_roundtrip();
  test_capsule_decode_paths();
#endif

  UNITTEST_END_SIMPLE
}
