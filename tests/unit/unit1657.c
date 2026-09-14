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

#if defined(USE_GNUTLS) || defined(USE_WOLFSSL) || defined(USE_SCHANNEL) || \
  defined(USE_MBEDTLS) || defined(USE_RUSTLS)
#include "vtls/x509asn1.h"

struct test1657_spec {
  CURLcode (*setbuf)(const struct test1657_spec *spec, struct dynbuf *buf);
  size_t n;
  CURLcode result_exp;
};

static CURLcode make1657_nested(const struct test1657_spec *spec,
                                struct dynbuf *buf)
{
  CURLcode result;
  size_t i;
  uint8_t open_undef[] = { 0x32, 0x80 };
  uint8_t close_undef[] = { 0x00, 0x00 };

  for(i = 0; i < spec->n; ++i) {
    result = curlx_dyn_addn(buf, open_undef, sizeof(open_undef));
    if(result)
      return result;
  }
  for(i = 0; i < spec->n; ++i) {
    result = curlx_dyn_addn(buf, close_undef, sizeof(close_undef));
    if(result)
      return result;
  }
  return CURLE_OK;
}

static const struct test1657_spec test1657_specs[] = {
  { make1657_nested, 3, CURLE_OK },
  { make1657_nested, 16, CURLE_OK },
  { make1657_nested, 17, CURLE_BAD_FUNCTION_ARGUMENT },
  { make1657_nested, 1024, CURLE_BAD_FUNCTION_ARGUMENT },
};

static bool do_test1657(const struct test1657_spec *spec, size_t i,
                        struct dynbuf *buf)
{
  CURLcode result;
  struct Curl_asn1Element elem;
  const uint8_t *in;
  const uint8_t *ptr;

  memset(&elem, 0, sizeof(elem));
  curlx_dyn_reset(buf);
  result = spec->setbuf(spec, buf);
  if(result) {
    curl_mfprintf(stderr, "test %zu: error setting buf %d\n", i, (int)result);
    return FALSE;
  }
  in = curlx_dyn_uptr(buf);
  ptr = getASN1Element(&elem, in, in + curlx_dyn_len(buf));
  result = ptr ? CURLE_OK : CURLE_BAD_FUNCTION_ARGUMENT;
  if(result != spec->result_exp) {
    curl_mfprintf(stderr, "test %zu: expect result %d, got %d\n",
                  i, (int)spec->result_exp, (int)result);
    return FALSE;
  }
  return TRUE;
}

struct test1657_cert_spec {
  const char * const pem;
  bool exp_success;
};

static const struct test1657_cert_spec test1657_certs[] = {
  { /* a valid certificate */
    "MIIBGTCBzKADAgECAhQ8Ssn8BaVsqlKKccv81NFuKY1vATAFBgMrZXAwADAeFw0y"
    "NjA5MDIwNDU0MjZaFw0yNjEwMDIwNDU0MjZaMAAwKjAFBgMrZXADIQBeG0S343s9"
    "5yRmIK8xZmGvUmiiYvRH5ZMcPq6rvHHKwqNYMFYwNQYDKgMEBC4wADAqMAUGAytl"
    "cAMhAPP5TXSe2WHt/bebbP8eHPXrG3LNxYz8TnHNgpwTFsT7MB0GA1UdDgQWBBR6"
    "aqL9LrZiIpgYCy0X4fNrhgFQsTAFBgMrZXADQQALU0OHGcIvfTwyin/+u9csJ9hZ"
    "W0c+XdHJY5uDdCR1O92K4Vnozf/QCe7ITOJ8aUnCs7Jgf5xrDgyXZNdum04A",
    TRUE
  },
  { /* a certificate with "validity" element that has too long length */
    "MIIBGTCBzKADAgECAhQ8Ssn8BaVsqlKKccv81NFuKY1vATAFBgMrZXAwADBZFw0y"
    "NjA5MDIwNDU0MjZaFw0yNjEwMDIwNDU0MjZaMAAwKjAFBgMrZXADIQBeG0S343s9"
    "5yRmIK8xZmGvUmiiYvRH5ZMcPq6rvHHKwqNYMFYwNQYDKgMEBC4wADAqMAUGAytl"
    "cAMhAPP5TXSe2WHt/bebbP8eHPXrG3LNxYz8TnHNgpwTFsT7MB0GA1UdDgQWBBR6"
    "aqL9LrZiIpgYCy0X4fNrhgFQsTAFBgMrZXADQQALU0OHGcIvfTwyin/+u9csJ9hZ"
    "W0c+XdHJY5uDdCR1O92K4Vnozf/QCe7ITOJ8aUnCs7Jgf5xrDgyXZNdum04A",
    FALSE
  }
};

static bool test1657_parse_cert(size_t i,
                                const struct test1657_cert_spec *spec)
{
  struct Curl_X509certificate cert;
  CURLcode result;
  uint8_t *cert_der;
  size_t cert_der_len;
  bool success;

  result = curlx_base64_decode(spec->pem, &cert_der, &cert_der_len);
  if(result) {
    curl_mfprintf(stderr, "cert %zu: base64 decoding failed: %d\n",
                  i, (int)result);
    return FALSE;
  }

  success = !Curl_parseX509(&cert, cert_der, cert_der +  cert_der_len);
  if(success != spec->exp_success) {
    curl_mfprintf(stderr, "cert %zu: parsing DER %sfailed\n", i,
                  spec->exp_success ? "" : "should have ");
    return FALSE;
  }

  curlx_free(cert_der);
  return TRUE;
}

static CURLcode test_unit1657(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  size_t i;
  bool all_ok = TRUE;
  struct dynbuf dbuf;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curlx_dyn_init(&dbuf, 32 * 1024);

  for(i = 0; i < CURL_ARRAYSIZE(test1657_specs); ++i) {
    if(!do_test1657(&test1657_specs[i], i, &dbuf))
      all_ok = FALSE;
  }
  fail_unless(all_ok, "some getASN1Element() tests failed");

  all_ok = TRUE;
  for(i = 0; i < CURL_ARRAYSIZE(test1657_certs); ++i) {
    if(!test1657_parse_cert(i, &test1657_certs[i]))
      all_ok = FALSE;
  }
  fail_unless(all_ok, "some certificate tests failed");

  curlx_dyn_free(&dbuf);
  curl_global_cleanup();

  UNITTEST_END_SIMPLE
}

#else

static CURLcode test_unit1657(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since getASN1Element() is not built in");
  UNITTEST_END_SIMPLE
}

#endif
