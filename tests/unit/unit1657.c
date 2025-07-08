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

#include "vtls/x509asn1.h"

#if defined(USE_GNUTLS) || defined(USE_SCHANNEL) || defined(USE_MBEDTLS)

struct test1657_spec {
  CURLcode (*setbuf)(const struct test1657_spec *spec, struct dynbuf *buf);
  size_t n;
  CURLcode exp_result;
};

static CURLcode make1657_nested(const struct test1657_spec *spec,
                                struct dynbuf *buf)
{
  CURLcode r;
  size_t i;
  unsigned char open_undef[] = { 0x32, 0x80 };
  unsigned char close_undef[] = { 0x00, 0x00 };

  for(i = 0; i < spec->n; ++i) {
    r = curlx_dyn_addn(buf, open_undef, sizeof(open_undef));
    if(r)
      return r;
  }
  for(i = 0; i < spec->n; ++i) {
    r = curlx_dyn_addn(buf, close_undef, sizeof(close_undef));
    if(r)
      return r;
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
  const char *in;

  memset(&elem, 0, sizeof(elem));
  curlx_dyn_reset(buf);
  result = spec->setbuf(spec, buf);
  if(result) {
    curl_mfprintf(stderr, "test %zu: error setting buf %d\n", i, result);
    return FALSE;
  }
  in = curlx_dyn_ptr(buf);
  result = Curl_x509_getASN1Element(&elem, in, in + curlx_dyn_len(buf));
  if(result != spec->exp_result) {
    curl_mfprintf(stderr, "test %zu: expect result %d, got %d\n",
                  i, spec->exp_result, result);
    return FALSE;
  }
  return TRUE;
}

static CURLcode test_unit1657(char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  size_t i;
  bool all_ok = TRUE;
  struct dynbuf dbuf;

  curlx_dyn_init(&dbuf, 32*1024);

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  for(i = 0; i < CURL_ARRAYSIZE(test1657_specs); ++i) {
    if(!do_test1657(&test1657_specs[i], i, &dbuf))
      all_ok = FALSE;
  }
  fail_unless(all_ok, "some tests of Curl_x509_getASN1Element() fails");

  curlx_dyn_free(&dbuf);
  curl_global_cleanup();

  UNITTEST_END_SIMPLE
}

#else

static CURLcode test_unit1657(char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since Curl_x509_getASN1Element() is not built in");
  UNITTEST_END_SIMPLE
}

#endif
