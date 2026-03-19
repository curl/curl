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

#if defined(USE_GNUTLS) || defined(USE_SCHANNEL) || defined(USE_MBEDTLS) || \
  defined(USE_RUSTLS)
#include "vtls/x509asn1.h"
#include "vtls/vtls.h"

struct test_1666 {
  const char *oid;
  const size_t size;
  const char *dotted;
  CURLcode result_exp;
};

/* the size of the object needs to deduct the null terminator */
#define OID(x) x, sizeof(x) - 1

static bool test1666(const struct test_1666 *spec, size_t i,
                     struct dynbuf *dbuf)
{
  CURLcode result;
  const char *oid = spec->oid;
  bool ok = TRUE;

  curlx_dyn_reset(dbuf);
  result = encodeOID(dbuf, oid, oid + spec->size);
  if(result != spec->result_exp) {
    curl_mfprintf(stderr, "test %zu: expect result %d, got %d\n",
                  i, spec->result_exp, result);
    if(!spec->result_exp) {
      curl_mfprintf(stderr, "test %zu: expected output '%s'\n",
                    i, spec->dotted);
    }
    ok = FALSE;
  }
  else if(!result && strcmp(spec->dotted, curlx_dyn_ptr(dbuf))) {
    curl_mfprintf(stderr,
                  "test %zu: expected output '%s', got '%s'\n",
                  i, spec->dotted, curlx_dyn_ptr(dbuf));
    ok = FALSE;
  }

  return ok;
}

static CURLcode test_unit1666(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  static const struct test_1666 test_specs[] = {
    { "", 0, "", CURLE_BAD_FUNCTION_ARGUMENT },
    { "\x81", 0, "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x8F\xFF\xFF\xFF\x7F"), "2.4294967215", CURLE_OK },
    { OID("\x90\x80\x80\x80\x00"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x88\x80\x80\x80\x4F"), "2.2147483647", CURLE_OK },
    { OID("\x88\x80\x80\x80\x50"), "2.2147483648", CURLE_OK },
    { OID("\x88\x80\x80\x80\x51"), "2.2147483649", CURLE_OK },
    { OID("\x88\x80\x80\x80\x52"), "2.2147483650", CURLE_OK },
    { OID("\x8F\xFF\xFF\xFF\x7F\x8F\xFF\xFF\xFF\x7F"),
      "2.4294967215.4294967295", CURLE_OK },
    { OID("\xB7\x28\x02"), "2.7000.2", CURLE_OK },
    { OID("\x81\x00"), "2.48", CURLE_OK },
    { OID("\x81\x00\x01"), "2.48.1", CURLE_OK },
    { OID("\x81\x00\x02"), "2.48.2", CURLE_OK },
    { OID("\xC0\x80\x81\x1F"), "2.134217807", CURLE_OK },
    { OID("\x2b\x06\x01\x04\x01\x82\x37\x15\x14"), "1.3.6.1.4.1.311.21.20",
      CURLE_OK },
    { OID("\x2b\x06\x01\x04\x01\x82\x37\x15"), "1.3.6.1.4.1.311.21",
      CURLE_OK },
    { OID("\x2b\x06\x01\x04\x01\x82\x37"), "1.3.6.1.4.1.311", CURLE_OK },
    { OID("\x2b\x06\x01\x04\x01"), "1.3.6.1.4.1", CURLE_OK },
    { OID("\x2b\x06\x01\x04"), "1.3.6.1.4", CURLE_OK },
    { OID("\x2b\x06\x01"), "1.3.6.1", CURLE_OK },
    { OID("\x2b\x06"), "1.3.6", CURLE_OK },
    { OID("\x2b"), "1.3", CURLE_OK },
    { OID("\x2c"), "1.4", CURLE_OK },
    { OID("\x2d"), "1.5", CURLE_OK },
    { OID("\x2e"), "1.6", CURLE_OK },
    { OID("\x2f"), "1.7", CURLE_OK },
    { OID("\x30"), "1.8", CURLE_OK },
    { OID("\x31"), "1.9", CURLE_OK },
    { OID("\x32"), "1.10", CURLE_OK },
    { OID("\x50"), "2.0", CURLE_OK },
    { OID("\x7f"), "2.47", CURLE_OK },
    { OID("\xff\x7f"), "2.16303", CURLE_OK },
    { OID("\xff"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\xff\x80\x01"), "2.2080689", CURLE_OK },
    { OID("\xff\x80\x80\x01"), "2.266338225", CURLE_OK },
    { OID("\x80\x80\x80\x80\x01"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\x80\x80\x80\x80\x01"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\x80\x80\x80\x80\x80\x01"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\xff\x7f"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\xff\xff\xff\x7f"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x2b\xff\xff\xff\xff\x7f"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\x80"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\x80\x80"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\x80\x80\x80"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\x80\x80\x80\x80"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x80\x80\x80\x80\x80\x80"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x2b\x06\x01\x04\x01\xee"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x00"), "0.0", CURLE_OK },
    { OID("\x01"), "0.1", CURLE_OK },
    { OID("\x02"), "0.2", CURLE_OK },
    { OID("\x03"), "0.3", CURLE_OK },
    { OID("\x04"), "0.4", CURLE_OK },
    { OID("\x05"), "0.5", CURLE_OK },
    { OID("\x2b\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
          "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
          "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"),
      "1.3.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1"
      ".1.1.1.1.1.1.1.1", CURLE_OK },
    { OID("\x2b\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64"
          "\x64\x64\x64\x64\x64\x64\x64\x64\x64\x7f"),
      "", CURLE_TOO_LARGE },
    { OID("\x2b\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64"
          "\x64\x64\x64\x64\x64\x64\x64\x64\x64\x63"),
      "", CURLE_TOO_LARGE },
    { OID("\x2b\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64\x64"
          "\x64\x64\x64\x64\x64\x64\x64\x64\x64\x09"),
      "", CURLE_TOO_LARGE },
    { OID("\x2b\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
          "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
          "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
          "\x01\x01\x01\x01\x01\x01\x01\x01"),
      "", CURLE_TOO_LARGE },
    /* one byte shorter than the previous is just below the limit: */
    { OID("\x2b\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
          "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
          "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
          "\x01\x01\x01\x01\x01\x01\x01"),
      "1.3.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1"
      ".1.1.1.1.1.1.1.1.1.1.1.1.1.1.1", CURLE_OK },
    { OID("\x78"), "2.40", CURLE_OK },
    { OID("\x81\x34"), "2.100", CURLE_OK },
    { OID("\x2b\x00\x01"), "1.3.0.1", CURLE_OK },
    { OID("\x2b\x06\x01\x00"), "1.3.6.1.0", CURLE_OK },
    { OID("\x2b\x8f\xff\xff\xff\x7f"), "1.3.4294967295", CURLE_OK },
    { OID("\x2b\x81\x00"), "1.3.128", CURLE_OK },
    { OID("\x2b\x80\x05"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x2b\x80\x80\x01"), "", CURLE_BAD_FUNCTION_ARGUMENT },
    { OID("\x2b\x06\x81"), "", CURLE_BAD_FUNCTION_ARGUMENT },
  };

  size_t i;
  struct dynbuf dbuf;
  bool all_ok = TRUE;

  /* the real code uses CURL_X509_STR_MAX for maximum size, but we set a
     smaller one here so that we can test running into the limit a little
     easier */
  curlx_dyn_init(&dbuf, 100);

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  for(i = 0; i < CURL_ARRAYSIZE(test_specs); ++i) {
    if(!test1666(&test_specs[i], i, &dbuf))
      all_ok = FALSE;
  }
  fail_unless(all_ok, "some tests of encodeOID() failed");

  curlx_dyn_free(&dbuf);
  curl_global_cleanup();

  UNITTEST_END_SIMPLE
}

#undef OID

#else

static CURLcode test_unit1666(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since encodeOID() is not built in");
  UNITTEST_END_SIMPLE
}

#endif
