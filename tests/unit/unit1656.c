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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "fetchcheck.h"

#include "vtls/x509asn1.h"

static FETCHcode unit_setup(void)
{
  return FETCHE_OK;
}

static void unit_stop(void)
{

}

#if defined(USE_GNUTLS) || defined(USE_SCHANNEL) || defined(USE_SECTRANSP) || \
  defined(USE_MBEDTLS)

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

struct test_spec {
  const char *input;
  const char *exp_output;
  FETCHcode exp_result;
};

static struct test_spec test_specs[] = {
  { "190321134340", "1903-21-13 43:40:00", FETCHE_OK },
  { "", NULL, FETCHE_BAD_FUNCTION_ARGUMENT },
  { "WTF", NULL, FETCHE_BAD_FUNCTION_ARGUMENT },
  { "0WTF", NULL, FETCHE_BAD_FUNCTION_ARGUMENT },
  { "19032113434", NULL, FETCHE_BAD_FUNCTION_ARGUMENT },
  { "19032113434WTF", NULL, FETCHE_BAD_FUNCTION_ARGUMENT },
  { "190321134340.", NULL, FETCHE_BAD_FUNCTION_ARGUMENT },
  { "190321134340.1", "1903-21-13 43:40:00.1", FETCHE_OK },
  { "19032113434017.0", "1903-21-13 43:40:17", FETCHE_OK },
  { "19032113434017.01", "1903-21-13 43:40:17.01", FETCHE_OK },
  { "19032113434003.001", "1903-21-13 43:40:03.001", FETCHE_OK },
  { "19032113434003.090", "1903-21-13 43:40:03.09", FETCHE_OK },
  { "190321134340Z", "1903-21-13 43:40:00 GMT", FETCHE_OK },
  { "19032113434017.0Z", "1903-21-13 43:40:17 GMT", FETCHE_OK },
  { "19032113434017.01Z", "1903-21-13 43:40:17.01 GMT", FETCHE_OK },
  { "19032113434003.001Z", "1903-21-13 43:40:03.001 GMT", FETCHE_OK },
  { "19032113434003.090Z", "1903-21-13 43:40:03.09 GMT", FETCHE_OK },
  { "190321134340CET", "1903-21-13 43:40:00 CET", FETCHE_OK },
  { "19032113434017.0CET", "1903-21-13 43:40:17 CET", FETCHE_OK },
  { "19032113434017.01CET", "1903-21-13 43:40:17.01 CET", FETCHE_OK },
  { "190321134340+02:30", "1903-21-13 43:40:00 UTC+02:30", FETCHE_OK },
  { "19032113434017.0+02:30", "1903-21-13 43:40:17 UTC+02:30", FETCHE_OK },
  { "19032113434017.01+02:30", "1903-21-13 43:40:17.01 UTC+02:30", FETCHE_OK },
  { "190321134340-3", "1903-21-13 43:40:00 UTC-3", FETCHE_OK },
  { "19032113434017.0-04", "1903-21-13 43:40:17 UTC-04", FETCHE_OK },
  { "19032113434017.01-01:10", "1903-21-13 43:40:17.01 UTC-01:10", FETCHE_OK },
};

static bool do_test(struct test_spec *spec, size_t i, struct dynbuf *dbuf)
{
  FETCHcode result;
  const char *in = spec->input;

  Curl_dyn_reset(dbuf);
  result = Curl_x509_GTime2str(dbuf, in, in + strlen(in));
  if(result != spec->exp_result) {
    fprintf(stderr, "test %zu: expect result %d, got %d\n",
            i, spec->exp_result, result);
    return FALSE;
  }
  else if(!result && strcmp(spec->exp_output, Curl_dyn_ptr(dbuf))) {
    fprintf(stderr, "test %zu: input '%s', expected output '%s', got '%s'\n",
            i, in, spec->exp_output, Curl_dyn_ptr(dbuf));
    return FALSE;
  }

  return TRUE;
}

UNITTEST_START
{
  size_t i;
  struct dynbuf dbuf;
  bool all_ok = TRUE;

  Curl_dyn_init(&dbuf, 32*1024);

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  for(i = 0; i < ARRAYSIZE(test_specs); ++i) {
    if(!do_test(&test_specs[i], i, &dbuf))
      all_ok = FALSE;
  }
  fail_unless(all_ok, "some tests of Curl_x509_GTime2str() fails");

  Curl_dyn_free(&dbuf);
  fetch_global_cleanup();
}
UNITTEST_STOP

#else

UNITTEST_START
{
  puts("not tested since Curl_x509_GTime2str() is not built-in");
}
UNITTEST_STOP

#endif
