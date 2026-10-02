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
#include "curl_range.h"

static CURLcode test_unit1700(const char *arg)
{
  CURL *easy;
  struct Curl_easy *data;
  CURLcode result;

  UNITTEST_BEGIN_SIMPLE

  /* Initialize the easy handle */
  result = curl_global_init(CURL_GLOBAL_ALL);
  abort_unless(result == CURLE_OK, "curl_global_init failed");
  easy = curl_easy_init();
  abort_unless(easy != NULL, "curl_easy_init failed");

  /* grab the data */
  data = (struct Curl_easy *)easy;

  /* used in the conditional block below, add the void
   * for the compiler */
  (void)data;

  /* Only include this test if one or more of FTP, FILE are enabled. */
#if !defined(CURL_DISABLE_FTP) || !defined(CURL_DISABLE_FILE)

  /* TC 1: Make sure Curl_range doesn't do anything unless the range
   * request data is properly initialized.
   *
   * The use_range and range variables are ANDead together within the
   * Curl_range function for this check, so for 3 out of 4 scenarios the
   * initialization could be incorrect. */

  /* TC 1 Case 1: both items incorrect */
  data->state.use_range = FALSE; /* range request is not enabled */
  data->state.range = NULL; /* range string is not set */

  fail_unless(Curl_range(data) == CURLE_OK,
              "call with no range set should still succeed");
  fail_unless(data->req.maxdownload == -1,
              "no range set should leave maxdownload at -1");

  /* TC 1 Case 2: use_range incorrect */

  data->state.use_range = FALSE; /* range request is not enabled */
  data->state.range = curlx_strdup("0-100"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_OK,
              "call with no use range should still succeed");
  fail_unless(data->req.maxdownload == -1,
              "valid range set should leave maxdownload at -1");

  curlx_free(data->state.range);

  /* TC 1 Case 3: range incorrect */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range = NULL; /* range string is not set */

  fail_unless(Curl_range(data) == CURLE_OK,
              "call with validuse range should still succeed");
  fail_unless(data->req.maxdownload == -1,
              "no range set should leave maxdownload at -1");

  /* TC 2: Garbage instead of a valid range */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range = curlx_strdup("NotANumber"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_RANGE_ERROR,
              "call with garbage number should fail");
  fail_unless(data->req.maxdownload == -1,
              "failed range should leave maxdownload at -1");

  curlx_free((char *)data->state.range);

  /* TC 3: A single stand alone range number should fail */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range = curlx_strdup("100"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_RANGE_ERROR,
              "call with single stand alone number should fail");
  fail_unless(data->req.maxdownload == -1,
              "failed range should leave maxdownload at -1");

  curlx_free((char *)data->state.range);

  /* TC 4: Passing in "-0" should fail */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range = curlx_strdup("-0"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_RANGE_ERROR,
              "call with -0 should fail");
  fail_unless(data->req.maxdownload == -1,
              "failed range should leave maxdownload at -1");

  curlx_free((char *)data->state.range);

  /* TC 5: Passing in a "from" greater than the "to" should fail */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range = curlx_strdup("100-50"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_RANGE_ERROR,
              "call with from > to should fail");
  fail_unless(data->req.maxdownload == -1,
              "failed range should leave maxdownload at -1");

  curlx_free((char *)data->state.range);

  /* TC 6: Passing in a range that is greater than CURL_OFF_T_MAX
   * should fail */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range =
    curlx_strdup("0-9223372036854775807"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_RANGE_ERROR,
              "call with range greater than CURL_OFF_T_MAX should fail");
  fail_unless(data->req.maxdownload == -1,
              "failed range should leave maxdownload at -1");

  curlx_free((char *)data->state.range);

  /* Finally, we're ready to test the success paths */

  /* TC 7: A number and a dash */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range = curlx_strdup("100-"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_OK,
              "call with number and dash should succeed");
  fail_unless(data->state.resume_from == 100,
              "resume_from should be set to 100");

  curlx_free((char *)data->state.range);

  /* TC 8: A dash and a number */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range = curlx_strdup("-100"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_OK,
              "call with dash and number should succeed");
  fail_unless(data->state.resume_from == -100,
              "resume_from should be set to -100");
  fail_unless(data->req.maxdownload == 100,
              "maxdownload should be set to 100");

  curlx_free((char *)data->state.range);

  /* TC 9: A number, a dash, and a number */
  data->state.use_range = TRUE; /* range request is enabled */
  data->state.range = curlx_strdup("100-201"); /* range string is set */

  fail_unless(Curl_range(data) == CURLE_OK,
              "call with number and number should succeed");
  fail_unless(data->state.resume_from == 100,
              "resume_from should be set to 100");
  fail_unless(data->req.maxdownload == 102,
              "maxdownload should be set to 102");

  curlx_free((char *)data->state.range);

#else
  fail(arg); /* avoid unused warning */
#endif /* !CURL_DISABLE_FTP || !CURL_DISABLE_FILE */

  /* clean up after we're done */
  curl_easy_cleanup(easy);
  curl_global_cleanup();

  UNITTEST_END_SIMPLE
}
