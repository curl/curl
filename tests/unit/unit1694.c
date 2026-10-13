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

/* Only include this test if one or more of FTP, FILE are enabled. */
#if !defined(CURL_DISABLE_FTP) || !defined(CURL_DISABLE_FILE)

static CURLcode t1694_setup(struct Curl_easy **easy)
{
  CURLcode result;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result)
    return result; /* init failed us */

  *easy = curl_easy_init();
  if(!*easy) {
    curl_global_cleanup();   /* roll back the half we did succeed at */
    return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

static void t1694_stop(struct Curl_easy *easy)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static CURLcode test_unit1694(const char *arg)
{
  struct Curl_easy *easy;

  UNITTEST_BEGIN(t1694_setup(&easy))

  struct testcase {
    /* Input values */
    bool use_range;         /* value for state.use_range */
    const char *range;      /* value for state.range, or NULL */
    /* Output values */
    CURLcode result;        /* expected return from Curl_range() */
    curl_off_t resume_from; /* expected state.resume_from after the call */
    curl_off_t maxdownload; /* expected req.maxdownload after the call */
  };

  static const struct testcase tests[] = {

    /* Make sure Curl_range doesn't do anything unless the range
     * request data is properly initialized.
     *
     * The use_range and range variables are ANDead together within the
     * Curl_range function for this check, so for 3 out of 4 scenarios the
     * initialization could be incorrect. */

    { FALSE, NULL,                    CURLE_OK,          0, -1 },
    { FALSE, "0-100",                 CURLE_OK,          0, -1 },
    { TRUE,  NULL,                    CURLE_OK,          0, -1 },

    /* Let's feed Curl_range some invalid ranges */

    /* Text instead of a numerical range */
    { TRUE,  "NotANumber",            CURLE_RANGE_ERROR, 0, -1 },
    /* A single stand alone "range" should fail */
    { TRUE,  "100",                   CURLE_RANGE_ERROR, 0, -1 },
    /* Passing in "-0" should fail */
    { TRUE,  "-0",                    CURLE_RANGE_ERROR, 0, -1 },
    /* Passing in a "from" greater than the "to" should fail */
    { TRUE,  "100-50",                CURLE_RANGE_ERROR, 0, -1 },
    /* Passing in a range that is greater than CURL_OFF_T_MAX
     * should fail */
    { TRUE,  "0-9223372036854775807", CURLE_RANGE_ERROR, 0, -1 },

    /* success paths */

    /* Start at a byte, go to the end */
    { TRUE,  "100-",                  CURLE_OK,        100, -1 },
    /* Start at the beginning, go to a byte */
    { TRUE,  "-100",                  CURLE_OK,       -100, 100 },
    /* A range of bytes */
    { TRUE,  "100-201",               CURLE_OK,        100, 102 }
  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
    CURLcode result;
    const char *range_str; /* printable version of the range for messages */

    /* Initialize the outputs in case any subsequent test paths
     * skip any writes to these values */
    easy->result = CURLE_UNSUPPORTED_PROTOCOL;
    easy->state.resume_from = 0;
    easy->req.maxdownload = -1;

    /* Set the input use_range flag according to the test case */
    easy->state.use_range = tests[i].use_range;

    /* Setup the input range, including a printable version */
    if(tests[i].range) {
      range_str = tests[i].range;
      easy->state.range = curlx_strdup(tests[i].range);
      if(!easy->state.range) {
        curl_mprintf("curlx_strdup failed for test case [%zu]\n", i);
        unittest_abort("out of memory");
      }
    }
    else {
      range_str = "(null)";
      easy->state.range = NULL;
    }

    result = Curl_range(easy); /* Exercise the code under test */

    /* Check the result code */
    if(result -= tests[i].result) {
      curl_mprintf("Curl_range(\"%s\") returned %d, expected %d [%zu]\n",
                   range_str, (int)result, (int)tests[i].result, i);
      fail("unexpected result code");
    }

    /* Check the resume_from value */
    if(easy->state.resume_from != tests[i].resume_from) {
      curl_mprintf("Curl_range(\"%s\") set resume_from to %" FMT_OFF_T
                   ", expected %" FMT_OFF_T " [%zu]\n",
                   range_str, easy->state.resume_from,
                   tests[i].resume_from, i);
      fail("resume_from mismatch");
    }

    /* Check the maxdownload value */
    if(easy->req.maxdownload != tests[i].maxdownload) {
      curl_mprintf("Curl_range(\"%s\") set maxdownload to %" FMT_OFF_T
                   ", expected %" FMT_OFF_T " [%zu]\n",
                   range_str, easy->req.maxdownload,
                   tests[i].maxdownload, i);
      fail("maxdownload mismatch");
    }

    /* Clean up after ourselves */
    if(tests[i].range)
      curlx_free(easy->state.range);
  }

  UNITTEST_END(t1694_stop(easy))
}

#else

static CURLcode test_unit1694(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since FTP and FILE are disabled");
  UNITTEST_END_SIMPLE
}

#endif /* !CURL_DISABLE_FTP || !CURL_DISABLE_FILE */


