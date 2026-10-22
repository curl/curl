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
     * request data is initialized.
     *
     * The use_range and range variables are ANDead together
     * at the top of this function. So for 3 out of 4 scenarios
     * where either of these could be uninitialized, we skip most
     * of the Curl_range code. Still returns "CURLE_OK" and
     * maxdownload set to -1 or "unlimited". */

    { FALSE, NULL,                    CURLE_OK,          -7, -1 },
    { FALSE, "0-100",                 CURLE_OK,          -7, -1 },
    { TRUE,  NULL,                    CURLE_OK,          -7, -1 },

    /*                                           */
    /* Let's feed Curl_range some invalid ranges */
    /*                                           */

    /* Text instead of a numerical range */
    { TRUE,  "NotANumber",            CURLE_RANGE_ERROR, -7, -8 },
    /* Hexadecimal not supported */
    { TRUE,  "0XDEAD-0XBEEF",         CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "0xdead-0xbeef",         CURLE_RANGE_ERROR, -7, -8 },
    /* Passing in "-0" should fail */
    { TRUE,  "-0",                    CURLE_RANGE_ERROR, -7, -8 },
    /* Passing in a "from" greater than the "to" should fail */
    { TRUE,  "130-50",                CURLE_RANGE_ERROR, -7, -8 },
    /* Passing in a range that is greater than CURL_OFF_T_MAX
     * should fail */
    { TRUE,  "0-9223372036854775807", CURLE_RANGE_ERROR, -7, -8 },
    /* Use a character from the zero area of the
     *  curlx_hexasciitable */
    { TRUE,  ":100-100",              CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "100:-100",              CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "_100-100",              CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "100_-100",              CURLE_RANGE_ERROR, -7, -8 },

    /*                     */
    /* Single number tests */
    /*                     */

    { TRUE,  "125",                   CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  " 126",                  CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "  127",                 CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "128 ",                  CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "129  ",                 CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "\t131",                 CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "\t\t132",               CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "133\t",                 CURLE_RANGE_ERROR, -7, -8 },
    { TRUE,  "134\t\t",               CURLE_RANGE_ERROR, -7, -8 },

    /*                        */
    /* No second number tests */
    /*                        */

    /* Returns OK and sets resume_from, maxdownload NOT set.
     * Comments mention " to end of file", so shouldn't
     * maxdownload be set to -1? */
    { TRUE,  "101-",                  CURLE_OK,          101, -8 },
    { TRUE,  "102- ",                 CURLE_OK,          102, -8 },
    { TRUE,  "103-  ",                CURLE_OK,          103, -8 },
    { TRUE,  "102-\t",                CURLE_OK,          102, -8 },
    { TRUE,  "103-\t\t",              CURLE_OK,          103, -8 },
    /* Returns Error */
    { TRUE,  " 113-",                 CURLE_RANGE_ERROR,  -7, -8 },
    { TRUE,  "  135-",                CURLE_RANGE_ERROR,  -7, -8 },
    { TRUE,  "114 -",                 CURLE_RANGE_ERROR,  -7, -8 },
    { TRUE,  "136  -",                CURLE_RANGE_ERROR,  -7, -8 },
    { TRUE,  "\t113-",                CURLE_RANGE_ERROR,  -7, -8 },
    { TRUE,  "\t\t135-",              CURLE_RANGE_ERROR,  -7, -8 },
    { TRUE,  "114\t-",                CURLE_RANGE_ERROR,  -7, -8 },
    { TRUE,  "136\t\t-",              CURLE_RANGE_ERROR,  -7, -8 },

    /*                       */
    /* No first number tests */
    /*                       */

    /* Typical success path */
    { TRUE,  "-104",                  CURLE_OK,          -104, 104 },
    { TRUE,  "-105 ",                 CURLE_OK,          -105, 105 },
    { TRUE,  "-106  ",                CURLE_OK,          -106, 106 },
    { TRUE,  "-142\t",                CURLE_OK,          -142, 142 },
    { TRUE,  "-143\t\t",              CURLE_OK,          -143, 143 },
    /* Sees that there is no 1st number, finds the dash and
     * skips it, sees no 2nd number due to the whitespace,
     * resume_from set to 0 via call to str_num_base, no writes to
     * maxdownload. */
    { TRUE,  "- 121",                 CURLE_OK,             0,  -8 },
    { TRUE,  "-  122",                CURLE_OK,             0,  -8 },
    { TRUE,  "-\t140",                CURLE_OK,             0,  -8 },
    { TRUE,  "-\t\t141",              CURLE_OK,             0,  -8 },
    /* Returns Error */
    { TRUE,  " -115",                 CURLE_RANGE_ERROR,   -7,  -8 },
    { TRUE,  "  -137",                CURLE_RANGE_ERROR,   -7,  -8 },
    { TRUE,  "\t-138",                CURLE_RANGE_ERROR,   -7,  -8 },
    { TRUE,  "\t\t-139",              CURLE_RANGE_ERROR,   -7,  -8 },

    /*                                     */
    /* Two number tests, single byte range */
    /*                                     */

    /* Typical success path */
    { TRUE,  "100-100",               CURLE_OK,            100,  1 },
    { TRUE,  "101-101 ",              CURLE_OK,            101,  1 },
    { TRUE,  "101-101\t",             CURLE_OK,            101,  1 },
    /* Parser can't get past the whitespace after the dash,
     * takes the no second number path in the code. */
    { TRUE,  "102- 102",              CURLE_OK,            102, -8 },
    { TRUE,  "103- 103 ",             CURLE_OK,            103, -8 },
    { TRUE,  "102-\t102",             CURLE_OK,            102, -8 },
    { TRUE,  "103-\t103\t",           CURLE_OK,            103, -8 },
    /* Returns Error */
    { TRUE,  "105 -105 ",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "104 -104",              CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "106 - 106",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "107 - 107 ",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 200-200",              CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 201-201 ",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 202- 202",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 203- 203 ",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 205 -205 ",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 204 -204",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 206 - 206",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 207 - 207 ",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "105\t-105\t",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "104\t-104",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "106\t-\t106",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "107\t-\t107\t",         CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t200-200",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t201-201\t",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t202-\t202",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t203-\t203\t",         CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t205\t-205\t",         CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t204\t-204",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t206\t-\t206",         CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t207\t-\t207 ",        CURLE_RANGE_ERROR,    -7, -8 },

    /*                                  */
    /* Two number tests, range of bytes */
    /*                                  */

    /* Typical success path */
    { TRUE,  "300-500",               CURLE_OK,            300,  201 },
    { TRUE,  "301-501 ",              CURLE_OK,            301,  201 },
    { TRUE,  "301-501\t",             CURLE_OK,            301,  201 },
    /* Parser can't get past the whitespace after the dash,
     * takes the no second number path in the code. */
    { TRUE,  "302- 502",              CURLE_OK,            302, -8 },
    { TRUE,  "303- 503 ",             CURLE_OK,            303, -8 },
    { TRUE,  "302-\t502",             CURLE_OK,            302, -8 },
    { TRUE,  "303-\t503\t",           CURLE_OK,            303, -8 },
    /* Returns Error */
    { TRUE,  "305 -505 ",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "304 -504",              CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "306 - 506",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "307 - 507 ",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 400-600",              CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 401-601 ",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 402- 602",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 403- 603 ",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 405 -605 ",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 404 -604",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 406 - 606",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  " 407 - 607 ",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "305\t-505\t",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "304\t-504",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "306\t-\t506",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "307\t-\t507\t",         CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t400-600",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t401-601\t",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t402-\t602",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t403-\t603\t",         CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t405\t-605\t",         CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t404\t-604",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t406\t-\t606",         CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "\t407\t-\t607 ",        CURLE_RANGE_ERROR,    -7, -8 },

    /* Largest supported range, and ends at the largest supported
     * number: (2^63 - 1) */
    { TRUE,  "1-9223372036854775807", CURLE_OK, 1, 9223372036854775807},

    /*                              */
    /* Mix of positive and negative */
    /*                              */

    /* These schenarios are returning OK, but have the same
     * logic challenges as above, due to the extra '-', ' ',
     * and '+'. */
    { TRUE,  "-108 - 208",            CURLE_OK,          -108, 108 },
    { TRUE,  "-109 - +209",           CURLE_OK,          -109, 109 },
    { TRUE,  "-110 - -210",           CURLE_OK,          -110, 110 },
    { TRUE,  "-108-208",              CURLE_OK,          -108, 108 },
    { TRUE,  "-109-+209",             CURLE_OK,          -109, 109 },
    { TRUE,  "-110--210",             CURLE_OK,          -110, 110 },
    { TRUE,  "101-+201",              CURLE_OK,            101, -8 },
    { TRUE,  "102--202",              CURLE_OK,            102, -8 },
    { TRUE,  "103-+203",              CURLE_OK,            103, -8 },
    /* Returns Error */
    { TRUE,  "101 - +201",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "102 - -202",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "103 - +203",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "+104 - 204",            CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "+105 - +205",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "+106 - -206",           CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "+104-204",              CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "+105-+205",             CURLE_RANGE_ERROR,    -7, -8 },
    { TRUE,  "+106--206",             CURLE_RANGE_ERROR,    -7, -8 },

    /*                     */
    /* Other success paths */
    /*                     */

    /* Curl ignores leading zeros */
    { TRUE,  "0008-0012",             CURLE_OK,           8, 5 },
    /* A single 0 at the beginning of a value is treated as an
     * octal value in C source code.  So going from an octal byte
     * 7 to an octal byte 10 would be 2 bytes.  Curl treats its
     * inputs as base 10 strings, so Curl would interpret this
     * as byte 7 to byte 10 and a 4 byte spread. */
    { TRUE,  "07-010",                CURLE_OK,           7, 4 }

  };

  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
    CURLcode result;
    const char *range_str; /* printable version of the range for messages */

    /* Initialize the outputs in case any subsequent test paths
     * skip any writes to these values */
    easy->result = CURLE_UNSUPPORTED_PROTOCOL;
    easy->state.resume_from = -7;
    easy->req.maxdownload = -8;

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
    if(result != tests[i].result) {
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
