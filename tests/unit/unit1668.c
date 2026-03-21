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

#ifndef CURL_DISABLE_FTP

struct test_1668 {
  const char *in;
  const char *out;
  bool rc;
};

static bool test1668(const struct test_1668 *spec, size_t i)
{
  bool rc;
  bool ok = TRUE;
  int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;

  rc = ftp_213_date(spec->in,
                    &year, &month, &day, &hour, &minute, &second);

  if(rc != spec->rc) {
    curl_mfprintf(stderr, "test %zu: expected result %d, got %d for %s\n",
                  i, spec->rc, rc, spec->in);
    ok = FALSE;
  }
  else if(rc) {
    char buffer[80];
    curl_msnprintf(buffer, sizeof(buffer),
                   "%04d-%02d-%02d %02d:%02d:%02d",
                   year, month, day, hour, minute, second);
    if(strcmp(buffer, spec->out)) {
      curl_mfprintf(stderr,
                    "test %zu: (from input %s) got '%s' expected '%s'\n", i,
                    spec->in, buffer, spec->out);
      ok = FALSE;
    }
  }

  return ok;
}

static CURLcode test_unit1668(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  static const struct test_1668 test_specs[] = {
    /* fractions are ignored, even when invalid */
    { "19980320114234.123", "1998-03-20 11:42:34", TRUE },
    { "19980320114234.000", "1998-03-20 11:42:34", TRUE },
    { "19980320114234.aaa", "1998-03-20 11:42:34", TRUE },
    { "19980320114234.999", "1998-03-20 11:42:34", TRUE },
    { "19980320114234", "1998-03-20 11:42:34", TRUE },
    { "09980320114234", "0998-03-20 11:42:34", TRUE },
    { "10980320114234", "1098-03-20 11:42:34", TRUE },
    { "19080320114234", "1908-03-20 11:42:34", TRUE },
    { "19900320114234", "1990-03-20 11:42:34", TRUE },
    /* invalid month is accepted */
    { "19980020114234", "1998-00-20 11:42:34", TRUE },
    /* invalid day is accepted */
    { "19980300114234", "1998-03-00 11:42:34", TRUE },
    { "19980320014234", "1998-03-20 01:42:34", TRUE },
    { "19980320110234", "1998-03-20 11:02:34", TRUE },
    { "19980320114204", "1998-03-20 11:42:04", TRUE },
    { "19980320114230", "1998-03-20 11:42:30", TRUE },
    /* not all invalid times are accepted */
    { "19980320256565", "", FALSE },
    { "19980320236565", "", FALSE },
    { "19980320235865", "", FALSE },
    /* invalid February is okay */
    { "19980231114234", "1998-02-31 11:42:34", TRUE },
    { ":9980231114234", "", FALSE },
    { "a9980231114234", "", FALSE },
    { "1:980231114234", "", FALSE },
    { "1a980231114234", "", FALSE },
    { "19:80231114234", "", FALSE },
    { "19b80231114234", "", FALSE },
    { "199:0231114234", "", FALSE },
    { "199c0231114234", "", FALSE },
    { "1998:231114234", "", FALSE },
    { "1998d231114234", "", FALSE },
    { "19980:31114234", "", FALSE },
    { "19980e31114234", "", FALSE },
    { "199802:1114234", "", FALSE },
    { "199802f1114234", "", FALSE },
    { "1998023:114234", "", FALSE },
    { "1998023/114234", "", FALSE },
    { "19980231:14234", "", FALSE },
    { "19980231x14234", "", FALSE },
    { "199802311:4234", "", FALSE },
    { "199802311z4234", "", FALSE },
    { "1998023111:234", "", FALSE },
    { "1998023111&234", "", FALSE },
    { "19980231114:34", "", FALSE },
    { "19980231114#34", "", FALSE },
    { "199802311142:4", "", FALSE },
    { "199802311142!4", "", FALSE },
    { "1998023111423:", "", FALSE },
    { "1998023111423@", "", FALSE },

    { "19980320114234--", "1998-03-20 11:42:34", TRUE },
    { " 19980320114234", "", FALSE },
    { "1998032011423", "", FALSE },
    { "199803201142", "", FALSE },
    { "19980320114", "", FALSE },
    { "199803201", "", FALSE },
    { "19980320", "", FALSE },
    { "1998032", "", FALSE },
    { "199803", "", FALSE },
    { "19980", "", FALSE },
    { "1998", "", FALSE },
    { "199", "", FALSE },
    { "19", "", FALSE },
    { "1", "", FALSE },
    { "", "", FALSE },
    { "20260320114234.123", "2026-03-20 11:42:34", TRUE },
    { "30260320114234.123", "3026-03-20 11:42:34", TRUE },
    { "40260320114234.123", "4026-03-20 11:42:34", TRUE },
    { "19980320114234\xff", "1998-03-20 11:42:34", TRUE },
    { "1998\x7e""320114234\xff", "", FALSE },
    { "1998\x7f""320114234\xff", "", FALSE },
    { "1998\x80""320114234\xff", "", FALSE },
    { "1998\x81""320114234\xff", "", FALSE },
    { "1998\x82""320114234\xff", "", FALSE },
    { "\xcc", "", FALSE },
    { "\x55", "", FALSE },
  };

  size_t i;
  bool all_ok = TRUE;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  for(i = 0; i < CURL_ARRAYSIZE(test_specs); ++i) {
    if(!test1668(&test_specs[i], i))
      all_ok = FALSE;
  }
  fail_unless(all_ok, "some tests of ftp_213_date() failed");
  curl_global_cleanup();

  UNITTEST_END_SIMPLE
}

#else /* without FTP */

static CURLcode test_unit1668(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since FTP is disabled");
  UNITTEST_END_SIMPLE
}

#endif
