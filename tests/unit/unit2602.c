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
#include "curlcheck.h"

#include "urldata.h"
#include "dynbuf.h"
#include "dynhds.h"
#include "curl_trc.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{
}


UNITTEST_START

  struct dynhds hds;
  struct dynbuf dbuf;
  CURLcode result;
  size_t i;

  /* add 1 more header than allowed */
  Curl_dynhds_init(&hds, 2, 128);
  fail_if(Curl_dynhds_count(&hds), "should be empty");
  fail_if(Curl_dynhds_add(&hds, "test1", 5, "123", 3), "add failed");
  fail_if(Curl_dynhds_add(&hds, "test2", 5, "456", 3), "add failed");
  /* remove and add without exceeding limits */
  for(i = 0; i < 100; ++i) {
    if(Curl_dynhds_remove(&hds, "test2", 5) != 1) {
      fail_if(TRUE, "should");
      break;
    }
    if(Curl_dynhds_add(&hds, "test2", 5, "456", 3)) {
      fail_if(TRUE, "add failed");
      break;
    }
  }
  fail_unless(Curl_dynhds_count(&hds) == 2, "should hold 2");
  /* set, replacing previous entry without exceeding limits */
  for(i = 0; i < 100; ++i) {
    if(Curl_dynhds_set(&hds, "test2", 5, "456", 3)) {
      fail_if(TRUE, "add failed");
      break;
    }
  }
  fail_unless(Curl_dynhds_count(&hds) == 2, "should hold 2");
  /* exceed limit on # of entries */
  result = Curl_dynhds_add(&hds, "test3", 5, "789", 3);
  fail_unless(result, "add should have failed");

  fail_unless(Curl_dynhds_count_name(&hds, "test", 4) == 0, "false positive");
  fail_unless(Curl_dynhds_count_name(&hds, "test1", 4) == 0, "false positive");
  fail_if(Curl_dynhds_get(&hds, "test1", 4), "false positive");
  fail_unless(Curl_dynhds_get(&hds, "test1", 5), "false negative");
  fail_unless(Curl_dynhds_count_name(&hds, "test1", 5) == 1, "should");
  fail_unless(Curl_dynhds_ccount_name(&hds, "test2") == 1, "should");
  fail_unless(Curl_dynhds_cget(&hds, "test2"), "should");
  fail_unless(Curl_dynhds_ccount_name(&hds, "TEST2") == 1, "should");
  fail_unless(Curl_dynhds_ccontains(&hds, "TesT2"), "should");
  fail_unless(Curl_dynhds_contains(&hds, "TeSt2", 5), "should");
  Curl_dynhds_free(&hds);

  /* add header exceeding max overall length */
  Curl_dynhds_init(&hds, 128, 10);
  fail_if(Curl_dynhds_add(&hds, "test1", 5, "123", 3), "add failed");
  fail_unless(Curl_dynhds_add(&hds, "test2", 5, "456", 3), "should fail");
  fail_if(Curl_dynhds_add(&hds, "t", 1, "1", 1), "add failed");
  Curl_dynhds_reset(&hds);
  Curl_dynhds_free(&hds);

  Curl_dynhds_init(&hds, 128, 4*1024);
  fail_if(Curl_dynhds_add(&hds, "test1", 5, "123", 3), "add failed");
  fail_if(Curl_dynhds_add(&hds, "test1", 5, "123", 3), "add failed");
  fail_if(Curl_dynhds_cadd(&hds, "blablabla", "thingies"), "add failed");
  fail_if(Curl_dynhds_h1_cadd_line(&hds, "blablabla: thingies"), "add failed");
  fail_unless(Curl_dynhds_ccount_name(&hds, "blablabla") == 2, "should");
  fail_unless(Curl_dynhds_cremove(&hds, "blablabla") == 2, "should");
  fail_if(Curl_dynhds_ccontains(&hds, "blablabla"), "should not");

  result = Curl_dynhds_h1_cadd_line(&hds, "blablabla thingies");
  fail_unless(result, "add should have failed");
  if(!result) {
    fail_unless(Curl_dynhds_ccount_name(&hds, "bLABlaBlA") == 0, "should");
    fail_if(Curl_dynhds_cadd(&hds, "Bla-Bla", "thingies"), "add failed");

    Curl_dyn_init(&dbuf, 32*1024);
    fail_if(Curl_dynhds_h1_dprint(&hds, &dbuf), "h1 print failed");
    if(Curl_dyn_ptr(&dbuf)) {
      fail_if(strcmp(Curl_dyn_ptr(&dbuf),
                     "test1: 123\r\ntest1: 123\r\nBla-Bla: thingies\r\n"),
                     "h1 format differs");
    }
    Curl_dyn_free(&dbuf);
  }

  Curl_dynhds_free(&hds);
  Curl_dynhds_init(&hds, 128, 4*1024);
  /* continuation without previous header fails */
  result = Curl_dynhds_h1_cadd_line(&hds, " indented value");
  fail_unless(result, "add should have failed");

  /* continuation with previous header must succeed */
  fail_if(Curl_dynhds_h1_cadd_line(&hds, "ti1: val1"), "add");
  fail_if(Curl_dynhds_h1_cadd_line(&hds, " val2"), "add indent");
  fail_if(Curl_dynhds_h1_cadd_line(&hds, "ti2: val1"), "add");
  fail_if(Curl_dynhds_h1_cadd_line(&hds, "\tval2"), "add indent");
  fail_if(Curl_dynhds_h1_cadd_line(&hds, "ti3: val1"), "add");
  fail_if(Curl_dynhds_h1_cadd_line(&hds, "     val2"), "add indent");

  Curl_dyn_init(&dbuf, 32*1024);
  fail_if(Curl_dynhds_h1_dprint(&hds, &dbuf), "h1 print failed");
  if(Curl_dyn_ptr(&dbuf)) {
    fprintf(stderr, "indent concat: %s\n", Curl_dyn_ptr(&dbuf));
    fail_if(strcmp(Curl_dyn_ptr(&dbuf),
                   "ti1: val1 val2\r\nti2: val1 val2\r\nti3: val1 val2\r\n"),
                   "wrong format");
  }
  Curl_dyn_free(&dbuf);

  Curl_dynhds_free(&hds);

UNITTEST_STOP
