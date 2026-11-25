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

#include "frzn_strs.h"

static CURLcode test_unit3903(const char *arg)
{
  struct Curl_frzn_strs *fstrs = NULL, *fstrs2 = NULL;
  struct curl_slist *slist = NULL, *l;
  const char *s, *s2;
  size_t idx;

  UNITTEST_BEGIN_SIMPLE

  fstrs = Curl_frzn_strs_from_slist(NULL);
  fail_unless(!fstrs, "fstrs from NULL slist not NULL");
  fstrs = Curl_frzn_strs_dup(NULL);
  fail_unless(!fstrs, "fstrs from NULL fstrs not NULL");

  slist = curl_slist_append(NULL, "host-a.invalid:59998:127.0.0.1");
  if(slist)
    curl_slist_append(slist, "host-b.invalid:59998:127.0.0.1");
  if(slist)
    curl_slist_append(slist, "host-c.invalid:59998:127.0.0.1");
  fail_unless(slist, "could not alloc slist");
  if(!slist)
    goto out;

  fstrs = Curl_frzn_strs_from_slist(slist);
  fail_unless(fstrs, "could not alloc fstrs");
  if(!fstrs)
    goto out;
  curl_mfprintf(stderr, "fstrs count %zu\n", Curl_frzn_strs_count(fstrs));
  fail_unless(Curl_frzn_strs_count(fstrs) == 3,
                        "fstrs count not correct");
  fail_unless(Curl_frzn_strs_get_str(fstrs, 4) == NULL,
                        "fstrs[4] not NULL");

  for(l = slist, idx = 0; l; l = l->next, ++idx) {
    curl_mfprintf(stderr, "check fstrs[%zu]\n", idx);
    s = Curl_frzn_strs_get_str(fstrs, idx);
    fail_unless(s && l->data && !strcmp(l->data, s),
                "string not identical in fstrs");
  }

  fstrs2 = Curl_frzn_strs_dup(fstrs);
  fail_unless(fstrs2, "could not alloc fstrs2");
  if(!fstrs2)
    goto out;
  curl_mfprintf(stderr, "fstrs2 count %zu\n", Curl_frzn_strs_count(fstrs2));
  fail_unless(Curl_frzn_strs_count(fstrs2) == Curl_frzn_strs_count(fstrs),
                        "fstrs2 count not correct");
  for(l = slist, idx = 0; l; l = l->next, ++idx) {
    curl_mfprintf(stderr, "check fstrs2[%zu]\n", idx);
    s = Curl_frzn_strs_get_str(fstrs, idx);
    s2 = Curl_frzn_strs_get_str(fstrs2, idx);
    fail_unless(s && s2 && !strcmp(s, s2),
                "string not identical in fstrs2");
  }

out:
  Curl_frzn_strs_free(fstrs2);
  Curl_frzn_strs_free(fstrs);
  curl_slist_free_all(slist);
  UNITTEST_END_SIMPLE
}
