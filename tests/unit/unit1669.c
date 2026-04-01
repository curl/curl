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
#include "altsvc.h"

static CURLcode test_unit1669(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_ALTSVC)
  char outname[256];
  CURL *curl;
  CURLcode result;
  struct altsvcinfo *asi = Curl_altsvc_init();
  abort_if(!asi, "Curl_altsvc_init");
  result = Curl_altsvc_load(asi, arg);
  fail_if(result, "Curl_altsvc_load");
  if(result)
    goto fail;
  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  fail_if(!curl, "curl_easy_init");
  if(!curl)
    goto fail;
  fail_unless(Curl_llist_count(&asi->list) == MAX_ALTSVC_ENTRIES,
              "wrong number of entries");
  curl_msnprintf(outname, sizeof(outname), "%s-out", arg);

  Curl_altsvc_save(curl, asi, outname);

  curl_easy_cleanup(curl);
fail:
  Curl_altsvc_cleanup(&asi);
#endif

  UNITTEST_END(curl_global_cleanup())
}
