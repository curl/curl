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

#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_HSTS)

#include "urldata.h"
#include "hsts.h"

/* create a HSTS file with lots of unique host names all using the same
   fixed expire time */
static void render_unit1674(const char *file)
{
  FILE *f = curlx_fopen(file, FOPEN_WRITETEXT);
  size_t i;
  if(!f)
    return;
  for(i = 0; i < (MAX_HSTS_ENTRIES + 5); i++) {
    curl_mfprintf(f, "host%zu.readfrom.example \"20211001 04:47:41\"\n", i);
  }
  curlx_fclose(f);
}

static CURLcode test_unit1674(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  struct hsts *h = Curl_hsts_init();
  CURL *easy;
  char savename[256];

  abort_unless(h, "Curl_hsts_init()");

  render_unit1674(arg);

  curl_global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  if(!easy) {
    Curl_hsts_cleanup(&h);
    abort_unless(easy, "curl_easy_init()");
  }

  Curl_hsts_loadfile(easy, h, arg);

  if(Curl_llist_count(&h->list) == MAX_HSTS_ENTRIES)
    curl_mprintf("OK\n");
  else
    curl_mprintf("Number of entries: %zu\n", Curl_llist_count(&h->list));

  curl_msnprintf(savename, sizeof(savename), "%s.save", arg);
  (void)Curl_hsts_save(easy, h, savename);
  Curl_hsts_cleanup(&h);
  curl_easy_cleanup(easy);

  UNITTEST_END(curl_global_cleanup())
}
#else
static CURLcode test_unit1674(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("nothing to do when HTTP or HSTS are disabled");
  UNITTEST_END_SIMPLE
}
#endif
