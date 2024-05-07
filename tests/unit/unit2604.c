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
#include "curl_path.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{
}


struct set {
  const char *cp;
  const char *expect;
  const char *home;
  CURLcode result;
};

struct set list[] = {
  { "a a", "a", "/home/", CURLE_OK},
  { "b a", "b", "/", CURLE_OK},
  { "a", "a", "/home/", CURLE_OK},
  { "b", "b", "/", CURLE_OK},
  { "\"foo bar\"\tb", "foo bar", "/", CURLE_OK},
  { "/~/hej", "/home/user/hej", "/home/user", CURLE_OK},
  { "\"foo bar", "", "/", CURLE_QUOTE_ERROR},
  { "\"foo\\\"bar\" a", "foo\"bar", "/", CURLE_OK},
  { "\"foo\\\'bar\" b", "foo\'bar", "/", CURLE_OK},
  { "\"foo\\\\bar\" c", "foo\\bar", "/", CURLE_OK},
  { "foo\"", "foo\"", "/", CURLE_OK},
  { "foo \"", "foo", "/", CURLE_OK},
  { NULL, NULL, NULL, CURLE_OK }
};

UNITTEST_START
#ifdef USE_SSH
{
  int i;
  int error = 0;
  for(i = 0; list[i].home; i++) {
    char *path;
    CURLcode result = Curl_get_pathname(list[i].cp, &path, list[i].home);
    printf("%u - Curl_get_pathname(\"%s\", ... \"%s\") == %u\n", i,
           list[i].cp, list[i].home, list[i].result);
    if(result != list[i].result) {
      printf("... returned %d\n", result);
      error++;
    }
    if(!result && path) {
      if(strcmp(path, list[i].expect)) {
        printf("... gave '%s', not '%s' as expected \n",
               path, list[i].expect);
        error++;
      }
      curl_free(path);
    }
  }
  return error;
}
#endif

UNITTEST_STOP
