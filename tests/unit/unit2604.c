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
#include "vssh/curl_path.h"
#include "memdebug.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{
}


struct set {
  const char *cp;
  const char *expect; /* the returned content */
  const char *next;   /* what cp points to after the call */
  const char *home;
  CURLcode result;
};

UNITTEST_START
#ifdef USE_SSH
{
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif

/* 60 a's */
#define SA60 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
/* 540 a's */
#define SA540 SA60 SA60 SA60 SA60 SA60 SA60 SA60 SA60 SA60
  int i;
  size_t too_long = 90720;
  struct set list[] = {
    { "-too-long-", "", "", "", CURLE_TOO_LARGE},
    { SA540 " c", SA540, "c", "/", CURLE_OK},
    { "\" " SA540 "\" c", " " SA540, "c", "/", CURLE_OK},
    { "a a", "a", "a", "/home/", CURLE_OK},
    { "b a", "b", "a", "/", CURLE_OK},
    { "a", "a", "", "/home/", CURLE_OK},
    { "b", "b", "", "/", CURLE_OK},
    { "\"foo bar\"\tb", "foo bar", "b", "/", CURLE_OK},
    { "/~/hej", "/home/user/hej", "", "/home/user", CURLE_OK},
    { "\"foo bar", "", "", "/", CURLE_QUOTE_ERROR},
    { "\"foo\\\"bar\" a", "foo\"bar", "a", "/", CURLE_OK},
    { "\"foo\\\'bar\" b", "foo\'bar", "b", "/", CURLE_OK},
    { "\"foo\\\\bar\" c", "foo\\bar", "c", "/", CURLE_OK},
    { "\"foo\\pbar\" c", "foo\\bar", "", "/", CURLE_QUOTE_ERROR},
    { "\"\" c", "", "", "", CURLE_QUOTE_ERROR},
    { "foo\"", "foo\"", "", "/", CURLE_OK},
    { "foo \"", "foo", "\"", "/", CURLE_OK},
    { NULL, NULL, NULL, NULL, CURLE_OK }
  };

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic warning "-Woverlength-strings"
#endif

  list[0].cp = calloc(1, too_long + 1);
  fail_unless(list[0].cp, "could not alloc too long value");
  memset((void *)list[0].cp, 'a', too_long);

  for(i = 0; list[i].home; i++) {
    char *path;
    const char *cp = list[i].cp;
    CURLcode result = Curl_get_pathname(&cp, &path, list[i].home);
    printf("%u - Curl_get_pathname(\"%s\", ... \"%s\") == %u\n", i,
           list[i].cp, list[i].home, list[i].result);
    if(result != list[i].result) {
      printf("... returned %d\n", result);
      unitfail++;
    }
    if(!result) {
      if(cp && strcmp(cp, list[i].next)) {
        printf("... cp points to '%s', not '%s' as expected \n",
               cp, list[i].next);
        unitfail++;
      }
      if(path && strcmp(path, list[i].expect)) {
        printf("... gave '%s', not '%s' as expected \n",
               path, list[i].expect);
        unitfail++;
      }
      curl_free(path);

    }
  }

  free((void *)list[0].cp);
}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#endif

UNITTEST_STOP
