/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#include "dotdot.h"

#include "memdebug.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{

}

struct dotdot {
  const char *input;
  const char *output;
};

UNITTEST_START

  unsigned int i;
  int fails=0;
  const struct dotdot pairs[] = {
    { "/a/b/c/./../../g", "/a/g" },
    { "mid/content=5/../6", "mid/6" },
    { "/hello/../moo", "/moo" },
    { "/1/../1", "/1" },
    { "/1/./1", "/1/1" },
    { "/1/..", "/" },
    { "/1/.", "/1/" },
    { "/1/./..", "/" },
    { "/1/./../2", "/2" },
    { "/hello/1/./../2", "/hello/2" },
    { "test/this", "test/this" },
    { "test/this/../now", "test/now" },
    { "/1../moo../foo", "/1../moo../foo"},
    { "/../../moo", "/moo"},
    { "/../../moo?andnot/../yay", "/moo?andnot/../yay"},
    { "/123?foo=/./&bar=/../", "/123?foo=/./&bar=/../"},
    { "/../moo/..?what", "/?what" },
    { "/", "/" },
    { "", "" },
    { "/.../", "/.../" },
  };

  for(i=0; i < sizeof(pairs)/sizeof(pairs[0]); i++) {
    char *out = Curl_dedotdotify((char *)pairs[i].input);
    abort_unless(out != NULL, "returned NULL!");

    if(strcmp(out, pairs[i].output)) {
      fprintf(stderr, "Test %d: '%s' gave '%s' instead of '%s'\n",
              i, pairs[i].input, out, pairs[i].output);
      fail("Test case output mismatched");
      fails++;
    }
    else
      fprintf(stderr, "Test %d: OK\n", i);
    free(out);
  }

  fail_if(fails, "output mismatched");

UNITTEST_STOP
