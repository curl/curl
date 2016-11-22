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

CURL *hnd;

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{
  if(hnd)
    curl_easy_cleanup(hnd);
}

struct test {
  const char *in;
  int inlen;
  const char *out;
  int outlen;
};

UNITTEST_START
{
  /* unescape, this => that */
  const struct test list1[]={
    {"%61", 3, "a", 1},
    {"%61a", 4, "aa", 2},
    {"%61b", 4, "ab", 2},
    {"%6 1", 4, "%6 1", 4},
    {"%61", 1, "%", 1},
    {"%61", 2, "%6", 2},
    {"%6%a", 4, "%6%a", 4},
    {"%6a", 0, "j", 1},
    {"%FF", 0, "\xff", 1},
    {"%FF%00%ff", 9, "\xff\x00\xff", 3},
    {"%-2", 0, "%-2", 3},
    {"%FG", 0, "%FG", 3},
    {NULL, 0, NULL, 0} /* end of list marker */
  };
  /* escape, this => that */
  const struct test list2[]={
    {"a", 1, "a", 1},
    {"/", 1, "%2F", 3},
    {"a=b", 3, "a%3Db", 5},
    {"a=b", 0, "a%3Db", 5},
    {"a=b", 1, "a", 1},
    {"a=b", 2, "a%3D", 4},
    {"1/./0", 5, "1%2F.%2F0", 9},
    {"-._~!#%&", 0, "-._~%21%23%25%26", 16},
    {"a", 2, "a%00", 4},
    {"a\xff\x01g", 4, "a%FF%01g", 8},
    {NULL, 0, NULL, 0} /* end of list marker */
  };
  int i;

  hnd = curl_easy_init();
  abort_unless(hnd != NULL, "returned NULL!");
  for(i=0; list1[i].in; i++) {
    int outlen;
    char *out = curl_easy_unescape(hnd,
                                   list1[i].in, list1[i].inlen,
                                   &outlen);

    abort_unless(out != NULL, "returned NULL!");
    fail_unless(outlen == list1[i].outlen, "wrong output length returned");
    fail_unless(!memcmp(out, list1[i].out, list1[i].outlen),
                "bad output data returned");

    printf("curl_easy_unescape test %d DONE\n", i);

    curl_free(out);
  }

  for(i=0; list2[i].in; i++) {
    int outlen;
    char *out = curl_easy_escape(hnd, list2[i].in, list2[i].inlen);
    abort_unless(out != NULL, "returned NULL!");

    outlen = (int)strlen(out);
    fail_unless(outlen == list2[i].outlen, "wrong output length returned");
    fail_unless(!memcmp(out, list2[i].out, list2[i].outlen),
                "bad output data returned");

    printf("curl_easy_escape test %d DONE (%s)\n", i, out);

    curl_free(out);
  }
}
UNITTEST_STOP
