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
#include "curl_get_line.h"

#if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_ALTSVC) ||  \
  !defined(CURL_DISABLE_HSTS) || !defined(CURL_DISABLE_NETRC)

/* The test XML does not supply a way to write files without newlines
 * so we write our own
 */

#define C64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define C256 C64 C64 C64 C64
#define C1024 C256 C256 C256 C256
#define C4096 C1024 C1024 C1024 C1024

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static CURLcode unit_stop(void)
{
  return CURLE_OK;
}

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif

#define NUMTESTS 6
static const char *filecontents[] = {
  /* Both should be read */
  "LINE1\n"
  "LINE2 NEWLINE\n",

  /* Both should be read */
  "LINE1\n"
  "LINE2 NONEWLINE",

  /* Only first should be read */
  "LINE1\n"
  C4096,

  /* First line should be read */
  "LINE1\n"
  C4096 "SOME EXTRA TEXT",

  /* First and third line should be read */
  "LINE1\n"
  C4096 "SOME EXTRA TEXT\n"
  "LINE3\n",

  "LINE1\x1aTEST"
};

#ifdef __GNUC__
#pragma GCC diagnostic warning "-Woverlength-strings"
#endif


UNITTEST_START
  size_t i;
  for(i = 0; i < NUMTESTS; i++) {
    FILE *fp;
    char buf[4096];
    int len = 4096;
    char *line;

    fp = fopen(arg, "wb");
    abort_unless(fp != NULL, "Cannot open testfile");
    fwrite(filecontents[i], 1, strlen(filecontents[i]), fp);
    fclose(fp);

    fp = fopen(arg, "rb");
    abort_unless(fp != NULL, "Cannot open testfile");

    fprintf(stderr, "Test %zd...", i);
    switch(i) {
      case 0:
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE1\n", line),
          "First line failed (1)");
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE2 NEWLINE\n", line),
          "Second line failed (1)");
        line = Curl_get_line(buf, len, fp);
        abort_unless(line == NULL, "Missed EOF (1)");
        break;
      case 1:
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE1\n", line),
          "First line failed (2)");
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE2 NONEWLINE\n", line),
          "Second line failed (2)");
        line = Curl_get_line(buf, len, fp);
        abort_unless(line == NULL, "Missed EOF (2)");
        break;
      case 2:
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE1\n", line),
          "First line failed (3)");
        line = Curl_get_line(buf, len, fp);
        fail_unless(line == NULL,
          "Did not detect max read on EOF (3)");
        break;
      case 3:
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE1\n", line),
          "First line failed (4)");
        line = Curl_get_line(buf, len, fp);
        fail_unless(line == NULL,
          "Did not ignore partial on EOF (4)");
        break;
      case 4:
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE1\n", line),
          "First line failed (5)");
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE3\n", line),
          "Third line failed (5)");
        line = Curl_get_line(buf, len, fp);
        abort_unless(line == NULL, "Missed EOF (5)");
        break;
      case 5:
        line = Curl_get_line(buf, len, fp);
        fail_unless(line && !strcmp("LINE1\x1aTEST\n", line),
          "Missed/Misinterpreted ^Z (6)");
        line = Curl_get_line(buf, len, fp);
        abort_unless(line == NULL, "Missed EOF (6)");
        break;
      default:
        abort_unless(1, "Unknown case");
        break;
    }
    fclose(fp);
    fprintf(stderr, "OK\n");
  }
UNITTEST_STOP

#else
static CURLcode unit_setup(void)
{
  return CURLE_OK;
}
static void unit_stop(void)
{
}
UNITTEST_START
UNITTEST_STOP

#endif
