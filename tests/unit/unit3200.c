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
#include "curl_get_line.h"
#include "memdebug.h"

static CURLcode test_unit3200(char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_ALTSVC) ||  \
  !defined(CURL_DISABLE_HSTS) || !defined(CURL_DISABLE_NETRC)

#if defined(CURL_GNUC_DIAG) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#endif

  /* The test XML does not supply a way to write files without newlines
   * so we write our own
   */

#define C64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define C256 C64 C64 C64 C64
#define C1024 C256 C256 C256 C256
#define C4096 C1024 C1024 C1024 C1024

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

    /* Only first should be read */
    "LINE1\n"
    C4096 "SOME EXTRA TEXT\n"
    "LINE3\n",

    "LINE1\x1aTEST"
  };

#if defined(CURL_GNUC_DIAG) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

  size_t i;
  int rc = 0;
  for(i = 0; i < CURL_ARRAYSIZE(filecontents); i++) {
    FILE *fp;
    struct dynbuf buf;
    size_t len = 4096;
    char *line;
    curlx_dyn_init(&buf, len);

    fp = fopen(arg, "wb");
    abort_unless(fp != NULL, "Cannot open testfile");
    fwrite(filecontents[i], 1, strlen(filecontents[i]), fp);
    fclose(fp);

    fp = fopen(arg, "rb");
    abort_unless(fp != NULL, "Cannot open testfile");

    curl_mfprintf(stderr, "Test %zd...", i);
    switch(i) {
      case 0:
        rc = Curl_get_line(&buf, fp);
        line = curlx_dyn_ptr(&buf);
        fail_unless(rc && line && !strcmp("LINE1\n", line),
                    "First line failed (1)");
        rc = Curl_get_line(&buf, fp);
        line = curlx_dyn_ptr(&buf);
        fail_unless(rc && line && !strcmp("LINE2 NEWLINE\n", line),
                    "Second line failed (1)");
        rc = Curl_get_line(&buf, fp);
        abort_unless(!curlx_dyn_len(&buf), "Missed EOF (1)");
        break;
      case 1:
        rc = Curl_get_line(&buf, fp);
        line = curlx_dyn_ptr(&buf);
        fail_unless(rc && line && !strcmp("LINE1\n", line),
                    "First line failed (2)");
        rc = Curl_get_line(&buf, fp);
        line = curlx_dyn_ptr(&buf);
        fail_unless(rc && line && !strcmp("LINE2 NONEWLINE\n", line),
                    "Second line failed (2)");
        rc = Curl_get_line(&buf, fp);
        abort_unless(!curlx_dyn_len(&buf), "Missed EOF (2)");
        break;
      case 2:
        rc = Curl_get_line(&buf, fp);
        line = curlx_dyn_ptr(&buf);
        fail_unless(rc && line && !strcmp("LINE1\n", line),
                    "First line failed (3)");
        rc = Curl_get_line(&buf, fp);
        fail_unless(!curlx_dyn_len(&buf),
                    "Did not detect max read on EOF (3)");
        break;
      case 3:
        rc = Curl_get_line(&buf, fp);
        line = curlx_dyn_ptr(&buf);
        fail_unless(rc && line && !strcmp("LINE1\n", line),
                    "First line failed (4)");
        rc = Curl_get_line(&buf, fp);
        fail_unless(!curlx_dyn_len(&buf),
                    "Did not ignore partial on EOF (4)");
        break;
      case 4:
        rc = Curl_get_line(&buf, fp);
        line = curlx_dyn_ptr(&buf);
        fail_unless(rc && line && !strcmp("LINE1\n", line),
                    "First line failed (5)");
        rc = Curl_get_line(&buf, fp);
        fail_unless(!curlx_dyn_len(&buf),
                    "Did not bail out on too long line");
        break;
      case 5:
        rc = Curl_get_line(&buf, fp);
        line = curlx_dyn_ptr(&buf);
        fail_unless(rc && line && !strcmp("LINE1\x1aTEST\n", line),
                    "Missed/Misinterpreted ^Z (6)");
        rc = Curl_get_line(&buf, fp);
        abort_unless(!curlx_dyn_len(&buf), "Missed EOF (6)");
        break;
      default:
        abort_unless(1, "Unknown case");
        break;
    }
    curlx_dyn_free(&buf);
    fclose(fp);
    curl_mfprintf(stderr, "OK\n");
  }
  return (CURLcode)rc;

#endif

  UNITTEST_END_SIMPLE
}
