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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3)
#include "vquic/vquic.h"
#include "curlx/win32-fopen.h"

static CURLcode test_unit3402(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  unsigned char scid[] = { 0x01, 0x02, 0x03 };
  char path[512];
  curlx_struct_stat st;
  CURL *easy = NULL;
  FILE *fp = NULL;
  int fd = -1;

  curl_msnprintf(path, sizeof(path), "%s/010203.sqlog", arg);
  fp = curlx_fopen(path, "wb");
  abort_unless(fp, "cannot pre-create qlog file");
  fail_unless(fwrite("stale qlog content", 1, 18, fp) == 18,
              "cannot write qlog file");
  curlx_fclose(fp);
  fp = NULL;

  easy = curl_easy_init();
  abort_unless(easy, "cannot create easy handle");
  if(Curl_qlogdir((struct Curl_easy *)easy, scid, sizeof(scid), &fd)
     != CURLE_OK || fd == -1)
    fail("cannot open qlog file");
  else {
    fail_unless(!curlx_fstat(fd, &st) && st.st_size == 0,
                "reopened qlog file was not truncated");
    curlx_close(fd);
  }
  curl_easy_cleanup(easy);
  remove(path);

  UNITTEST_END_SIMPLE
}
#else
static CURLcode test_unit3402(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested without HTTP/3");
  UNITTEST_END_SIMPLE
}
#endif
