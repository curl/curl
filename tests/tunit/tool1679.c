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
#include "tool_operate.h"

#include "curlx/fopen.h"

static CURLcode test_tool1679(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  /* regfile_size_left() must return the number of bytes that remain to
     read from the current file position, since a descriptor for
     /dev/stdin or /dev/fd/N can arrive with a nonzero position */

  static const char content[] = "0123456789abcdefghijklmnopqrstu";
  static const char *fname = "tool1679.txt";
  const curl_off_t fsize = (curl_off_t)strlen(content); /* 31 bytes */

  struct positions {
    curl_off_t seek_to;
    curl_off_t expected;
  };

  static const struct positions tests[] = {
    { 0, 31 },   /* at the start: everything remains */
    { 10, 21 },  /* middle: the remainder */
    { 30, 1 },   /* on the last byte */
    { 31, 0 },   /* at EOF: nothing remains */
    { 40, 0 }    /* beyond EOF: nothing remains */
  };

  FILE *fp = curlx_fopen(fname, "wb");
  size_t i;
  int fd;

  abort_unless(fp != NULL, "cannot create test file");
  fail_unless(fwrite(content, 1, (size_t)fsize, fp) == (size_t)fsize,
              "short write");
  curlx_fclose(fp);

  fd = curlx_open(fname, O_RDONLY | CURL_O_BINARY);
  abort_unless(fd != -1, "cannot open test file");

  for(i = 0; i < CURL_ARRAYSIZE(tests); i++) {
    curl_off_t left;
    fail_unless(curl_lseek(fd, tests[i].seek_to, SEEK_SET) != LSEEK_ERROR,
                "lseek failed");
    left = regfile_size_left(fd, fsize);
    if(left != tests[i].expected) {
      curl_mprintf("seek to %" CURL_FORMAT_CURL_OFF_T " expected %"
                   CURL_FORMAT_CURL_OFF_T " remaining, got %"
                   CURL_FORMAT_CURL_OFF_T "\n",
                   tests[i].seek_to, tests[i].expected, left);
      fail("wrong remaining size");
    }
    /* the helper must not move the file position */
    fail_unless((curl_off_t)curl_lseek(fd, 0, SEEK_CUR) == tests[i].seek_to,
                "file position moved");
  }

  curlx_close(fd);
  remove(fname);

  UNITTEST_END_SIMPLE
}
