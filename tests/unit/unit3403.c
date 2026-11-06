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

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGTCP2) && defined(USE_NGHTTP3)

static unsigned char written[16];
static size_t written_len;
static int calls;

static ssize_t mock_write(int fd, const void *data, size_t len)
{
  size_t n = len;
  (void)fd;
  ++calls;
  if(calls == 1) {
    /* !checksrc! disable ERRNOVAR 1 */
    errno = EINTR;
    return -1;
  }
  if(calls == 2)
    n = 2;
  memcpy(written + written_len, data, n);
  written_len += n;
  return (ssize_t)n;
}

static CURLcode test_unit3403(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  static const char record[] = "qlog record";

  written_len = 0;
  calls = 0;
  fail_unless(qlog_write_all(42, record, sizeof(record) - 1, mock_write),
              "interrupted and short writes should be retried");
  fail_unless(written_len == sizeof(record) - 1 &&
              !memcmp(written, record, sizeof(record) - 1) && calls == 3,
              "qlog record was not written in full");

  UNITTEST_END_SIMPLE
}
#else
static CURLcode test_unit3403(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested without ngtcp2 HTTP/3");
  UNITTEST_END_SIMPLE
}
#endif
