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
#include "urldata.h"
#include "sendf.h"

#ifdef CURL_MEMDEBUG

static int t3307_close_count;

static curl_off_t t3307_total_length(struct Curl_easy *data,
                                     struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  /* Arm failure after the client reader is installed, just before the
     line-conversion reader is created. No allocation ordinal is needed.
     Each unit test runs in its own process, so failures stay armed for
     cleanup. */
  curl_dbg_memlimit(0);
  return 1;
}

static void t3307_close(struct Curl_easy *data, struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  ++t3307_close_count;
}

static const struct Curl_crtype t3307_reader = {
  "unit3307",
  Curl_creader_def_init,
  Curl_creader_def_read,
  t3307_close,
  Curl_creader_def_needs_rewind,
  t3307_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_cntrl,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct Curl_creader)
};

static CURLcode test_unit3307(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  struct Curl_easy data;
  struct Curl_creader *reader;
  CURLcode result;

  memset(&data, 0, sizeof(data));
  data.set.crlf = TRUE;
  t3307_close_count = 0;

  result = Curl_creader_create(&reader, &data, &t3307_reader, CURL_CR_CLIENT);
  abort_unless(!result, "create client reader");

  result = Curl_creader_set(&data, reader);

  fail_unless(result == CURLE_OUT_OF_MEMORY,
              "line-conversion reader allocation must fail");
  fail_unless(!data.req.reader.stack,
              "failed reader setup must leave an empty stack");
  fail_unless(t3307_close_count == 1,
              "failed reader setup must close the client reader once");

  /* Let the old implementation fail the assertion without following its
     dangling pointer during cleanup. */
  if(result == CURLE_OUT_OF_MEMORY && t3307_close_count == 1)
    data.req.reader.stack = NULL;

  Curl_client_cleanup(&data);
  fail_unless(t3307_close_count == 1,
              "cleanup must not close the failed reader again");

  UNITTEST_END_SIMPLE
}

#else
static CURLcode test_unit3307(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}
#endif /* CURL_MEMDEBUG */
