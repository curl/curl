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
static unsigned int t3310_closed;
static curl_off_t t3310_length;

static void t3310_close(struct Curl_easy *data, struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  ++t3310_closed;
}

static curl_off_t t3310_total_length(struct Curl_easy *data,
                                    struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return t3310_length;
}

static const struct Curl_crtype t3310_reader = {
  "test",
  Curl_creader_def_init,
  Curl_creader_def_read,
  t3310_close,
  Curl_creader_def_needs_rewind,
  t3310_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_cntrl,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct Curl_creader)
};

static CURLcode test_unit3310(const char *arg)
{
  struct Curl_easy *easy = NULL;
  UNITTEST_BEGIN(curl_global_init(CURL_GLOBAL_ALL))
  struct Curl_creader *reader = NULL;
  CURLcode result;
  char buf[8];
  size_t nread = 0;
  bool eos = FALSE;

  easy = curl_easy_init();
  abort_unless(easy, "easy init");
  curl_easy_setopt(easy, CURLOPT_CRLF, 1L);
  fail_unless(Curl_creader_set_buf(easy, "a\n", 2) == CURLE_OK,
              "set ordinary upload");
  fail_unless(Curl_client_read(easy, buf, sizeof(buf), &nread, &eos) ==
              CURLE_OK, "read ordinary upload");
  fail_unless(nread == 3 && !memcmp(buf, "a\r\n", 3), "CRLF conversion");
  Curl_client_cleanup(easy);

  t3310_closed = 0;
  t3310_length = 1;
  result = Curl_creader_create(&reader, easy, &t3310_reader, CURL_CR_CLIENT);
  abort_unless(!result, "create reader");
  fail_unless(Curl_creader_set(easy, reader) == CURLE_OK, "set reader");
  Curl_client_cleanup(easy);
  fail_unless(t3310_closed == 1, "reader closed exactly once");

  /* Unknown length also needs a CRLF conversion reader. */
  t3310_length = -1;
  result = Curl_creader_create(&reader, easy, &t3310_reader, CURL_CR_CLIENT);
  abort_unless(!result, "create replacement reader");
  /* Fail the next allocation, which creates the CRLF conversion reader. */
  curl_dbg_memlimit(0);
  result = Curl_creader_set(easy, reader);
  fail_unless(result == CURLE_OUT_OF_MEMORY, "CRLF allocation failure");
  fail_unless(t3310_closed == 2, "failed reader closed exactly once");
  fail_unless(!easy->req.reader.stack, "failed stack must be empty");
  Curl_client_cleanup(easy);
  fail_unless(t3310_closed == 2, "cleanup must not close twice");

  UNITTEST_END((curl_easy_cleanup(easy), curl_global_cleanup()))
}
#else
static CURLcode test_unit3310(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}
#endif
