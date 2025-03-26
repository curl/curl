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
#include "bufref.h"
#include "memdebug.h"

static struct bufref bufref;

static int freecount = 0;

static void test_free(void *p)
{
  fail_unless(p, "pointer to free may not be NULL");
  freecount++;
  free(p);
}

static CURLcode unit_setup(void)
{
  Curl_bufref_init(&bufref);
  return CURLE_OK;
}

static void unit_stop(void)
{
  Curl_bufref_free(&bufref);
}

UNITTEST_START
{
  const char *buffer = NULL;
  CURLcode result = CURLE_OK;

  /**
   * testing Curl_bufref_init.
   * @assumptions:
   * 1: data size will be 0
   * 2: reference will be NULL
   * 3: destructor will be NULL
   */

  fail_unless(!bufref.ptr, "Initial reference must be NULL");
  fail_unless(!bufref.len, "Initial length must be NULL");
  fail_unless(!bufref.dtor, "Destructor must be NULL");

  /**
   * testing Curl_bufref_set
   */

  buffer = malloc(13);
  abort_unless(buffer, "Out of memory");
  Curl_bufref_set(&bufref, buffer, 13, test_free);

  fail_unless((const char *)bufref.ptr == buffer, "Referenced data badly set");
  fail_unless(bufref.len == 13, "Data size badly set");
  fail_unless(bufref.dtor == test_free, "Destructor badly set");

  /**
   * testing Curl_bufref_ptr
   */

  fail_unless((const char *) Curl_bufref_ptr(&bufref) == buffer,
              "Wrong pointer value returned");

  /**
   * testing Curl_bufref_len
   */

  fail_unless(Curl_bufref_len(&bufref) == 13, "Wrong data size returned");

  /**
   * testing Curl_bufref_memdup
   */

  result = Curl_bufref_memdup(&bufref, "1661", 3);
  abort_unless(result == CURLE_OK, curl_easy_strerror(result));
  fail_unless(freecount == 1, "Destructor not called");
  fail_unless((const char *)bufref.ptr != buffer, "Returned pointer not set");
  buffer = (const char *)Curl_bufref_ptr(&bufref);
  fail_unless(buffer, "Allocated pointer is NULL");
  fail_unless(bufref.len == 3, "Wrong data size stored");
  if(buffer) {
    fail_unless(!buffer[3], "Duplicated data should have been truncated");
    fail_unless(!strcmp(buffer, "166"), "Bad duplicated data");
  }

  /**
   * testing Curl_bufref_free
   */

  Curl_bufref_free(&bufref);
  fail_unless(freecount == 1, "Wrong destructor called");
  fail_unless(!bufref.ptr, "Initial reference must be NULL");
  fail_unless(!bufref.len, "Initial length must be NULL");
  fail_unless(!bufref.dtor, "Destructor must be NULL");
}
UNITTEST_STOP
