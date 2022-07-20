/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "urldata.h"
#include "sendf.h"

/*
 * This test hardcodes the knowledge of the buffer size which is internal to
 * Curl_infof(). If that buffer is changed in size, this tests needs to be
 * updated to still be valid.
 */

static struct Curl_easy *data;

static char input[4096];
static char result[4096];

int debugf_cb(CURL *handle, curl_infotype type, char *buf, size_t size,
              void *userptr);

/*
 * This debugf callback is simply dumping the string into the static buffer
 * for the unit test to inspect. Since we know that we're only dealing with
 * text we can afford the luxury of skipping the type check here.
 */
int
debugf_cb(CURL *handle, curl_infotype type, char *buf, size_t size,
                void *userptr)
{
  (void)handle;
  (void)type;
  (void)userptr;

  memset(result, '\0', sizeof(result));
  memcpy(result, buf, size);
  return 0;
}

static CURLcode
unit_setup(void)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  data = curl_easy_init();
  if(!data) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  curl_easy_setopt(data, CURLOPT_DEBUGFUNCTION, debugf_cb);
  curl_easy_setopt(data, CURLOPT_VERBOSE, 1L);
  return res;
}

static void
unit_stop(void)
{
  curl_easy_cleanup(data);
  curl_global_cleanup();
}

static int verify(const char *info, const char *two)
{
  /* the 'info' one has a newline appended */
  char *nl = strchr(info, '\n');
  if(!nl)
    return 1; /* nope */
  return strncmp(info, two, nl - info);
}

UNITTEST_START

/* Injecting a simple short string via a format */
msnprintf(input, sizeof(input), "Simple Test");
Curl_infof(data, "%s", input);
fail_unless(verify(result, input) == 0, "Simple string test");

/* Injecting a few different variables with a format */
Curl_infof(data, "%s %u testing %lu", input, 42, 43L);
fail_unless(verify(result, "Simple Test 42 testing 43\n") == 0,
            "Format string");

/* Variations of empty strings */
Curl_infof(data, "");
fail_unless(strlen(result) == 1, "Empty string");
Curl_infof(data, "%s", NULL);
fail_unless(verify(result, "(nil)") == 0, "Passing NULL as string");

/* A string just long enough to not be truncated */
memset(input, '\0', sizeof(input));
memset(input, 'A', 2047);
Curl_infof(data, "%s", input);
fail_unless(strlen(result) == 2048, "No truncation of infof input");
fail_unless(verify(result, input) == 0, "No truncation of infof input");
fail_unless(result[sizeof(result) - 1] == '\0',
            "No truncation of infof input");

/* Just over the limit for truncation without newline */
memset(input + 2047, 'A', 4);
Curl_infof(data, "%s", input);
fail_unless(strlen(result) == 2048, "Truncation of infof input 1");
fail_unless(result[sizeof(result) - 1] == '\0', "Truncation of infof input 1");

/* Just over the limit for truncation with newline */
memset(input + 2047, 'A', 4);
memset(input + 2047 + 4, '\n', 1);
Curl_infof(data, "%s", input);
fail_unless(strlen(result) == 2048, "Truncation of infof input 2");
fail_unless(result[sizeof(result) - 1] == '\0', "Truncation of infof input 2");

/* Way over the limit for truncation with newline */
memset(input, '\0', sizeof(input));
memset(input, 'A', sizeof(input) - 1);
Curl_infof(data, "%s", input);
fail_unless(strlen(result) == 2048, "Truncation of infof input 3");
fail_unless(result[sizeof(result) - 1] == '\0', "Truncation of infof input 3");


UNITTEST_STOP
