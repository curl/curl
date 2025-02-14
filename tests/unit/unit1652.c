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

#include "urldata.h"
#include "sendf.h"

/*
 * This test hardcodes the knowledge of the buffer size which is internal to
 * Curl_infof(). If that buffer is changed in size, this tests needs to be
 * updated to still be valid.
 */

static struct Curl_easy *testdata;

static char input[4096];
static char output[4096];

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

  memset(output, '\0', sizeof(output));
  memcpy(output, buf, size);
  return 0;
}

static CURLcode
unit_setup(void)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  testdata = curl_easy_init();
  if(!testdata) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  curl_easy_setopt(testdata, CURLOPT_DEBUGFUNCTION, debugf_cb);
  curl_easy_setopt(testdata, CURLOPT_VERBOSE, 1L);
  return res;
}

static void
unit_stop(void)
{
  curl_easy_cleanup(testdata);
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

#if defined(CURL_GNUC_DIAG) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-zero-length"
#if __GNUC__ >= 7
#pragma GCC diagnostic ignored "-Wformat-overflow"
#endif
#endif

/* Injecting a simple short string via a format */
msnprintf(input, sizeof(input), "Simple Test");
Curl_infof(testdata, "%s", input);
fail_unless(verify(output, input) == 0, "Simple string test");

/* Injecting a few different variables with a format */
Curl_infof(testdata, "%s %u testing %lu", input, 42, 43L);
fail_unless(verify(output, "Simple Test 42 testing 43\n") == 0,
            "Format string");

/* Variations of empty strings */
Curl_infof(testdata, "");
fail_unless(strlen(output) == 1, "Empty string");
Curl_infof(testdata, "%s", (char *)NULL);
fail_unless(verify(output, "(nil)") == 0, "Passing NULL as string");

/* Note: libcurl's tracebuffer hold 2048 bytes, so the max strlen() we
 * get out of it is 2047, since we need a \0 at the end.
 * Curl_infof() in addition adds a \n at the end, making the effective
 * output 2046 characters.
 * Any input that long or longer will truncated, ending in '...\n'.
 */

/* A string just long enough to not be truncated */
memset(input, '\0', sizeof(input));
memset(input, 'A', 2045);
Curl_infof(testdata, "%s", input);
fprintf(stderr, "output len %d: %s", (int)strlen(output), output);
/* output is input + \n */
fail_unless(strlen(output) == 2046, "No truncation of infof input");
fail_unless(verify(output, input) == 0, "No truncation of infof input");
fail_unless(output[sizeof(output) - 1] == '\0',
            "No truncation of infof input");

/* Just over the limit without newline for truncation via '...' */
memset(input + 2045, 'A', 4);
Curl_infof(testdata, "%s", input);
fprintf(stderr, "output len %d: %s", (int)strlen(output), output);
fail_unless(strlen(output) == 2047, "Truncation of infof input 1");
fail_unless(output[sizeof(output) - 1] == '\0', "Truncation of infof input 1");

/* Just over the limit with newline for truncation via '...' */
memset(input + 2045, 'A', 4);
memset(input + 2045 + 4, '\n', 1);
Curl_infof(testdata, "%s", input);
fprintf(stderr, "output len %d: %s", (int)strlen(output), output);
fail_unless(strlen(output) == 2047, "Truncation of infof input 2");
fail_unless(output[sizeof(output) - 1] == '\0', "Truncation of infof input 2");

/* Way over the limit for truncation via '...' */
memset(input, '\0', sizeof(input));
memset(input, 'A', sizeof(input) - 1);
Curl_infof(testdata, "%s", input);
fprintf(stderr, "output len %d: %s", (int)strlen(output), output);
fail_unless(strlen(output) == 2047, "Truncation of infof input 3");
fail_unless(output[sizeof(output) - 1] == '\0', "Truncation of infof input 3");

#if defined(CURL_GNUC_DIAG) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

UNITTEST_STOP
