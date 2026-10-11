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
#include "first.h"

#ifdef HAVE_LOCALE_H
#include <locale.h> /* for setlocale() */
#endif

#if defined(UNITTESTS) && !defined(BUILDING_LIBCURL)
#include "tool_stderr.h"  /* for tool_init_stderr() */
#endif

const char *libtest_arg2 = NULL;
const char *libtest_arg3 = NULL;
const char *libtest_arg4 = NULL;
const char *libtest_arg5 = NULL;
int test_argc;
const char **test_argv;
int testnum;

struct curltime tv_test_start; /* for test timing */

int unitfail; /* for unittests */

#ifdef CURL_MEMDEBUG
static void memory_tracking_init(void)
{
  const char *env;
  /* if CURL_MEMDEBUG is set, this starts memory tracking message logging */
  env = getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as filename */
    curl_dbg_memdebug(env);
  }
  /* if CURL_MEMLIMIT is set, this enables fail-on-alloc-number-N feature */
  env = getenv("CURL_MEMLIMIT");
  if(env) {
    curl_off_t num;
    if(!curlx_str_number(&env, &num, LONG_MAX) && num > 0)
      curl_dbg_memlimit((long)num);
  }
}
#else
#define memory_tracking_init() Curl_nop_stmt
#endif

/* returns a hexdump in a static memory area */
char *hexdump(const unsigned char *buf, size_t len)
{
  static char dump[(200 * 3) + 1];
  char *p = dump;
  size_t i;
  if(len > 200)
    return NULL;
  for(i = 0; i < len; i++, p += 3)
    curl_msnprintf(p, 4, "%02x ", buf[i]);
  return dump;
}

int main(int argc, const char *argv[])
{
  const char *URL = "";
  CURLcode result;
  entry_func_t entry_func;
  const char *entry_name;
  const char *env;
  size_t tmp;

#ifdef _WIN32
  if(argc == 2 && !strcmp(argv[1], "--dump-module-paths")) {
    return 0;
  }
#endif

  CURL_BINMODE(stdout);

  memory_tracking_init();
#ifdef _WIN32
  curlx_now_init();
#endif

  /*
   * Setup proper locale from environment. This is needed to enable locale-
   * specific behavior by the C library in order to test for undesired side
   * effects that could cause in libcurl.
   */
#ifdef HAVE_SETLOCALE
  setlocale(LC_ALL, "");
#endif

  test_argc = argc - 1;
  test_argv = argv + 1;

  if(argc < 2) {
    curl_mfprintf(stderr, "Pass testname "
                  "(and URL as argument for numbered tests) please\n");
    return 1;
  }

  entry_name = argv[1];
  entry_func = NULL;
  for(tmp = 0; s_entries[tmp].ptr; ++tmp) {
    if(!strcmp(entry_name, s_entries[tmp].name)) {
      entry_func = s_entries[tmp].ptr;
      break;
    }
  }

  if(!entry_func) {
    curl_mfprintf(stderr, "Test '%s' not found.\n", entry_name);
    return 1;
  }

  if(argc > 2) {
    URL = argv[2];
    curl_mfprintf(stderr, "URL: %s\n", URL);
  }

  if(argc > 3)
    libtest_arg2 = argv[3];

  if(argc > 4)
    libtest_arg3 = argv[4];

  if(argc > 5)
    libtest_arg4 = argv[5];

  if(argc > 6)
    libtest_arg5 = argv[6];

  testnum = 0;
  env = getenv("CURL_TESTNUM");
  if(env) {
    curl_off_t num;
    if(!curlx_str_number(&env, &num, INT_MAX) && num > 0)
      testnum = (int)num;
  }

#if defined(UNITTESTS) && !defined(BUILDING_LIBCURL)
  tool_init_stderr();
#endif

  result = entry_func(URL);
  curl_mfprintf(stderr, "Test ended with result %d\n", (int)result);

#ifdef _WIN32
  /* flush buffers of all streams regardless of mode */
  _flushall();
#endif

  /* Regular program status codes are limited to 0..127 and 126 and 127 have
   * special meanings by the shell, so limit a normal return code to 125 */
  return result <= 125 ? result : 125;
}
