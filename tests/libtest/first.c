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
#include "test.h"
#include "first.h"

#ifdef HAVE_LOCALE_H
#  include <locale.h> /* for setlocale() */
#endif

#include "memdebug.h"
#include "timediff.h"
#include "tool_binmode.h"

int select_wrapper(int nfds, fd_set *rd, fd_set *wr, fd_set *exc,
                   struct timeval *tv)
{
  if(nfds < 0) {
    SET_SOCKERRNO(SOCKEINVAL);
    return -1;
  }
#ifdef USE_WINSOCK
  /*
   * Winsock select() requires that at least one of the three fd_set
   * pointers is not NULL and points to a non-empty fdset. IOW Winsock
   * select() can not be used to sleep without a single fd_set.
   */
  if(!nfds) {
    Sleep((DWORD)curlx_tvtoms(tv));
    return 0;
  }
#endif
  return select(nfds, rd, wr, exc, tv);
}

void wait_ms(int ms)
{
  if(ms < 0)
    return;
#ifdef USE_WINSOCK
  Sleep((DWORD)ms);
#else
  {
    struct timeval t;
    curlx_mstotv(&t, ms);
    select_wrapper(0, NULL, NULL, NULL, &t);
  }
#endif
}

char *libtest_arg2 = NULL;
char *libtest_arg3 = NULL;
char *libtest_arg4 = NULL;
int test_argc;
char **test_argv;

struct timeval tv_test_start; /* for test timing */

int unitfail; /* for unittests */

#ifdef CURLDEBUG
static void memory_tracking_init(void)
{
  char *env;
  /* if CURL_MEMDEBUG is set, this starts memory tracking message logging */
  env = getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as file name */
    curl_dbg_memdebug(env);
  }
  /* if CURL_MEMLIMIT is set, this enables fail-on-alloc-number-N feature */
  env = getenv("CURL_MEMLIMIT");
  if(env) {
    char *endptr;
    long num = strtol(env, &endptr, 10);
    if((endptr != env) && (endptr == env + strlen(env)) && (num > 0))
      curl_dbg_memlimit(num);
  }
}
#else
#  define memory_tracking_init() Curl_nop_stmt
#endif

/* returns a hexdump in a static memory area */
char *hexdump(const unsigned char *buf, size_t len)
{
  static char dump[200 * 3 + 1];
  char *p = dump;
  size_t i;
  if(len > 200)
    return NULL;
  for(i = 0; i < len; i++, p += 3)
    msnprintf(p, 4, "%02x ", buf[i]);
  return dump;
}


int main(int argc, char **argv)
{
  char *URL;
  CURLcode result;
  int basearg;
  test_func_t test_func;

  CURL_SET_BINMODE(stdout);

  memory_tracking_init();

  /*
   * Setup proper locale from environment. This is needed to enable locale-
   * specific behavior by the C library in order to test for undesired side
   * effects that could cause in libcurl.
   */
#ifdef HAVE_SETLOCALE
  setlocale(LC_ALL, "");
#endif

  test_argc = argc;
  test_argv = argv;

#ifdef CURLTESTS_BUNDLED
  {
    char *test_name;

    --test_argc;
    ++test_argv;

    basearg = 2;

    if(argc < (basearg + 1)) {
      fprintf(stderr, "Pass testname and URL as arguments please\n");
      return 1;
    }

    test_name = argv[basearg - 1];
    test_func = NULL;
    {
      size_t tmp;
      for(tmp = 0; tmp < CURL_ARRAYSIZE(s_tests); ++tmp) {
        if(strcmp(test_name, s_tests[tmp].name) == 0) {
          test_func = s_tests[tmp].ptr;
          break;
        }
      }
    }

    if(!test_func) {
      fprintf(stderr, "Test '%s' not found.\n", test_name);
      return 1;
    }
  }
#else
  basearg = 1;

  if(argc < (basearg + 1)) {
    fprintf(stderr, "Pass URL as argument please\n");
    return 1;
  }

  test_func = test;
#endif

  if(argc > (basearg + 1))
    libtest_arg2 = argv[basearg + 1];

  if(argc > (basearg + 2))
    libtest_arg3 = argv[basearg + 2];

  if(argc > (basearg + 2))
    libtest_arg4 = argv[basearg + 3];

  URL = argv[basearg]; /* provide this to the rest */

  fprintf(stderr, "URL: %s\n", URL);

  result = test_func(URL);
  fprintf(stderr, "Test ended with result %d\n", result);

#ifdef _WIN32
  /* flush buffers of all streams regardless of mode */
  _flushall();
#endif

  /* Regular program status codes are limited to 0..127 and 126 and 127 have
   * special meanings by the shell, so limit a normal return code to 125 */
  return (int)result <= 125 ? (int)result : 125;
}
