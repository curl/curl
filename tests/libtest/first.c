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

#include "memdebug.h"

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

char *libtest_arg2 = NULL;
char *libtest_arg3 = NULL;
char *libtest_arg4 = NULL;
int test_argc;
char **test_argv;
int testnum;

struct curltime tv_test_start; /* for test timing */

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
    curl_msnprintf(p, 4, "%02x ", buf[i]);
  return dump;
}


int main(int argc, char **argv)
{
  char *URL;
  CURLcode result;
  entry_func_t entry_func;
  char *entry_name;
  char *env;
  size_t tmp;

  CURLX_SET_BINMODE(stdout);

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

  if(argc < 3) {
    curl_mfprintf(stderr, "Pass testname and URL as arguments please\n");
    return 1;
  }

  entry_name = argv[1];
  entry_func = NULL;
  for(tmp = 0; s_entries[tmp].ptr; ++tmp) {
    if(strcmp(entry_name, s_entries[tmp].name) == 0) {
      entry_func = s_entries[tmp].ptr;
      break;
    }
  }

  if(!entry_func) {
    curl_mfprintf(stderr, "Test '%s' not found.\n", entry_name);
    return 1;
  }

  if(argc > 3)
    libtest_arg2 = argv[3];

  if(argc > 4)
    libtest_arg3 = argv[4];

  if(argc > 5)
    libtest_arg4 = argv[5];

  URL = argv[2]; /* provide this to the rest */

  env = getenv("CURL_TESTNUM");
  if(env)
    testnum = atoi(env);
  else
    testnum = 0;

  curl_mfprintf(stderr, "URL: %s\n", URL);

  result = entry_func(URL);
  curl_mfprintf(stderr, "Test ended with result %d\n", result);

#ifdef _WIN32
  /* flush buffers of all streams regardless of mode */
  _flushall();
#endif

  /* Regular program status codes are limited to 0..127 and 126 and 127 have
   * special meanings by the shell, so limit a normal return code to 125 */
  return (int)result <= 125 ? (int)result : 125;
}
