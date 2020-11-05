/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "test.h"

#ifdef HAVE_LOCALE_H
#  include <locale.h> /* for setlocale() */
#endif

#ifdef HAVE_IO_H
#  include <io.h> /* for setmode() */
#endif

#ifdef HAVE_FCNTL_H
#  include <fcntl.h> /* for setmode() */
#endif

#ifdef USE_NSS
#include <nspr.h>
#endif

#ifdef CURLDEBUG
#  define MEMDEBUG_NODEFINES
#  include "memdebug.h"
#endif

int select_wrapper(int nfds, fd_set *rd, fd_set *wr, fd_set *exc,
                   struct timeval *tv)
{
  if(nfds < 0) {
    SET_SOCKERRNO(EINVAL);
    return -1;
  }
#ifdef USE_WINSOCK
  /*
   * Winsock select() requires that at least one of the three fd_set
   * pointers is not NULL and points to a non-empty fdset. IOW Winsock
   * select() can not be used to sleep without a single fd_set.
   */
  if(!nfds) {
    Sleep((1000*tv->tv_sec) + (DWORD)(((double)tv->tv_usec)/1000.0));
    return 0;
  }
#endif
  return select(nfds, rd, wr, exc, tv);
}

void wait_ms(int ms)
{
  struct timeval t;
  t.tv_sec = ms/1000;
  ms -= (int)t.tv_sec * 1000;
  t.tv_usec = ms * 1000;
  select_wrapper(0, NULL, NULL, NULL, &t);
}

char *libtest_arg2 = NULL;
char *libtest_arg3 = NULL;
int test_argc;
char **test_argv;

struct timeval tv_test_start; /* for test timing */

#ifdef UNITTESTS
int unitfail; /* for unittests */
#endif

#ifdef CURLDEBUG
static void memory_tracking_init(void)
{
  char *env;
  /* if CURL_MEMDEBUG is set, this starts memory tracking message logging */
  env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as file name */
    char fname[CURL_MT_LOGFNAME_BUFSIZE];
    if(strlen(env) >= CURL_MT_LOGFNAME_BUFSIZE)
      env[CURL_MT_LOGFNAME_BUFSIZE-1] = '\0';
    strcpy(fname, env);
    curl_free(env);
    curl_dbg_memdebug(fname);
    /* this weird stuff here is to make curl_free() get called before
       curl_dbg_memdebug() as otherwise memory tracking will log a free()
       without an alloc! */
  }
  /* if CURL_MEMLIMIT is set, this enables fail-on-alloc-number-N feature */
  env = curl_getenv("CURL_MEMLIMIT");
  if(env) {
    char *endptr;
    long num = strtol(env, &endptr, 10);
    if((endptr != env) && (endptr == env + strlen(env)) && (num > 0))
      curl_dbg_memlimit(num);
    curl_free(env);
  }
}
#else
#  define memory_tracking_init() Curl_nop_stmt
#endif

/* returns a hexdump in a static memory area */
char *hexdump(const unsigned char *buffer, size_t len)
{
  static char dump[200 * 3 + 1];
  char *p = dump;
  size_t i;
  if(len > 200)
    return NULL;
  for(i = 0; i<len; i++, p += 3)
    msnprintf(p, 4, "%02x ", buffer[i]);
  return dump;
}


int main(int argc, char **argv)
{
  char *URL;
  int result;

#ifdef O_BINARY
#  ifdef __HIGHC__
  _setmode(stdout, O_BINARY);
#  else
  setmode(fileno(stdout), O_BINARY);
#  endif
#endif

  memory_tracking_init();

  /*
   * Setup proper locale from environment. This is needed to enable locale-
   * specific behaviour by the C library in order to test for undesired side
   * effects that could cause in libcurl.
   */
#ifdef HAVE_SETLOCALE
  setlocale(LC_ALL, "");
#endif

  if(argc< 2) {
    fprintf(stderr, "Pass URL as argument please\n");
    return 1;
  }

  test_argc = argc;
  test_argv = argv;

  if(argc>2)
    libtest_arg2 = argv[2];

  if(argc>3)
    libtest_arg3 = argv[3];

  URL = argv[1]; /* provide this to the rest */

  fprintf(stderr, "URL: %s\n", URL);

  result = test(URL);

#ifdef USE_NSS
  if(PR_Initialized())
    /* prevent valgrind from reporting possibly lost memory (fd cache, ...) */
    PR_Cleanup();
#endif

  return result;
}
