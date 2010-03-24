/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

#ifdef HAVE_LOCALE_H
#include <locale.h> /* for setlocale() */
#endif

#ifdef CURLDEBUG
#  define MEMDEBUG_NODEFINES
#  include "memdebug.h"
#endif

int select_test (int num_fds, fd_set *rd, fd_set *wr, fd_set *exc,
                 struct timeval *tv)
{
#ifdef USE_WINSOCK
  /* Winsock doesn't like no socket set in 'rd', 'wr' or 'exc'. This is
   * case when 'num_fds <= 0. So sleep.
   */
  if (num_fds <= 0) {
    Sleep(1000*tv->tv_sec + tv->tv_usec/1000);
    return 0;
  }
#endif
  return select(num_fds, rd, wr, exc, tv);
}

char *libtest_arg2=NULL;
char *libtest_arg3=NULL;
int test_argc;
char **test_argv;


int main(int argc, char **argv)
{
  char *URL;

#ifdef CURLDEBUG
  /* this sends all memory debug messages to a logfile named memdump */
  char *env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as file name */
    char *s = strdup(env);
    curl_free(env);
    curl_memdebug(s);
    free(s);
    /* this weird strdup() and stuff here is to make the curl_free() get
       called before the memdebug() as otherwise the memdebug tracing will
       with tracing a free() without an alloc! */
  }
  /* this enables the fail-on-alloc-number-N functionality */
  env = curl_getenv("CURL_MEMLIMIT");
  if(env) {
    curl_memlimit(atoi(env));
    curl_free(env);
  }
#endif

  /*
   * Setup proper locale from environment. This is needed to enable locale-
   * specific behaviour by the C library in order to test for undesired side
   * effects that could cause in libcurl.
   */
#ifdef HAVE_SETLOCALE
  setlocale(LC_ALL, "");
#endif

  if(argc< 2 ) {
    fprintf(stderr, "Pass URL as argument please\n");
    return 1;
  }

  test_argc = argc;
  test_argv = argv;

  if(argc>2)
    libtest_arg2=argv[2];

  if(argc>3)
    libtest_arg3=argv[3];

  URL = argv[1]; /* provide this to the rest */

  fprintf(stderr, "URL: %s\n", URL);

  return test(URL);
}
