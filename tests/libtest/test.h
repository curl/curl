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

/* Now include the curl_setup.h file from libcurl's private libdir (the source
   version, but that might include "curl_config.h" from the build dir so we
   need both of them in the include path), so that we get good in-depth
   knowledge about the system we're building this on */

#define CURL_NO_OLDIES

#include "curl_setup.h"

#include <curl/curl.h>

#ifdef HAVE_SYS_SELECT_H
/* since so many tests use select(), we can just as well include it here */
#include <sys/select.h>
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#include "curl_printf.h"

#ifdef _WIN32
#define sleep(sec) Sleep ((sec)*1000)
#endif

#define test_setopt(A,B,C)                                      \
  if((res = curl_easy_setopt((A), (B), (C))) != CURLE_OK)       \
    goto test_cleanup

#define test_multi_setopt(A,B,C)                                \
  if((res = curl_multi_setopt((A), (B), (C))) != CURLE_OK)      \
    goto test_cleanup

extern char *libtest_arg2; /* set by first.c to the argv[2] or NULL */
extern char *libtest_arg3; /* set by first.c to the argv[3] or NULL */

/* argc and argv as passed in to the main() function */
extern int test_argc;
extern char **test_argv;

extern struct timeval tv_test_start; /* for test timing */

extern int select_wrapper(int nfds, fd_set *rd, fd_set *wr, fd_set *exc,
                          struct timeval *tv);

extern void wait_ms(int ms); /* wait this many milliseconds */

extern int test(char *URL); /* the actual test function provided by each
                               individual libXXX.c file */

extern char *hexdump(const unsigned char *buffer, size_t len);

extern int unitfail;

/*
** TEST_ERR_* values must be greater than CURL_LAST CURLcode in order
** to avoid confusion with any CURLcode or CURLMcode. These TEST_ERR_*
** codes are returned to signal test specific situations and should
** not get mixed with CURLcode or CURLMcode values.
**
** For portability reasons TEST_ERR_* values should be less than 127.
*/

#define TEST_ERR_MAJOR_BAD     (CURLcode) 126
#define TEST_ERR_RUNS_FOREVER  (CURLcode) 125
#define TEST_ERR_EASY_INIT     (CURLcode) 124
#define TEST_ERR_MULTI         (CURLcode) 123
#define TEST_ERR_NUM_HANDLES   (CURLcode) 122
#define TEST_ERR_SELECT        (CURLcode) 121
#define TEST_ERR_SUCCESS       (CURLcode) 120
#define TEST_ERR_FAILURE       (CURLcode) 119
#define TEST_ERR_USAGE         (CURLcode) 118
#define TEST_ERR_FOPEN         (CURLcode) 117
#define TEST_ERR_FSTAT         (CURLcode) 116
#define TEST_ERR_BAD_TIMEOUT   (CURLcode) 115

/*
** Macros for test source code readability/maintainability.
**
** All of the following macros require that an int data type 'res' variable
** exists in scope where macro is used, and that it has been initialized to
** zero before the macro is used.
**
** exe_* and chk_* macros are helper macros not intended to be used from
** outside of this header file. Arguments 'Y' and 'Z' of these represent
** source code file and line number, while Arguments 'A', 'B', etc, are
** the arguments used to actually call a libcurl function.
**
** All easy_* and multi_* macros call a libcurl function and evaluate if
** the function has succeeded or failed. When the function succeeds 'res'
** variable is not set nor cleared and program continues normal flow. On
** the other hand if function fails 'res' variable is set and a jump to
** label 'test_cleanup' is performed.
**
** Every easy_* and multi_* macros have a res_easy_* and res_multi_* macro
** counterpart that operates in the same way with the exception that no
** jump takes place in case of failure. res_easy_* and res_multi_* macros
** should be immediately followed by checking if 'res' variable has been
** set.
**
** 'res' variable when set will hold a CURLcode, CURLMcode, or any of the
** TEST_ERR_* values defined above. It is advisable to return this value
** as test result.
*/

/* ---------------------------------------------------------------- */

#define exe_easy_init(A,Y,Z) do {                                 \
  if(((A) = curl_easy_init()) == NULL) {                          \
    fprintf(stderr, "%s:%d curl_easy_init() failed\n", (Y), (Z)); \
    res = TEST_ERR_EASY_INIT;                                     \
  }                                                               \
} while(0)

#define res_easy_init(A) \
  exe_easy_init((A), (__FILE__), (__LINE__))

#define chk_easy_init(A,Y,Z) do { \
  exe_easy_init((A), (Y), (Z));   \
  if(res)                         \
    goto test_cleanup;            \
} while(0)

#define easy_init(A) \
  chk_easy_init((A), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_init(A,Y,Z) do {                                 \
  if(((A) = curl_multi_init()) == NULL) {                          \
    fprintf(stderr, "%s:%d curl_multi_init() failed\n", (Y), (Z)); \
    res = TEST_ERR_MULTI;                                          \
  }                                                                \
} while(0)

#define res_multi_init(A) \
  exe_multi_init((A), (__FILE__), (__LINE__))

#define chk_multi_init(A,Y,Z) do { \
  exe_multi_init((A), (Y), (Z));   \
  if(res)                          \
    goto test_cleanup;             \
} while(0)

#define multi_init(A) \
  chk_multi_init((A), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_easy_setopt(A,B,C,Y,Z) do {                    \
  CURLcode ec;                                             \
  if((ec = curl_easy_setopt((A), (B), (C))) != CURLE_OK) { \
    fprintf(stderr, "%s:%d curl_easy_setopt() failed, "    \
            "with code %d (%s)\n",                         \
            (Y), (Z), (int)ec, curl_easy_strerror(ec));    \
    res = ec;                                              \
  }                                                        \
} while(0)

#define res_easy_setopt(A, B, C) \
  exe_easy_setopt((A), (B), (C), (__FILE__), (__LINE__))

#define chk_easy_setopt(A, B, C, Y, Z) do { \
  exe_easy_setopt((A), (B), (C), (Y), (Z)); \
  if(res)                                   \
    goto test_cleanup;                      \
} while(0)

#define easy_setopt(A, B, C) \
  chk_easy_setopt((A), (B), (C), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_setopt(A, B, C, Y, Z) do {                \
  CURLMcode ec;                                             \
  if((ec = curl_multi_setopt((A), (B), (C))) != CURLM_OK) { \
    fprintf(stderr, "%s:%d curl_multi_setopt() failed, "    \
            "with code %d (%s)\n",                          \
            (Y), (Z), (int)ec, curl_multi_strerror(ec));    \
    res = TEST_ERR_MULTI;                                   \
  }                                                         \
} while(0)

#define res_multi_setopt(A,B,C) \
  exe_multi_setopt((A), (B), (C), (__FILE__), (__LINE__))

#define chk_multi_setopt(A,B,C,Y,Z) do {     \
  exe_multi_setopt((A), (B), (C), (Y), (Z)); \
  if(res)                                    \
    goto test_cleanup;                       \
} while(0)

#define multi_setopt(A,B,C) \
  chk_multi_setopt((A), (B), (C), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_add_handle(A,B,Y,Z) do {                   \
  CURLMcode ec;                                              \
  if((ec = curl_multi_add_handle((A), (B))) != CURLM_OK) {   \
    fprintf(stderr, "%s:%d curl_multi_add_handle() failed, " \
            "with code %d (%s)\n",                           \
            (Y), (Z), (int)ec, curl_multi_strerror(ec));     \
    res = TEST_ERR_MULTI;                                    \
  }                                                          \
} while(0)

#define res_multi_add_handle(A, B) \
  exe_multi_add_handle((A), (B), (__FILE__), (__LINE__))

#define chk_multi_add_handle(A, B, Y, Z) do { \
  exe_multi_add_handle((A), (B), (Y), (Z));   \
  if(res)                                     \
    goto test_cleanup;                        \
} while(0)

#define multi_add_handle(A, B) \
  chk_multi_add_handle((A), (B), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_remove_handle(A,B,Y,Z) do {                   \
  CURLMcode ec;                                                 \
  if((ec = curl_multi_remove_handle((A), (B))) != CURLM_OK) {   \
    fprintf(stderr, "%s:%d curl_multi_remove_handle() failed, " \
            "with code %d (%s)\n",                              \
            (Y), (Z), (int)ec, curl_multi_strerror(ec));        \
    res = TEST_ERR_MULTI;                                       \
  }                                                             \
} while(0)

#define res_multi_remove_handle(A, B) \
  exe_multi_remove_handle((A), (B), (__FILE__), (__LINE__))

#define chk_multi_remove_handle(A, B, Y, Z) do { \
  exe_multi_remove_handle((A), (B), (Y), (Z));   \
  if(res)                                        \
    goto test_cleanup;                           \
} while(0)


#define multi_remove_handle(A, B) \
  chk_multi_remove_handle((A), (B), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_perform(A,B,Y,Z) do {                          \
  CURLMcode ec;                                                  \
  if((ec = curl_multi_perform((A), (B))) != CURLM_OK) {          \
    fprintf(stderr, "%s:%d curl_multi_perform() failed, "        \
            "with code %d (%s)\n",                               \
            (Y), (Z), (int)ec, curl_multi_strerror(ec));         \
    res = TEST_ERR_MULTI;                                        \
  }                                                              \
  else if(*((B)) < 0) {                                          \
    fprintf(stderr, "%s:%d curl_multi_perform() succeeded, "     \
            "but returned invalid running_handles value (%d)\n", \
            (Y), (Z), (int)*((B)));                              \
    res = TEST_ERR_NUM_HANDLES;                                  \
  }                                                              \
} while(0)

#define res_multi_perform(A, B) \
  exe_multi_perform((A), (B), (__FILE__), (__LINE__))

#define chk_multi_perform(A, B, Y, Z) do { \
  exe_multi_perform((A), (B), (Y), (Z));   \
  if(res)                                  \
    goto test_cleanup;                     \
} while(0)

#define multi_perform(A,B) \
  chk_multi_perform((A), (B), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_fdset(A, B, C, D, E, Y, Z) do {                    \
  CURLMcode ec;                                                      \
  if((ec = curl_multi_fdset((A), (B), (C), (D), (E))) != CURLM_OK) { \
    fprintf(stderr, "%s:%d curl_multi_fdset() failed, "              \
            "with code %d (%s)\n",                                   \
            (Y), (Z), (int)ec, curl_multi_strerror(ec));             \
    res = TEST_ERR_MULTI;                                            \
  }                                                                  \
  else if(*((E)) < -1) {                                             \
    fprintf(stderr, "%s:%d curl_multi_fdset() succeeded, "           \
            "but returned invalid max_fd value (%d)\n",              \
            (Y), (Z), (int)*((E)));                                  \
    res = TEST_ERR_NUM_HANDLES;                                      \
  }                                                                  \
} while(0)

#define res_multi_fdset(A, B, C, D, E) \
  exe_multi_fdset((A), (B), (C), (D), (E), (__FILE__), (__LINE__))

#define chk_multi_fdset(A, B, C, D, E, Y, Z) do {       \
    exe_multi_fdset((A), (B), (C), (D), (E), (Y), (Z)); \
    if(res)                                             \
      goto test_cleanup;                                \
  } while(0)

#define multi_fdset(A, B, C, D, E) \
  chk_multi_fdset((A), (B), (C), (D), (E), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_timeout(A,B,Y,Z) do {                      \
  CURLMcode ec;                                              \
  if((ec = curl_multi_timeout((A), (B))) != CURLM_OK) {      \
    fprintf(stderr, "%s:%d curl_multi_timeout() failed, "    \
            "with code %d (%s)\n",                           \
            (Y), (Z), (int)ec, curl_multi_strerror(ec));     \
    res = TEST_ERR_BAD_TIMEOUT;                              \
  }                                                          \
  else if(*((B)) < -1L) {                                    \
    fprintf(stderr, "%s:%d curl_multi_timeout() succeeded, " \
            "but returned invalid timeout value (%ld)\n",    \
            (Y), (Z), (long)*((B)));                         \
    res = TEST_ERR_BAD_TIMEOUT;                              \
  }                                                          \
} while(0)

#define res_multi_timeout(A, B) \
  exe_multi_timeout((A), (B), (__FILE__), (__LINE__))

#define chk_multi_timeout(A, B, Y, Z) do { \
    exe_multi_timeout((A), (B), (Y), (Z)); \
    if(res)                                \
      goto test_cleanup;                   \
  } while(0)

#define multi_timeout(A, B) \
  chk_multi_timeout((A), (B), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_poll(A,B,C,D,E,Y,Z) do {                          \
  CURLMcode ec;                                                     \
  if((ec = curl_multi_poll((A), (B), (C), (D), (E))) != CURLM_OK) { \
    fprintf(stderr, "%s:%d curl_multi_poll() failed, "              \
            "with code %d (%s)\n",                                  \
            (Y), (Z), (int)ec, curl_multi_strerror(ec));            \
    res = TEST_ERR_MULTI;                                           \
  }                                                                 \
  else if(*((E)) < 0) {                                             \
    fprintf(stderr, "%s:%d curl_multi_poll() succeeded, "           \
            "but returned invalid numfds value (%d)\n",             \
            (Y), (Z), (int)*((E)));                                 \
    res = TEST_ERR_NUM_HANDLES;                                     \
  }                                                                 \
} while(0)

#define res_multi_poll(A, B, C, D, E) \
  exe_multi_poll((A), (B), (C), (D), (E), (__FILE__), (__LINE__))

#define chk_multi_poll(A, B, C, D, E, Y, Z) do {     \
  exe_multi_poll((A), (B), (C), (D), (E), (Y), (Z)); \
  if(res)                                            \
    goto test_cleanup;                               \
} while(0)

#define multi_poll(A, B, C, D, E) \
  chk_multi_poll((A), (B), (C), (D), (E), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_multi_wakeup(A,Y,Z) do {                     \
  CURLMcode ec;                                          \
  if((ec = curl_multi_wakeup((A))) != CURLM_OK) {        \
    fprintf(stderr, "%s:%d curl_multi_wakeup() failed, " \
            "with code %d (%s)\n",                       \
            (Y), (Z), (int)ec, curl_multi_strerror(ec)); \
    res = TEST_ERR_MULTI;                                \
  }                                                      \
} while(0)

#define res_multi_wakeup(A) \
  exe_multi_wakeup((A), (__FILE__), (__LINE__))

#define chk_multi_wakeup(A, Y, Z) do { \
  exe_multi_wakeup((A), (Y), (Z));     \
  if(res)                              \
    goto test_cleanup;                 \
} while(0)

#define multi_wakeup(A) \
  chk_multi_wakeup((A), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_select_test(A, B, C, D, E, Y, Z) do {               \
    int ec;                                                     \
    if(select_wrapper((A), (B), (C), (D), (E)) == -1) {         \
      ec = SOCKERRNO;                                           \
      fprintf(stderr, "%s:%d select() failed, with "            \
              "errno %d (%s)\n",                                \
              (Y), (Z), ec, strerror(ec));                      \
      res = TEST_ERR_SELECT;                                    \
    }                                                           \
  } while(0)

#define res_select_test(A, B, C, D, E) \
  exe_select_test((A), (B), (C), (D), (E), (__FILE__), (__LINE__))

#define chk_select_test(A, B, C, D, E, Y, Z) do {       \
    exe_select_test((A), (B), (C), (D), (E), (Y), (Z)); \
    if(res)                                             \
      goto test_cleanup;                                \
  } while(0)

#define select_test(A, B, C, D, E) \
  chk_select_test((A), (B), (C), (D), (E), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define start_test_timing() do { \
  tv_test_start = tutil_tvnow(); \
} while(0)

#define exe_test_timedout(Y,Z) do {                                       \
  long timediff = tutil_tvdiff(tutil_tvnow(), tv_test_start);             \
  if(timediff > (TEST_HANG_TIMEOUT)) {                                    \
    fprintf(stderr, "%s:%d ABORTING TEST, since it seems "                \
            "that it would have run forever (%ld ms > %ld ms)\n",         \
            (Y), (Z), timediff, (long) (TEST_HANG_TIMEOUT));              \
    res = TEST_ERR_RUNS_FOREVER;                                          \
  }                                                                       \
} while(0)

#define res_test_timedout() \
  exe_test_timedout((__FILE__), (__LINE__))

#define chk_test_timedout(Y, Z) do { \
    exe_test_timedout(Y, Z);         \
    if(res)                          \
      goto test_cleanup;             \
  } while(0)

#define abort_on_test_timeout() \
  chk_test_timedout((__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_global_init(A,Y,Z) do {                     \
  CURLcode ec;                                          \
  if((ec = curl_global_init((A))) != CURLE_OK) {        \
    fprintf(stderr, "%s:%d curl_global_init() failed, " \
            "with code %d (%s)\n",                      \
            (Y), (Z), (int)ec, curl_easy_strerror(ec)); \
    res = ec;                                           \
  }                                                     \
} while(0)

#define res_global_init(A) \
  exe_global_init((A), (__FILE__), (__LINE__))

#define chk_global_init(A, Y, Z) do { \
    exe_global_init((A), (Y), (Z));   \
    if(res)                           \
      return res;                     \
  } while(0)

/* global_init() is different than other macros. In case of
   failure it 'return's instead of going to 'test_cleanup'. */

#define global_init(A) \
  chk_global_init((A), (__FILE__), (__LINE__))

#define NO_SUPPORT_BUILT_IN                     \
  int test(char *URL)                           \
  {                                             \
    (void)URL;                                  \
    fprintf(stderr, "Missing support\n");       \
    return 1;                                   \
  }

/* ---------------------------------------------------------------- */
