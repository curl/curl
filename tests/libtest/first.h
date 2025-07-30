#ifndef HEADER_LIBTEST_FIRST_H
#define HEADER_LIBTEST_FIRST_H
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
#define CURL_NO_OLDIES
#define CURL_DISABLE_DEPRECATION

/* Now include the curl_setup.h file from libcurl's private libdir (the source
   version, but that might include "curl_config.h" from the build dir so we
   need both of them in the include path), so that we get good in-depth
   knowledge about the system we're building this on */
#include "curl_setup.h"

#include <curl/curl.h>

typedef CURLcode (*entry_func_t)(const char *);

struct entry_s {
  const char *name;
  entry_func_t ptr;
};

extern const struct entry_s s_entries[];

extern int unitfail; /* for unittests */

#include <curlx/curlx.h>

#ifdef HAVE_SYS_SELECT_H
/* since so many tests use select(), we can just as well include it here */
#include <sys/select.h>
#endif

#include "curl_printf.h"

/* GCC <4.6 does not support '#pragma GCC diagnostic push' and
   does not support 'pragma GCC diagnostic' inside functions. */
#if (defined(__GNUC__) && \
  ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 6))))
#define CURL_GNUC_DIAG
#endif

#define test_setopt(A,B,C)                                      \
  if((res = curl_easy_setopt((A), (B), (C))) != CURLE_OK)       \
    goto test_cleanup

#define test_multi_setopt(A,B,C)                                \
  if((res = curl_multi_setopt((A), (B), (C))) != CURLE_OK)      \
    goto test_cleanup

extern const char *libtest_arg2; /* set by first.c to the argv[2] or NULL */
extern const char *libtest_arg3; /* set by first.c to the argv[3] or NULL */
extern const char *libtest_arg4; /* set by first.c to the argv[4] or NULL */

/* argc and argv as passed in to the main() function */
extern int test_argc;
extern const char **test_argv;
extern int testnum;
extern struct curltime tv_test_start; /* for test timing */

extern int coptind;
extern const char *coptarg;
int cgetopt(int argc, const char * const argv[], const char *optstring);

extern int select_wrapper(int nfds, fd_set *rd, fd_set *wr, fd_set *exc,
                          struct timeval *tv);

extern char *hexdump(const unsigned char *buffer, size_t len);

#ifndef CURL_DISABLE_WEBSOCKETS
CURLcode ws_send_ping(CURL *curl, const char *send_payload);
CURLcode ws_recv_pong(CURL *curl, const char *expected_payload);
/* just close the connection */
void ws_close(CURL *curl);
#endif

/*
** TEST_ERR_* values must within the CURLcode range to not cause compiler
** errors.

** For portability reasons TEST_ERR_* values should be less than 127.
*/

#define TEST_ERR_MAJOR_BAD     CURLE_OBSOLETE20
#define TEST_ERR_RUNS_FOREVER  CURLE_OBSOLETE24
#define TEST_ERR_EASY_INIT     CURLE_OBSOLETE29
#define TEST_ERR_MULTI         CURLE_OBSOLETE32
#define TEST_ERR_NUM_HANDLES   CURLE_OBSOLETE34
#define TEST_ERR_SELECT        CURLE_OBSOLETE40
#define TEST_ERR_SUCCESS       CURLE_OBSOLETE41
#define TEST_ERR_FAILURE       CURLE_OBSOLETE44
#define TEST_ERR_USAGE         CURLE_OBSOLETE46
#define TEST_ERR_FOPEN         CURLE_OBSOLETE50
#define TEST_ERR_FSTAT         CURLE_OBSOLETE51
#define TEST_ERR_BAD_TIMEOUT   CURLE_OBSOLETE57

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

#define exe_easy_init(A,Y,Z) do {                                       \
  if(((A) = curl_easy_init()) == NULL) {                                \
    curl_mfprintf(stderr, "%s:%d curl_easy_init() failed\n", (Y), (Z)); \
    res = TEST_ERR_EASY_INIT;                                           \
  }                                                                     \
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

#define exe_multi_init(A,Y,Z) do {                                       \
  if(((A) = curl_multi_init()) == NULL) {                                \
    curl_mfprintf(stderr, "%s:%d curl_multi_init() failed\n", (Y), (Z)); \
    res = TEST_ERR_MULTI;                                                \
  }                                                                      \
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

#define exe_easy_setopt(A,B,C,Y,Z) do {                       \
  CURLcode ec;                                                \
  if((ec = curl_easy_setopt((A), (B), (C))) != CURLE_OK) {    \
    curl_mfprintf(stderr, "%s:%d curl_easy_setopt() failed, " \
                  "with code %d (%s)\n",                      \
                  (Y), (Z), ec, curl_easy_strerror(ec));      \
    res = ec;                                                 \
  }                                                           \
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

#define exe_multi_setopt(A, B, C, Y, Z) do {                   \
  CURLMcode ec;                                                \
  if((ec = curl_multi_setopt((A), (B), (C))) != CURLM_OK) {    \
    curl_mfprintf(stderr, "%s:%d curl_multi_setopt() failed, " \
                  "with code %d (%s)\n",                       \
                  (Y), (Z), ec, curl_multi_strerror(ec));      \
    res = TEST_ERR_MULTI;                                      \
  }                                                            \
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

#define exe_multi_add_handle(A,B,Y,Z) do {                         \
  CURLMcode ec;                                                    \
  if((ec = curl_multi_add_handle((A), (B))) != CURLM_OK) {         \
    curl_mfprintf(stderr, "%s:%d curl_multi_add_handle() failed, " \
                  "with code %d (%s)\n",                           \
                  (Y), (Z), ec, curl_multi_strerror(ec));          \
    res = TEST_ERR_MULTI;                                          \
  }                                                                \
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

#define exe_multi_remove_handle(A,B,Y,Z) do {                         \
  CURLMcode ec;                                                       \
  if((ec = curl_multi_remove_handle((A), (B))) != CURLM_OK) {         \
    curl_mfprintf(stderr, "%s:%d curl_multi_remove_handle() failed, " \
                  "with code %d (%s)\n",                              \
                  (Y), (Z), ec, curl_multi_strerror(ec));             \
    res = TEST_ERR_MULTI;                                             \
  }                                                                   \
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

#define exe_multi_perform(A,B,Y,Z) do {                                \
  CURLMcode ec;                                                        \
  if((ec = curl_multi_perform((A), (B))) != CURLM_OK) {                \
    curl_mfprintf(stderr, "%s:%d curl_multi_perform() failed, "        \
                  "with code %d (%s)\n",                               \
                  (Y), (Z), ec, curl_multi_strerror(ec));              \
    res = TEST_ERR_MULTI;                                              \
  }                                                                    \
  else if(*((B)) < 0) {                                                \
    curl_mfprintf(stderr, "%s:%d curl_multi_perform() succeeded, "     \
                  "but returned invalid running_handles value (%d)\n", \
                  (Y), (Z), (int)*((B)));                              \
    res = TEST_ERR_NUM_HANDLES;                                        \
  }                                                                    \
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
    curl_mfprintf(stderr, "%s:%d curl_multi_fdset() failed, "        \
                  "with code %d (%s)\n",                             \
                  (Y), (Z), ec, curl_multi_strerror(ec));            \
    res = TEST_ERR_MULTI;                                            \
  }                                                                  \
  else if(*((E)) < -1) {                                             \
    curl_mfprintf(stderr, "%s:%d curl_multi_fdset() succeeded, "     \
                  "but returned invalid max_fd value (%d)\n",        \
                  (Y), (Z), (int)*((E)));                            \
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

#define exe_multi_timeout(A,B,Y,Z) do {                            \
  CURLMcode ec;                                                    \
  if((ec = curl_multi_timeout((A), (B))) != CURLM_OK) {            \
    curl_mfprintf(stderr, "%s:%d curl_multi_timeout() failed, "    \
                  "with code %d (%s)\n",                           \
                  (Y), (Z), ec, curl_multi_strerror(ec));          \
    res = TEST_ERR_BAD_TIMEOUT;                                    \
  }                                                                \
  else if(*((B)) < -1L) {                                          \
    curl_mfprintf(stderr, "%s:%d curl_multi_timeout() succeeded, " \
                  "but returned invalid timeout value (%ld)\n",    \
                  (Y), (Z), (long)*((B)));                         \
    res = TEST_ERR_BAD_TIMEOUT;                                    \
  }                                                                \
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
    curl_mfprintf(stderr, "%s:%d curl_multi_poll() failed, "        \
                  "with code %d (%s)\n",                            \
                  (Y), (Z), ec, curl_multi_strerror(ec));           \
    res = TEST_ERR_MULTI;                                           \
  }                                                                 \
  else if(*((E)) < 0) {                                             \
    curl_mfprintf(stderr, "%s:%d curl_multi_poll() succeeded, "     \
                  "but returned invalid numfds value (%d)\n",       \
                  (Y), (Z), (int)*((E)));                           \
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

#define exe_multi_wakeup(A,Y,Z) do {                           \
  CURLMcode ec;                                                \
  if((ec = curl_multi_wakeup((A))) != CURLM_OK) {              \
    curl_mfprintf(stderr, "%s:%d curl_multi_wakeup() failed, " \
                  "with code %d (%s)\n",                       \
                  (Y), (Z), ec, curl_multi_strerror(ec));      \
    res = TEST_ERR_MULTI;                                      \
  }                                                            \
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

#define exe_select_test(A, B, C, D, E, Y, Z) do {          \
    int ec;                                                \
    if(select_wrapper((A), (B), (C), (D), (E)) == -1) {    \
      ec = SOCKERRNO;                                      \
      curl_mfprintf(stderr, "%s:%d select() failed, with " \
                    "errno %d (%s)\n",                     \
                    (Y), (Z), ec, strerror(ec));           \
      res = TEST_ERR_SELECT;                               \
    }                                                      \
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
  tv_test_start = curlx_now(); \
} while(0)

#define TEST_HANG_TIMEOUT 60 * 1000  /* global default */

#define exe_test_timedout(T,Y,Z) do {                                   \
  timediff_t timediff = curlx_timediff(curlx_now(), tv_test_start);     \
  if(timediff > (T)) {                                                  \
    curl_mfprintf(stderr, "%s:%d ABORTING TEST, since it seems "        \
                  "that it would have run forever (%ld ms > %ld ms)\n", \
                  (Y), (Z), (long)timediff, (long)(TEST_HANG_TIMEOUT)); \
    res = TEST_ERR_RUNS_FOREVER;                                        \
  }                                                                     \
} while(0)

#define res_test_timedout() \
  exe_test_timedout(TEST_HANG_TIMEOUT, (__FILE__), (__LINE__))

#define res_test_timedout_custom(T) \
  exe_test_timedout((T), (__FILE__), (__LINE__))

#define chk_test_timedout(T, Y, Z) do { \
    exe_test_timedout(T, Y, Z);         \
    if(res)                             \
      goto test_cleanup;                \
  } while(0)

#define abort_on_test_timeout() \
  chk_test_timedout(TEST_HANG_TIMEOUT, (__FILE__), (__LINE__))

#define abort_on_test_timeout_custom(T) \
  chk_test_timedout((T), (__FILE__), (__LINE__))

/* ---------------------------------------------------------------- */

#define exe_global_init(A,Y,Z) do {                           \
  CURLcode ec;                                                \
  if((ec = curl_global_init((A))) != CURLE_OK) {              \
    curl_mfprintf(stderr, "%s:%d curl_global_init() failed, " \
                  "with code %d (%s)\n",                      \
                  (Y), (Z), ec, curl_easy_strerror(ec));      \
    res = ec;                                                 \
  }                                                           \
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
  {                                             \
    (void)URL;                                  \
    curl_mfprintf(stderr, "Missing support\n"); \
    return CURLE_UNSUPPORTED_PROTOCOL;          \
  }

#define NUM_HANDLES 4  /* global default */

#endif /* HEADER_LIBTEST_FIRST_H */
