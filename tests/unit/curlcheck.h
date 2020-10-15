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
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

/* The fail macros mark the current test step as failed, and continue */
#define fail_if(expr, msg)                              \
  if(expr) {                                            \
    fprintf(stderr, "%s:%d Assertion '%s' met: %s\n",   \
            __FILE__, __LINE__, #expr, msg);            \
    unitfail++;                                         \
  }

#define fail_unless(expr, msg)                           \
  if(!(expr)) {                                          \
    fprintf(stderr, "%s:%d Assertion '%s' failed: %s\n", \
            __FILE__, __LINE__, #expr, msg);             \
    unitfail++;                                          \
  }

#define verify_memory(dynamic, check, len)                                  \
  if(dynamic && memcmp(dynamic, check, len)) {                              \
    fprintf(stderr, "%s:%d Memory buffer mismatch size %d. '%s' is not\n",  \
            __FILE__, __LINE__, len,                                        \
            hexdump((const unsigned char *)check, len));                    \
    fprintf(stderr, "%s:%d the same as '%s'\n", __FILE__, __LINE__,         \
            hexdump((const unsigned char *)dynamic, len));                  \
    unitfail++;                                                             \
  }

/* fail() is for when the test case figured out by itself that a check
   proved a failure */
#define fail(msg) do {                                                 \
    fprintf(stderr, "%s:%d test failed: '%s'\n",                       \
            __FILE__, __LINE__, msg);                                  \
    unitfail++;                                                        \
  } while(0)


/* The abort macros mark the current test step as failed, and exit the test */
#define abort_if(expr, msg)                                   \
  if(expr) {                                                  \
    fprintf(stderr, "%s:%d Abort assertion '%s' met: %s\n",   \
            __FILE__, __LINE__, #expr, msg);                  \
    unitfail++;                                               \
    goto unit_test_abort;                                     \
  }

#define abort_unless(expr, msg)                                \
  if(!(expr)) {                                                \
    fprintf(stderr, "%s:%d Abort assertion '%s' failed: %s\n", \
            __FILE__, __LINE__, #expr, msg);                   \
    unitfail++;                                                \
    goto unit_test_abort;                                      \
  }

#define abort_test(msg) do {                                  \
    fprintf(stderr, "%s:%d test aborted: '%s'\n",             \
            __FILE__, __LINE__, msg);                         \
    unitfail++;                                               \
    goto unit_test_abort;                                     \
  } while(0)



extern int unitfail;

#define UNITTEST_START                          \
  int test(char *arg)                           \
  {                                             \
    (void)arg;                                  \
    if(unit_setup()) {                          \
      fail("unit_setup() failure");             \
    }                                           \
    else {

#define UNITTEST_STOP                           \
    goto unit_test_abort; /* avoid warning */   \
unit_test_abort:                                \
    unit_stop();                                \
  }                                             \
  return unitfail;                              \
  }
