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

/* The fail macros mark the current test step as failed, and continue */
#define fail_if(expr, msg)                                             \
  do {                                                                 \
    if(expr) {                                                         \
      curl_mfprintf(stderr, "%s:%d FAILED Assertion '%s' met: %s\n",   \
                    __FILE__, __LINE__, #expr, msg);                   \
      unitfail++;                                                      \
    }                                                                  \
  } while(0)

#define fail_unless(expr, msg)                                   \
  do {                                                           \
    if(!(expr)) {                                                \
      curl_mfprintf(stderr, "%s:%d Assertion '%s' FAILED: %s\n", \
                    __FILE__, __LINE__, #expr, msg);             \
      unitfail++;                                                \
    }                                                            \
  } while(0)

#define verify_memory(dynamic, check, len)                                  \
  do {                                                                      \
    if(dynamic && memcmp(dynamic, check, len)) {                            \
      curl_mfprintf(stderr, "%s:%d Memory buffer FAILED match size %d. "    \
                    "'%s' is not\n", __FILE__, __LINE__, len,               \
                    hexdump((const unsigned char *)check, len));            \
      curl_mfprintf(stderr, "%s:%d the same as '%s'\n", __FILE__, __LINE__, \
                    hexdump((const unsigned char *)dynamic, len));          \
      unitfail++;                                                           \
    }                                                                       \
  } while(0)

/* fail() is for when the test case figured out by itself that a check
   proved a failure */
#define fail(msg) do {                                                  \
    curl_mfprintf(stderr, "%s:%d test FAILED: '%s'\n",                  \
                  __FILE__, __LINE__, msg);                             \
    unitfail++;                                                         \
  } while(0)

/* The abort macros mark the current test step as failed, and exit the test */
#define abort_if(expr, msg)                                           \
  do {                                                                \
    if(expr) {                                                        \
      curl_mfprintf(stderr, "%s:%d ABORT assertion '%s' met: %s\n",   \
                    __FILE__, __LINE__, #expr, msg);                  \
      unitfail++;                                                     \
      goto unit_test_abort;                                           \
    }                                                                 \
  } while(0)

#define abort_unless(expr, msg)                                         \
  do {                                                                  \
    if(!(expr)) {                                                       \
      curl_mfprintf(stderr, "%s:%d ABORT assertion '%s' failed: %s\n",  \
                    __FILE__, __LINE__, #expr, msg);                    \
      unitfail++;                                                       \
      goto unit_test_abort;                                             \
    }                                                                   \
  } while(0)

#define unittest_abort(msg)                                         \
  do {                                                              \
    curl_mfprintf(stderr, "%s:%d test ABORTED: '%s'\n",             \
                  __FILE__, __LINE__, msg);                         \
    unitfail++;                                                     \
    goto unit_test_abort;                                           \
  } while(0)


#define UNITTEST_BEGIN_SIMPLE                   \
  (void)arg;                                    \
  {

#define UNITTEST_END_SIMPLE                     \
    goto unit_test_abort; /* avoid warning */   \
  }                                             \
unit_test_abort:                                \
  return (CURLcode)unitfail;

#define UNITTEST_BEGIN(setupfunc)               \
  (void)arg;                                    \
  if(setupfunc) {                               \
    fail("unit_setup() FAILURE");               \
    return (CURLcode)unitfail;                  \
  }                                             \
  {

#define UNITTEST_END(stopfunc)                  \
    goto unit_test_abort; /* avoid warning */   \
  }                                             \
unit_test_abort:                                \
  stopfunc;                                     \
  return (CURLcode)unitfail;
