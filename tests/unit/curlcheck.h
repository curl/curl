/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

#define fail_if(expr, msg)                              \
  if(expr) {                                            \
    fprintf(stderr, "%s:%d Assertion '%s' met: %s\n" ,  \
            __FILE__, __LINE__, #expr, msg);            \
    unitfail++;                                         \
  }

#define fail_unless(expr, msg)                           \
  if(!(expr)) {                                          \
    fprintf(stderr, "%s:%d Assertion '%s' failed: %s\n", \
            __FILE__, __LINE__, #expr, msg);             \
    unitfail++;                                          \
  }

#define verify_memory(dynamic, check, len)                              \
  if(memcmp(dynamic, check, len)) {                                     \
    fprintf(stderr, "%s:%d The dynamic string didn't match '%s'\n",     \
            __FILE__, __LINE__, check);                                 \
    unitfail++;                                                         \
  }

extern int unitfail;

#define UNITTEST_START                          \
  int test(char *unused)                        \
  {                                             \
  (void)unused;                                 \
  unit_setup();                                 \
  {

#define UNITTEST_STOP                           \
  }                                             \
  unit_stop();                                  \
  return unitfail;                              \
  }

