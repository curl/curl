/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

/*
 * The purpose of this test is to minimally exercise libcurl's internal
 * curl_m*printf formatting capabilities and handling of some data types.
 */

#include "test.h"

int curl_msprintf(char *buffer, const char *format, ...);


#if (CURL_SIZEOF_CURL_OFF_T > 4)
#  if (CURL_SIZEOF_LONG > 4)
#    define MPRNT_SUFFIX_CURL_OFF_T  L
#  else
#    define MPRNT_SUFFIX_CURL_OFF_T  LL
#  endif
#else
#  if (CURL_SIZEOF_LONG > 2)
#    define MPRNT_SUFFIX_CURL_OFF_T  L
#  else
#    define MPRNT_SUFFIX_CURL_OFF_T  LL
#  endif
#endif

#ifdef CURL_ISOCPP
#  define MPRNT_OFF_T_C_HELPER2(Val,Suffix) Val ## Suffix
#else
#  define MPRNT_OFF_T_C_HELPER2(Val,Suffix) Val/**/Suffix
#endif
#define MPRNT_OFF_T_C_HELPER1(Val,Suffix) MPRNT_OFF_T_C_HELPER2(Val,Suffix)
#define MPRNT_OFF_T_C(Val)  MPRNT_OFF_T_C_HELPER1(Val,MPRNT_SUFFIX_CURL_OFF_T)


#define BUFSZ    256
#define NUM_ULONG_TESTS  4
#define NUM_SLONG_TESTS  7
#define NUM_COFFT_TESTS  7


struct unslong_st {
  unsigned long num;    /* unsigned long   */
  const char *expected; /* expected string */
  char result[BUFSZ];   /* result string   */
};


struct siglong_st {
  long num;             /* signed long     */
  const char *expected; /* expected string */
  char result[BUFSZ];   /* result string   */
};


struct curloff_st {
  curl_off_t num;       /* curl_off_t      */
  const char *expected; /* expected string */
  char result[BUFSZ];   /* result string   */
};


static struct unslong_st ul_test[NUM_ULONG_TESTS];
static struct siglong_st sl_test[NUM_SLONG_TESTS];
static struct curloff_st co_test[NUM_COFFT_TESTS];


static int test_unsigned_long_formatting(void)
{
  int i, j;
  int failed = 0;

  ul_test[0].num = 0x0L;
  ul_test[0].expected = "0";
  ul_test[1].num = 0x1L;
  ul_test[1].expected = "1";
#if (CURL_SIZEOF_LONG == 2)
  ul_test[2].num = 0xFFL;
  ul_test[2].expected = "255";
  ul_test[3].num = 0xFFFFL;
  ul_test[3].expected = "65535";
#elif (CURL_SIZEOF_LONG == 4)
  ul_test[2].num = 0xFFFFL;
  ul_test[2].expected = "65535";
  ul_test[3].num = 0xFFFFFFFFL;
  ul_test[3].expected = "4294967295";
#elif (CURL_SIZEOF_LONG == 8)
  ul_test[2].num = 0xFFFFFFFFL;
  ul_test[2].expected = "4294967295";
  ul_test[3].num = 0xFFFFFFFFFFFFFFFFL;
  ul_test[3].expected = "18446744073709551615";
#endif

  for(i=0; i<NUM_ULONG_TESTS; i++) {

    for(j=0; j<BUFSZ; j++)
      ul_test[i].result[j] = 'X';
    ul_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(ul_test[i].result, "%lu", ul_test[i].num);

    if(!memcmp(ul_test[i].result,
               ul_test[i].expected,
               strlen(ul_test[i].expected)))
      printf("unsigned long test #%d: OK\n", i+1);
    else {
      printf("unsigned long test #%d: Failed (Expected: %s Got: %s)\n",
             i+1, ul_test[i].expected, ul_test[i].result);
      failed++;
    }

  }

  return failed;
}


static int test_signed_long_formatting(void)
{
  int i, j;
  int failed = 0;

  sl_test[0].num = 0x0L;
  sl_test[0].expected = "0";
  sl_test[1].num = 0x1L;
  sl_test[1].expected = "1";
  sl_test[2].num = -0x1L;
  sl_test[2].expected = "-1";
#if (CURL_SIZEOF_LONG == 2)
  sl_test[3].num = 0x7FL;
  sl_test[3].expected = "127";
  sl_test[4].num = 0x7FFFL;
  sl_test[4].expected = "32767";
  sl_test[5].num = -0x7FL -1L;
  sl_test[5].expected = "-128";
  sl_test[6].num = -0x7FFFL -1L;
  sl_test[6].expected = "-32768";
#elif (CURL_SIZEOF_LONG == 4)
  sl_test[3].num = 0x7FFFL;
  sl_test[3].expected = "32767";
  sl_test[4].num = 0x7FFFFFFFL;
  sl_test[4].expected = "2147483647";
  sl_test[5].num = -0x7FFFL -1L;
  sl_test[5].expected = "-32768";
  sl_test[6].num = -0x7FFFFFFFL -1L;
  sl_test[6].expected = "-2147483648";
#elif (CURL_SIZEOF_LONG == 8)
  sl_test[3].num = 0x7FFFFFFFL;
  sl_test[3].expected = "2147483647";
  sl_test[4].num = 0x7FFFFFFFFFFFFFFFL;
  sl_test[4].expected = "9223372036854775807";
  sl_test[5].num = -0x7FFFFFFFL -1L;
  sl_test[5].expected = "-2147483648";
  sl_test[6].num = -0x7FFFFFFFFFFFFFFFL -1L;
  sl_test[6].expected = "-9223372036854775808";
#endif

  for(i=0; i<NUM_SLONG_TESTS; i++) {

    for(j=0; j<BUFSZ; j++)
      sl_test[i].result[j] = 'X';
    sl_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(sl_test[i].result, "%ld", sl_test[i].num);

    if(!memcmp(sl_test[i].result,
               sl_test[i].expected,
               strlen(sl_test[i].expected)))
      printf("signed long test #%d: OK\n", i+1);
    else {
      printf("signed long test #%d: Failed (Expected: %s Got: %s)\n",
             i+1, sl_test[i].expected, sl_test[i].result);
      failed++;
    }

  }

  return failed;
}


static int test_curl_off_t_formatting(void)
{
  int i, j;
  int failed = 0;

  co_test[0].num = MPRNT_OFF_T_C(0x0);
  co_test[0].expected = "0";
  co_test[1].num = MPRNT_OFF_T_C(0x1);
  co_test[1].expected = "1";
  co_test[2].num = -MPRNT_OFF_T_C(0x1);
  co_test[2].expected = "-1";
#if (CURL_SIZEOF_CURL_OFF_T == 2)
  co_test[3].num = MPRNT_OFF_T_C(0x7F);
  co_test[3].expected = "127";
  co_test[4].num = MPRNT_OFF_T_C(0x7FFF);
  co_test[4].expected = "32767";
  co_test[5].num = -MPRNT_OFF_T_C(0x7F) -MPRNT_OFF_T_C(1);
  co_test[5].expected = "-128";
  co_test[6].num = -MPRNT_OFF_T_C(0x7FFF) -MPRNT_OFF_T_C(1);
  co_test[6].expected = "-32768";
#elif (CURL_SIZEOF_CURL_OFF_T == 4)
  co_test[3].num = MPRNT_OFF_T_C(0x7FFF);
  co_test[3].expected = "32767";
  co_test[4].num = MPRNT_OFF_T_C(0x7FFFFFFF);
  co_test[4].expected = "2147483647";
  co_test[5].num = -MPRNT_OFF_T_C(0x7FFF) -MPRNT_OFF_T_C(1);
  co_test[5].expected = "-32768";
  co_test[6].num = -MPRNT_OFF_T_C(0x7FFFFFFF) -MPRNT_OFF_T_C(1);
  co_test[6].expected = "-2147483648";
#elif (CURL_SIZEOF_CURL_OFF_T == 8)
  co_test[3].num = MPRNT_OFF_T_C(0x7FFFFFFF);
  co_test[3].expected = "2147483647";
  co_test[4].num = MPRNT_OFF_T_C(0x7FFFFFFFFFFFFFFF);
  co_test[4].expected = "9223372036854775807";
  co_test[5].num = -MPRNT_OFF_T_C(0x7FFFFFFF) -MPRNT_OFF_T_C(1);
  co_test[5].expected = "-2147483648";
  co_test[6].num = -MPRNT_OFF_T_C(0x7FFFFFFFFFFFFFFF) -MPRNT_OFF_T_C(1);
  co_test[6].expected = "-9223372036854775808";
#endif

  for(i=0; i<NUM_COFFT_TESTS; i++) {

    for(j=0; j<BUFSZ; j++)
      co_test[i].result[j] = 'X';
    co_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(co_test[i].result, "%" FORMAT_OFF_T, co_test[i].num);

    if(!memcmp(co_test[i].result,
               co_test[i].expected,
               strlen(co_test[i].expected)))
      printf("curl_off_t test #%d: OK\n", i+1);
    else {
      printf("curl_off_t test #%d: Failed (Expected: %s Got: %s)\n",
             i+1, co_test[i].expected, co_test[i].result);
      failed++;
    }

  }

  return failed;
}


int test(char *URL)
{
  int errors = 0;
  (void)URL; /* not used */

  errors += test_unsigned_long_formatting();

  errors += test_signed_long_formatting();

  errors += test_curl_off_t_formatting();

  if(errors)
    return TEST_ERR_MAJOR_BAD;
  else
    return 0;
}
