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

/*
 * The purpose of this test is to minimally exercise libcurl's internal
 * curl_m*printf formatting capabilities and handling of some data types.
 */

#include "test.h"

#include <limits.h>

#ifdef HAVE_LOCALE_H
#  include <locale.h> /* for setlocale() */
#endif

#include "memdebug.h"

#if (SIZEOF_CURL_OFF_T > SIZEOF_LONG)
#  define MPRNT_SUFFIX_CURL_OFF_T  LL
#else
#  define MPRNT_SUFFIX_CURL_OFF_T  L
#endif


#ifdef CURL_ISOCPP
#  define MPRNT_OFF_T_C_HELPER2(Val,Suffix) Val ## Suffix
#else
#  define MPRNT_OFF_T_C_HELPER2(Val,Suffix) Val/**/Suffix
#endif
#define MPRNT_OFF_T_C_HELPER1(Val,Suffix) MPRNT_OFF_T_C_HELPER2(Val,Suffix)
#define MPRNT_OFF_T_C(Val)  MPRNT_OFF_T_C_HELPER1(Val,MPRNT_SUFFIX_CURL_OFF_T)


#define BUFSZ    256
#define USHORT_TESTS_ARRSZ 1 + 100
#define SSHORT_TESTS_ARRSZ 1 + 100
#define UINT_TESTS_ARRSZ   1 + 100
#define SINT_TESTS_ARRSZ   1 + 100
#define ULONG_TESTS_ARRSZ  1 + 100
#define SLONG_TESTS_ARRSZ  1 + 100
#define COFFT_TESTS_ARRSZ  1 + 100


struct unsshort_st {
  unsigned short num;   /* unsigned short  */
  const char *expected; /* expected string */
  char result[BUFSZ];   /* result string   */
};


struct sigshort_st {
  short num;            /* signed short    */
  const char *expected; /* expected string */
  char result[BUFSZ];   /* result string   */
};


struct unsint_st {
  unsigned int num;     /* unsigned int    */
  const char *expected; /* expected string */
  char result[BUFSZ];   /* result string   */
};


struct sigint_st {
  int num;              /* signed int      */
  const char *expected; /* expected string */
  char result[BUFSZ];   /* result string   */
};


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


static struct unsshort_st us_test[USHORT_TESTS_ARRSZ];
static struct sigshort_st ss_test[SSHORT_TESTS_ARRSZ];
static struct unsint_st   ui_test[UINT_TESTS_ARRSZ];
static struct sigint_st   si_test[SINT_TESTS_ARRSZ];
static struct unslong_st  ul_test[ULONG_TESTS_ARRSZ];
static struct siglong_st  sl_test[SLONG_TESTS_ARRSZ];
static struct curloff_st  co_test[COFFT_TESTS_ARRSZ];


static int test_unsigned_short_formatting(void)
{
  int i, j;
  int num_ushort_tests = 0;
  int failed = 0;

#if (SIZEOF_SHORT == 1)

  i = 1; us_test[i].num = 0xFFU; us_test[i].expected = "256";
  i++; us_test[i].num = 0xF0U; us_test[i].expected = "240";
  i++; us_test[i].num = 0x0FU; us_test[i].expected = "15";

  i++; us_test[i].num = 0xE0U; us_test[i].expected = "224";
  i++; us_test[i].num = 0x0EU; us_test[i].expected = "14";

  i++; us_test[i].num = 0xC0U; us_test[i].expected = "192";
  i++; us_test[i].num = 0x0CU; us_test[i].expected = "12";

  i++; us_test[i].num = 0x01U; us_test[i].expected = "1";
  i++; us_test[i].num = 0x00U; us_test[i].expected = "0";

  num_ushort_tests = i;

#elif (SIZEOF_SHORT == 2)

  i = 1; us_test[i].num = 0xFFFFU; us_test[i].expected = "65535";
  i++; us_test[i].num = 0xFF00U; us_test[i].expected = "65280";
  i++; us_test[i].num = 0x00FFU; us_test[i].expected = "255";

  i++; us_test[i].num = 0xF000U; us_test[i].expected = "61440";
  i++; us_test[i].num = 0x0F00U; us_test[i].expected = "3840";
  i++; us_test[i].num = 0x00F0U; us_test[i].expected = "240";
  i++; us_test[i].num = 0x000FU; us_test[i].expected = "15";

  i++; us_test[i].num = 0xC000U; us_test[i].expected = "49152";
  i++; us_test[i].num = 0x0C00U; us_test[i].expected = "3072";
  i++; us_test[i].num = 0x00C0U; us_test[i].expected = "192";
  i++; us_test[i].num = 0x000CU; us_test[i].expected = "12";

  i++; us_test[i].num = 0x0001U; us_test[i].expected = "1";
  i++; us_test[i].num = 0x0000U; us_test[i].expected = "0";

  num_ushort_tests = i;

#elif (SIZEOF_SHORT == 4)

  i = 1; us_test[i].num = 0xFFFFFFFFU; us_test[i].expected = "4294967295";
  i++; us_test[i].num = 0xFFFF0000U; us_test[i].expected = "4294901760";
  i++; us_test[i].num = 0x0000FFFFU; us_test[i].expected = "65535";

  i++; us_test[i].num = 0xFF000000U; us_test[i].expected = "4278190080";
  i++; us_test[i].num = 0x00FF0000U; us_test[i].expected = "16711680";
  i++; us_test[i].num = 0x0000FF00U; us_test[i].expected = "65280";
  i++; us_test[i].num = 0x000000FFU; us_test[i].expected = "255";

  i++; us_test[i].num = 0xF0000000U; us_test[i].expected = "4026531840";
  i++; us_test[i].num = 0x0F000000U; us_test[i].expected = "251658240";
  i++; us_test[i].num = 0x00F00000U; us_test[i].expected = "15728640";
  i++; us_test[i].num = 0x000F0000U; us_test[i].expected = "983040";
  i++; us_test[i].num = 0x0000F000U; us_test[i].expected = "61440";
  i++; us_test[i].num = 0x00000F00U; us_test[i].expected = "3840";
  i++; us_test[i].num = 0x000000F0U; us_test[i].expected = "240";
  i++; us_test[i].num = 0x0000000FU; us_test[i].expected = "15";

  i++; us_test[i].num = 0xC0000000U; us_test[i].expected = "3221225472";
  i++; us_test[i].num = 0x0C000000U; us_test[i].expected = "201326592";
  i++; us_test[i].num = 0x00C00000U; us_test[i].expected = "12582912";
  i++; us_test[i].num = 0x000C0000U; us_test[i].expected = "786432";
  i++; us_test[i].num = 0x0000C000U; us_test[i].expected = "49152";
  i++; us_test[i].num = 0x00000C00U; us_test[i].expected = "3072";
  i++; us_test[i].num = 0x000000C0U; us_test[i].expected = "192";
  i++; us_test[i].num = 0x0000000CU; us_test[i].expected = "12";

  i++; us_test[i].num = 0x00000001U; us_test[i].expected = "1";
  i++; us_test[i].num = 0x00000000U; us_test[i].expected = "0";

  num_ushort_tests = i;

#endif

  for(i = 1; i <= num_ushort_tests; i++) {

    for(j = 0; j<BUFSZ; j++)
      us_test[i].result[j] = 'X';
    us_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(us_test[i].result, "%hu", us_test[i].num);

    if(memcmp(us_test[i].result,
               us_test[i].expected,
               strlen(us_test[i].expected))) {
      printf("unsigned short test #%.2d: Failed (Expected: %s Got: %s)\n",
             i, us_test[i].expected, us_test[i].result);
      failed++;
    }

  }

  if(!failed)
    printf("All curl_mprintf() unsigned short tests OK!\n");
  else
    printf("Some curl_mprintf() unsigned short tests Failed!\n");

  return failed;
}


static int test_signed_short_formatting(void)
{
  int i, j;
  int num_sshort_tests = 0;
  int failed = 0;

#if (SIZEOF_SHORT == 1)

  i = 1; ss_test[i].num = 0x7F; ss_test[i].expected = "127";

  i++; ss_test[i].num = 0x70; ss_test[i].expected = "112";
  i++; ss_test[i].num = 0x07; ss_test[i].expected = "7";

  i++; ss_test[i].num = 0x50; ss_test[i].expected = "80";
  i++; ss_test[i].num = 0x05; ss_test[i].expected = "5";

  i++; ss_test[i].num = 0x01; ss_test[i].expected = "1";
  i++; ss_test[i].num = 0x00; ss_test[i].expected = "0";

  i++; ss_test[i].num = -0x7F -1; ss_test[i].expected = "-128";

  i++; ss_test[i].num = -0x70 -1; ss_test[i].expected = "-113";
  i++; ss_test[i].num = -0x07 -1; ss_test[i].expected = "-8";

  i++; ss_test[i].num = -0x50 -1; ss_test[i].expected = "-81";
  i++; ss_test[i].num = -0x05 -1; ss_test[i].expected = "-6";

  i++; ss_test[i].num =  0x00 -1; ss_test[i].expected = "-1";

  num_sshort_tests = i;

#elif (SIZEOF_SHORT == 2)

  i = 1; ss_test[i].num = 0x7FFF; ss_test[i].expected = "32767";
  i++; ss_test[i].num = 0x7FFE; ss_test[i].expected = "32766";
  i++; ss_test[i].num = 0x7FFD; ss_test[i].expected = "32765";
  i++; ss_test[i].num = 0x7F00; ss_test[i].expected = "32512";
  i++; ss_test[i].num = 0x07F0; ss_test[i].expected = "2032";
  i++; ss_test[i].num = 0x007F; ss_test[i].expected = "127";

  i++; ss_test[i].num = 0x7000; ss_test[i].expected = "28672";
  i++; ss_test[i].num = 0x0700; ss_test[i].expected = "1792";
  i++; ss_test[i].num = 0x0070; ss_test[i].expected = "112";
  i++; ss_test[i].num = 0x0007; ss_test[i].expected = "7";

  i++; ss_test[i].num = 0x5000; ss_test[i].expected = "20480";
  i++; ss_test[i].num = 0x0500; ss_test[i].expected = "1280";
  i++; ss_test[i].num = 0x0050; ss_test[i].expected = "80";
  i++; ss_test[i].num = 0x0005; ss_test[i].expected = "5";

  i++; ss_test[i].num = 0x0001; ss_test[i].expected = "1";
  i++; ss_test[i].num = 0x0000; ss_test[i].expected = "0";

  i++; ss_test[i].num = -0x7FFF -1; ss_test[i].expected = "-32768";
  i++; ss_test[i].num = -0x7FFE -1; ss_test[i].expected = "-32767";
  i++; ss_test[i].num = -0x7FFD -1; ss_test[i].expected = "-32766";
  i++; ss_test[i].num = -0x7F00 -1; ss_test[i].expected = "-32513";
  i++; ss_test[i].num = -0x07F0 -1; ss_test[i].expected = "-2033";
  i++; ss_test[i].num = -0x007F -1; ss_test[i].expected = "-128";

  i++; ss_test[i].num = -0x7000 -1; ss_test[i].expected = "-28673";
  i++; ss_test[i].num = -0x0700 -1; ss_test[i].expected = "-1793";
  i++; ss_test[i].num = -0x0070 -1; ss_test[i].expected = "-113";
  i++; ss_test[i].num = -0x0007 -1; ss_test[i].expected = "-8";

  i++; ss_test[i].num = -0x5000 -1; ss_test[i].expected = "-20481";
  i++; ss_test[i].num = -0x0500 -1; ss_test[i].expected = "-1281";
  i++; ss_test[i].num = -0x0050 -1; ss_test[i].expected = "-81";
  i++; ss_test[i].num = -0x0005 -1; ss_test[i].expected = "-6";

  i++; ss_test[i].num =  0x0000 -1; ss_test[i].expected = "-1";

  num_sshort_tests = i;

#elif (SIZEOF_SHORT == 4)

  i = 1; ss_test[i].num = 0x7FFFFFFF; ss_test[i].expected = "2147483647";
  i++; ss_test[i].num = 0x7FFFFFFE; ss_test[i].expected = "2147483646";
  i++; ss_test[i].num = 0x7FFFFFFD; ss_test[i].expected = "2147483645";
  i++; ss_test[i].num = 0x7FFF0000; ss_test[i].expected = "2147418112";
  i++; ss_test[i].num = 0x00007FFF; ss_test[i].expected = "32767";

  i++; ss_test[i].num = 0x7F000000; ss_test[i].expected = "2130706432";
  i++; ss_test[i].num = 0x007F0000; ss_test[i].expected = "8323072";
  i++; ss_test[i].num = 0x00007F00; ss_test[i].expected = "32512";
  i++; ss_test[i].num = 0x0000007F; ss_test[i].expected = "127";

  i++; ss_test[i].num = 0x70000000; ss_test[i].expected = "1879048192";
  i++; ss_test[i].num = 0x07000000; ss_test[i].expected = "117440512";
  i++; ss_test[i].num = 0x00700000; ss_test[i].expected = "7340032";
  i++; ss_test[i].num = 0x00070000; ss_test[i].expected = "458752";
  i++; ss_test[i].num = 0x00007000; ss_test[i].expected = "28672";
  i++; ss_test[i].num = 0x00000700; ss_test[i].expected = "1792";
  i++; ss_test[i].num = 0x00000070; ss_test[i].expected = "112";
  i++; ss_test[i].num = 0x00000007; ss_test[i].expected = "7";

  i++; ss_test[i].num = 0x50000000; ss_test[i].expected = "1342177280";
  i++; ss_test[i].num = 0x05000000; ss_test[i].expected = "83886080";
  i++; ss_test[i].num = 0x00500000; ss_test[i].expected = "5242880";
  i++; ss_test[i].num = 0x00050000; ss_test[i].expected = "327680";
  i++; ss_test[i].num = 0x00005000; ss_test[i].expected = "20480";
  i++; ss_test[i].num = 0x00000500; ss_test[i].expected = "1280";
  i++; ss_test[i].num = 0x00000050; ss_test[i].expected = "80";
  i++; ss_test[i].num = 0x00000005; ss_test[i].expected = "5";

  i++; ss_test[i].num = 0x00000001; ss_test[i].expected = "1";
  i++; ss_test[i].num = 0x00000000; ss_test[i].expected = "0";

  i++; ss_test[i].num = -0x7FFFFFFF -1; ss_test[i].expected = "-2147483648";
  i++; ss_test[i].num = -0x7FFFFFFE -1; ss_test[i].expected = "-2147483647";
  i++; ss_test[i].num = -0x7FFFFFFD -1; ss_test[i].expected = "-2147483646";
  i++; ss_test[i].num = -0x7FFF0000 -1; ss_test[i].expected = "-2147418113";
  i++; ss_test[i].num = -0x00007FFF -1; ss_test[i].expected = "-32768";

  i++; ss_test[i].num = -0x7F000000 -1; ss_test[i].expected = "-2130706433";
  i++; ss_test[i].num = -0x007F0000 -1; ss_test[i].expected = "-8323073";
  i++; ss_test[i].num = -0x00007F00 -1; ss_test[i].expected = "-32513";
  i++; ss_test[i].num = -0x0000007F -1; ss_test[i].expected = "-128";

  i++; ss_test[i].num = -0x70000000 -1; ss_test[i].expected = "-1879048193";
  i++; ss_test[i].num = -0x07000000 -1; ss_test[i].expected = "-117440513";
  i++; ss_test[i].num = -0x00700000 -1; ss_test[i].expected = "-7340033";
  i++; ss_test[i].num = -0x00070000 -1; ss_test[i].expected = "-458753";
  i++; ss_test[i].num = -0x00007000 -1; ss_test[i].expected = "-28673";
  i++; ss_test[i].num = -0x00000700 -1; ss_test[i].expected = "-1793";
  i++; ss_test[i].num = -0x00000070 -1; ss_test[i].expected = "-113";
  i++; ss_test[i].num = -0x00000007 -1; ss_test[i].expected = "-8";

  i++; ss_test[i].num = -0x50000000 -1; ss_test[i].expected = "-1342177281";
  i++; ss_test[i].num = -0x05000000 -1; ss_test[i].expected = "-83886081";
  i++; ss_test[i].num = -0x00500000 -1; ss_test[i].expected = "-5242881";
  i++; ss_test[i].num = -0x00050000 -1; ss_test[i].expected = "-327681";
  i++; ss_test[i].num = -0x00005000 -1; ss_test[i].expected = "-20481";
  i++; ss_test[i].num = -0x00000500 -1; ss_test[i].expected = "-1281";
  i++; ss_test[i].num = -0x00000050 -1; ss_test[i].expected = "-81";
  i++; ss_test[i].num = -0x00000005 -1; ss_test[i].expected = "-6";

  i++; ss_test[i].num =  0x00000000 -1; ss_test[i].expected = "-1";

  num_sshort_tests = i;

#endif

  for(i = 1; i <= num_sshort_tests; i++) {

    for(j = 0; j<BUFSZ; j++)
      ss_test[i].result[j] = 'X';
    ss_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(ss_test[i].result, "%hd", ss_test[i].num);

    if(memcmp(ss_test[i].result,
              ss_test[i].expected,
              strlen(ss_test[i].expected))) {
      printf("signed short test #%.2d: Failed (Expected: %s Got: %s)\n",
             i, ss_test[i].expected, ss_test[i].result);
      failed++;
    }

  }

  if(!failed)
    printf("All curl_mprintf() signed short tests OK!\n");
  else
    printf("Some curl_mprintf() signed short tests Failed!\n");

  return failed;
}


static int test_unsigned_int_formatting(void)
{
  int i, j;
  int num_uint_tests = 0;
  int failed = 0;

#if (SIZEOF_INT == 2)

  i = 1; ui_test[i].num = 0xFFFFU; ui_test[i].expected = "65535";
  i++; ui_test[i].num = 0xFF00U; ui_test[i].expected = "65280";
  i++; ui_test[i].num = 0x00FFU; ui_test[i].expected = "255";

  i++; ui_test[i].num = 0xF000U; ui_test[i].expected = "61440";
  i++; ui_test[i].num = 0x0F00U; ui_test[i].expected = "3840";
  i++; ui_test[i].num = 0x00F0U; ui_test[i].expected = "240";
  i++; ui_test[i].num = 0x000FU; ui_test[i].expected = "15";

  i++; ui_test[i].num = 0xC000U; ui_test[i].expected = "49152";
  i++; ui_test[i].num = 0x0C00U; ui_test[i].expected = "3072";
  i++; ui_test[i].num = 0x00C0U; ui_test[i].expected = "192";
  i++; ui_test[i].num = 0x000CU; ui_test[i].expected = "12";

  i++; ui_test[i].num = 0x0001U; ui_test[i].expected = "1";
  i++; ui_test[i].num = 0x0000U; ui_test[i].expected = "0";

  num_uint_tests = i;

#elif (SIZEOF_INT == 4)

  i = 1; ui_test[i].num = 0xFFFFFFFFU; ui_test[i].expected = "4294967295";
  i++; ui_test[i].num = 0xFFFF0000U; ui_test[i].expected = "4294901760";
  i++; ui_test[i].num = 0x0000FFFFU; ui_test[i].expected = "65535";

  i++; ui_test[i].num = 0xFF000000U; ui_test[i].expected = "4278190080";
  i++; ui_test[i].num = 0x00FF0000U; ui_test[i].expected = "16711680";
  i++; ui_test[i].num = 0x0000FF00U; ui_test[i].expected = "65280";
  i++; ui_test[i].num = 0x000000FFU; ui_test[i].expected = "255";

  i++; ui_test[i].num = 0xF0000000U; ui_test[i].expected = "4026531840";
  i++; ui_test[i].num = 0x0F000000U; ui_test[i].expected = "251658240";
  i++; ui_test[i].num = 0x00F00000U; ui_test[i].expected = "15728640";
  i++; ui_test[i].num = 0x000F0000U; ui_test[i].expected = "983040";
  i++; ui_test[i].num = 0x0000F000U; ui_test[i].expected = "61440";
  i++; ui_test[i].num = 0x00000F00U; ui_test[i].expected = "3840";
  i++; ui_test[i].num = 0x000000F0U; ui_test[i].expected = "240";
  i++; ui_test[i].num = 0x0000000FU; ui_test[i].expected = "15";

  i++; ui_test[i].num = 0xC0000000U; ui_test[i].expected = "3221225472";
  i++; ui_test[i].num = 0x0C000000U; ui_test[i].expected = "201326592";
  i++; ui_test[i].num = 0x00C00000U; ui_test[i].expected = "12582912";
  i++; ui_test[i].num = 0x000C0000U; ui_test[i].expected = "786432";
  i++; ui_test[i].num = 0x0000C000U; ui_test[i].expected = "49152";
  i++; ui_test[i].num = 0x00000C00U; ui_test[i].expected = "3072";
  i++; ui_test[i].num = 0x000000C0U; ui_test[i].expected = "192";
  i++; ui_test[i].num = 0x0000000CU; ui_test[i].expected = "12";

  i++; ui_test[i].num = 0x00000001U; ui_test[i].expected = "1";
  i++; ui_test[i].num = 0x00000000U; ui_test[i].expected = "0";

  num_uint_tests = i;

#elif (SIZEOF_INT == 8)

  /* !checksrc! disable LONGLINE all */
  i = 1; ui_test[i].num = 0xFFFFFFFFFFFFFFFFU; ui_test[i].expected = "18446744073709551615";
  i++; ui_test[i].num = 0xFFFFFFFF00000000U; ui_test[i].expected = "18446744069414584320";
  i++; ui_test[i].num = 0x00000000FFFFFFFFU; ui_test[i].expected = "4294967295";

  i++; ui_test[i].num = 0xFFFF000000000000U; ui_test[i].expected = "18446462598732840960";
  i++; ui_test[i].num = 0x0000FFFF00000000U; ui_test[i].expected = "281470681743360";
  i++; ui_test[i].num = 0x00000000FFFF0000U; ui_test[i].expected = "4294901760";
  i++; ui_test[i].num = 0x000000000000FFFFU; ui_test[i].expected = "65535";

  i++; ui_test[i].num = 0xFF00000000000000U; ui_test[i].expected = "18374686479671623680";
  i++; ui_test[i].num = 0x00FF000000000000U; ui_test[i].expected = "71776119061217280";
  i++; ui_test[i].num = 0x0000FF0000000000U; ui_test[i].expected = "280375465082880";
  i++; ui_test[i].num = 0x000000FF00000000U; ui_test[i].expected = "1095216660480";
  i++; ui_test[i].num = 0x00000000FF000000U; ui_test[i].expected = "4278190080";
  i++; ui_test[i].num = 0x0000000000FF0000U; ui_test[i].expected = "16711680";
  i++; ui_test[i].num = 0x000000000000FF00U; ui_test[i].expected = "65280";
  i++; ui_test[i].num = 0x00000000000000FFU; ui_test[i].expected = "255";

  i++; ui_test[i].num = 0xF000000000000000U; ui_test[i].expected = "17293822569102704640";
  i++; ui_test[i].num = 0x0F00000000000000U; ui_test[i].expected = "1080863910568919040";
  i++; ui_test[i].num = 0x00F0000000000000U; ui_test[i].expected = "67553994410557440";
  i++; ui_test[i].num = 0x000F000000000000U; ui_test[i].expected = "4222124650659840";
  i++; ui_test[i].num = 0x0000F00000000000U; ui_test[i].expected = "263882790666240";
  i++; ui_test[i].num = 0x00000F0000000000U; ui_test[i].expected = "16492674416640";
  i++; ui_test[i].num = 0x000000F000000000U; ui_test[i].expected = "1030792151040";
  i++; ui_test[i].num = 0x0000000F00000000U; ui_test[i].expected = "64424509440";
  i++; ui_test[i].num = 0x00000000F0000000U; ui_test[i].expected = "4026531840";
  i++; ui_test[i].num = 0x000000000F000000U; ui_test[i].expected = "251658240";
  i++; ui_test[i].num = 0x0000000000F00000U; ui_test[i].expected = "15728640";
  i++; ui_test[i].num = 0x00000000000F0000U; ui_test[i].expected = "983040";
  i++; ui_test[i].num = 0x000000000000F000U; ui_test[i].expected = "61440";
  i++; ui_test[i].num = 0x0000000000000F00U; ui_test[i].expected = "3840";
  i++; ui_test[i].num = 0x00000000000000F0U; ui_test[i].expected = "240";
  i++; ui_test[i].num = 0x000000000000000FU; ui_test[i].expected = "15";

  i++; ui_test[i].num = 0xC000000000000000U; ui_test[i].expected = "13835058055282163712";
  i++; ui_test[i].num = 0x0C00000000000000U; ui_test[i].expected = "864691128455135232";
  i++; ui_test[i].num = 0x00C0000000000000U; ui_test[i].expected = "54043195528445952";
  i++; ui_test[i].num = 0x000C000000000000U; ui_test[i].expected = "3377699720527872";
  i++; ui_test[i].num = 0x0000C00000000000U; ui_test[i].expected = "211106232532992";
  i++; ui_test[i].num = 0x00000C0000000000U; ui_test[i].expected = "13194139533312";
  i++; ui_test[i].num = 0x000000C000000000U; ui_test[i].expected = "824633720832";
  i++; ui_test[i].num = 0x0000000C00000000U; ui_test[i].expected = "51539607552";
  i++; ui_test[i].num = 0x00000000C0000000U; ui_test[i].expected = "3221225472";
  i++; ui_test[i].num = 0x000000000C000000U; ui_test[i].expected = "201326592";
  i++; ui_test[i].num = 0x0000000000C00000U; ui_test[i].expected = "12582912";
  i++; ui_test[i].num = 0x00000000000C0000U; ui_test[i].expected = "786432";
  i++; ui_test[i].num = 0x000000000000C000U; ui_test[i].expected = "49152";
  i++; ui_test[i].num = 0x0000000000000C00U; ui_test[i].expected = "3072";
  i++; ui_test[i].num = 0x00000000000000C0U; ui_test[i].expected = "192";
  i++; ui_test[i].num = 0x000000000000000CU; ui_test[i].expected = "12";

  i++; ui_test[i].num = 0x00000001U; ui_test[i].expected = "1";
  i++; ui_test[i].num = 0x00000000U; ui_test[i].expected = "0";

  num_uint_tests = i;

#endif

  for(i = 1; i <= num_uint_tests; i++) {

    for(j = 0; j<BUFSZ; j++)
      ui_test[i].result[j] = 'X';
    ui_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(ui_test[i].result, "%u", ui_test[i].num);

    if(memcmp(ui_test[i].result,
               ui_test[i].expected,
               strlen(ui_test[i].expected))) {
      printf("unsigned int test #%.2d: Failed (Expected: %s Got: %s)\n",
             i, ui_test[i].expected, ui_test[i].result);
      failed++;
    }

  }

  if(!failed)
    printf("All curl_mprintf() unsigned int tests OK!\n");
  else
    printf("Some curl_mprintf() unsigned int tests Failed!\n");

  return failed;
}


static int test_signed_int_formatting(void)
{
  int i, j;
  int num_sint_tests = 0;
  int failed = 0;

#if (SIZEOF_INT == 2)

  i = 1; si_test[i].num = 0x7FFF; si_test[i].expected = "32767";
  i++; si_test[i].num = 0x7FFE; si_test[i].expected = "32766";
  i++; si_test[i].num = 0x7FFD; si_test[i].expected = "32765";
  i++; si_test[i].num = 0x7F00; si_test[i].expected = "32512";
  i++; si_test[i].num = 0x07F0; si_test[i].expected = "2032";
  i++; si_test[i].num = 0x007F; si_test[i].expected = "127";

  i++; si_test[i].num = 0x7000; si_test[i].expected = "28672";
  i++; si_test[i].num = 0x0700; si_test[i].expected = "1792";
  i++; si_test[i].num = 0x0070; si_test[i].expected = "112";
  i++; si_test[i].num = 0x0007; si_test[i].expected = "7";

  i++; si_test[i].num = 0x5000; si_test[i].expected = "20480";
  i++; si_test[i].num = 0x0500; si_test[i].expected = "1280";
  i++; si_test[i].num = 0x0050; si_test[i].expected = "80";
  i++; si_test[i].num = 0x0005; si_test[i].expected = "5";

  i++; si_test[i].num = 0x0001; si_test[i].expected = "1";
  i++; si_test[i].num = 0x0000; si_test[i].expected = "0";

  i++; si_test[i].num = -0x7FFF -1; si_test[i].expected = "-32768";
  i++; si_test[i].num = -0x7FFE -1; si_test[i].expected = "-32767";
  i++; si_test[i].num = -0x7FFD -1; si_test[i].expected = "-32766";
  i++; si_test[i].num = -0x7F00 -1; si_test[i].expected = "-32513";
  i++; si_test[i].num = -0x07F0 -1; si_test[i].expected = "-2033";
  i++; si_test[i].num = -0x007F -1; si_test[i].expected = "-128";

  i++; si_test[i].num = -0x7000 -1; si_test[i].expected = "-28673";
  i++; si_test[i].num = -0x0700 -1; si_test[i].expected = "-1793";
  i++; si_test[i].num = -0x0070 -1; si_test[i].expected = "-113";
  i++; si_test[i].num = -0x0007 -1; si_test[i].expected = "-8";

  i++; si_test[i].num = -0x5000 -1; si_test[i].expected = "-20481";
  i++; si_test[i].num = -0x0500 -1; si_test[i].expected = "-1281";
  i++; si_test[i].num = -0x0050 -1; si_test[i].expected = "-81";
  i++; si_test[i].num = -0x0005 -1; si_test[i].expected = "-6";

  i++; si_test[i].num =  0x0000 -1; si_test[i].expected = "-1";

  num_sint_tests = i;

#elif (SIZEOF_INT == 4)

  i = 1; si_test[i].num = 0x7FFFFFFF; si_test[i].expected = "2147483647";
  i++; si_test[i].num = 0x7FFFFFFE; si_test[i].expected = "2147483646";
  i++; si_test[i].num = 0x7FFFFFFD; si_test[i].expected = "2147483645";
  i++; si_test[i].num = 0x7FFF0000; si_test[i].expected = "2147418112";
  i++; si_test[i].num = 0x00007FFF; si_test[i].expected = "32767";

  i++; si_test[i].num = 0x7F000000; si_test[i].expected = "2130706432";
  i++; si_test[i].num = 0x007F0000; si_test[i].expected = "8323072";
  i++; si_test[i].num = 0x00007F00; si_test[i].expected = "32512";
  i++; si_test[i].num = 0x0000007F; si_test[i].expected = "127";

  i++; si_test[i].num = 0x70000000; si_test[i].expected = "1879048192";
  i++; si_test[i].num = 0x07000000; si_test[i].expected = "117440512";
  i++; si_test[i].num = 0x00700000; si_test[i].expected = "7340032";
  i++; si_test[i].num = 0x00070000; si_test[i].expected = "458752";
  i++; si_test[i].num = 0x00007000; si_test[i].expected = "28672";
  i++; si_test[i].num = 0x00000700; si_test[i].expected = "1792";
  i++; si_test[i].num = 0x00000070; si_test[i].expected = "112";
  i++; si_test[i].num = 0x00000007; si_test[i].expected = "7";

  i++; si_test[i].num = 0x50000000; si_test[i].expected = "1342177280";
  i++; si_test[i].num = 0x05000000; si_test[i].expected = "83886080";
  i++; si_test[i].num = 0x00500000; si_test[i].expected = "5242880";
  i++; si_test[i].num = 0x00050000; si_test[i].expected = "327680";
  i++; si_test[i].num = 0x00005000; si_test[i].expected = "20480";
  i++; si_test[i].num = 0x00000500; si_test[i].expected = "1280";
  i++; si_test[i].num = 0x00000050; si_test[i].expected = "80";
  i++; si_test[i].num = 0x00000005; si_test[i].expected = "5";

  i++; si_test[i].num = 0x00000001; si_test[i].expected = "1";
  i++; si_test[i].num = 0x00000000; si_test[i].expected = "0";

  i++; si_test[i].num = -0x7FFFFFFF -1; si_test[i].expected = "-2147483648";
  i++; si_test[i].num = -0x7FFFFFFE -1; si_test[i].expected = "-2147483647";
  i++; si_test[i].num = -0x7FFFFFFD -1; si_test[i].expected = "-2147483646";
  i++; si_test[i].num = -0x7FFF0000 -1; si_test[i].expected = "-2147418113";
  i++; si_test[i].num = -0x00007FFF -1; si_test[i].expected = "-32768";

  i++; si_test[i].num = -0x7F000000 -1; si_test[i].expected = "-2130706433";
  i++; si_test[i].num = -0x007F0000 -1; si_test[i].expected = "-8323073";
  i++; si_test[i].num = -0x00007F00 -1; si_test[i].expected = "-32513";
  i++; si_test[i].num = -0x0000007F -1; si_test[i].expected = "-128";

  i++; si_test[i].num = -0x70000000 -1; si_test[i].expected = "-1879048193";
  i++; si_test[i].num = -0x07000000 -1; si_test[i].expected = "-117440513";
  i++; si_test[i].num = -0x00700000 -1; si_test[i].expected = "-7340033";
  i++; si_test[i].num = -0x00070000 -1; si_test[i].expected = "-458753";
  i++; si_test[i].num = -0x00007000 -1; si_test[i].expected = "-28673";
  i++; si_test[i].num = -0x00000700 -1; si_test[i].expected = "-1793";
  i++; si_test[i].num = -0x00000070 -1; si_test[i].expected = "-113";
  i++; si_test[i].num = -0x00000007 -1; si_test[i].expected = "-8";

  i++; si_test[i].num = -0x50000000 -1; si_test[i].expected = "-1342177281";
  i++; si_test[i].num = -0x05000000 -1; si_test[i].expected = "-83886081";
  i++; si_test[i].num = -0x00500000 -1; si_test[i].expected = "-5242881";
  i++; si_test[i].num = -0x00050000 -1; si_test[i].expected = "-327681";
  i++; si_test[i].num = -0x00005000 -1; si_test[i].expected = "-20481";
  i++; si_test[i].num = -0x00000500 -1; si_test[i].expected = "-1281";
  i++; si_test[i].num = -0x00000050 -1; si_test[i].expected = "-81";
  i++; si_test[i].num = -0x00000005 -1; si_test[i].expected = "-6";

  i++; si_test[i].num =  0x00000000 -1; si_test[i].expected = "-1";

  num_sint_tests = i;

#elif (SIZEOF_INT == 8)

  i = 1; si_test[i].num = 0x7FFFFFFFFFFFFFFF; si_test[i].expected = "9223372036854775807";
  i++; si_test[i].num = 0x7FFFFFFFFFFFFFFE; si_test[i].expected = "9223372036854775806";
  i++; si_test[i].num = 0x7FFFFFFFFFFFFFFD; si_test[i].expected = "9223372036854775805";
  i++; si_test[i].num = 0x7FFFFFFF00000000; si_test[i].expected = "9223372032559808512";
  i++; si_test[i].num = 0x000000007FFFFFFF; si_test[i].expected = "2147483647";

  i++; si_test[i].num = 0x7FFF000000000000; si_test[i].expected = "9223090561878065152";
  i++; si_test[i].num = 0x00007FFF00000000; si_test[i].expected = "140733193388032";
  i++; si_test[i].num = 0x000000007FFF0000; si_test[i].expected = "2147418112";
  i++; si_test[i].num = 0x0000000000007FFF; si_test[i].expected = "32767";

  i++; si_test[i].num = 0x7F00000000000000; si_test[i].expected = "9151314442816847872";
  i++; si_test[i].num = 0x007F000000000000; si_test[i].expected = "35747322042253312";
  i++; si_test[i].num = 0x00007F0000000000; si_test[i].expected = "139637976727552";
  i++; si_test[i].num = 0x0000007F00000000; si_test[i].expected = "545460846592";
  i++; si_test[i].num = 0x000000007F000000; si_test[i].expected = "2130706432";
  i++; si_test[i].num = 0x00000000007F0000; si_test[i].expected = "8323072";
  i++; si_test[i].num = 0x0000000000007F00; si_test[i].expected = "32512";
  i++; si_test[i].num = 0x000000000000007F; si_test[i].expected = "127";

  i++; si_test[i].num = 0x7000000000000000; si_test[i].expected = "8070450532247928832";
  i++; si_test[i].num = 0x0700000000000000; si_test[i].expected = "504403158265495552";
  i++; si_test[i].num = 0x0070000000000000; si_test[i].expected = "31525197391593472";
  i++; si_test[i].num = 0x0007000000000000; si_test[i].expected = "1970324836974592";
  i++; si_test[i].num = 0x0000700000000000; si_test[i].expected = "123145302310912";
  i++; si_test[i].num = 0x0000070000000000; si_test[i].expected = "7696581394432";
  i++; si_test[i].num = 0x0000007000000000; si_test[i].expected = "481036337152";
  i++; si_test[i].num = 0x0000000700000000; si_test[i].expected = "30064771072";
  i++; si_test[i].num = 0x0000000070000000; si_test[i].expected = "1879048192";
  i++; si_test[i].num = 0x0000000007000000; si_test[i].expected = "117440512";
  i++; si_test[i].num = 0x0000000000700000; si_test[i].expected = "7340032";
  i++; si_test[i].num = 0x0000000000070000; si_test[i].expected = "458752";
  i++; si_test[i].num = 0x0000000000007000; si_test[i].expected = "28672";
  i++; si_test[i].num = 0x0000000000000700; si_test[i].expected = "1792";
  i++; si_test[i].num = 0x0000000000000070; si_test[i].expected = "112";
  i++; si_test[i].num = 0x0000000000000007; si_test[i].expected = "7";

  i++; si_test[i].num = 0x0000000000000001; si_test[i].expected = "1";
  i++; si_test[i].num = 0x0000000000000000; si_test[i].expected = "0";

  i++; si_test[i].num = -0x7FFFFFFFFFFFFFFF -1; si_test[i].expected = "-9223372036854775808";
  i++; si_test[i].num = -0x7FFFFFFFFFFFFFFE -1; si_test[i].expected = "-9223372036854775807";
  i++; si_test[i].num = -0x7FFFFFFFFFFFFFFD -1; si_test[i].expected = "-9223372036854775806";
  i++; si_test[i].num = -0x7FFFFFFF00000000 -1; si_test[i].expected = "-9223372032559808513";
  i++; si_test[i].num = -0x000000007FFFFFFF -1; si_test[i].expected = "-2147483648";

  i++; si_test[i].num = -0x7FFF000000000000 -1; si_test[i].expected = "-9223090561878065153";
  i++; si_test[i].num = -0x00007FFF00000000 -1; si_test[i].expected = "-140733193388033";
  i++; si_test[i].num = -0x000000007FFF0000 -1; si_test[i].expected = "-2147418113";
  i++; si_test[i].num = -0x0000000000007FFF -1; si_test[i].expected = "-32768";

  i++; si_test[i].num = -0x7F00000000000000 -1; si_test[i].expected = "-9151314442816847873";
  i++; si_test[i].num = -0x007F000000000000 -1; si_test[i].expected = "-35747322042253313";
  i++; si_test[i].num = -0x00007F0000000000 -1; si_test[i].expected = "-139637976727553";
  i++; si_test[i].num = -0x0000007F00000000 -1; si_test[i].expected = "-545460846593";
  i++; si_test[i].num = -0x000000007F000000 -1; si_test[i].expected = "-2130706433";
  i++; si_test[i].num = -0x00000000007F0000 -1; si_test[i].expected = "-8323073";
  i++; si_test[i].num = -0x0000000000007F00 -1; si_test[i].expected = "-32513";
  i++; si_test[i].num = -0x000000000000007F -1; si_test[i].expected = "-128";

  i++; si_test[i].num = -0x7000000000000000 -1; si_test[i].expected = "-8070450532247928833";
  i++; si_test[i].num = -0x0700000000000000 -1; si_test[i].expected = "-504403158265495553";
  i++; si_test[i].num = -0x0070000000000000 -1; si_test[i].expected = "-31525197391593473";
  i++; si_test[i].num = -0x0007000000000000 -1; si_test[i].expected = "-1970324836974593";
  i++; si_test[i].num = -0x0000700000000000 -1; si_test[i].expected = "-123145302310913";
  i++; si_test[i].num = -0x0000070000000000 -1; si_test[i].expected = "-7696581394433";
  i++; si_test[i].num = -0x0000007000000000 -1; si_test[i].expected = "-481036337153";
  i++; si_test[i].num = -0x0000000700000000 -1; si_test[i].expected = "-30064771073";
  i++; si_test[i].num = -0x0000000070000000 -1; si_test[i].expected = "-1879048193";
  i++; si_test[i].num = -0x0000000007000000 -1; si_test[i].expected = "-117440513";
  i++; si_test[i].num = -0x0000000000700000 -1; si_test[i].expected = "-7340033";
  i++; si_test[i].num = -0x0000000000070000 -1; si_test[i].expected = "-458753";
  i++; si_test[i].num = -0x0000000000007000 -1; si_test[i].expected = "-28673";
  i++; si_test[i].num = -0x0000000000000700 -1; si_test[i].expected = "-1793";
  i++; si_test[i].num = -0x0000000000000070 -1; si_test[i].expected = "-113";
  i++; si_test[i].num = -0x0000000000000007 -1; si_test[i].expected = "-8";

  i++; si_test[i].num =  0x0000000000000000 -1; si_test[i].expected = "-1";

  num_sint_tests = i;

#endif

  for(i = 1; i <= num_sint_tests; i++) {

    for(j = 0; j<BUFSZ; j++)
      si_test[i].result[j] = 'X';
    si_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(si_test[i].result, "%d", si_test[i].num);

    if(memcmp(si_test[i].result,
              si_test[i].expected,
              strlen(si_test[i].expected))) {
      printf("signed int test #%.2d: Failed (Expected: %s Got: %s)\n",
             i, si_test[i].expected, si_test[i].result);
      failed++;
    }

  }

  if(!failed)
    printf("All curl_mprintf() signed int tests OK!\n");
  else
    printf("Some curl_mprintf() signed int tests Failed!\n");

  return failed;
}


static int test_unsigned_long_formatting(void)
{
  int i, j;
  int num_ulong_tests = 0;
  int failed = 0;

#if (SIZEOF_LONG == 2)

  i = 1; ul_test[i].num = 0xFFFFUL; ul_test[i].expected = "65535";
  i++; ul_test[i].num = 0xFF00UL; ul_test[i].expected = "65280";
  i++; ul_test[i].num = 0x00FFUL; ul_test[i].expected = "255";

  i++; ul_test[i].num = 0xF000UL; ul_test[i].expected = "61440";
  i++; ul_test[i].num = 0x0F00UL; ul_test[i].expected = "3840";
  i++; ul_test[i].num = 0x00F0UL; ul_test[i].expected = "240";
  i++; ul_test[i].num = 0x000FUL; ul_test[i].expected = "15";

  i++; ul_test[i].num = 0xC000UL; ul_test[i].expected = "49152";
  i++; ul_test[i].num = 0x0C00UL; ul_test[i].expected = "3072";
  i++; ul_test[i].num = 0x00C0UL; ul_test[i].expected = "192";
  i++; ul_test[i].num = 0x000CUL; ul_test[i].expected = "12";

  i++; ul_test[i].num = 0x0001UL; ul_test[i].expected = "1";
  i++; ul_test[i].num = 0x0000UL; ul_test[i].expected = "0";

  num_ulong_tests = i;

#elif (SIZEOF_LONG == 4)

  i = 1; ul_test[i].num = 0xFFFFFFFFUL; ul_test[i].expected = "4294967295";
  i++; ul_test[i].num = 0xFFFF0000UL; ul_test[i].expected = "4294901760";
  i++; ul_test[i].num = 0x0000FFFFUL; ul_test[i].expected = "65535";

  i++; ul_test[i].num = 0xFF000000UL; ul_test[i].expected = "4278190080";
  i++; ul_test[i].num = 0x00FF0000UL; ul_test[i].expected = "16711680";
  i++; ul_test[i].num = 0x0000FF00UL; ul_test[i].expected = "65280";
  i++; ul_test[i].num = 0x000000FFUL; ul_test[i].expected = "255";

  i++; ul_test[i].num = 0xF0000000UL; ul_test[i].expected = "4026531840";
  i++; ul_test[i].num = 0x0F000000UL; ul_test[i].expected = "251658240";
  i++; ul_test[i].num = 0x00F00000UL; ul_test[i].expected = "15728640";
  i++; ul_test[i].num = 0x000F0000UL; ul_test[i].expected = "983040";
  i++; ul_test[i].num = 0x0000F000UL; ul_test[i].expected = "61440";
  i++; ul_test[i].num = 0x00000F00UL; ul_test[i].expected = "3840";
  i++; ul_test[i].num = 0x000000F0UL; ul_test[i].expected = "240";
  i++; ul_test[i].num = 0x0000000FUL; ul_test[i].expected = "15";

  i++; ul_test[i].num = 0xC0000000UL; ul_test[i].expected = "3221225472";
  i++; ul_test[i].num = 0x0C000000UL; ul_test[i].expected = "201326592";
  i++; ul_test[i].num = 0x00C00000UL; ul_test[i].expected = "12582912";
  i++; ul_test[i].num = 0x000C0000UL; ul_test[i].expected = "786432";
  i++; ul_test[i].num = 0x0000C000UL; ul_test[i].expected = "49152";
  i++; ul_test[i].num = 0x00000C00UL; ul_test[i].expected = "3072";
  i++; ul_test[i].num = 0x000000C0UL; ul_test[i].expected = "192";
  i++; ul_test[i].num = 0x0000000CUL; ul_test[i].expected = "12";

  i++; ul_test[i].num = 0x00000001UL; ul_test[i].expected = "1";
  i++; ul_test[i].num = 0x00000000UL; ul_test[i].expected = "0";

  num_ulong_tests = i;

#elif (SIZEOF_LONG == 8)

  i = 1; ul_test[i].num = 0xFFFFFFFFFFFFFFFFUL; ul_test[i].expected = "18446744073709551615";
  i++; ul_test[i].num = 0xFFFFFFFF00000000UL; ul_test[i].expected = "18446744069414584320";
  i++; ul_test[i].num = 0x00000000FFFFFFFFUL; ul_test[i].expected = "4294967295";

  i++; ul_test[i].num = 0xFFFF000000000000UL; ul_test[i].expected = "18446462598732840960";
  i++; ul_test[i].num = 0x0000FFFF00000000UL; ul_test[i].expected = "281470681743360";
  i++; ul_test[i].num = 0x00000000FFFF0000UL; ul_test[i].expected = "4294901760";
  i++; ul_test[i].num = 0x000000000000FFFFUL; ul_test[i].expected = "65535";

  i++; ul_test[i].num = 0xFF00000000000000UL; ul_test[i].expected = "18374686479671623680";
  i++; ul_test[i].num = 0x00FF000000000000UL; ul_test[i].expected = "71776119061217280";
  i++; ul_test[i].num = 0x0000FF0000000000UL; ul_test[i].expected = "280375465082880";
  i++; ul_test[i].num = 0x000000FF00000000UL; ul_test[i].expected = "1095216660480";
  i++; ul_test[i].num = 0x00000000FF000000UL; ul_test[i].expected = "4278190080";
  i++; ul_test[i].num = 0x0000000000FF0000UL; ul_test[i].expected = "16711680";
  i++; ul_test[i].num = 0x000000000000FF00UL; ul_test[i].expected = "65280";
  i++; ul_test[i].num = 0x00000000000000FFUL; ul_test[i].expected = "255";

  i++; ul_test[i].num = 0xF000000000000000UL; ul_test[i].expected = "17293822569102704640";
  i++; ul_test[i].num = 0x0F00000000000000UL; ul_test[i].expected = "1080863910568919040";
  i++; ul_test[i].num = 0x00F0000000000000UL; ul_test[i].expected = "67553994410557440";
  i++; ul_test[i].num = 0x000F000000000000UL; ul_test[i].expected = "4222124650659840";
  i++; ul_test[i].num = 0x0000F00000000000UL; ul_test[i].expected = "263882790666240";
  i++; ul_test[i].num = 0x00000F0000000000UL; ul_test[i].expected = "16492674416640";
  i++; ul_test[i].num = 0x000000F000000000UL; ul_test[i].expected = "1030792151040";
  i++; ul_test[i].num = 0x0000000F00000000UL; ul_test[i].expected = "64424509440";
  i++; ul_test[i].num = 0x00000000F0000000UL; ul_test[i].expected = "4026531840";
  i++; ul_test[i].num = 0x000000000F000000UL; ul_test[i].expected = "251658240";
  i++; ul_test[i].num = 0x0000000000F00000UL; ul_test[i].expected = "15728640";
  i++; ul_test[i].num = 0x00000000000F0000UL; ul_test[i].expected = "983040";
  i++; ul_test[i].num = 0x000000000000F000UL; ul_test[i].expected = "61440";
  i++; ul_test[i].num = 0x0000000000000F00UL; ul_test[i].expected = "3840";
  i++; ul_test[i].num = 0x00000000000000F0UL; ul_test[i].expected = "240";
  i++; ul_test[i].num = 0x000000000000000FUL; ul_test[i].expected = "15";

  i++; ul_test[i].num = 0xC000000000000000UL; ul_test[i].expected = "13835058055282163712";
  i++; ul_test[i].num = 0x0C00000000000000UL; ul_test[i].expected = "864691128455135232";
  i++; ul_test[i].num = 0x00C0000000000000UL; ul_test[i].expected = "54043195528445952";
  i++; ul_test[i].num = 0x000C000000000000UL; ul_test[i].expected = "3377699720527872";
  i++; ul_test[i].num = 0x0000C00000000000UL; ul_test[i].expected = "211106232532992";
  i++; ul_test[i].num = 0x00000C0000000000UL; ul_test[i].expected = "13194139533312";
  i++; ul_test[i].num = 0x000000C000000000UL; ul_test[i].expected = "824633720832";
  i++; ul_test[i].num = 0x0000000C00000000UL; ul_test[i].expected = "51539607552";
  i++; ul_test[i].num = 0x00000000C0000000UL; ul_test[i].expected = "3221225472";
  i++; ul_test[i].num = 0x000000000C000000UL; ul_test[i].expected = "201326592";
  i++; ul_test[i].num = 0x0000000000C00000UL; ul_test[i].expected = "12582912";
  i++; ul_test[i].num = 0x00000000000C0000UL; ul_test[i].expected = "786432";
  i++; ul_test[i].num = 0x000000000000C000UL; ul_test[i].expected = "49152";
  i++; ul_test[i].num = 0x0000000000000C00UL; ul_test[i].expected = "3072";
  i++; ul_test[i].num = 0x00000000000000C0UL; ul_test[i].expected = "192";
  i++; ul_test[i].num = 0x000000000000000CUL; ul_test[i].expected = "12";

  i++; ul_test[i].num = 0x00000001UL; ul_test[i].expected = "1";
  i++; ul_test[i].num = 0x00000000UL; ul_test[i].expected = "0";

  num_ulong_tests = i;

#endif

  for(i = 1; i <= num_ulong_tests; i++) {

    for(j = 0; j<BUFSZ; j++)
      ul_test[i].result[j] = 'X';
    ul_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(ul_test[i].result, "%lu", ul_test[i].num);

    if(memcmp(ul_test[i].result,
               ul_test[i].expected,
               strlen(ul_test[i].expected))) {
      printf("unsigned long test #%.2d: Failed (Expected: %s Got: %s)\n",
             i, ul_test[i].expected, ul_test[i].result);
      failed++;
    }

  }

  if(!failed)
    printf("All curl_mprintf() unsigned long tests OK!\n");
  else
    printf("Some curl_mprintf() unsigned long tests Failed!\n");

  return failed;
}


static int test_signed_long_formatting(void)
{
  int i, j;
  int num_slong_tests = 0;
  int failed = 0;

#if (SIZEOF_LONG == 2)

  i = 1; sl_test[i].num = 0x7FFFL; sl_test[i].expected = "32767";
  i++; sl_test[i].num = 0x7FFEL; sl_test[i].expected = "32766";
  i++; sl_test[i].num = 0x7FFDL; sl_test[i].expected = "32765";
  i++; sl_test[i].num = 0x7F00L; sl_test[i].expected = "32512";
  i++; sl_test[i].num = 0x07F0L; sl_test[i].expected = "2032";
  i++; sl_test[i].num = 0x007FL; sl_test[i].expected = "127";

  i++; sl_test[i].num = 0x7000L; sl_test[i].expected = "28672";
  i++; sl_test[i].num = 0x0700L; sl_test[i].expected = "1792";
  i++; sl_test[i].num = 0x0070L; sl_test[i].expected = "112";
  i++; sl_test[i].num = 0x0007L; sl_test[i].expected = "7";

  i++; sl_test[i].num = 0x5000L; sl_test[i].expected = "20480";
  i++; sl_test[i].num = 0x0500L; sl_test[i].expected = "1280";
  i++; sl_test[i].num = 0x0050L; sl_test[i].expected = "80";
  i++; sl_test[i].num = 0x0005L; sl_test[i].expected = "5";

  i++; sl_test[i].num = 0x0001L; sl_test[i].expected = "1";
  i++; sl_test[i].num = 0x0000L; sl_test[i].expected = "0";

  i++; sl_test[i].num = -0x7FFFL -1L; sl_test[i].expected = "-32768";
  i++; sl_test[i].num = -0x7FFEL -1L; sl_test[i].expected = "-32767";
  i++; sl_test[i].num = -0x7FFDL -1L; sl_test[i].expected = "-32766";
  i++; sl_test[i].num = -0x7F00L -1L; sl_test[i].expected = "-32513";
  i++; sl_test[i].num = -0x07F0L -1L; sl_test[i].expected = "-2033";
  i++; sl_test[i].num = -0x007FL -1L; sl_test[i].expected = "-128";

  i++; sl_test[i].num = -0x7000L -1L; sl_test[i].expected = "-28673";
  i++; sl_test[i].num = -0x0700L -1L; sl_test[i].expected = "-1793";
  i++; sl_test[i].num = -0x0070L -1L; sl_test[i].expected = "-113";
  i++; sl_test[i].num = -0x0007L -1L; sl_test[i].expected = "-8";

  i++; sl_test[i].num = -0x5000L -1L; sl_test[i].expected = "-20481";
  i++; sl_test[i].num = -0x0500L -1L; sl_test[i].expected = "-1281";
  i++; sl_test[i].num = -0x0050L -1L; sl_test[i].expected = "-81";
  i++; sl_test[i].num = -0x0005L -1L; sl_test[i].expected = "-6";

  i++; sl_test[i].num =  0x0000L -1L; sl_test[i].expected = "-1";

  num_slong_tests = i;

#elif (SIZEOF_LONG == 4)

  i = 1; sl_test[i].num = 0x7FFFFFFFL; sl_test[i].expected = "2147483647";
  i++; sl_test[i].num = 0x7FFFFFFEL; sl_test[i].expected = "2147483646";
  i++; sl_test[i].num = 0x7FFFFFFDL; sl_test[i].expected = "2147483645";
  i++; sl_test[i].num = 0x7FFF0000L; sl_test[i].expected = "2147418112";
  i++; sl_test[i].num = 0x00007FFFL; sl_test[i].expected = "32767";

  i++; sl_test[i].num = 0x7F000000L; sl_test[i].expected = "2130706432";
  i++; sl_test[i].num = 0x007F0000L; sl_test[i].expected = "8323072";
  i++; sl_test[i].num = 0x00007F00L; sl_test[i].expected = "32512";
  i++; sl_test[i].num = 0x0000007FL; sl_test[i].expected = "127";

  i++; sl_test[i].num = 0x70000000L; sl_test[i].expected = "1879048192";
  i++; sl_test[i].num = 0x07000000L; sl_test[i].expected = "117440512";
  i++; sl_test[i].num = 0x00700000L; sl_test[i].expected = "7340032";
  i++; sl_test[i].num = 0x00070000L; sl_test[i].expected = "458752";
  i++; sl_test[i].num = 0x00007000L; sl_test[i].expected = "28672";
  i++; sl_test[i].num = 0x00000700L; sl_test[i].expected = "1792";
  i++; sl_test[i].num = 0x00000070L; sl_test[i].expected = "112";
  i++; sl_test[i].num = 0x00000007L; sl_test[i].expected = "7";

  i++; sl_test[i].num = 0x50000000L; sl_test[i].expected = "1342177280";
  i++; sl_test[i].num = 0x05000000L; sl_test[i].expected = "83886080";
  i++; sl_test[i].num = 0x00500000L; sl_test[i].expected = "5242880";
  i++; sl_test[i].num = 0x00050000L; sl_test[i].expected = "327680";
  i++; sl_test[i].num = 0x00005000L; sl_test[i].expected = "20480";
  i++; sl_test[i].num = 0x00000500L; sl_test[i].expected = "1280";
  i++; sl_test[i].num = 0x00000050L; sl_test[i].expected = "80";
  i++; sl_test[i].num = 0x00000005L; sl_test[i].expected = "5";

  i++; sl_test[i].num = 0x00000001L; sl_test[i].expected = "1";
  i++; sl_test[i].num = 0x00000000L; sl_test[i].expected = "0";

  i++; sl_test[i].num = -0x7FFFFFFFL -1L; sl_test[i].expected = "-2147483648";
  i++; sl_test[i].num = -0x7FFFFFFEL -1L; sl_test[i].expected = "-2147483647";
  i++; sl_test[i].num = -0x7FFFFFFDL -1L; sl_test[i].expected = "-2147483646";
  i++; sl_test[i].num = -0x7FFF0000L -1L; sl_test[i].expected = "-2147418113";
  i++; sl_test[i].num = -0x00007FFFL -1L; sl_test[i].expected = "-32768";

  i++; sl_test[i].num = -0x7F000000L -1L; sl_test[i].expected = "-2130706433";
  i++; sl_test[i].num = -0x007F0000L -1L; sl_test[i].expected = "-8323073";
  i++; sl_test[i].num = -0x00007F00L -1L; sl_test[i].expected = "-32513";
  i++; sl_test[i].num = -0x0000007FL -1L; sl_test[i].expected = "-128";

  i++; sl_test[i].num = -0x70000000L -1L; sl_test[i].expected = "-1879048193";
  i++; sl_test[i].num = -0x07000000L -1L; sl_test[i].expected = "-117440513";
  i++; sl_test[i].num = -0x00700000L -1L; sl_test[i].expected = "-7340033";
  i++; sl_test[i].num = -0x00070000L -1L; sl_test[i].expected = "-458753";
  i++; sl_test[i].num = -0x00007000L -1L; sl_test[i].expected = "-28673";
  i++; sl_test[i].num = -0x00000700L -1L; sl_test[i].expected = "-1793";
  i++; sl_test[i].num = -0x00000070L -1L; sl_test[i].expected = "-113";
  i++; sl_test[i].num = -0x00000007L -1L; sl_test[i].expected = "-8";

  i++; sl_test[i].num = -0x50000000L -1L; sl_test[i].expected = "-1342177281";
  i++; sl_test[i].num = -0x05000000L -1L; sl_test[i].expected = "-83886081";
  i++; sl_test[i].num = -0x00500000L -1L; sl_test[i].expected = "-5242881";
  i++; sl_test[i].num = -0x00050000L -1L; sl_test[i].expected = "-327681";
  i++; sl_test[i].num = -0x00005000L -1L; sl_test[i].expected = "-20481";
  i++; sl_test[i].num = -0x00000500L -1L; sl_test[i].expected = "-1281";
  i++; sl_test[i].num = -0x00000050L -1L; sl_test[i].expected = "-81";
  i++; sl_test[i].num = -0x00000005L -1L; sl_test[i].expected = "-6";

  i++; sl_test[i].num =  0x00000000L -1L; sl_test[i].expected = "-1";

  num_slong_tests = i;

#elif (SIZEOF_LONG == 8)

  i = 1; sl_test[i].num = 0x7FFFFFFFFFFFFFFFL; sl_test[i].expected = "9223372036854775807";
  i++; sl_test[i].num = 0x7FFFFFFFFFFFFFFEL; sl_test[i].expected = "9223372036854775806";
  i++; sl_test[i].num = 0x7FFFFFFFFFFFFFFDL; sl_test[i].expected = "9223372036854775805";
  i++; sl_test[i].num = 0x7FFFFFFF00000000L; sl_test[i].expected = "9223372032559808512";
  i++; sl_test[i].num = 0x000000007FFFFFFFL; sl_test[i].expected = "2147483647";

  i++; sl_test[i].num = 0x7FFF000000000000L; sl_test[i].expected = "9223090561878065152";
  i++; sl_test[i].num = 0x00007FFF00000000L; sl_test[i].expected = "140733193388032";
  i++; sl_test[i].num = 0x000000007FFF0000L; sl_test[i].expected = "2147418112";
  i++; sl_test[i].num = 0x0000000000007FFFL; sl_test[i].expected = "32767";

  i++; sl_test[i].num = 0x7F00000000000000L; sl_test[i].expected = "9151314442816847872";
  i++; sl_test[i].num = 0x007F000000000000L; sl_test[i].expected = "35747322042253312";
  i++; sl_test[i].num = 0x00007F0000000000L; sl_test[i].expected = "139637976727552";
  i++; sl_test[i].num = 0x0000007F00000000L; sl_test[i].expected = "545460846592";
  i++; sl_test[i].num = 0x000000007F000000L; sl_test[i].expected = "2130706432";
  i++; sl_test[i].num = 0x00000000007F0000L; sl_test[i].expected = "8323072";
  i++; sl_test[i].num = 0x0000000000007F00L; sl_test[i].expected = "32512";
  i++; sl_test[i].num = 0x000000000000007FL; sl_test[i].expected = "127";

  i++; sl_test[i].num = 0x7000000000000000L; sl_test[i].expected = "8070450532247928832";
  i++; sl_test[i].num = 0x0700000000000000L; sl_test[i].expected = "504403158265495552";
  i++; sl_test[i].num = 0x0070000000000000L; sl_test[i].expected = "31525197391593472";
  i++; sl_test[i].num = 0x0007000000000000L; sl_test[i].expected = "1970324836974592";
  i++; sl_test[i].num = 0x0000700000000000L; sl_test[i].expected = "123145302310912";
  i++; sl_test[i].num = 0x0000070000000000L; sl_test[i].expected = "7696581394432";
  i++; sl_test[i].num = 0x0000007000000000L; sl_test[i].expected = "481036337152";
  i++; sl_test[i].num = 0x0000000700000000L; sl_test[i].expected = "30064771072";
  i++; sl_test[i].num = 0x0000000070000000L; sl_test[i].expected = "1879048192";
  i++; sl_test[i].num = 0x0000000007000000L; sl_test[i].expected = "117440512";
  i++; sl_test[i].num = 0x0000000000700000L; sl_test[i].expected = "7340032";
  i++; sl_test[i].num = 0x0000000000070000L; sl_test[i].expected = "458752";
  i++; sl_test[i].num = 0x0000000000007000L; sl_test[i].expected = "28672";
  i++; sl_test[i].num = 0x0000000000000700L; sl_test[i].expected = "1792";
  i++; sl_test[i].num = 0x0000000000000070L; sl_test[i].expected = "112";
  i++; sl_test[i].num = 0x0000000000000007L; sl_test[i].expected = "7";

  i++; sl_test[i].num = 0x0000000000000001L; sl_test[i].expected = "1";
  i++; sl_test[i].num = 0x0000000000000000L; sl_test[i].expected = "0";

  i++; sl_test[i].num = -0x7FFFFFFFFFFFFFFFL -1L; sl_test[i].expected = "-9223372036854775808";
  i++; sl_test[i].num = -0x7FFFFFFFFFFFFFFEL -1L; sl_test[i].expected = "-9223372036854775807";
  i++; sl_test[i].num = -0x7FFFFFFFFFFFFFFDL -1L; sl_test[i].expected = "-9223372036854775806";
  i++; sl_test[i].num = -0x7FFFFFFF00000000L -1L; sl_test[i].expected = "-9223372032559808513";
  i++; sl_test[i].num = -0x000000007FFFFFFFL -1L; sl_test[i].expected = "-2147483648";

  i++; sl_test[i].num = -0x7FFF000000000000L -1L; sl_test[i].expected = "-9223090561878065153";
  i++; sl_test[i].num = -0x00007FFF00000000L -1L; sl_test[i].expected = "-140733193388033";
  i++; sl_test[i].num = -0x000000007FFF0000L -1L; sl_test[i].expected = "-2147418113";
  i++; sl_test[i].num = -0x0000000000007FFFL -1L; sl_test[i].expected = "-32768";

  i++; sl_test[i].num = -0x7F00000000000000L -1L; sl_test[i].expected = "-9151314442816847873";
  i++; sl_test[i].num = -0x007F000000000000L -1L; sl_test[i].expected = "-35747322042253313";
  i++; sl_test[i].num = -0x00007F0000000000L -1L; sl_test[i].expected = "-139637976727553";
  i++; sl_test[i].num = -0x0000007F00000000L -1L; sl_test[i].expected = "-545460846593";
  i++; sl_test[i].num = -0x000000007F000000L -1L; sl_test[i].expected = "-2130706433";
  i++; sl_test[i].num = -0x00000000007F0000L -1L; sl_test[i].expected = "-8323073";
  i++; sl_test[i].num = -0x0000000000007F00L -1L; sl_test[i].expected = "-32513";
  i++; sl_test[i].num = -0x000000000000007FL -1L; sl_test[i].expected = "-128";

  i++; sl_test[i].num = -0x7000000000000000L -1L; sl_test[i].expected = "-8070450532247928833";
  i++; sl_test[i].num = -0x0700000000000000L -1L; sl_test[i].expected = "-504403158265495553";
  i++; sl_test[i].num = -0x0070000000000000L -1L; sl_test[i].expected = "-31525197391593473";
  i++; sl_test[i].num = -0x0007000000000000L -1L; sl_test[i].expected = "-1970324836974593";
  i++; sl_test[i].num = -0x0000700000000000L -1L; sl_test[i].expected = "-123145302310913";
  i++; sl_test[i].num = -0x0000070000000000L -1L; sl_test[i].expected = "-7696581394433";
  i++; sl_test[i].num = -0x0000007000000000L -1L; sl_test[i].expected = "-481036337153";
  i++; sl_test[i].num = -0x0000000700000000L -1L; sl_test[i].expected = "-30064771073";
  i++; sl_test[i].num = -0x0000000070000000L -1L; sl_test[i].expected = "-1879048193";
  i++; sl_test[i].num = -0x0000000007000000L -1L; sl_test[i].expected = "-117440513";
  i++; sl_test[i].num = -0x0000000000700000L -1L; sl_test[i].expected = "-7340033";
  i++; sl_test[i].num = -0x0000000000070000L -1L; sl_test[i].expected = "-458753";
  i++; sl_test[i].num = -0x0000000000007000L -1L; sl_test[i].expected = "-28673";
  i++; sl_test[i].num = -0x0000000000000700L -1L; sl_test[i].expected = "-1793";
  i++; sl_test[i].num = -0x0000000000000070L -1L; sl_test[i].expected = "-113";
  i++; sl_test[i].num = -0x0000000000000007L -1L; sl_test[i].expected = "-8";

  i++; sl_test[i].num =  0x0000000000000000L -1L; sl_test[i].expected = "-1";

  num_slong_tests = i;

#endif

  for(i = 1; i <= num_slong_tests; i++) {

    for(j = 0; j<BUFSZ; j++)
      sl_test[i].result[j] = 'X';
    sl_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(sl_test[i].result, "%ld", sl_test[i].num);

    if(memcmp(sl_test[i].result,
              sl_test[i].expected,
              strlen(sl_test[i].expected))) {
      printf("signed long test #%.2d: Failed (Expected: %s Got: %s)\n",
             i, sl_test[i].expected, sl_test[i].result);
      failed++;
    }

  }

  if(!failed)
    printf("All curl_mprintf() signed long tests OK!\n");
  else
    printf("Some curl_mprintf() signed long tests Failed!\n");

  return failed;
}


static int test_curl_off_t_formatting(void)
{
  int i, j;
  int num_cofft_tests = 0;
  int failed = 0;

#if (SIZEOF_CURL_OFF_T == 2)

  i = 1; co_test[i].num = MPRNT_OFF_T_C(0x7FFF); co_test[i].expected = "32767";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFE); co_test[i].expected = "32766";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFD); co_test[i].expected = "32765";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7F00); co_test[i].expected = "32512";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x07F0); co_test[i].expected = "2032";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x007F); co_test[i].expected = "127";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x7000); co_test[i].expected = "28672";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0700); co_test[i].expected = "1792";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0070); co_test[i].expected = "112";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0007); co_test[i].expected = "7";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x5000); co_test[i].expected = "20480";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0500); co_test[i].expected = "1280";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0050); co_test[i].expected = "80";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0005); co_test[i].expected = "5";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x0001); co_test[i].expected = "1";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000); co_test[i].expected = "0";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFF) -MPRNT_OFF_T_C(1); co_test[i].expected = "-32768";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFE) -MPRNT_OFF_T_C(1); co_test[i].expected = "-32767";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFD) -MPRNT_OFF_T_C(1); co_test[i].expected = "-32766";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7F00) -MPRNT_OFF_T_C(1); co_test[i].expected = "-32513";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x07F0) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2033";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x007F) -MPRNT_OFF_T_C(1); co_test[i].expected = "-128";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-28673";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0700) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1793";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0070) -MPRNT_OFF_T_C(1); co_test[i].expected = "-113";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0007) -MPRNT_OFF_T_C(1); co_test[i].expected = "-8";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x5000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-20481";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0500) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1281";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0050) -MPRNT_OFF_T_C(1); co_test[i].expected = "-81";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0005) -MPRNT_OFF_T_C(1); co_test[i].expected = "-6";

  i++; co_test[i].num =  MPRNT_OFF_T_C(0x0000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1";

  num_cofft_tests = i;

#elif (SIZEOF_CURL_OFF_T == 4)

  i = 1; co_test[i].num = MPRNT_OFF_T_C(0x7FFFFFFF); co_test[i].expected = "2147483647";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFFFFFE); co_test[i].expected = "2147483646";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFFFFFD); co_test[i].expected = "2147483645";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFF0000); co_test[i].expected = "2147418112";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00007FFF); co_test[i].expected = "32767";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x7F000000); co_test[i].expected = "2130706432";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x007F0000); co_test[i].expected = "8323072";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00007F00); co_test[i].expected = "32512";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000007F); co_test[i].expected = "127";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x70000000); co_test[i].expected = "1879048192";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x07000000); co_test[i].expected = "117440512";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00700000); co_test[i].expected = "7340032";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00070000); co_test[i].expected = "458752";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00007000); co_test[i].expected = "28672";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000700); co_test[i].expected = "1792";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000070); co_test[i].expected = "112";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000007); co_test[i].expected = "7";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x50000000); co_test[i].expected = "1342177280";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x05000000); co_test[i].expected = "83886080";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00500000); co_test[i].expected = "5242880";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00050000); co_test[i].expected = "327680";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00005000); co_test[i].expected = "20480";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000500); co_test[i].expected = "1280";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000050); co_test[i].expected = "80";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000005); co_test[i].expected = "5";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000001); co_test[i].expected = "1";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000000); co_test[i].expected = "0";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFFFFFF) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2147483648";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFFFFFE) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2147483647";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFFFFFD) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2147483646";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFF0000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2147418113";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00007FFF) -MPRNT_OFF_T_C(1); co_test[i].expected = "-32768";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7F000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2130706433";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x007F0000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-8323073";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00007F00) -MPRNT_OFF_T_C(1); co_test[i].expected = "-32513";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000007F) -MPRNT_OFF_T_C(1); co_test[i].expected = "-128";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x70000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1879048193";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x07000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-117440513";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00700000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-7340033";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00070000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-458753";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00007000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-28673";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00000700) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1793";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00000070) -MPRNT_OFF_T_C(1); co_test[i].expected = "-113";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00000007) -MPRNT_OFF_T_C(1); co_test[i].expected = "-8";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x50000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1342177281";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x05000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-83886081";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00500000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-5242881";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00050000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-327681";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00005000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-20481";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00000500) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1281";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00000050) -MPRNT_OFF_T_C(1); co_test[i].expected = "-81";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00000005) -MPRNT_OFF_T_C(1); co_test[i].expected = "-6";

  i++; co_test[i].num =  MPRNT_OFF_T_C(0x00000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1";

  num_cofft_tests = i;

#elif (SIZEOF_CURL_OFF_T == 8)

  i = 1; co_test[i].num = MPRNT_OFF_T_C(0x7FFFFFFFFFFFFFFF); co_test[i].expected = "9223372036854775807";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFFFFFFFFFFFFFE); co_test[i].expected = "9223372036854775806";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFFFFFFFFFFFFFD); co_test[i].expected = "9223372036854775805";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFFFFFF00000000); co_test[i].expected = "9223372032559808512";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x000000007FFFFFFF); co_test[i].expected = "2147483647";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x7FFF000000000000); co_test[i].expected = "9223090561878065152";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00007FFF00000000); co_test[i].expected = "140733193388032";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x000000007FFF0000); co_test[i].expected = "2147418112";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000007FFF); co_test[i].expected = "32767";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x7F00000000000000); co_test[i].expected = "9151314442816847872";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x007F000000000000); co_test[i].expected = "35747322042253312";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00007F0000000000); co_test[i].expected = "139637976727552";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000007F00000000); co_test[i].expected = "545460846592";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x000000007F000000); co_test[i].expected = "2130706432";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x00000000007F0000); co_test[i].expected = "8323072";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000007F00); co_test[i].expected = "32512";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x000000000000007F); co_test[i].expected = "127";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x7000000000000000); co_test[i].expected = "8070450532247928832";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0700000000000000); co_test[i].expected = "504403158265495552";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0070000000000000); co_test[i].expected = "31525197391593472";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0007000000000000); co_test[i].expected = "1970324836974592";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000700000000000); co_test[i].expected = "123145302310912";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000070000000000); co_test[i].expected = "7696581394432";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000007000000000); co_test[i].expected = "481036337152";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000700000000); co_test[i].expected = "30064771072";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000070000000); co_test[i].expected = "1879048192";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000007000000); co_test[i].expected = "117440512";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000700000); co_test[i].expected = "7340032";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000070000); co_test[i].expected = "458752";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000007000); co_test[i].expected = "28672";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000000700); co_test[i].expected = "1792";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000000070); co_test[i].expected = "112";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000000007); co_test[i].expected = "7";

  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000000001); co_test[i].expected = "1";
  i++; co_test[i].num = MPRNT_OFF_T_C(0x0000000000000000); co_test[i].expected = "0";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFFFFFFFFFFFFFF) -MPRNT_OFF_T_C(1); co_test[i].expected = "-9223372036854775808";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFFFFFFFFFFFFFE) -MPRNT_OFF_T_C(1); co_test[i].expected = "-9223372036854775807";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFFFFFFFFFFFFFD) -MPRNT_OFF_T_C(1); co_test[i].expected = "-9223372036854775806";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFFFFFF00000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-9223372032559808513";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x000000007FFFFFFF) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2147483648";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7FFF000000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-9223090561878065153";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00007FFF00000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-140733193388033";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x000000007FFF0000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2147418113";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000000007FFF) -MPRNT_OFF_T_C(1); co_test[i].expected = "-32768";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7F00000000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-9151314442816847873";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x007F000000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-35747322042253313";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00007F0000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-139637976727553";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000007F00000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-545460846593";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x000000007F000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-2130706433";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x00000000007F0000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-8323073";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000000007F00) -MPRNT_OFF_T_C(1); co_test[i].expected = "-32513";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x000000000000007F) -MPRNT_OFF_T_C(1); co_test[i].expected = "-128";

  i++; co_test[i].num = -MPRNT_OFF_T_C(0x7000000000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-8070450532247928833";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0700000000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-504403158265495553";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0070000000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-31525197391593473";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0007000000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1970324836974593";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000700000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-123145302310913";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000070000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-7696581394433";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000007000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-481036337153";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000700000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-30064771073";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000070000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1879048193";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000007000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-117440513";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000000700000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-7340033";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000000070000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-458753";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000000007000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-28673";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000000000700) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1793";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000000000070) -MPRNT_OFF_T_C(1); co_test[i].expected = "-113";
  i++; co_test[i].num = -MPRNT_OFF_T_C(0x0000000000000007) -MPRNT_OFF_T_C(1); co_test[i].expected = "-8";

  i++; co_test[i].num =  MPRNT_OFF_T_C(0x0000000000000000) -MPRNT_OFF_T_C(1); co_test[i].expected = "-1";

  num_cofft_tests = i;

#endif

  for(i = 1; i <= num_cofft_tests; i++) {

    for(j = 0; j<BUFSZ; j++)
      co_test[i].result[j] = 'X';
    co_test[i].result[BUFSZ-1] = '\0';

    (void)curl_msprintf(co_test[i].result, "%" CURL_FORMAT_CURL_OFF_T,
                        co_test[i].num);

    if(memcmp(co_test[i].result,
              co_test[i].expected,
              strlen(co_test[i].expected))) {
      printf("curl_off_t test #%.2d: Failed (Expected: %s Got: %s)\n",
             i, co_test[i].expected, co_test[i].result);
      failed++;
    }

  }

  if(!failed)
    printf("All curl_mprintf() curl_off_t tests OK!\n");
  else
    printf("Some curl_mprintf() curl_off_t tests Failed!\n");

  return failed;
}

static int _string_check(int linenumber, char *buf, const char *buf2)
{
  if(strcmp(buf, buf2)) {
    /* they shouldn't differ */
    printf("sprintf line %d failed:\nwe      '%s'\nsystem: '%s'\n",
           linenumber, buf, buf2);
    return 1;
  }
  return 0;
}
#define string_check(x,y) _string_check(__LINE__, x, y)

static int _strlen_check(int linenumber, char *buf, size_t len)
{
  size_t buflen = strlen(buf);
  if(len != buflen) {
    /* they shouldn't differ */
    printf("sprintf strlen:%d failed:\nwe '%zu'\nsystem: '%zu'\n",
           linenumber, buflen, len);
    return 1;
  }
  return 0;
}

#define strlen_check(x,y) _strlen_check(__LINE__, x, y)

/*
 * The output strings in this test need to have been verified with a system
 * sprintf() before used here.
 */
static int test_string_formatting(void)
{
  int errors = 0;
  char buf[256];
  curl_msnprintf(buf, sizeof(buf), "%0*d%s", 2, 9, "foo");
  errors += string_check(buf, "09foo");

  curl_msnprintf(buf, sizeof(buf), "%*.*s", 5, 2, "foo");
  errors += string_check(buf, "   fo");

  curl_msnprintf(buf, sizeof(buf), "%*.*s", 2, 5, "foo");
  errors += string_check(buf, "foo");

  curl_msnprintf(buf, sizeof(buf), "%*.*s", 0, 10, "foo");
  errors += string_check(buf, "foo");

  curl_msnprintf(buf, sizeof(buf), "%-10s", "foo");
  errors += string_check(buf, "foo       ");

  curl_msnprintf(buf, sizeof(buf), "%10s", "foo");
  errors += string_check(buf, "       foo");

  curl_msnprintf(buf, sizeof(buf), "%*.*s", -10, -10, "foo");
  errors += string_check(buf, "foo       ");

  if(!errors)
    printf("All curl_mprintf() strings tests OK!\n");
  else
    printf("Some curl_mprintf() string tests Failed!\n");

  return errors;
}

static int test_weird_arguments(void)
{
  int errors = 0;
  char buf[256];
  int rc;

  /* MAX_PARAMETERS is 128, try exact 128! */
  rc = curl_msnprintf(buf, sizeof(buf),
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 1 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 2 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 3 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 4 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 5 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 6 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 7 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 8 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 9 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 10 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 11 */
                      "%d%d%d%d%d%d%d%d"     /* 8 */
                      ,
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 1 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 2 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 3 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 4 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 5 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 6 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 7 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 8 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 9 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 10 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 11 */
                      0, 1, 2, 3, 4, 5, 6, 7); /* 8 */

  if(rc != 128) {
    printf("curl_mprintf() returned %d and not 128!\n", rc);
    errors++;
  }

  errors += string_check(buf,
                         "0123456789" /* 10 */
                         "0123456789" /* 10 1 */
                         "0123456789" /* 10 2 */
                         "0123456789" /* 10 3 */
                         "0123456789" /* 10 4 */
                         "0123456789" /* 10 5 */
                         "0123456789" /* 10 6 */
                         "0123456789" /* 10 7 */
                         "0123456789" /* 10 8 */
                         "0123456789" /* 10 9 */
                         "0123456789" /* 10 10*/
                         "0123456789" /* 10 11 */
                         "01234567"   /* 8 */
    );

  /* MAX_PARAMETERS is 128, try more! */
  buf[0] = 0;
  rc = curl_msnprintf(buf, sizeof(buf),
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 1 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 2 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 3 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 4 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 5 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 6 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 7 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 8 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 9 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 10 */
                      "%d%d%d%d%d%d%d%d%d%d" /* 10 11 */
                      "%d%d%d%d%d%d%d%d%d"   /* 9 */
                      ,
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 1 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 2 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 3 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 4 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 5 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 6 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 7 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 8 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 9 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 10 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 10 11 */
                      0, 1, 2, 3, 4, 5, 6, 7, 8);   /* 9 */

  if(rc != -1) {
    printf("curl_mprintf() returned %d and not -1!\n", rc);
    errors++;
  }

  errors += string_check(buf, "");

  /* Do not skip sanity checks with parameters! */
  buf[0] = 0;
  rc = curl_msnprintf(buf, sizeof(buf), "%d, %.*1$d", 500, 1);

  if(rc != 256) {
    printf("curl_mprintf() returned %d and not 256!\n", rc);
    errors++;
  }

  errors += strlen_check(buf, 255);

  if(errors)
    printf("Some curl_mprintf() weird arguments tests failed!\n");

  return errors;
}

/* DBL_MAX value from Linux */
/* !checksrc! disable PLUSNOSPACE 1 */
#define MAXIMIZE -1.7976931348623157081452E+308

static int test_float_formatting(void)
{
  int errors = 0;
  char buf[512]; /* larger than max float size */
  curl_msnprintf(buf, sizeof(buf), "%f", 9.0);
  errors += string_check(buf, "9.000000");

  curl_msnprintf(buf, sizeof(buf), "%.1f", 9.1);
  errors += string_check(buf, "9.1");

  curl_msnprintf(buf, sizeof(buf), "%.2f", 9.1);
  errors += string_check(buf, "9.10");

  curl_msnprintf(buf, sizeof(buf), "%.0f", 9.1);
  errors += string_check(buf, "9");

  curl_msnprintf(buf, sizeof(buf), "%0f", 9.1);
  errors += string_check(buf, "9.100000");

  curl_msnprintf(buf, sizeof(buf), "%10f", 9.1);
  errors += string_check(buf, "  9.100000");

  curl_msnprintf(buf, sizeof(buf), "%10.3f", 9.1);
  errors += string_check(buf, "     9.100");

  curl_msnprintf(buf, sizeof(buf), "%-10.3f", 9.1);
  errors += string_check(buf, "9.100     ");

  curl_msnprintf(buf, sizeof(buf), "%-10.3f", 9.123456);
  errors += string_check(buf, "9.123     ");

  curl_msnprintf(buf, sizeof(buf), "%.-2f", 9.1);
  errors += string_check(buf, "9.100000");

  curl_msnprintf(buf, sizeof(buf), "%*f", 10, 9.1);
  errors += string_check(buf, "  9.100000");

  curl_msnprintf(buf, sizeof(buf), "%*f", 3, 9.1);
  errors += string_check(buf, "9.100000");

  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.2987654);
  errors += string_check(buf, "9.298765");

  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.298765);
  errors += string_check(buf, "9.298765");

  curl_msnprintf(buf, sizeof(buf), "%*f", 6, 9.29876);
  errors += string_check(buf, "9.298760");

  curl_msnprintf(buf, sizeof(buf), "%.*f", 6, 9.2987654);
  errors += string_check(buf, "9.298765");
  curl_msnprintf(buf, sizeof(buf), "%.*f", 5, 9.2987654);
  errors += string_check(buf, "9.29877");
  curl_msnprintf(buf, sizeof(buf), "%.*f", 4, 9.2987654);
  errors += string_check(buf, "9.2988");
  curl_msnprintf(buf, sizeof(buf), "%.*f", 3, 9.2987654);
  errors += string_check(buf, "9.299");
  curl_msnprintf(buf, sizeof(buf), "%.*f", 2, 9.2987654);
  errors += string_check(buf, "9.30");
  curl_msnprintf(buf, sizeof(buf), "%.*f", 1, 9.2987654);
  errors += string_check(buf, "9.3");
  curl_msnprintf(buf, sizeof(buf), "%.*f", 0, 9.2987654);
  errors += string_check(buf, "9");

  /* very large precisions easily turn into system specific outputs so we only
     check the output buffer length here as we know the internal limit */

  curl_msnprintf(buf, sizeof(buf), "%.*f", (1<<30), 9.2987654);
  errors += strlen_check(buf, 325);

  curl_msnprintf(buf, sizeof(buf), "%10000.10000f", 9.2987654);
  errors += strlen_check(buf, 325);

  curl_msnprintf(buf, sizeof(buf), "%240.10000f",
                 123456789123456789123456789.2987654);
  errors += strlen_check(buf, 325);

  /* check negative when used signed */
  curl_msnprintf(buf, sizeof(buf), "%*f", INT_MIN, 9.1);
  errors += string_check(buf, "9.100000");

  /* curl_msnprintf() limits a single float output to 325 bytes maximum
     width */
  curl_msnprintf(buf, sizeof(buf), "%*f", (1<<30), 9.1);
  errors += string_check(buf, "                                                                                                                                                                                                                                                                                                                             9.100000");
  curl_msnprintf(buf, sizeof(buf), "%100000f", 9.1);
  errors += string_check(buf, "                                                                                                                                                                                                                                                                                                                             9.100000");

  curl_msnprintf(buf, sizeof(buf), "%f", MAXIMIZE);
  errors += strlen_check(buf, 317);

  curl_msnprintf(buf, 2, "%f", MAXIMIZE);
  errors += strlen_check(buf, 1);
  curl_msnprintf(buf, 3, "%f", MAXIMIZE);
  errors += strlen_check(buf, 2);
  curl_msnprintf(buf, 4, "%f", MAXIMIZE);
  errors += strlen_check(buf, 3);
  curl_msnprintf(buf, 5, "%f", MAXIMIZE);
  errors += strlen_check(buf, 4);
  curl_msnprintf(buf, 6, "%f", MAXIMIZE);
  errors += strlen_check(buf, 5);

  if(!errors)
    printf("All float strings tests OK!\n");
  else
    printf("test_float_formatting Failed!\n");

  return errors;
}
/* !checksrc! enable LONGLINE */

int test(char *URL)
{
  int errors = 0;
  (void)URL; /* not used */

#ifdef HAVE_SETLOCALE
  /*
   * The test makes assumptions about the numeric locale (specifically,
   * RADIXCHAR) so set it to a known working (and portable) one.
   */
  setlocale(LC_NUMERIC, "C");
#endif

  errors += test_weird_arguments();

  errors += test_unsigned_short_formatting();

  errors += test_signed_short_formatting();

  errors += test_unsigned_int_formatting();

  errors += test_signed_int_formatting();

  errors += test_unsigned_long_formatting();

  errors += test_signed_long_formatting();

  errors += test_curl_off_t_formatting();

  errors += test_string_formatting();

  errors += test_float_formatting();

  if(errors)
    return TEST_ERR_MAJOR_BAD;
  else
    return 0;
}
