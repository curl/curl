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
#include "curlcheck.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#include <curl/curl.h>

#include "curlx/strparse.h"

#include "memdebug.h" /* LAST include file */

static CURLcode unit_setup(void)
{
  CURLcode res = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return res;
}

static void unit_stop(void)
{
  curl_global_cleanup();
}

UNITTEST_START
{
  static const char *wordparse[] = {
    "word",
    "word ",
    " word ",
    "wo rd",
    "word(",
    "wor(d",
    "perfect",
    "",
    "longerth",
    NULL
  };

  int i;
  printf("curlx_str_word\n");
  for(i = 0; wordparse[i]; i++) {
    struct Curl_str out;
    const char *line = wordparse[i];
    const char *orgline = line;
    int rc = curlx_str_word(&line, &out, 7);
    printf("%u: (\"%s\") %d, \"%.*s\" [%d], line %d\n",
           i, orgline, rc, (int)out.len, out.str, (int)out.len,
           (int)(line - orgline));
  }

  printf("curlx_str_until\n");
  for(i = 0; wordparse[i]; i++) {
    struct Curl_str out;
    const char *line = wordparse[i];
    const char *orgline = line;
    int rc = curlx_str_until(&line, &out, 7, 'd');
    printf("%u: (\"%s\") %d, \"%.*s\" [%d], line %d\n",
           i, orgline, rc, (int)out.len, out.str, (int)out.len,
           (int)(line - orgline));
  }

  {
    static const char *qwords[] = {
      "\"word\"",
      "\"word",
      "word\"",
      "\"word\"\"",
      "\"word\" ",
      " \"word\"",
      "\"perfect\"",
      "\"p r e t\"",
      "\"perfec\\\"",
      "\"\"",
      "",
      "\"longerth\"",
      NULL
    };

    printf("curlx_str_quotedword\n");
    for(i = 0; qwords[i]; i++) {
      struct Curl_str out;
      const char *line = qwords[i];
      const char *orgline = line;
      int rc = curlx_str_quotedword(&line, &out, 7);
      printf("%u: (\"%s\") %d, \"%.*s\" [%d], line %d\n",
             i, orgline, rc, (int)out.len, out.str, (int)out.len,
             (int)(line - orgline));
    }
  }

  {
    static const char *single[] = {
      "a",
      "aa",
      "A",
      "b",
      "\\",
      " ",
      "",
      NULL
    };
    printf("curlx_str_single\n");
    for(i = 0; single[i]; i++) {
      const char *line = single[i];
      const char *orgline = line;
      int rc = curlx_str_single(&line, 'a');
      printf("%u: (\"%s\") %d, line %d\n",
             i, orgline, rc, (int)(line - orgline));
    }
  }
  {
    static const char *single[] = {
      "a",
      "aa",
      "A",
      "b",
      "\\",
      " ",
      "\t",
      "\n",
      "",
      NULL
    };
    printf("curlx_str_singlespace\n");
    for(i = 0; single[i]; i++) {
      const char *line = single[i];
      const char *orgline = line;
      int rc = curlx_str_singlespace(&line);
      printf("%u: (\"%s\") %d, line %d\n",
             i, orgline, rc, (int)(line - orgline));
    }
  }

  {
    static const char *single[] = {
      "a",
      "aa",
      "A",
      "b",
      "\\",
      " ",
      "",
      NULL
    };
    printf("curlx_str_single\n");
    for(i = 0; single[i]; i++) {
      const char *line = single[i];
      const char *orgline = line;
      int rc = curlx_str_single(&line, 'a');
      printf("%u: (\"%s\") %d, line %d\n",
             i, orgline, rc, (int)(line - orgline));
    }
  }
  {
    static const char *nums[] = {
      "1",
      "10000",
      "1234",
      "1235",
      "1236",
      "01234",
      "00000000000000000000000000001234",
      "0123 345",
      "0123O345",
      "-12",
      " 123",
      "",
      NULL
    };
    printf("curlx_str_number\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = curlx_str_number(&line, &num, 1235);
      printf("%u: (\"%s\") %d, [%u] line %d\n",
             i, orgline, rc, (int)num, (int)(line - orgline));
    }
  }

  {
    struct t {
      const char *str;
      curl_off_t max;
    };
    static struct t nums[] = {
      { "00", 8},
      { "1", 8},
      { "1", 1},
      { "2", 1},
      { "2", 2},
      { "5", 6},
      { "000000000000000000000006", 6},
      { "7", 6},
      { "8", 6},
      { "9", 8},
      { "10", 10},
      { "11", 10},
      { "12", 10},
      {NULL, 0}
    };
    printf("curlx_str_number varying max\n");
    for(i = 0; nums[i].str; i++) {
      curl_off_t num;
      const char *line = nums[i].str;
      const char *orgline = line;
      int rc = curlx_str_number(&line, &num, nums[i].max);
      curl_mprintf("%u: (\"%s\") max %" CURL_FORMAT_CURL_OFF_T
                   " == %d, [%" CURL_FORMAT_CURL_OFF_T "]\n",
                   i, orgline, nums[i].max, rc, num);
    }
  }

  {
    struct t {
      const char *str;
      curl_off_t max;
    };
    static struct t nums[] = {
      { "00", 8},
      { "1", 8},
      { "1", 1},
      { "2", 1},
      { "2", 2},
      { "5", 6},
      { "000000000000000000000006", 6},
      { "7", 6},
      { "8", 6},
      { "9", 8},
      { "a", 14},
      { "b", 14},
      { "c", 14},
      { "d", 14},
      { "e", 14},
      { "f", 14},
      { "f", 15},
      { "10", 16},
      { "11", 16},
      { "12", 16},
      {NULL, 0}
    };
    printf("curlx_str_hex varying max\n");
    for(i = 0; nums[i].str; i++) {
      curl_off_t num;
      const char *line = nums[i].str;
      const char *orgline = line;
      int rc = curlx_str_hex(&line, &num, nums[i].max);
      curl_mprintf("%u: (\"%s\") max %" CURL_FORMAT_CURL_OFF_T
                   " == %d, [%" CURL_FORMAT_CURL_OFF_T "]\n",
                   i, orgline, nums[i].max, rc, num);
    }
  }

  {
    struct t {
      const char *str;
      curl_off_t max;
    };
    static struct t nums[] = {
      { "00", 4},
      { "1", 4},
      { "1", 4},
      { "2", 4},
      { "3", 4},
      { "4", 4},
      { "5", 4},
      { "000000000000000000000006", 6},
      { "7", 7},
      { "10", 8},
      { "11", 8},
      { "11", 9},
      { "12", 9},
      { "13", 9},
      { "8", 10},
      {NULL, 0}
    };
    printf("curlx_str_octal varying max\n");
    for(i = 0; nums[i].str; i++) {
      curl_off_t num;
      const char *line = nums[i].str;
      const char *orgline = line;
      int rc = curlx_str_octal(&line, &num, nums[i].max);
      curl_mprintf("%u: (\"%s\") max %" CURL_FORMAT_CURL_OFF_T
                   " == %d, [%" CURL_FORMAT_CURL_OFF_T "]\n",
                   i, orgline, nums[i].max, rc, num);
    }
  }

  {
    /* CURL_OFF_T is typically 9223372036854775807 */
    static const char *nums[] = {
      "9223372036854775807", /* 2^63 -1 */
      "9223372036854775808", /* 2^63  */
      "18446744073709551615", /* 2^64 - 1 */
      "18446744073709551616", /* 2^64 */
      "18446744073709551617", /* 2^64 + 1 */
      "0123456799a",
      "0123456789",
      "123498760b",
      "1234987607611298232",
      "1111111111111111111",
      "2222222222222222222",
      "00000000000000000000000000000009223372036854775807",
      "3333333333333333333",
      "4444444444444444444",
      "5555555555555555555",
      "6666666666666666666",
      "7777777777777777777",
      "8888888888888888888",
      "999999999999999999",
      NULL
    };
    printf("curlx_str_number / max\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = curlx_str_number(&line, &num, CURL_OFF_T_MAX);
      curl_mprintf("%u: (\"%s\") %d, [%" CURL_FORMAT_CURL_OFF_T "] line %d\n",
                   i, orgline, rc, num, (int)(line - orgline));
    }
  }

  {
    static const char *newl[] = {
      "a",
      "aa",
      "A",
      "b",
      "\\",
      " ",
      "\n",
      "\r",
      "\r\n",
      "\x0c",
      "",
      NULL
    };
    printf("curlx_str_newline\n");
    for(i = 0; newl[i]; i++) {
      const char *line = newl[i];
      const char *orgline = line;
      int rc = curlx_str_newline(&line);
      curl_mprintf("%u: (%%%02x) %d, line %d\n",
                   i, *orgline, rc, (int)(line - orgline));
    }
  }

  {
    static const char *nums[] = {
      "1",
      "1000",
      "1234",
      "1235",
      "1236",
      "01234",
      "00000000000000000000000000001234",
      "0123 345",
      "0123O345",
      "-12",
      " 123",
      "",
      NULL
    };
    printf("curlx_str_hex\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = curlx_str_hex(&line, &num, 0x1235);
      curl_mprintf("%u: (\"%s\") %d, [%u] line %d\n",
                   i, orgline, rc, (int)num, (int)(line - orgline));
    }
  }

  {
    static const char *nums[] = {
      "1",
      "1000",
      "1234",
      "1235",
      "1236",
      "01234",
      "00000000000000000000000000001234",
      "0123 345",
      "0123O345",
      "-12",
      " 123",
      "",
      NULL
    };
    printf("curlx_str_octal\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = curlx_str_octal(&line, &num, 01235);
      curl_mprintf("%u: (\"%s\") %d, [%u] line %d\n",
                   i, orgline, rc, (int)num, (int)(line - orgline));
    }
  }

  {
    /* CURL_OFF_T is typically 2^63-1 */
    static const char *nums[] = {
      "777777777777777777777", /* 2^63 -1 */
      "1000000000000000000000", /* 2^63  */
      "111111111111111111111",
      "222222222222222222222",
      "333333333333333333333",
      "444444444444444444444",
      "555555555555555555555",
      "666666666666666666666",
      NULL
    };
    printf("curlx_str_octal / max\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = curlx_str_octal(&line, &num, CURL_OFF_T_MAX);
      curl_mprintf("%u: (\"%s\") %d, [%" CURL_FORMAT_CURL_OFF_T "] line %d\n",
                   i, orgline, rc, num, (int)(line - orgline));
    }
  }

  {
    /* CURL_OFF_T is typically 2^63-1 */
    static const char *nums[] = {
      "7FFFFFFFFFFFFFFF", /* 2^63 -1 */
      "8000000000000000", /* 2^63  */
      "1111111111111111",
      "2222222222222222",
      "3333333333333333",
      "4444444444444444",
      "5555555555555555",
      "6666666666666666",
      "7777777777777777",
      "888888888888888",
      "999999999999999",
      "aaaaaaaaAAAAAAA",
      "bbbbbbbbBBBBBBB",
      "BBBBBBBBbbbbbbb",
      "ccccccccCCCCCCC",
      "ddddddddDDDDDDD",
      "eeeeeeeeEEEEEEE",
      "ffffffffFFFFFFF",
      "abcdef",
      "ABCDEF",
      NULL
    };
    printf("curlx_str_hex / max\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = curlx_str_hex(&line, &num, CURL_OFF_T_MAX);
      curl_mprintf("%u: (\"%s\") %d, [%" CURL_FORMAT_CURL_OFF_T "] line %d\n",
                   i, orgline, rc, num, (int)(line - orgline));
    }
  }

}
UNITTEST_STOP
