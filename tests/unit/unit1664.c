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

#include "strparse.h"

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
  printf("Curl_str_word\n");
  for(i = 0; wordparse[i]; i++) {
    struct Curl_str out;
    const char *line = wordparse[i];
    const char *orgline = line;
    int rc = Curl_str_word(&line, &out, 7);
    printf("%u: (\"%s\") %d, \"%.*s\" [%d], line %d\n",
           i, orgline, rc, (int)out.len, out.str, (int)out.len,
           (int)(line - orgline));
  }

  printf("Curl_str_until\n");
  for(i = 0; wordparse[i]; i++) {
    struct Curl_str out;
    const char *line = wordparse[i];
    const char *orgline = line;
    int rc = Curl_str_until(&line, &out, 7, 'd');
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

    printf("Curl_str_quotedword\n");
    for(i = 0; qwords[i]; i++) {
      struct Curl_str out;
      const char *line = qwords[i];
      const char *orgline = line;
      int rc = Curl_str_quotedword(&line, &out, 7);
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
    printf("Curl_str_single\n");
    for(i = 0; single[i]; i++) {
      const char *line = single[i];
      const char *orgline = line;
      int rc = Curl_str_single(&line, 'a');
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
    printf("Curl_str_singlespace\n");
    for(i = 0; single[i]; i++) {
      const char *line = single[i];
      const char *orgline = line;
      int rc = Curl_str_singlespace(&line);
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
    printf("Curl_str_single\n");
    for(i = 0; single[i]; i++) {
      const char *line = single[i];
      const char *orgline = line;
      int rc = Curl_str_single(&line, 'a');
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
    printf("Curl_str_number\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = Curl_str_number(&line, &num, 1235);
      printf("%u: (\"%s\") %d, [%u] line %d\n",
             i, orgline, rc, (int)num, (int)(line - orgline));
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
      NULL
    };
    printf("Curl_str_number / max\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = Curl_str_number(&line, &num, CURL_OFF_T_MAX);
      printf("%u: (\"%s\") %d, [%" CURL_FORMAT_CURL_OFF_T "] line %d\n",
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
      "",
      NULL
    };
    printf("Curl_str_newline\n");
    for(i = 0; newl[i]; i++) {
      const char *line = newl[i];
      const char *orgline = line;
      int rc = Curl_str_newline(&line);
      printf("%u: (\"%s\") %d, line %d\n",
             i, orgline, rc, (int)(line - orgline));
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
    printf("Curl_str_hex\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = Curl_str_hex(&line, &num, 0x1235);
      printf("%u: (\"%s\") %d, [%u] line %d\n",
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
    printf("Curl_str_octal\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = Curl_str_octal(&line, &num, 01235);
      printf("%u: (\"%s\") %d, [%u] line %d\n",
             i, orgline, rc, (int)num, (int)(line - orgline));
    }
  }

  {
    /* CURL_OFF_T is typically 2^63-1 */
    static const char *nums[] = {
      "777777777777777777777", /* 2^63 -1 */
      "1000000000000000000000", /* 2^63  */
      NULL
    };
    printf("Curl_str_octal / max\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = Curl_str_octal(&line, &num, CURL_OFF_T_MAX);
      printf("%u: (\"%s\") %d, [%" CURL_FORMAT_CURL_OFF_T "] line %d\n",
             i, orgline, rc, num, (int)(line - orgline));
    }
  }

  {
    /* CURL_OFF_T is typically 2^63-1 */
    static const char *nums[] = {
      "7FFFFFFFFFFFFFFF", /* 2^63 -1 */
      "8000000000000000", /* 2^63  */
      NULL
    };
    printf("Curl_str_hex / max\n");
    for(i = 0; nums[i]; i++) {
      curl_off_t num;
      const char *line = nums[i];
      const char *orgline = line;
      int rc = Curl_str_hex(&line, &num, CURL_OFF_T_MAX);
      printf("%u: (\"%s\") %d, [%" CURL_FORMAT_CURL_OFF_T "] line %d\n",
             i, orgline, rc, num, (int)(line - orgline));
    }
  }

}
UNITTEST_STOP
