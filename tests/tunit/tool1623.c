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
#include "unitcheck.h"

#include "tool_getparam.h"

struct check1623 {
  const char *input;
  curl_off_t amount;
  ParameterError err;
};

static CURLcode test_tool1623(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  {
    int i;
    static const struct check1623 check[] = {
      { "0", 0, PARAM_OK},
      { "00", 0, PARAM_OK},
      { "000", 0, PARAM_OK},
      { "1", 1, PARAM_OK},
      { "1b", 1, PARAM_OK},
      { "99B", 99, PARAM_OK},
      { "2", 2, PARAM_OK},
      { "3", 3, PARAM_OK},
      { "4", 4, PARAM_OK},
      { "5", 5, PARAM_OK},
      { "6", 6, PARAM_OK},
      { "7", 7, PARAM_OK},
      { "77", 77, PARAM_OK},
      { "8", 8, PARAM_OK},
      { "9", 9, PARAM_OK},
      { "10", 10, PARAM_OK},
      { "010", 10, PARAM_OK},
      { "000000000000000000000000000000000010", 10, PARAM_OK},
      { "1k", 1024, PARAM_OK},
      { "2K", 2048, PARAM_OK},
      { "3k", 3072, PARAM_OK},
      { "4K", 4096, PARAM_OK},
      { "5k", 5120, PARAM_OK},
      { "6K", 6144, PARAM_OK},
      { "7k", 7168, PARAM_OK},
      { "8K", 8192, PARAM_OK},
      { "9k", 9216, PARAM_OK},
      { "10K", 10240, PARAM_OK},
      { "20M", 20971520, PARAM_OK},
      { "30G", 32212254720, PARAM_OK},
      { "40T", 43980465111040, PARAM_OK},
      { "50P", 56294995342131200, PARAM_OK},
      { "1.1k", 1126, PARAM_OK},
      { "1.01k", 1034, PARAM_OK},
      { "1.001k", 1025, PARAM_OK},
      { "1.0001k", 1024, PARAM_OK},
      { "22.1m", 23173529, PARAM_OK},
      { "22.01m", 23079157, PARAM_OK},
      { "22.001m", 23069720, PARAM_OK},
      { "22.0001m", 23068776, PARAM_OK},
      { "22.00001m", 23068682, PARAM_OK},
      { "22.000001m", 23068673, PARAM_OK},
      { "22.0000001m", 23068672, PARAM_OK},
      { "22.000000001m", 23068672, PARAM_OK},
      { "3.4", 0, PARAM_BAD_USE},
      { "3.14b", 0, PARAM_BAD_USE},
      { "5000.9P", 5630512844129278361, PARAM_OK},
      { "5000.99P", 5630614175120894197, PARAM_OK},
      { "5000.999P", 5630624308220055781, PARAM_OK},
      { "5000.9999P", 5630625321529969316, PARAM_OK},
      { "8191P", 9222246136947933184, PARAM_OK},
      { "8191.9999999P", 9223372036735343194, PARAM_OK},
      { "8192P", 0, PARAM_NUMBER_TOO_LARGE},
      { "9223372036854775807", 9223372036854775807, PARAM_OK},
      { "9223372036854775808", 0, PARAM_NUMBER_TOO_LARGE},
      { "a", 0, PARAM_BAD_NUMERIC},
      { "-2", 0, PARAM_BAD_NUMERIC},
      { "+2", 0, PARAM_BAD_NUMERIC},
      { "2,2k", 0, PARAM_BAD_USE},
      { NULL, 0, PARAM_OK } /* end of list */
    };

    for(i = 0; check[i].input; i++) {
      bool ok = FALSE;
      curl_off_t output = 0;
      ParameterError err =
        GetSizeParameter(check[i].input, &output);
      if(err != check[i].err)
        curl_mprintf("'%s' unexpectedly returned %d \n",
                     check[i].input, err);
      else if(check[i].amount != output)
        curl_mprintf("'%s' unexpectedly gave %" FMT_OFF_T "\n",
                     check[i].input, output);
      else {
#if 0 /* enable for debugging */
        if(err)
          curl_mprintf("'%s' returned %d\n", check[i].input, err);
        else
          curl_mprintf("'%s' == %" FMT_OFF_T "\n", check[i].input, output);
#endif
        ok = TRUE;
      }
      if(!ok)
        unitfail++;
    }
  }
  UNITTEST_END_SIMPLE
}
