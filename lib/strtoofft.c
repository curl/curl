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

#include "curl_setup.h"

#include "strtoofft.h"
#include "strparse.h"

/*
 * Parse a positive number up to 63-bit number written in ASCII. Skip leading
 * blanks. No support for prefixes.
 */
CURLofft curlx_strtoofft(const char *str, char **endp, int base,
                         curl_off_t *num)
{
  curl_off_t number;
  int rc;
  *num = 0; /* clear by default */
  DEBUGASSERT((base == 10) || (base == 16));

  while(ISBLANK(*str))
    str++;

  rc = base == 10 ?
    Curl_str_number(&str, &number, CURL_OFF_T_MAX) :
    Curl_str_hex(&str, &number, CURL_OFF_T_MAX);

  if(endp)
    *endp = (char *)str;
  if(rc == STRE_OVERFLOW)
    /* overflow */
    return CURL_OFFT_FLOW;
  else if(rc)
    /* nothing parsed */
    return CURL_OFFT_INVAL;

  *num = number;
  return CURL_OFFT_OK;
}
