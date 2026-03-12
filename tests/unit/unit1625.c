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

#include "urldata.h"
#include "url.h"

struct check1625 {
  const char *in;
  const char *hdr;
  const char *extract;
  bool expect;
};

static CURLcode test_unit1625(const char *arg)
{
  size_t i;
  static const struct check1625 list[] = {
    /* basic case */
    { "Encoding: gzip, chunked", "Encoding:", "chunked", TRUE },
    /* different case */
    { "Encoding: gzip, chunked", "Encoding:", "CHUNKED", TRUE },
    /* another different case */
    { "Encoding: gzip, CHUNKED", "Encoding:", "chunked", TRUE },
    /* the other value */
    { "Encoding: gzip, chunked", "Encoding:", "gzip", TRUE },
    /* without space */
    { "Encoding: gzip,chunked", "Encoding:", "gzip", TRUE },
    /* multiple spaces */
    { "Encoding:    gzip,     chunked", "Encoding:", "chunked", TRUE },
    /* tabs */
    { "Encoding: gzip, \tchunked", "Encoding:", "chunked", TRUE },
    /* end with CR */
    { "Encoding: gzip\r\n", "Encoding:", "gzip", TRUE },
    /* end with LF */
    { "Encoding: gzip\n", "Encoding:", "gzip", TRUE },
    /* end with tab */
    { "Encoding: gzip\t", "Encoding:", "gzip", TRUE },
    /* end with space + LF */
    { "Encoding: gzip \n", "Encoding:", "gzip", TRUE },
    /* missing value */
    { "Encoding: gzip, chunked", "Encoding:", "br", FALSE },
    /* wrong header */
    { "Encoding: gzip, chunked", "Encodin:", "chunked", FALSE },
    /* prefix only */
    { "Encoding: gzip2, chunked", "Encoding:", "gzip", FALSE },
    /* suffix only */
    { "Encoding: agzip, chunked", "Encoding:", "gzip", FALSE },
    /* not the right header */
    { "Decoding: gzip, chunked", "Encoding:", "gzip", FALSE },
  };
  (void)arg;

  for(i = 0; i < CURL_ARRAYSIZE(list); i++) {
    bool check = Curl_compareheader(list[i].in,
                                    list[i].hdr, strlen(list[i].hdr),
                                    list[i].extract, strlen(list[i].extract));
    if(check != list[i].expect) {
      curl_mprintf("Input: %s\n"
                   "Header: %s\n"
                   "Look for: %s\n"
                   "Returned: %s\n",
                   list[i].in, list[i].hdr, list[i].extract,
                   check ? "TRUE" : "FALSE");
      break;
    }
  }

  curl_mprintf("%zu invokes\n", i);

  if(i != CURL_ARRAYSIZE(list))
    return CURLE_FAILED_INIT;

  return CURLE_OK;
}
