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

static void checksize(const char *name, size_t size, size_t allowed)
{
  if(size > allowed) {
    fprintf(stderr, "BAD: struct %s is %d bytes, allowed to be %d",
            name, (int)size, (int)allowed);
    fprintf(stderr, ": %d bytes too big\n", (int)(size - allowed));
    unitfail++;
  }
  else {
    printf("FINE: struct %s is %d bytes, allowed %d (margin: %d bytes)\n",
           name, (int)size, (int)allowed, (int)(allowed - size));
  }
}

/* the maximum sizes we allow specific structs to grow to */
#define MAX_CURL_EASY           5800
#define MAX_CONNECTDATA         1300
#define MAX_CURL_MULTI          750
#define MAX_CURL_HTTPPOST       112
#define MAX_CURL_SLIST          16
#define MAX_CURL_KHKEY          24
#define MAX_CURL_HSTSENTRY      40
#define MAX_CURL_INDEX          16
#define MAX_CURL_MIME           96
#define MAX_CURL_MIMEPART       440
#define MAX_CURL_CERTINFO       16
#define MAX_CURL_TLSSESSIONINFO 16
#define MAX_CURL_BLOB           24
#define MAX_CURLMSG             24
#define MAX_CURL_HEADER         48

static CURLcode test_unit3214(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  checksize("Curl_easy", sizeof(struct Curl_easy), MAX_CURL_EASY);
  checksize("connectdata", sizeof(struct connectdata), MAX_CONNECTDATA);
  checksize("Curl_multi", sizeof(struct Curl_multi), MAX_CURL_MULTI);

  /* public structs MUST NOT change (unless controlled), but exact sizes
     depend on architecture */
  checksize("curl_httppost", sizeof(struct curl_httppost), MAX_CURL_HTTPPOST);
  checksize("curl_slist", sizeof(struct curl_slist), MAX_CURL_SLIST);
  checksize("curl_khkey", sizeof(struct curl_khkey), MAX_CURL_KHKEY);
  checksize("curl_hstsentry", sizeof(struct curl_hstsentry),
            MAX_CURL_HSTSENTRY);
  checksize("curl_index", sizeof(struct curl_index), MAX_CURL_INDEX);
  checksize("curl_mime", sizeof(struct curl_mime), MAX_CURL_MIME);
  checksize("curl_mimepart", sizeof(struct curl_mimepart), MAX_CURL_MIMEPART);
  checksize("curl_certinfo", sizeof(struct curl_certinfo), MAX_CURL_CERTINFO);
  checksize("curl_tlssessioninfo", sizeof(struct curl_tlssessioninfo),
            MAX_CURL_TLSSESSIONINFO);
  checksize("curl_blob", sizeof(struct curl_blob), MAX_CURL_BLOB);
  checksize("CURLMsg", sizeof(struct CURLMsg), MAX_CURLMSG);
  checksize("curl_header", sizeof(struct curl_header), MAX_CURL_HEADER);

  UNITTEST_END_SIMPLE
}
