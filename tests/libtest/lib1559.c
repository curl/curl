/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define EXCESSIVE 10*1000*1000
int test(char *URL)
{
  CURLcode res = 0;
  CURL *curl = NULL;
  char *longurl = malloc(EXCESSIVE);
  CURLU *u;
  (void)URL;

  if(!longurl)
    return 1;

  memset(longurl, 'a', EXCESSIVE);
  longurl[EXCESSIVE-1] = 0;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  res = curl_easy_setopt(curl, CURLOPT_URL, longurl);
  printf("CURLOPT_URL %d bytes URL == %d\n",
         EXCESSIVE, (int)res);

  res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, longurl);
  printf("CURLOPT_POSTFIELDS %d bytes data == %d\n",
         EXCESSIVE, (int)res);

  u = curl_url();
  if(u) {
    CURLUcode uc = curl_url_set(u, CURLUPART_URL, longurl, 0);
    printf("CURLUPART_URL %d bytes URL == %d\n",
           EXCESSIVE, (int)uc);
    uc = curl_url_set(u, CURLUPART_SCHEME, longurl, CURLU_NON_SUPPORT_SCHEME);
    printf("CURLUPART_SCHEME %d bytes scheme == %d\n",
           EXCESSIVE, (int)uc);
    uc = curl_url_set(u, CURLUPART_USER, longurl, 0);
    printf("CURLUPART_USER %d bytes user == %d\n",
           EXCESSIVE, (int)uc);
    curl_url_cleanup(u);
  }

test_cleanup:
  free(longurl);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res; /* return the final return code */
}
