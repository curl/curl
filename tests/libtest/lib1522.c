/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* test case and code based on https://github.com/curl/curl/issues/2847 */

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static char g_Data[40 * 1024]; /* POST 40KB */

static int sockopt_callback(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose)
{
  int sndbufsize = 4 * 1024; /* 4KB send buffer */
  (void) clientp;
  (void) purpose;
#if defined(SOL_SOCKET) && defined(SO_SNDBUF)
  setsockopt(curlfd, SOL_SOCKET, SO_SNDBUF,
             (const char *)&sndbufsize, sizeof(sndbufsize));
#else
  (void)curlfd;
#endif
  return CURL_SOCKOPT_OK;
}

int test(char *URL)
{
  CURLcode code;
  struct curl_slist *pHeaderList = NULL;
  CURL *pCurl = curl_easy_init();
  memset(g_Data, 'A', sizeof(g_Data)); /* send As! */

  curl_easy_setopt(pCurl, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
  curl_easy_setopt(pCurl, CURLOPT_URL, URL);
  curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, g_Data);
  curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, (long)sizeof(g_Data));

  /* Remove "Expect: 100-continue" */
  pHeaderList = curl_slist_append(pHeaderList, "Expect:");

  curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, pHeaderList);

  code = curl_easy_perform(pCurl);

  if(code == CURLE_OK) {
    curl_off_t uploadSize;
    curl_easy_getinfo(pCurl, CURLINFO_SIZE_UPLOAD_T, &uploadSize);

    printf("uploadSize = %ld\n", (long)uploadSize);

    if((size_t) uploadSize == sizeof(g_Data)) {
      printf("!!!!!!!!!! PASS\n");
    }
    else {
      printf("!!!!!!!!!! FAIL\n");
    }
  }
  else {
    printf("curl_easy_perform() failed. e = %d\n", code);
  }

  curl_slist_free_all(pHeaderList);
  curl_easy_cleanup(pCurl);

  return 0;
}
