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
#include "first.h"

/* test case and code based on https://github.com/curl/curl/issues/2847 */

#include "testtrace.h"
#include "memdebug.h"

static int sockopt_callback(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose)
{
#if defined(SOL_SOCKET) && defined(SO_SNDBUF)
  int sndbufsize = 4 * 1024; /* 4KB send buffer */
  (void)clientp;
  (void)purpose;
  setsockopt(curlfd, SOL_SOCKET, SO_SNDBUF,
             (char *)&sndbufsize, sizeof(sndbufsize));
#else
  (void)clientp;
  (void)curlfd;
  (void)purpose;
#endif
  return CURL_SOCKOPT_OK;
}

static CURLcode test_lib1522(const char *URL)
{
  static char g_Data[40 * 1024]; /* POST 40KB */

  CURLcode code = TEST_ERR_MAJOR_BAD;
  CURLcode res;
  struct curl_slist *pHeaderList = NULL;
  CURL *curl = curl_easy_init();
  memset(g_Data, 'A', sizeof(g_Data)); /* send As! */

  curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, g_Data);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)sizeof(g_Data));

  debug_config.nohex = TRUE;
  debug_config.tracetime = TRUE;
  test_setopt(curl, CURLOPT_DEBUGDATA, &debug_config);
  test_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* Remove "Expect: 100-continue" */
  pHeaderList = curl_slist_append(pHeaderList, "Expect:");

  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, pHeaderList);

  code = curl_easy_perform(curl);

  if(code == CURLE_OK) {
    curl_off_t uploadSize;
    curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD_T, &uploadSize);

    curl_mprintf("uploadSize = %" CURL_FORMAT_CURL_OFF_T "\n", uploadSize);

    if((size_t) uploadSize == sizeof(g_Data)) {
      curl_mprintf("!!!!!!!!!! PASS\n");
    }
    else {
      curl_mprintf("sent %zu, libcurl says %" CURL_FORMAT_CURL_OFF_T "\n",
                   sizeof(g_Data), uploadSize);
    }
  }
  else {
    curl_mprintf("curl_easy_perform() failed. e = %d\n", code);
  }
test_cleanup:
  curl_slist_free_all(pHeaderList);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return code;
}
