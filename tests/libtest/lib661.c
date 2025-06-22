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

#include "memdebug.h"

static CURLcode test_lib661(char *URL)
{
   CURLcode res;
   CURL *curl = NULL;
   char *newURL = NULL;
   struct curl_slist *slist = NULL;

   if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
     curl_mfprintf(stderr, "curl_global_init() failed\n");
     return TEST_ERR_MAJOR_BAD;
   }

   curl = curl_easy_init();
   if(!curl) {
     curl_mfprintf(stderr, "curl_easy_init() failed\n");
     res = TEST_ERR_MAJOR_BAD;
     goto test_cleanup;
   }

   /* test: CURLFTPMETHOD_SINGLECWD with absolute path should
            skip CWD to entry path */
   newURL = curl_maprintf("%s/folderA/661", URL);
   test_setopt(curl, CURLOPT_URL, newURL);
   test_setopt(curl, CURLOPT_VERBOSE, 1L);
   test_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, 1L);
   test_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long) CURLFTPMETHOD_SINGLECWD);
   res = curl_easy_perform(curl);
   if(res != CURLE_REMOTE_FILE_NOT_FOUND)
     goto test_cleanup;

   curl_free(newURL);
   newURL = curl_maprintf("%s/folderB/661", URL);
   test_setopt(curl, CURLOPT_URL, newURL);
   res = curl_easy_perform(curl);
   if(res != CURLE_REMOTE_FILE_NOT_FOUND)
     goto test_cleanup;

   /* test: CURLFTPMETHOD_NOCWD with absolute path should
      never emit CWD (for both new and reused easy handle) */
   curl_easy_cleanup(curl);
   curl = curl_easy_init();
   if(!curl) {
     curl_mfprintf(stderr, "curl_easy_init() failed\n");
     res = TEST_ERR_MAJOR_BAD;
     goto test_cleanup;
   }

   curl_free(newURL);
   newURL = curl_maprintf("%s/folderA/661", URL);
   test_setopt(curl, CURLOPT_URL, newURL);
   test_setopt(curl, CURLOPT_VERBOSE, 1L);
   test_setopt(curl, CURLOPT_IGNORE_CONTENT_LENGTH, 1L);
   test_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long) CURLFTPMETHOD_NOCWD);
   res = curl_easy_perform(curl);
   if(res != CURLE_REMOTE_FILE_NOT_FOUND)
     goto test_cleanup;

   /* curve ball: CWD /folderB before reusing connection with _NOCWD */
   curl_free(newURL);
   newURL = curl_maprintf("%s/folderB/661", URL);
   test_setopt(curl, CURLOPT_URL, newURL);
   test_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long) CURLFTPMETHOD_SINGLECWD);
   res = curl_easy_perform(curl);
   if(res != CURLE_REMOTE_FILE_NOT_FOUND)
     goto test_cleanup;

   curl_free(newURL);
   newURL = curl_maprintf("%s/folderA/661", URL);
   test_setopt(curl, CURLOPT_URL, newURL);
   test_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long) CURLFTPMETHOD_NOCWD);
   res = curl_easy_perform(curl);
   if(res != CURLE_REMOTE_FILE_NOT_FOUND)
     goto test_cleanup;

   /* test: CURLFTPMETHOD_NOCWD with home-relative path should
      not emit CWD for first FTP access after login */
   curl_easy_cleanup(curl);
   curl = curl_easy_init();
   if(!curl) {
     curl_mfprintf(stderr, "curl_easy_init() failed\n");
     res = TEST_ERR_MAJOR_BAD;
     goto test_cleanup;
   }

   slist = curl_slist_append(NULL, "SYST");
   if(!slist) {
     curl_mfprintf(stderr, "curl_slist_append() failed\n");
     res = TEST_ERR_MAJOR_BAD;
     goto test_cleanup;
   }

   test_setopt(curl, CURLOPT_URL, URL);
   test_setopt(curl, CURLOPT_VERBOSE, 1L);
   test_setopt(curl, CURLOPT_NOBODY, 1L);
   test_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long) CURLFTPMETHOD_NOCWD);
   test_setopt(curl, CURLOPT_QUOTE, slist);
   res = curl_easy_perform(curl);
   if(res)
     goto test_cleanup;

   /* test: CURLFTPMETHOD_SINGLECWD with home-relative path should
      not emit CWD for first FTP access after login */
   curl_easy_cleanup(curl);
   curl = curl_easy_init();
   if(!curl) {
     curl_mfprintf(stderr, "curl_easy_init() failed\n");
     res = TEST_ERR_MAJOR_BAD;
     goto test_cleanup;
   }

   test_setopt(curl, CURLOPT_URL, URL);
   test_setopt(curl, CURLOPT_VERBOSE, 1L);
   test_setopt(curl, CURLOPT_NOBODY, 1L);
   test_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long) CURLFTPMETHOD_SINGLECWD);
   test_setopt(curl, CURLOPT_QUOTE, slist);
   res = curl_easy_perform(curl);
   if(res)
     goto test_cleanup;

   /* test: CURLFTPMETHOD_NOCWD with home-relative path should
      not emit CWD for second FTP access when not needed +
      bonus: see if path buffering survives curl_easy_reset() */
   curl_easy_reset(curl);
   test_setopt(curl, CURLOPT_URL, URL);
   test_setopt(curl, CURLOPT_VERBOSE, 1L);
   test_setopt(curl, CURLOPT_NOBODY, 1L);
   test_setopt(curl, CURLOPT_FTP_FILEMETHOD, (long) CURLFTPMETHOD_NOCWD);
   test_setopt(curl, CURLOPT_QUOTE, slist);
   res = curl_easy_perform(curl);

test_cleanup:

   if(res)
     curl_mfprintf(stderr, "test encountered error %d\n", res);
   curl_slist_free_all(slist);
   curl_free(newURL);
   curl_easy_cleanup(curl);
   curl_global_cleanup();

   return res;
}
