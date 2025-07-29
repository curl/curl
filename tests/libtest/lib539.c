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

static CURLcode test_lib539(const char *URL)
{
  CURLcode res;
  CURL *curl;
  char *newURL = NULL;
  struct curl_slist *slist = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /*
   * Begin with curl set to use a single CWD to the URL's directory.
   */
  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_FTP_FILEMETHOD, CURLFTPMETHOD_SINGLECWD);

  res = curl_easy_perform(curl);
  if(res == CURLE_OK) {
    /*
     * Change the FTP_FILEMETHOD option to use full paths rather than a CWD
     * command. Use an innocuous QUOTE command, after which curl will CWD to
     * ftp_conn->entrypath and then (on the next call to ftp_statemach_act)
     * find a non-zero ftpconn->dirdepth even though no directories are stored
     * in the ftpconn->dirs array (after a call to freedirs).
     */

    slist = curl_slist_append(NULL, "SYST");
    if(!slist) {
      curl_free(newURL);
      curl_easy_cleanup(curl);
      curl_global_cleanup();
      return TEST_ERR_MAJOR_BAD;
    }

    test_setopt(curl, CURLOPT_URL, libtest_arg2);
    test_setopt(curl, CURLOPT_FTP_FILEMETHOD, CURLFTPMETHOD_NOCWD);
    test_setopt(curl, CURLOPT_QUOTE, slist);

    res = curl_easy_perform(curl);
  }
test_cleanup:

  curl_slist_free_all(slist);
  curl_free(newURL);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
