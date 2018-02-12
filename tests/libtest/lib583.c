/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/*
 * This test case is based on the sample code provided by Saqib Ali
 * https://curl.haxx.se/mail/lib-2011-03/0066.html
 */

#include "test.h"

#include <sys/stat.h>

#include "memdebug.h"

int test(char *URL)
{
  int stillRunning;
  CURLM *multiHandle = NULL;
  CURL *curl = NULL;
  CURLMcode res = CURLM_OK;

  global_init(CURL_GLOBAL_ALL);

  multi_init(multiHandle);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_USERPWD, libtest_arg2);
  easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, "curl_client_key.pub");
  easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, "curl_client_key");

  easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_INFILESIZE, (long)5);

  multi_add_handle(multiHandle, curl);

  /* this tests if removing an easy handle immediately after multi
     perform has been called succeeds or not. */

  fprintf(stderr, "curl_multi_perform()...\n");

  multi_perform(multiHandle, &stillRunning);

  fprintf(stderr, "curl_multi_perform() succeeded\n");

  fprintf(stderr, "curl_multi_remove_handle()...\n");
  res = curl_multi_remove_handle(multiHandle, curl);
  if(res)
    fprintf(stderr, "curl_multi_remove_handle() failed, "
            "with code %d\n", (int)res);
  else
    fprintf(stderr, "curl_multi_remove_handle() succeeded\n");

test_cleanup:

  /* undocumented cleanup sequence - type UB */

  curl_easy_cleanup(curl);
  curl_multi_cleanup(multiHandle);
  curl_global_cleanup();

  return (int)res;
}
