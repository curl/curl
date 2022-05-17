/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "test.h"

#include "memdebug.h"

#include <curl/multi.h>

int test(char *URL)
{
  CURLM *handle;
  int res = CURLE_OK;
  static const char * const bl_servers[] =
     {"Microsoft-IIS/6.0", "nginx/0.8.54", NULL};
  static const char * const bl_sites[] =
     {"curl.se:443", "example.com:80", NULL};

  global_init(CURL_GLOBAL_ALL);
  handle = curl_multi_init();
  (void)URL; /* unused */

  curl_multi_setopt(handle, CURLMOPT_PIPELINING_SERVER_BL, bl_servers);
  curl_multi_setopt(handle, CURLMOPT_PIPELINING_SITE_BL, bl_sites);
  curl_multi_cleanup(handle);
  curl_global_cleanup();
  return 0;
}
