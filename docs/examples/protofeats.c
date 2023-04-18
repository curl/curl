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
/* <DESC>
 * Outputs all protocols and features supported
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

#if !CURL_AT_LEAST_VERSION(7,87,0)
#error "too old libcurl"
#endif

int main(void)
{
  curl_version_info_data *ver;
  const char *const *ptr;

  curl_global_init(CURL_GLOBAL_ALL);

  ver = curl_version_info(CURLVERSION_NOW);
  printf("Protocols:\n");
  for(ptr = ver->protocols; *ptr; ++ptr)
    printf("  %s\n", *ptr);
  printf("Features:\n");
  for(ptr = ver->feature_names; *ptr; ++ptr)
    printf("  %s\n", *ptr);

  curl_global_cleanup();
  return 0;
}
