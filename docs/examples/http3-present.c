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
/* <DESC>
 * Checks if HTTP/3 support is present in libcurl.
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

int main(void)
{
  curl_version_info_data *ver;

  curl_global_init(CURL_GLOBAL_ALL);

  ver = curl_version_info(CURLVERSION_NOW);
  if(ver->features & CURL_VERSION_HTTP2)
    printf("HTTP/2 support is present\n");

  if(ver->features & CURL_VERSION_HTTP3)
    printf("HTTP/3 support is present\n");

  if(ver->features & CURL_VERSION_ALTSVC)
    printf("Alt-svc support is present\n");

  curl_global_cleanup();
  return 0;
}
