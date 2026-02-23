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
#include <curl/curl.h>
#include <iostream>

class CurlClass {
public:
  void curl_multi_setopt(void *a, int b, long c) {
    std::cout << curl_version() << std::endl;
  }
};

int main(int argc, const char **argv)
{
  (void)argc;
  std::cout << "libcurl C++ test:" << std::endl;
  std::cout << argv[0] << std::endl;
  CurlClass mycurl;
  mycurl.curl_multi_setopt(nullptr, 0, 0);
  ::curl_easy_setopt(nullptr, CURLOPT_URL, "https://example.com/");
  std::cout << "---" << std::endl;
  return 0;
}
