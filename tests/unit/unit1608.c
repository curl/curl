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
#include "unitcheck.h"

#include "hostip.h"

#ifndef CURL_DISABLE_SHUFFLE_DNS

CURLcode Curl_shuffle_addr(struct Curl_easy *data,
                           struct Curl_addrinfo **addr);

static struct Curl_addrinfo addrs[8];

static CURLcode t1608_setup(void)
{
  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(addrs) - 1; i++) {
    addrs[i].ai_next = &addrs[i + 1];
  }

  return CURLE_OK;
}

static CURLcode test_unit1608(const char *arg)
{
  UNITTEST_BEGIN(t1608_setup())

  int i;
  CURLcode code;
  struct Curl_addrinfo *addrhead = addrs;

  struct Curl_easy *easy = curl_easy_init();
  abort_unless(easy, "out of memory");

  code = curl_easy_setopt(easy, CURLOPT_DNS_SHUFFLE_ADDRESSES, 1L);
  abort_unless(code == CURLE_OK, "curl_easy_setopt failed");

  /* Shuffle repeatedly and make sure that the list changes */
  for(i = 0; i < 10; i++) {
    if(CURLE_OK != Curl_shuffle_addr(easy, &addrhead))
      break;
    if(addrhead != addrs)
      break;
  }

  curl_easy_cleanup(easy);
  curl_global_cleanup();

  abort_unless(addrhead != addrs, "addresses are not being reordered");

  UNITTEST_END(curl_global_cleanup())
}

#else

static CURLcode test_unit1608(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
}

#endif
