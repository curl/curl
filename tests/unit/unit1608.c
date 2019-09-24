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
#include "curlcheck.h"

#include "hostip.h"

CURLcode Curl_shuffle_addr(struct Curl_easy *data,
                           Curl_addrinfo **addr);

#define NUM_ADDRS 8
static struct Curl_addrinfo addrs[NUM_ADDRS];

static CURLcode unit_setup(void)
{
  int i;
  for(i = 0; i < NUM_ADDRS - 1; i++) {
    addrs[i].ai_next = &addrs[i + 1];
  }

  return CURLE_OK;
}

static void unit_stop(void)
{

}

UNITTEST_START
{
  int i;
  CURLcode code;
  struct Curl_addrinfo* addrhead = addrs;

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

  return 0;
}
UNITTEST_STOP
