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
#include "urldata.h"

static CURLcode test_create2413(const char *name,
                                CURL *curl,
                                const struct Curl_scheme *scheme,
                                const char *hostname,
                                uint16_t port,
                                const char *exp_hostname,
                                bool exp_ipv6,
                                const char *exp_zoneid)
{
  struct Curl_peer *peer = NULL;
  CURLcode result;

  result = Curl_peer_create((struct Curl_easy *)curl,
                            scheme, hostname, port, &peer);
  if(result) {
    curl_mfprintf(stderr, "%s: create failed %d", name, (int)result);
    goto out;
  }

  result = CURLE_FAILED_INIT;
  if(peer->scheme != scheme) {
    curl_mfprintf(stderr, "%s: has wrong scheme", name);
  }
  else if(!curl_strequal(peer->user_hostname, hostname)) {
    curl_mfprintf(stderr, "%s: user_hostname=%s, expected %s", name,
                  peer->user_hostname, exp_hostname);
  }
  else if(exp_hostname && !curl_strequal(peer->hostname, exp_hostname))
    curl_mfprintf(stderr, "%s: hostname=%s, expected %s", name,
                  peer->hostname, exp_hostname);
  else if(peer->port != port)
    curl_mfprintf(stderr, "%s: port=%u, expected %u", name,
                  peer->port, port);
  else if((bool)peer->ipv6 != exp_ipv6)
    curl_mfprintf(stderr, "%s: ipv6=%d, expected %d", name,
                  peer->ipv6, exp_ipv6);
  else if(exp_zoneid &&
          (!peer->zoneid || !curl_strequal(exp_zoneid, peer->zoneid)))
    curl_mfprintf(stderr, "%s: zoneid=%s, expected %s", name,
                  peer->zoneid, exp_zoneid);
  else if(!exp_zoneid && peer->zoneid)
    curl_mfprintf(stderr, "%s: zoneid=%s, expected nothing", name,
                  peer->zoneid);
  else
    result = CURLE_OK;

out:
  Curl_peer_unlink(&peer);
  fail_unless(!result, "check failed");
  return result;
}

static CURLcode test_unit2413(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  CURL *curl;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    goto unit_test_abort;
  }

  test_create2413("peer1", curl, &Curl_scheme_https, "test.curl.se", 1234,
                  "test.curl.se", FALSE, NULL);
  test_create2413("peer2", curl, &Curl_scheme_https, "127.0.0.1", 1234,
                  "127.0.0.1", FALSE, NULL);
  test_create2413("peer3", curl, &Curl_scheme_https, "::1", 1234,
                  "::1", TRUE, NULL);
  test_create2413("peer4", curl, &Curl_scheme_https, "[::1]", 1234,
                  "::1", TRUE, NULL);
  test_create2413("peer5", curl, &Curl_scheme_https, "test.curl.se.", 1234,
                  "test.curl.se.", FALSE, NULL);
  test_create2413("peer6", curl, &Curl_scheme_https, "[::1%tada]", 1234,
                  "::1", TRUE, "tada");
  test_create2413("peer7", curl, &Curl_scheme_https, "::1%tada", 1234,
                  "::1", TRUE, "tada");

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  UNITTEST_END_SIMPLE
}
