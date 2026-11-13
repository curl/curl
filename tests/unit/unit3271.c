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
#include "connect.h"
#include "curl_addrinfo.h"

static CURLcode t3271_setup(void)
{
  CURLcode result = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return result;
}

/* CURLOPT_RESOLVE address parsing test - to test the following defect fix:

   1. if there is already existing host:port pair in the DNS cache and
      we call CURLOPT_RESOLVE, it should also replace addresses.
      for example, if there is "test.com:80" with address "1.1.1.1"
      and we called CURLOPT_RESOLVE with address "2.2.2.2", then DNS entry
      needs to reflect that.

   2. when cached address is already there and close to expire, then by the
      time request is made, it can get expired.  This happens because, when
      we set address using CURLOPT_RESOLVE,
      it usually marks as permanent (by setting timestamp to zero). However,
      if address already exists in the cache, then it does not mark it, but
      leaves it as it is.
      We are fixing this by setting timestamp to zero if address already
      exists too.

   Test:

   - insert new entry
   - verify that timestamp is not zero
   - call set options with CURLOPT_RESOLVE
   - then, call Curl_loadhostpairs

   expected result: cached address has zero timestamp.

   - call set options with CURLOPT_RESOLVE with same host:port pair,
     different address.
   - then, call Curl_loadhostpairs

   expected result: cached address has zero timestamp and new address
 */

static CURLcode test_unit3271(const char *arg)
{
  UNITTEST_BEGIN(t3271_setup())

  struct testcase {
    /* host:port:address[,address]... */
    const char *optval;

    /* lowercase host and port to retrieve the addresses from hostcache */
    const char *host;
    uint16_t port;

    /* 0 to 9 addresses expected from hostcache */
    const char *address[10];
  };

  static const struct testcase tests[] = {
    /* spaces are not allowed */
    { "test.com:80:127.0.0.1",
      "test.com", 80, { "127.0.0.1", }
    },
    { "test.com:80:127.0.0.2",
      "test.com", 80, { "127.0.0.2", }
    },
  };

  size_t i;
  struct Curl_multi *multi = NULL;
  struct Curl_easy *easy = NULL;
  struct curl_slist *list = NULL;
  char hostname[258];
  struct dnsc_id long_id;
  struct Curl_dns_entry *long_dns;

  /* Check full hostname matching when the DNS cache key is truncated. */
  memset(hostname, 'a', sizeof(hostname) - 1);
  hostname[sizeof(hostname) - 1] = 0;
  long_dns = curlx_calloc(1, sizeof(*long_dns) + sizeof(hostname));
  abort_unless(long_dns, "could not allocate cache entry");
  hostname[255] = 0;
  memcpy(long_dns->hostname, hostname, 256);
  hostname[255] = 'a';
  long_dns->hostlen = 255;
  long_dns->port = 80;
  long_id.port = 80;
  curlx_str_assign(&long_id.name, hostname, strlen(hostname));
  fail_unless(!dnsc_id_matches_entry(&long_id, long_dns),
              "long query must not match shorter cached hostname");
  memcpy(long_dns->hostname, hostname, sizeof(hostname));
  long_dns->hostlen = (uint16_t)strlen(hostname);
  fail_unless(dnsc_id_matches_entry(&long_id, long_dns),
              "identical long hostname must match");
  hostname[0] = 'A';
  fail_unless(dnsc_id_matches_entry(&long_id, long_dns),
              "long hostname lookup must remain case insensitive");
  hostname[255] = 0;
  curlx_str_assign(&long_id.name, hostname, strlen(hostname));
  fail_unless(!dnsc_id_matches_entry(&long_id, long_dns),
              "short query must not match longer cached hostname");
  curlx_free(long_dns);

  /* important: we setup cache outside of the loop and also clean cache after
     the loop. In contrast, for example, test 1607 sets up and cleans cache on
     each iteration. */

  for(i = 0; i < CURL_ARRAYSIZE(tests); ++i) {
    size_t j;
    size_t addressnum = CURL_ARRAYSIZE(tests[i].address);
    struct Curl_addrinfo *addr;
    struct Curl_dns_entry *dns;
    struct dnsc_id id;
    struct dnsc_key key;
    const char type = CURL_DNST_ADDR;
    bool problem = FALSE;
    struct Curl_peer *peer = NULL;
    easy = curl_easy_init();
    if(!easy) {
      curl_global_cleanup();
      return CURLE_OUT_OF_MEMORY;
    }
    /* create a multi handle and add the easy handle to it so that the
       hostcache is setup */
    multi = curl_multi_init();
    if(!multi)
      goto error;
    curl_multi_add_handle(multi, easy);

    list = curl_slist_append(NULL, tests[i].optval);
    if(!list)
      goto error;

    curl_easy_setopt(easy, CURLOPT_RESOLVE, list);

    if(Curl_loadhostpairs(easy))
      goto error;

    if(Curl_peer_create(easy, &Curl_scheme_http,
                        tests[i].host, tests[i].port, &peer))
      goto error;

    dnsc_peer2id(&id, type, peer);
    dnsc_id2key(&key, &id);
    dns = Curl_hash_pick(&multi->dnscache.entries, key.data, key.len);

    addr = dns ? dns->addr : NULL;

    for(j = 0; j < addressnum; ++j) {
      uint16_t port = 0;
      char ipaddress[MAX_IPADR_LEN] = { 0 };

      if(!addr && !tests[i].address[j])
        break;

      if(addr && sockaddr2string(addr->ai_addr, addr->ai_addrlen,
                                 ipaddress, &port)) {
        curl_mfprintf(stderr,
                      "%s:%d tests[%zu] failed. Curl_addr2string failed.\n",
                      __FILE__, __LINE__, i);
        problem = TRUE;
        break;
      }

      if(addr && !tests[i].address[j]) {
        curl_mfprintf(stderr, "%s:%d tests[%zu] failed. the retrieved addr "
                      "is %s but tests[%zu].address[%zu] is NULL.\n",
                      __FILE__, __LINE__, i, ipaddress, i, j);
        problem = TRUE;
        break;
      }

      if(!addr && tests[i].address[j]) {
        curl_mfprintf(stderr, "%s:%d tests[%zu] failed. the retrieved addr "
                      "is NULL but tests[%zu].address[%zu] is %s.\n",
                      __FILE__, __LINE__, i, i, j, tests[i].address[j]);
        problem = TRUE;
        break;
      }

      if(!curl_strequal(ipaddress, tests[i].address[j])) {
        curl_mfprintf(stderr, "%s:%d tests[%zu] failed. the retrieved addr "
                      "%s is not equal to tests[%zu].address[%zu] %s.\n",
                      __FILE__, __LINE__, i, ipaddress, i, j,
                      tests[i].address[j]);
        problem = TRUE;
        break;
      }

      if(port != tests[i].port) {
        curl_mfprintf(stderr, "%s:%d tests[%zu] failed. the retrieved port "
                      "for tests[%zu].address[%zu] is %d "
                      "but tests[%zu].port is %d.\n",
                      __FILE__, __LINE__, i, i, j, port, i, tests[i].port);
        problem = TRUE;
        break;
      }

      if(!addr)
        break;

      addr = addr->ai_next;
    }
    Curl_peer_unlink(&peer);

    curl_easy_cleanup(easy);
    easy = NULL;
    curl_multi_cleanup(multi);
    multi = NULL;
    curl_slist_free_all(list);
    list = NULL;

    if(problem) {
      unitfail++;
      continue;
    }
  }
  goto unit_test_abort;
error:
  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);
  curl_slist_free_all(list);

  UNITTEST_END(curl_global_cleanup())
}
