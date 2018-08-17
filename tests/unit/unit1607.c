/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "urldata.h"
#include "connect.h"
#include "share.h"

#include "memdebug.h" /* LAST include file */

static struct Curl_easy *easy;
static struct curl_hash *hostcache;

static void unit_stop(void)
{
  curl_easy_cleanup(easy);
  curl_global_cleanup();
}

static CURLcode unit_setup(void)
{
  int res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);

  easy = curl_easy_init();
  if(!easy) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }

  hostcache = Curl_global_host_cache_init();
  if(!hostcache) {
    unit_stop();
    return CURLE_OUT_OF_MEMORY;
  }

  return res;
}

struct testcase {
  /* host:port:address[,address]... */
  const char *optval;

  /* lowercase host and port to retrieve the addresses from hostcache */
  const char *host;
  int port;

  /* 0 to 9 addresses expected from hostcache */
  const char *address[10];
};


/* In builds without IPv6 support CURLOPT_RESOLVE should skip over those
   addresses, so we have to do that as well. */
static const char skip = 0;
#ifdef ENABLE_IPV6
#define IPV6ONLY(x) x
#else
#define IPV6ONLY(x) &skip
#endif

/* CURLOPT_RESOLVE address parsing tests */
static const struct testcase tests[] = {
  /* spaces aren't allowed, for now */
  { "test.com:80:127.0.0.1, 127.0.0.2",
    "test.com", 80, { NULL, }
  },
  { "TEST.com:80:,,127.0.0.1,,,127.0.0.2,,,,::1,,,",
    "test.com", 80, { "127.0.0.1", "127.0.0.2", IPV6ONLY("::1"), }
  },
  { "test.com:80:::1,127.0.0.1",
    "test.com", 80, { IPV6ONLY("::1"), "127.0.0.1", }
  },
  { "test.com:80:[::1],127.0.0.1",
    "test.com", 80, { IPV6ONLY("::1"), "127.0.0.1", }
  },
  { "test.com:80:::1",
    "test.com", 80, { IPV6ONLY("::1"), }
  },
  { "test.com:80:[::1]",
    "test.com", 80, { IPV6ONLY("::1"), }
  },
  { "test.com:80:127.0.0.1",
    "test.com", 80, { "127.0.0.1", }
  },
  { "test.com:80:,127.0.0.1",
    "test.com", 80, { "127.0.0.1", }
  },
  { "test.com:80:127.0.0.1,",
    "test.com", 80, { "127.0.0.1", }
  },
  { "test.com:0:127.0.0.1",
    "test.com", 0, { "127.0.0.1", }
  },
};

UNITTEST_START
  int i;
  int testnum = sizeof(tests) / sizeof(struct testcase);

  for(i = 0; i < testnum; ++i, curl_easy_reset(easy)) {
    int j;
    int addressnum = sizeof(tests[i].address) / sizeof(*tests[i].address);
    struct Curl_addrinfo *addr;
    struct Curl_dns_entry *dns;
    struct curl_slist *list;
    void *entry_id;
    bool problem = false;

    Curl_hostcache_clean(easy, hostcache);
    easy->dns.hostcache = hostcache;
    easy->dns.hostcachetype = HCACHE_GLOBAL;

    list = curl_slist_append(NULL, tests[i].optval);
    if(!list)
        goto unit_test_abort;
    curl_easy_setopt(easy, CURLOPT_RESOLVE, list);

    Curl_loadhostpairs(easy);

    entry_id = (void *)aprintf("%s:%d", tests[i].host, tests[i].port);
    if(!entry_id) {
      curl_slist_free_all(list);
      goto unit_test_abort;
    }
    dns = Curl_hash_pick(easy->dns.hostcache, entry_id, strlen(entry_id) + 1);
    free(entry_id);
    entry_id = NULL;

    addr = dns ? dns->addr : NULL;

    for(j = 0; j < addressnum; ++j) {
      long port = 0;
      char ipaddress[MAX_IPADR_LEN] = {0};

      if(!addr && !tests[i].address[j])
        break;

      if(tests[i].address[j] == &skip)
        continue;

      if(addr && !Curl_getaddressinfo(addr->ai_addr,
                                      ipaddress, &port)) {
        fprintf(stderr, "%s:%d tests[%d] failed. getaddressinfo failed.\n",
                __FILE__, __LINE__, i);
        problem = true;
        break;
      }

      if(addr && !tests[i].address[j]) {
        fprintf(stderr, "%s:%d tests[%d] failed. the retrieved addr "
                "is %s but tests[%d].address[%d] is NULL.\n",
                __FILE__, __LINE__, i, ipaddress, i, j);
        problem = true;
        break;
      }

      if(!addr && tests[i].address[j]) {
        fprintf(stderr, "%s:%d tests[%d] failed. the retrieved addr "
                "is NULL but tests[%d].address[%d] is %s.\n",
                __FILE__, __LINE__, i, i, j, tests[i].address[j]);
        problem = true;
        break;
      }

      if(!curl_strequal(ipaddress, tests[i].address[j])) {
        fprintf(stderr, "%s:%d tests[%d] failed. the retrieved addr "
                "%s is not equal to tests[%d].address[%d] %s.\n",
                __FILE__, __LINE__, i, ipaddress, i, j, tests[i].address[j]);
        problem = true;
        break;
      }

      if(port != tests[i].port) {
        fprintf(stderr, "%s:%d tests[%d] failed. the retrieved port "
                "for tests[%d].address[%d] is %ld but tests[%d].port is %d.\n",
                __FILE__, __LINE__, i, i, j, port, i, tests[i].port);
        problem = true;
        break;
      }

      if(dns->timestamp != 0) {
        fprintf(stderr, "%s:%d tests[%d] failed. the timestamp is not zero. "
                "for tests[%d].address[%d\n",
                __FILE__, __LINE__, i, i, j);
        problem = true;
        break;
      }

      addr = addr->ai_next;
    }

    Curl_hostcache_clean(easy, easy->dns.hostcache);
    curl_slist_free_all(list);

    if(problem) {
      unitfail++;
      continue;
    }
  }
UNITTEST_STOP
