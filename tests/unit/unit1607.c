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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "fetchcheck.h"

#include "urldata.h"
#include "connect.h"
#include "share.h"

#include "memdebug.h" /* LAST include file */

static void unit_stop(void)
{
  fetch_global_cleanup();
}

static FETCHcode unit_setup(void)
{
  FETCHcode res = FETCHE_OK;

  global_init(FETCH_GLOBAL_ALL);

  return res;
}

struct testcase
{
  /* host:port:address[,address]... */
  const char *optval;

  /* lowercase host and port to retrieve the addresses from hostcache */
  const char *host;
  int port;

  /* whether we expect a permanent or non-permanent cache entry */
  bool permanent;

  /* 0 to 9 addresses expected from hostcache */
  const char *address[10];
};

/* In builds without IPv6 support FETCHOPT_RESOLVE should skip over those
   addresses, so we have to do that as well. */
static const char skip = 0;
#ifdef USE_IPV6
#define IPV6ONLY(x) x
#else
#define IPV6ONLY(x) &skip
#endif

/* FETCHOPT_RESOLVE address parsing tests */
static const struct testcase tests[] = {
    /* spaces aren't allowed, for now */
    {"test.com:80:127.0.0.1, 127.0.0.2",
     "test.com",
     80,
     TRUE,
     {
         NULL,
     }},
    {"TEST.com:80:,,127.0.0.1,,,127.0.0.2,,,,::1,,,",
     "test.com",
     80,
     TRUE,
     {
         "127.0.0.1",
         "127.0.0.2",
         IPV6ONLY("::1"),
     }},
    {"test.com:80:::1,127.0.0.1",
     "test.com",
     80,
     TRUE,
     {
         IPV6ONLY("::1"),
         "127.0.0.1",
     }},
    {"test.com:80:[::1],127.0.0.1",
     "test.com",
     80,
     TRUE,
     {
         IPV6ONLY("::1"),
         "127.0.0.1",
     }},
    {"test.com:80:::1",
     "test.com",
     80,
     TRUE,
     {
         IPV6ONLY("::1"),
     }},
    {"test.com:80:[::1]",
     "test.com",
     80,
     TRUE,
     {
         IPV6ONLY("::1"),
     }},
    {"test.com:80:127.0.0.1",
     "test.com",
     80,
     TRUE,
     {
         "127.0.0.1",
     }},
    {"test.com:80:,127.0.0.1",
     "test.com",
     80,
     TRUE,
     {
         "127.0.0.1",
     }},
    {"test.com:80:127.0.0.1,",
     "test.com",
     80,
     TRUE,
     {
         "127.0.0.1",
     }},
    {"test.com:0:127.0.0.1",
     "test.com",
     0,
     TRUE,
     {
         "127.0.0.1",
     }},
    {"+test.com:80:127.0.0.1,",
     "test.com",
     80,
     FALSE,
     {
         "127.0.0.1",
     }},
};

UNITTEST_START
{
  int i;
  int testnum = sizeof(tests) / sizeof(struct testcase);
  struct Fetch_multi *multi = NULL;
  struct Fetch_easy *easy = NULL;
  struct fetch_slist *list = NULL;

  for (i = 0; i < testnum; ++i)
  {
    int j;
    int addressnum = sizeof(tests[i].address) / sizeof(*tests[i].address);
    struct Fetch_addrinfo *addr;
    struct Fetch_dns_entry *dns;
    void *entry_id;
    bool problem = false;
    easy = fetch_easy_init();
    if (!easy)
      goto error;

    /* create a multi handle and add the easy handle to it so that the
       hostcache is setup */
    multi = fetch_multi_init();
    fetch_multi_add_handle(multi, easy);

    list = fetch_slist_append(NULL, tests[i].optval);
    if (!list)
      goto error;
    fetch_easy_setopt(easy, FETCHOPT_RESOLVE, list);

    Fetch_loadhostpairs(easy);

    entry_id = (void *)aprintf("%s:%d", tests[i].host, tests[i].port);
    if (!entry_id)
      goto error;
    dns = Fetch_hash_pick(easy->dns.hostcache, entry_id, strlen(entry_id) + 1);
    free(entry_id);
    entry_id = NULL;

    addr = dns ? dns->addr : NULL;

    for (j = 0; j < addressnum; ++j)
    {
      int port = 0;
      char ipaddress[MAX_IPADR_LEN] = {0};

      if (!addr && !tests[i].address[j])
        break;

      if (tests[i].address[j] == &skip)
        continue;

      if (addr && !Fetch_addr2string(addr->ai_addr, addr->ai_addrlen,
                                    ipaddress, &port))
      {
        fprintf(stderr, "%s:%d tests[%d] failed. getaddressinfo failed.\n",
                __FILE__, __LINE__, i);
        problem = true;
        break;
      }

      if (addr && !tests[i].address[j])
      {
        fprintf(stderr, "%s:%d tests[%d] failed. the retrieved addr "
                        "is %s but tests[%d].address[%d] is NULL.\n",
                __FILE__, __LINE__, i, ipaddress, i, j);
        problem = true;
        break;
      }

      if (!addr && tests[i].address[j])
      {
        fprintf(stderr, "%s:%d tests[%d] failed. the retrieved addr "
                        "is NULL but tests[%d].address[%d] is %s.\n",
                __FILE__, __LINE__, i, i, j, tests[i].address[j]);
        problem = true;
        break;
      }

      if (!fetch_strequal(ipaddress, tests[i].address[j]))
      {
        fprintf(stderr, "%s:%d tests[%d] failed. the retrieved addr "
                        "%s is not equal to tests[%d].address[%d] %s.\n",
                __FILE__, __LINE__, i, ipaddress, i, j, tests[i].address[j]);
        problem = true;
        break;
      }

      if (port != tests[i].port)
      {
        fprintf(stderr, "%s:%d tests[%d] failed. the retrieved port "
                        "for tests[%d].address[%d] is %d but tests[%d].port is %d.\n",
                __FILE__, __LINE__, i, i, j, port, i, tests[i].port);
        problem = true;
        break;
      }

      if (dns->timestamp && tests[i].permanent)
      {
        fprintf(stderr, "%s:%d tests[%d] failed. the timestamp is not zero "
                        "but tests[%d].permanent is TRUE\n",
                __FILE__, __LINE__, i, i);
        problem = true;
        break;
      }

      if (dns->timestamp == 0 && !tests[i].permanent)
      {
        fprintf(stderr, "%s:%d tests[%d] failed. the timestamp is zero "
                        "but tests[%d].permanent is FALSE\n",
                __FILE__, __LINE__, i, i);
        problem = true;
        break;
      }

      addr = addr->ai_next;
    }

    fetch_easy_cleanup(easy);
    easy = NULL;
    fetch_multi_cleanup(multi);
    multi = NULL;
    fetch_slist_free_all(list);
    list = NULL;

    if (problem)
    {
      unitfail++;
      continue;
    }
  }
error:
  fetch_easy_cleanup(easy);
  fetch_multi_cleanup(multi);
  fetch_slist_free_all(list);
}
UNITTEST_STOP
