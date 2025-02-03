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

  /* 0 to 9 addresses expected from hostcache */
  const char *address[10];
};

/* FETCHOPT_RESOLVE address parsing test - to test the following defect fix:

 1) if there is already existing host:port pair in the DNS cache and
 we call FETCHOPT_RESOLVE, it should also replace addresses.
 for example, if there is "test.com:80" with address "1.1.1.1"
 and we called FETCHOPT_RESOLVE with address "2.2.2.2", then DNS entry needs to
 reflect that.

 2) when cached address is already there and close to expire, then by the
 time request is made, it can get expired.  This happens because, when
 we set address using FETCHOPT_RESOLVE,
 it usually marks as permanent (by setting timestamp to zero). However,
 if address already exists
in the cache, then it does not mark it, but just leaves it as it is.
 So we fixing this by timestamp to zero if address already exists too.

Test:

 - insert new entry
 - verify that timestamp is not zero
 - call set options with FETCHOPT_RESOLVE
 - then, call Fetch_loadhostpairs

 expected result: cached address has zero timestamp.

 - call set options with FETCHOPT_RESOLVE with same host:port pair,
   different address.
 - then, call Fetch_loadhostpairs

 expected result: cached address has zero timestamp and new address
*/

static const struct testcase tests[] = {
    /* spaces aren't allowed, for now */
    {"test.com:80:127.0.0.1",
     "test.com",
     80,
     {
         "127.0.0.1",
     }},
    {"test.com:80:127.0.0.2",
     "test.com",
     80,
     {
         "127.0.0.2",
     }},
};

UNITTEST_START
{
  int i;
  int testnum = sizeof(tests) / sizeof(struct testcase);
  struct Fetch_multi *multi = NULL;
  struct Fetch_easy *easy = NULL;
  struct fetch_slist *list = NULL;

  /* important: we setup cache outside of the loop
    and also clean cache after the loop. In contrast,for example,
    test 1607 sets up and cleans cache on each iteration. */

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
    {
      fetch_global_cleanup();
      return FETCHE_OUT_OF_MEMORY;
    }
    /* create a multi handle and add the easy handle to it so that the
       hostcache is setup */
    multi = fetch_multi_init();
    if (!multi)
      goto error;
    fetch_multi_add_handle(multi, easy);

    list = fetch_slist_append(NULL, tests[i].optval);
    if (!list)
      goto error;

    fetch_easy_setopt(easy, FETCHOPT_RESOLVE, list);

    if (Fetch_loadhostpairs(easy))
      goto error;

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

      if (addr && !Fetch_addr2string(addr->ai_addr, addr->ai_addrlen,
                                    ipaddress, &port))
      {
        fprintf(stderr, "%s:%d tests[%d] failed. Fetch_addr2string failed.\n",
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
  goto unit_test_abort;
error:
  fetch_easy_cleanup(easy);
  fetch_multi_cleanup(multi);
  fetch_slist_free_all(list);
}
UNITTEST_STOP
