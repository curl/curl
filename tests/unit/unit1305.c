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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "fetchx.h"

#include "hash.h"
#include "hostip.h"

#include "memdebug.h" /* LAST include file */

static struct Fetch_easy *testdata;
static struct Fetch_hash hp;
static char *data_key;
static struct Fetch_dns_entry *data_node;

static FETCHcode unit_setup(void)
{
  testdata = fetch_easy_init();
  if (!testdata)
  {
    fetch_global_cleanup();
    return FETCHE_OUT_OF_MEMORY;
  }

  Fetch_init_dnscache(&hp, 7);
  return FETCHE_OK;
}

static void unit_stop(void)
{
  if (data_node)
  {
    Fetch_freeaddrinfo(data_node->addr);
    free(data_node);
  }
  free(data_key);
  Fetch_hash_destroy(&hp);

  fetch_easy_cleanup(testdata);
  fetch_global_cleanup();
}

static struct Fetch_addrinfo *fake_ai(void)
{
  static struct Fetch_addrinfo *ai;
  static const char dummy[] = "dummy";
  size_t namelen = sizeof(dummy); /* including the null-terminator */

  ai = calloc(1, sizeof(struct Fetch_addrinfo) + sizeof(struct sockaddr_in) +
                     namelen);
  if (!ai)
    return NULL;

  ai->ai_addr = (void *)((char *)ai + sizeof(struct Fetch_addrinfo));
  ai->ai_canonname = (void *)((char *)ai->ai_addr +
                              sizeof(struct sockaddr_in));
  memcpy(ai->ai_canonname, dummy, namelen);

  ai->ai_family = AF_INET;
  ai->ai_addrlen = sizeof(struct sockaddr_in);

  return ai;
}

static FETCHcode create_node(void)
{
  data_key = aprintf("%s:%d", "dummy", 0);
  if (!data_key)
    return FETCHE_OUT_OF_MEMORY;

  data_node = calloc(1, sizeof(struct Fetch_dns_entry));
  if (!data_node)
    return FETCHE_OUT_OF_MEMORY;

  data_node->addr = fake_ai();
  if (!data_node->addr)
    return FETCHE_OUT_OF_MEMORY;

  return FETCHE_OK;
}

UNITTEST_START

struct Fetch_dns_entry *nodep;
size_t key_len;

/* Test 1305 exits without adding anything to the hash */
if (strcmp(arg, "1305") != 0)
{
  FETCHcode rc = create_node();
  abort_unless(rc == FETCHE_OK, "data node creation failed");
  key_len = strlen(data_key);

  data_node->refcount = 1; /* hash will hold the reference */
  nodep = Fetch_hash_add(&hp, data_key, key_len + 1, data_node);
  abort_unless(nodep, "insertion into hash failed");
  /* Freeing will now be done by Fetch_hash_destroy */
  data_node = NULL;
}

UNITTEST_STOP
