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

#include "hostip.h"

#ifndef FETCH_DISABLE_SHUFFLE_DNS

FETCHcode Fetch_shuffle_addr(struct Fetch_easy *data,
                            struct Fetch_addrinfo **addr);

#define NUM_ADDRS 8
static struct Fetch_addrinfo addrs[NUM_ADDRS];

static FETCHcode unit_setup(void)
{
  int i;
  for (i = 0; i < NUM_ADDRS - 1; i++)
  {
    addrs[i].ai_next = &addrs[i + 1];
  }

  return FETCHE_OK;
}

static void unit_stop(void)
{
  fetch_global_cleanup();
}

UNITTEST_START

int i;
FETCHcode code;
struct Fetch_addrinfo *addrhead = addrs;

struct Fetch_easy *easy = fetch_easy_init();
abort_unless(easy, "out of memory");

code = fetch_easy_setopt(easy, FETCHOPT_DNS_SHUFFLE_ADDRESSES, 1L);
abort_unless(code == FETCHE_OK, "fetch_easy_setopt failed");

/* Shuffle repeatedly and make sure that the list changes */
for (i = 0; i < 10; i++)
{
  if (FETCHE_OK != Fetch_shuffle_addr(easy, &addrhead))
    break;
  if (addrhead != addrs)
    break;
}

fetch_easy_cleanup(easy);
fetch_global_cleanup();

abort_unless(addrhead != addrs, "addresses are not being reordered");

UNITTEST_STOP

#else
static FETCHcode unit_setup(void)
{
  return FETCHE_OK;
}
static void unit_stop(void)
{
}
UNITTEST_START
UNITTEST_STOP

#endif
