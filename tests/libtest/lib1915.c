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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

#include "testtrace.h"
#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

struct entry
{
  const char *name;
  const char *exp;
};

static const struct entry preload_hosts[] = {
#if (SIZEOF_TIME_T < 5)
    {"1.example.com", "20370320 01:02:03"},
    {"2.example.com", "20370320 03:02:01"},
    {"3.example.com", "20370319 01:02:03"},
#else
    {"1.example.com", "25250320 01:02:03"},
    {"2.example.com", "25250320 03:02:01"},
    {"3.example.com", "25250319 01:02:03"},
#endif
    {"4.example.com", ""},
    {NULL, NULL} /* end of list marker */
};

struct state
{
  int index;
};

/* "read" is from the point of the library, it wants data from us */
static FETCHSTScode hstsread(FETCH *easy, struct fetch_hstsentry *e,
                             void *userp)
{
  const char *host;
  const char *expire;
  struct state *s = (struct state *)userp;
  (void)easy;
  host = preload_hosts[s->index].name;
  expire = preload_hosts[s->index++].exp;

  if (host && (strlen(host) < e->namelen))
  {
    strcpy(e->name, host);
    e->includeSubDomains = FALSE;
    strcpy(e->expire, expire);
    fprintf(stderr, "add '%s'\n", host);
  }
  else
    return FETCHSTS_DONE;
  return FETCHSTS_OK;
}

/* verify error from callback */
static FETCHSTScode hstsreadfail(FETCH *easy, struct fetch_hstsentry *e,
                                 void *userp)
{
  (void)easy;
  (void)e;
  (void)userp;
  return FETCHSTS_FAIL;
}

/* check that we get the hosts back in the save */
static FETCHSTScode hstswrite(FETCH *easy, struct fetch_hstsentry *e,
                              struct fetch_index *i, void *userp)
{
  (void)easy;
  (void)userp;
  printf("[%zu/%zu] %s %s\n", i->index, i->total, e->name, e->expire);
  return FETCHSTS_OK;
}

/*
 * Read/write HSTS cache entries via callback.
 */

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *hnd;
  struct state st = {0};

  global_init(FETCH_GLOBAL_ALL);

  libtest_debug_config.nohex = 1;
  libtest_debug_config.tracetime = 1;

  easy_init(hnd);
  easy_setopt(hnd, FETCHOPT_URL, URL);
  easy_setopt(hnd, FETCHOPT_CONNECTTIMEOUT, 1L);
  easy_setopt(hnd, FETCHOPT_HSTSREADFUNCTION, hstsread);
  easy_setopt(hnd, FETCHOPT_HSTSREADDATA, &st);
  easy_setopt(hnd, FETCHOPT_HSTSWRITEFUNCTION, hstswrite);
  easy_setopt(hnd, FETCHOPT_HSTSWRITEDATA, &st);
  easy_setopt(hnd, FETCHOPT_HSTS_CTRL, FETCHHSTS_ENABLE);
  easy_setopt(hnd, FETCHOPT_DEBUGDATA, &libtest_debug_config);
  easy_setopt(hnd, FETCHOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(hnd, FETCHOPT_VERBOSE, 1L);
  res = fetch_easy_perform(hnd);
  fetch_easy_cleanup(hnd);
  hnd = NULL;
  if (res == FETCHE_OPERATION_TIMEDOUT) /* we expect that on Windows */
    res = FETCHE_COULDNT_CONNECT;
  printf("First request returned %d\n", res);
  res = FETCHE_OK;

  easy_init(hnd);
  easy_setopt(hnd, FETCHOPT_URL, URL);
  easy_setopt(hnd, FETCHOPT_CONNECTTIMEOUT, 1L);
  easy_setopt(hnd, FETCHOPT_HSTSREADFUNCTION, hstsreadfail);
  easy_setopt(hnd, FETCHOPT_HSTSREADDATA, &st);
  easy_setopt(hnd, FETCHOPT_HSTSWRITEFUNCTION, hstswrite);
  easy_setopt(hnd, FETCHOPT_HSTSWRITEDATA, &st);
  easy_setopt(hnd, FETCHOPT_HSTS_CTRL, FETCHHSTS_ENABLE);
  easy_setopt(hnd, FETCHOPT_DEBUGDATA, &libtest_debug_config);
  easy_setopt(hnd, FETCHOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(hnd, FETCHOPT_VERBOSE, 1L);
  res = fetch_easy_perform(hnd);
  fetch_easy_cleanup(hnd);
  hnd = NULL;
  printf("Second request returned %d\n", res);

test_cleanup:
  fetch_easy_cleanup(hnd);
  fetch_global_cleanup();
  return res;
}
