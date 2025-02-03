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
#include "test.h"
#include "memdebug.h"

static const char *const HOSTHEADER = "Host: www.host.foo.com";
#define JAR libtest_arg2
#define THREADS 2

/* struct containing data of a thread */
struct Tdata
{
  FETCHSH *share;
  char *url;
};

struct userdata
{
  const char *text;
  int counter;
};

static int locks[3];

/* lock callback */
static void test_lock(FETCH *handle, fetch_lock_data data,
                      fetch_lock_access laccess, void *useptr)
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;
  int locknum;

  (void)handle;
  (void)laccess;

  switch (data)
  {
  case FETCH_LOCK_DATA_SHARE:
    what = "share";
    locknum = 0;
    break;
  case FETCH_LOCK_DATA_DNS:
    what = "dns";
    locknum = 1;
    break;
  case FETCH_LOCK_DATA_COOKIE:
    what = "cookie";
    locknum = 2;
    break;
  default:
    fprintf(stderr, "lock: no such data: %d\n", (int)data);
    return;
  }

  /* detect locking of locked locks */
  if (locks[locknum])
  {
    printf("lock: double locked %s\n", what);
    return;
  }
  locks[locknum]++;

  printf("lock:   %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* unlock callback */
static void test_unlock(FETCH *handle, fetch_lock_data data, void *useptr)
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;
  int locknum;
  (void)handle;
  switch (data)
  {
  case FETCH_LOCK_DATA_SHARE:
    what = "share";
    locknum = 0;
    break;
  case FETCH_LOCK_DATA_DNS:
    what = "dns";
    locknum = 1;
    break;
  case FETCH_LOCK_DATA_COOKIE:
    what = "cookie";
    locknum = 2;
    break;
  default:
    fprintf(stderr, "unlock: no such data: %d\n", (int)data);
    return;
  }

  /* detect unlocking of unlocked locks */
  if (!locks[locknum])
  {
    printf("unlock: double unlocked %s\n", what);
    return;
  }
  locks[locknum]--;

  printf("unlock: %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* build host entry */
static struct fetch_slist *sethost(struct fetch_slist *headers)
{
  (void)headers;
  return fetch_slist_append(NULL, HOSTHEADER);
}

/* the dummy thread function */
static void *test_fire(void *ptr)
{
  FETCHcode code;
  struct fetch_slist *headers;
  struct Tdata *tdata = (struct Tdata *)ptr;
  FETCH *fetch;

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    return NULL;
  }

  headers = sethost(NULL);
  fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, headers);
  fetch_easy_setopt(fetch, FETCHOPT_URL, tdata->url);
  fetch_easy_setopt(fetch, FETCHOPT_COOKIEFILE, "");
  printf("FETCHOPT_SHARE\n");
  fetch_easy_setopt(fetch, FETCHOPT_SHARE, tdata->share);

  printf("PERFORM\n");
  code = fetch_easy_perform(fetch);
  if (code)
  {
    int i = 0;
    fprintf(stderr, "perform url '%s' repeat %d failed, fetchcode %d\n",
            tdata->url, i, (int)code);
  }

  printf("CLEANUP\n");
  fetch_easy_cleanup(fetch);
  fetch_slist_free_all(headers);

  return NULL;
}

/* build request url */
static char *suburl(const char *base, int i)
{
  return fetch_maprintf("%s%.4d", base, i);
}

/* test function */
FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCHSHcode scode = FETCHSHE_OK;
  FETCHcode code = FETCHE_OK;
  char *url = NULL;
  struct Tdata tdata;
  FETCH *fetch;
  FETCHSH *share;
  struct fetch_slist *headers = NULL;
  struct fetch_slist *cookies = NULL;
  struct fetch_slist *next_cookie = NULL;
  int i;
  struct userdata user;

  user.text = "Pigs in space";
  user.counter = 0;

  printf("GLOBAL_INIT\n");
  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* prepare share */
  printf("SHARE_INIT\n");
  share = fetch_share_init();
  if (!share)
  {
    fprintf(stderr, "fetch_share_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if (FETCHSHE_OK == scode)
  {
    printf("FETCHSHOPT_LOCKFUNC\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_LOCKFUNC, test_lock);
  }
  if (FETCHSHE_OK == scode)
  {
    printf("FETCHSHOPT_UNLOCKFUNC\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_UNLOCKFUNC, test_unlock);
  }
  if (FETCHSHE_OK == scode)
  {
    printf("FETCHSHOPT_USERDATA\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_USERDATA, &user);
  }
  if (FETCHSHE_OK == scode)
  {
    printf("FETCH_LOCK_DATA_COOKIE\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_COOKIE);
  }
  if (FETCHSHE_OK == scode)
  {
    printf("FETCH_LOCK_DATA_DNS\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_DNS);
  }

  if (FETCHSHE_OK != scode)
  {
    fprintf(stderr, "fetch_share_setopt() failed\n");
    fetch_share_cleanup(share);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* initial cookie manipulation */
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_share_cleanup(share);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  printf("FETCHOPT_SHARE\n");
  test_setopt(fetch, FETCHOPT_SHARE, share);
  printf("FETCHOPT_COOKIELIST injected_and_clobbered\n");
  test_setopt(fetch, FETCHOPT_COOKIELIST,
              "Set-Cookie: injected_and_clobbered=yes; "
              "domain=host.foo.com; expires=Sat Feb 2 11:56:27 GMT 2030");
  printf("FETCHOPT_COOKIELIST ALL\n");
  test_setopt(fetch, FETCHOPT_COOKIELIST, "ALL");
  printf("FETCHOPT_COOKIELIST session\n");
  test_setopt(fetch, FETCHOPT_COOKIELIST, "Set-Cookie: session=elephants");
  printf("FETCHOPT_COOKIELIST injected\n");
  test_setopt(fetch, FETCHOPT_COOKIELIST,
              "Set-Cookie: injected=yes; domain=host.foo.com; "
              "expires=Sat Feb 2 11:56:27 GMT 2030");
  printf("FETCHOPT_COOKIELIST SESS\n");
  test_setopt(fetch, FETCHOPT_COOKIELIST, "SESS");
  printf("CLEANUP\n");
  fetch_easy_cleanup(fetch);

  res = FETCHE_OK;

  /* start treads */
  for (i = 1; i <= THREADS; i++)
  {

    /* set thread data */
    tdata.url = suburl(URL, i); /* must be fetch_free()d */
    tdata.share = share;

    /* simulate thread, direct call of "thread" function */
    printf("*** run %d\n", i);
    test_fire(&tdata);

    fetch_free(tdata.url);
  }

  /* fetch another one and save cookies */
  printf("*** run %d\n", i);
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_share_cleanup(share);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  url = suburl(URL, i);
  headers = sethost(NULL);
  test_setopt(fetch, FETCHOPT_HTTPHEADER, headers);
  test_setopt(fetch, FETCHOPT_URL, url);
  printf("FETCHOPT_SHARE\n");
  test_setopt(fetch, FETCHOPT_SHARE, share);
  printf("FETCHOPT_COOKIEJAR\n");
  test_setopt(fetch, FETCHOPT_COOKIEJAR, JAR);
  printf("FETCHOPT_COOKIELIST FLUSH\n");
  test_setopt(fetch, FETCHOPT_COOKIELIST, "FLUSH");

  printf("PERFORM\n");
  fetch_easy_perform(fetch);

  printf("CLEANUP\n");
  fetch_easy_cleanup(fetch);
  fetch_free(url);
  fetch_slist_free_all(headers);

  /* load cookies */
  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_share_cleanup(share);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  url = suburl(URL, i);
  headers = sethost(NULL);
  test_setopt(fetch, FETCHOPT_HTTPHEADER, headers);
  test_setopt(fetch, FETCHOPT_URL, url);
  printf("FETCHOPT_SHARE\n");
  test_setopt(fetch, FETCHOPT_SHARE, share);
  printf("FETCHOPT_COOKIELIST ALL\n");
  test_setopt(fetch, FETCHOPT_COOKIELIST, "ALL");
  printf("FETCHOPT_COOKIEJAR\n");
  test_setopt(fetch, FETCHOPT_COOKIEFILE, JAR);
  printf("FETCHOPT_COOKIELIST RELOAD\n");
  test_setopt(fetch, FETCHOPT_COOKIELIST, "RELOAD");

  code = fetch_easy_getinfo(fetch, FETCHINFO_COOKIELIST, &cookies);
  if (code != FETCHE_OK)
  {
    fprintf(stderr, "fetch_easy_getinfo() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  printf("loaded cookies:\n");
  if (!cookies)
  {
    fprintf(stderr, "  reloading cookies from '%s' failed\n", JAR);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  printf("-----------------\n");
  next_cookie = cookies;
  while (next_cookie)
  {
    printf("  %s\n", next_cookie->data);
    next_cookie = next_cookie->next;
  }
  printf("-----------------\n");
  fetch_slist_free_all(cookies);

  /* try to free share, expect to fail because share is in use */
  printf("try SHARE_CLEANUP...\n");
  scode = fetch_share_cleanup(share);
  if (scode == FETCHSHE_OK)
  {
    fprintf(stderr, "fetch_share_cleanup succeed but error expected\n");
    share = NULL;
  }
  else
  {
    printf("SHARE_CLEANUP failed, correct\n");
  }

test_cleanup:

  /* clean up last handle */
  printf("CLEANUP\n");
  fetch_easy_cleanup(fetch);
  fetch_slist_free_all(headers);
  fetch_free(url);

  /* free share */
  printf("SHARE_CLEANUP\n");
  scode = fetch_share_cleanup(share);
  if (scode != FETCHSHE_OK)
    fprintf(stderr, "fetch_share_cleanup failed, code errno %d\n",
            (int)scode);

  printf("GLOBAL_CLEANUP\n");
  fetch_global_cleanup();

  return res;
}
