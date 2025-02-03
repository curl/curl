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

#define THREADS 2

/* struct containing data of a thread */
struct Tdata {
  FETCHSH *share;
  char *url;
};

struct userdata {
  const char *text;
  int counter;
};

/* lock callback */
static void test_lock(FETCH *handle, fetch_lock_data data,
                      fetch_lock_access laccess, void *useptr)
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;

  (void)handle;
  (void)laccess;

  switch(data) {
    case FETCH_LOCK_DATA_SHARE:
      what = "share";
      break;
    case FETCH_LOCK_DATA_DNS:
      what = "dns";
      break;
    case FETCH_LOCK_DATA_COOKIE:
      what = "cookie";
      break;
    case FETCH_LOCK_DATA_SSL_SESSION:
      what = "ssl_session";
      break;
    default:
      fprintf(stderr, "lock: no such data: %d\n", (int)data);
      return;
  }
  printf("lock:   %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* unlock callback */
static void test_unlock(FETCH *handle, fetch_lock_data data, void *useptr)
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;
  (void)handle;
  switch(data) {
    case FETCH_LOCK_DATA_SHARE:
      what = "share";
      break;
    case FETCH_LOCK_DATA_DNS:
      what = "dns";
      break;
    case FETCH_LOCK_DATA_COOKIE:
      what = "cookie";
      break;
    case FETCH_LOCK_DATA_SSL_SESSION:
      what = "ssl_session";
      break;
    default:
      fprintf(stderr, "unlock: no such data: %d\n", (int)data);
      return;
  }
  printf("unlock: %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* the dummy thread function */
static void *test_fire(void *ptr)
{
  FETCHcode code;
  struct Tdata *tdata = (struct Tdata*)ptr;
  FETCH *fetch;

  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    return NULL;
  }

  fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 0L);
  fetch_easy_setopt(fetch, FETCHOPT_VERBOSE,    1L);
  fetch_easy_setopt(fetch, FETCHOPT_URL,        tdata->url);
  printf("FETCHOPT_SHARE\n");
  fetch_easy_setopt(fetch, FETCHOPT_SHARE, tdata->share);

  printf("PERFORM\n");
  code = fetch_easy_perform(fetch);
  if(code != FETCHE_OK) {
    int i = 0;
    fprintf(stderr, "perform url '%s' repeat %d failed, fetchcode %d\n",
            tdata->url, i, (int)code);
  }

  printf("CLEANUP\n");
  fetch_easy_cleanup(fetch);

  return NULL;
}

/* test function */
FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCHSHcode scode = FETCHSHE_OK;
  char *url;
  struct Tdata tdata;
  FETCH *fetch;
  FETCHSH *share;
  int i;
  struct userdata user;

  user.text = "Pigs in space";
  user.counter = 0;

  printf("GLOBAL_INIT\n");
  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* prepare share */
  printf("SHARE_INIT\n");
  share = fetch_share_init();
  if(!share) {
    fprintf(stderr, "fetch_share_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if(FETCHSHE_OK == scode) {
    printf("FETCHSHOPT_LOCKFUNC\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_LOCKFUNC, test_lock);
  }
  if(FETCHSHE_OK == scode) {
    printf("FETCHSHOPT_UNLOCKFUNC\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_UNLOCKFUNC, test_unlock);
  }
  if(FETCHSHE_OK == scode) {
    printf("FETCHSHOPT_USERDATA\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_USERDATA, &user);
  }
  if(FETCHSHE_OK == scode) {
    printf("FETCH_LOCK_DATA_SSL_SESSION\n");
    scode = fetch_share_setopt(share, FETCHSHOPT_SHARE,
                              FETCH_LOCK_DATA_SSL_SESSION);
  }

  if(FETCHSHE_OK != scode) {
    fprintf(stderr, "fetch_share_setopt() failed\n");
    fetch_share_cleanup(share);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }


  /* start treads */
  for(i = 1; i <= THREADS; i++) {

    /* set thread data */
    tdata.url   = URL;
    tdata.share = share;

    /* simulate thread, direct call of "thread" function */
    printf("*** run %d\n",i);
    test_fire(&tdata);
  }


  /* fetch another one */
  printf("*** run %d\n", i);
  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_share_cleanup(share);
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  url = URL;
  test_setopt(fetch, FETCHOPT_URL, url);
  printf("FETCHOPT_SHARE\n");
  test_setopt(fetch, FETCHOPT_SHARE, share);

  printf("PERFORM\n");
  res = fetch_easy_perform(fetch);

  /* try to free share, expect to fail because share is in use */
  printf("try SHARE_CLEANUP...\n");
  scode = fetch_share_cleanup(share);
  if(scode == FETCHSHE_OK) {
    fprintf(stderr, "fetch_share_cleanup succeed but error expected\n");
    share = NULL;
  }
  else {
    printf("SHARE_CLEANUP failed, correct\n");
  }

test_cleanup:

  /* clean up last handle */
  printf("CLEANUP\n");
  fetch_easy_cleanup(fetch);

  /* free share */
  printf("SHARE_CLEANUP\n");
  scode = fetch_share_cleanup(share);
  if(scode != FETCHSHE_OK)
    fprintf(stderr, "fetch_share_cleanup failed, code errno %d\n",
            (int)scode);

  printf("GLOBAL_CLEANUP\n");
  fetch_global_cleanup();

  return res;
}
