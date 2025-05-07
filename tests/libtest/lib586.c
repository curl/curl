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
#include "test.h"
#include "memdebug.h"

#define THREADS 2

/* struct containing data of a thread */
struct Tdata {
  CURLSH *share;
  char *url;
};

struct userdata {
  const char *text;
  int counter;
};

/* lock callback */
static void test_lock(CURL *handle, curl_lock_data data,
                      curl_lock_access laccess, void *useptr)
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;

  (void)handle;
  (void)laccess;

  switch(data) {
    case CURL_LOCK_DATA_SHARE:
      what = "share";
      break;
    case CURL_LOCK_DATA_DNS:
      what = "dns";
      break;
    case CURL_LOCK_DATA_COOKIE:
      what = "cookie";
      break;
    case CURL_LOCK_DATA_SSL_SESSION:
      what = "ssl_session";
      break;
    default:
      curl_mfprintf(stderr, "lock: no such data: %d\n", (int)data);
      return;
  }
  curl_mprintf("lock:   %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* unlock callback */
static void test_unlock(CURL *handle, curl_lock_data data, void *useptr)
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;
  (void)handle;
  switch(data) {
    case CURL_LOCK_DATA_SHARE:
      what = "share";
      break;
    case CURL_LOCK_DATA_DNS:
      what = "dns";
      break;
    case CURL_LOCK_DATA_COOKIE:
      what = "cookie";
      break;
    case CURL_LOCK_DATA_SSL_SESSION:
      what = "ssl_session";
      break;
    default:
      curl_mfprintf(stderr, "unlock: no such data: %d\n", (int)data);
      return;
  }
  curl_mprintf("unlock: %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* the dummy thread function */
static void *test_fire(void *ptr)
{
  CURLcode code;
  struct Tdata *tdata = (struct Tdata*)ptr;
  CURL *curl;

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    return NULL;
  }

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_VERBOSE,    1L);
  curl_easy_setopt(curl, CURLOPT_URL,        tdata->url);
  curl_mprintf("CURLOPT_SHARE\n");
  curl_easy_setopt(curl, CURLOPT_SHARE, tdata->share);

  curl_mprintf("PERFORM\n");
  code = curl_easy_perform(curl);
  if(code != CURLE_OK) {
    int i = 0;
    curl_mfprintf(stderr, "perform url '%s' repeat %d failed, curlcode %d\n",
            tdata->url, i, (int)code);
  }

  curl_mprintf("CLEANUP\n");
  curl_easy_cleanup(curl);

  return NULL;
}

/* test function */
CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  CURLSHcode scode = CURLSHE_OK;
  char *url;
  struct Tdata tdata;
  CURL *curl;
  CURLSH *share;
  int i;
  struct userdata user;

  user.text = "Pigs in space";
  user.counter = 0;

  curl_mprintf("GLOBAL_INIT\n");
  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* prepare share */
  curl_mprintf("SHARE_INIT\n");
  share = curl_share_init();
  if(!share) {
    curl_mfprintf(stderr, "curl_share_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if(CURLSHE_OK == scode) {
    curl_mprintf("CURLSHOPT_LOCKFUNC\n");
    scode = curl_share_setopt(share, CURLSHOPT_LOCKFUNC, test_lock);
  }
  if(CURLSHE_OK == scode) {
    curl_mprintf("CURLSHOPT_UNLOCKFUNC\n");
    scode = curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, test_unlock);
  }
  if(CURLSHE_OK == scode) {
    curl_mprintf("CURLSHOPT_USERDATA\n");
    scode = curl_share_setopt(share, CURLSHOPT_USERDATA, &user);
  }
  if(CURLSHE_OK == scode) {
    curl_mprintf("CURL_LOCK_DATA_SSL_SESSION\n");
    scode = curl_share_setopt(share, CURLSHOPT_SHARE,
                              CURL_LOCK_DATA_SSL_SESSION);
  }

  if(CURLSHE_OK != scode) {
    curl_mfprintf(stderr, "curl_share_setopt() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }


  /* start treads */
  for(i = 1; i <= THREADS; i++) {

    /* set thread data */
    tdata.url   = URL;
    tdata.share = share;

    /* simulate thread, direct call of "thread" function */
    curl_mprintf("*** run %d\n",i);
    test_fire(&tdata);
  }


  /* fetch another one */
  curl_mprintf("*** run %d\n", i);
  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  url = URL;
  test_setopt(curl, CURLOPT_URL, url);
  curl_mprintf("CURLOPT_SHARE\n");
  test_setopt(curl, CURLOPT_SHARE, share);

  curl_mprintf("PERFORM\n");
  res = curl_easy_perform(curl);

  /* try to free share, expect to fail because share is in use */
  curl_mprintf("try SHARE_CLEANUP...\n");
  scode = curl_share_cleanup(share);
  if(scode == CURLSHE_OK) {
    curl_mfprintf(stderr, "curl_share_cleanup succeed but error expected\n");
    share = NULL;
  }
  else {
    curl_mprintf("SHARE_CLEANUP failed, correct\n");
  }

test_cleanup:

  /* clean up last handle */
  curl_mprintf("CLEANUP\n");
  curl_easy_cleanup(curl);

  /* free share */
  curl_mprintf("SHARE_CLEANUP\n");
  scode = curl_share_cleanup(share);
  if(scode != CURLSHE_OK)
    curl_mfprintf(stderr, "curl_share_cleanup failed, code errno %d\n",
            (int)scode);

  curl_mprintf("GLOBAL_CLEANUP\n");
  curl_global_cleanup();

  return res;
}
