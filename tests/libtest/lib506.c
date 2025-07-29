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
#include "first.h"

#include "testutil.h"
#include "memdebug.h"

#define JAR libtest_arg2
#define THREADS 2

/* struct containing data of a thread */
struct t506_Tdata {
  CURLSH *share;
  char *url;
};

struct t506_userdata {
  const char *text;
  int counter;
};

static int locks[3];

/* lock callback */
static void t506_test_lock(CURL *handle, curl_lock_data data,
                           curl_lock_access laccess, void *useptr)
{
  const char *what;
  struct t506_userdata *user = (struct t506_userdata *)useptr;
  int locknum;

  (void)handle;
  (void)laccess;

  switch(data) {
    case CURL_LOCK_DATA_SHARE:
      what = "share";
      locknum = 0;
      break;
    case CURL_LOCK_DATA_DNS:
      what = "dns";
      locknum = 1;
      break;
    case CURL_LOCK_DATA_COOKIE:
      what = "cookie";
      locknum = 2;
      break;
    default:
      curl_mfprintf(stderr, "lock: no such data: %d\n", (int)data);
      return;
  }

  /* detect locking of locked locks */
  if(locks[locknum]) {
    curl_mprintf("lock: double locked %s\n", what);
    return;
  }
  locks[locknum]++;

  curl_mprintf("lock:   %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* unlock callback */
static void t506_test_unlock(CURL *handle, curl_lock_data data, void *useptr)
{
  const char *what;
  struct t506_userdata *user = (struct t506_userdata *)useptr;
  int locknum;
  (void)handle;
  switch(data) {
    case CURL_LOCK_DATA_SHARE:
      what = "share";
      locknum = 0;
      break;
    case CURL_LOCK_DATA_DNS:
      what = "dns";
      locknum = 1;
      break;
    case CURL_LOCK_DATA_COOKIE:
      what = "cookie";
      locknum = 2;
      break;
    default:
      curl_mfprintf(stderr, "unlock: no such data: %d\n", (int)data);
      return;
  }

  /* detect unlocking of unlocked locks */
  if(!locks[locknum]) {
    curl_mprintf("unlock: double unlocked %s\n", what);
    return;
  }
  locks[locknum]--;

  curl_mprintf("unlock: %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* build host entry */
static struct curl_slist *sethost(struct curl_slist *headers)
{
  (void)headers;
  return curl_slist_append(NULL, "Host: www.host.foo.com");
}

/* the dummy thread function */
static void *t506_test_fire(void *ptr)
{
  CURLcode code;
  struct curl_slist *headers;
  struct t506_Tdata *tdata = (struct t506_Tdata*)ptr;
  CURL *curl;

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    return NULL;
  }

  headers = sethost(NULL);
  curl_easy_setopt(curl, CURLOPT_VERBOSE,    1L);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_URL,        tdata->url);
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
  curl_mprintf("CURLOPT_SHARE\n");
  curl_easy_setopt(curl, CURLOPT_SHARE, tdata->share);

  curl_mprintf("PERFORM\n");
  code = curl_easy_perform(curl);
  if(code) {
    int i = 0;
    curl_mfprintf(stderr, "perform url '%s' repeat %d failed, curlcode %d\n",
                  tdata->url, i, (int)code);
  }

  curl_mprintf("CLEANUP\n");
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  return NULL;
}

/* test function */
static CURLcode test_lib506(char *URL)
{
  CURLcode res;
  CURLSHcode scode = CURLSHE_OK;
  CURLcode code = CURLE_OK;
  char *url = NULL;
  struct t506_Tdata tdata;
  CURL *curl;
  CURLSH *share;
  struct curl_slist *headers = NULL;
  struct curl_slist *cookies = NULL;
  struct curl_slist *next_cookie = NULL;
  int i;
  struct t506_userdata user;

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
    scode = curl_share_setopt(share, CURLSHOPT_LOCKFUNC, t506_test_lock);
  }
  if(CURLSHE_OK == scode) {
    curl_mprintf("CURLSHOPT_UNLOCKFUNC\n");
    scode = curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, t506_test_unlock);
  }
  if(CURLSHE_OK == scode) {
    curl_mprintf("CURLSHOPT_USERDATA\n");
    scode = curl_share_setopt(share, CURLSHOPT_USERDATA, &user);
  }
  if(CURLSHE_OK == scode) {
    curl_mprintf("CURL_LOCK_DATA_COOKIE\n");
    scode = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
  }
  if(CURLSHE_OK == scode) {
    curl_mprintf("CURL_LOCK_DATA_DNS\n");
    scode = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
  }

  if(CURLSHE_OK != scode) {
    curl_mfprintf(stderr, "curl_share_setopt() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* initial cookie manipulation */
  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  curl_mprintf("CURLOPT_SHARE\n");
  test_setopt(curl, CURLOPT_SHARE,      share);
  curl_mprintf("CURLOPT_COOKIELIST injected_and_clobbered\n");
  test_setopt(curl, CURLOPT_COOKIELIST,
               "Set-Cookie: injected_and_clobbered=yes; "
               "domain=host.foo.com; expires=Sat Feb 2 11:56:27 GMT 2030");
  curl_mprintf("CURLOPT_COOKIELIST ALL\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "ALL");
  curl_mprintf("CURLOPT_COOKIELIST session\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "Set-Cookie: session=elephants");
  curl_mprintf("CURLOPT_COOKIELIST injected\n");
  test_setopt(curl, CURLOPT_COOKIELIST,
               "Set-Cookie: injected=yes; domain=host.foo.com; "
               "expires=Sat Feb 2 11:56:27 GMT 2030");
  curl_mprintf("CURLOPT_COOKIELIST SESS\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "SESS");
  curl_mprintf("CLEANUP\n");
  curl_easy_cleanup(curl);


  /* start treads */
  for(i = 1; i <= THREADS; i++) {

    /* set thread data */
    tdata.url   = tutil_suburl(URL, i); /* must be curl_free()d */
    tdata.share = share;

    /* simulate thread, direct call of "thread" function */
    curl_mprintf("*** run %d\n",i);
    t506_test_fire(&tdata);

    curl_free(tdata.url);
  }


  /* fetch another one and save cookies */
  curl_mprintf("*** run %d\n", i);
  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  url = tutil_suburl(URL, i);
  headers = sethost(NULL);
  test_setopt(curl, CURLOPT_HTTPHEADER, headers);
  test_setopt(curl, CURLOPT_URL,        url);
  curl_mprintf("CURLOPT_SHARE\n");
  test_setopt(curl, CURLOPT_SHARE,      share);
  curl_mprintf("CURLOPT_COOKIEJAR\n");
  test_setopt(curl, CURLOPT_COOKIEJAR,  JAR);
  curl_mprintf("CURLOPT_COOKIELIST FLUSH\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "FLUSH");

  curl_mprintf("PERFORM\n");
  curl_easy_perform(curl);

  curl_mprintf("CLEANUP\n");
  curl_easy_cleanup(curl);
  curl_free(url);
  curl_slist_free_all(headers);

  /* load cookies */
  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  url = tutil_suburl(URL, i);
  headers = sethost(NULL);
  test_setopt(curl, CURLOPT_HTTPHEADER, headers);
  test_setopt(curl, CURLOPT_URL,        url);
  curl_mprintf("CURLOPT_SHARE\n");
  test_setopt(curl, CURLOPT_SHARE,      share);
  curl_mprintf("CURLOPT_COOKIELIST ALL\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "ALL");
  curl_mprintf("CURLOPT_COOKIEJAR\n");
  test_setopt(curl, CURLOPT_COOKIEFILE, JAR);
  curl_mprintf("CURLOPT_COOKIELIST RELOAD\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "RELOAD");

  res = CURLE_OK;

  code = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
  if(code != CURLE_OK) {
    curl_mfprintf(stderr, "curl_easy_getinfo() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  curl_mprintf("loaded cookies:\n");
  if(!cookies) {
    curl_mfprintf(stderr, "  reloading cookies from '%s' failed\n", JAR);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  curl_mprintf("-----------------\n");
  next_cookie = cookies;
  while(next_cookie) {
    curl_mprintf("  %s\n", next_cookie->data);
    next_cookie = next_cookie->next;
  }
  curl_mprintf("-----------------\n");
  curl_slist_free_all(cookies);

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
  curl_slist_free_all(headers);
  curl_free(url);

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
