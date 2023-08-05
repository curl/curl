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

static const char * const HOSTHEADER = "Host: www.host.foo.com";
#define JAR libtest_arg2
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

static int locks[3];

/* lock callback */
static void my_lock(CURL *handle, curl_lock_data data,
                    curl_lock_access laccess, void *useptr)
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;
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
      fprintf(stderr, "lock: no such data: %d\n", (int)data);
      return;
  }

  /* detect locking of locked locks */
  if(locks[locknum]) {
    printf("lock: double locked %s\n", what);
    return;
  }
  locks[locknum]++;

  printf("lock:   %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}

/* unlock callback */
static void my_unlock(CURL *handle, curl_lock_data data, void *useptr)
{
  const char *what;
  struct userdata *user = (struct userdata *)useptr;
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
      fprintf(stderr, "unlock: no such data: %d\n", (int)data);
      return;
  }

  /* detect unlocking of unlocked locks */
  if(!locks[locknum]) {
    printf("unlock: double unlocked %s\n", what);
    return;
  }
  locks[locknum]--;

  printf("unlock: %-6s [%s]: %d\n", what, user->text, user->counter);
  user->counter++;
}


/* build host entry */
static struct curl_slist *sethost(struct curl_slist *headers)
{
  (void)headers;
  return curl_slist_append(NULL, HOSTHEADER);
}


/* the dummy thread function */
static void *fire(void *ptr)
{
  CURLcode code;
  struct curl_slist *headers;
  struct Tdata *tdata = (struct Tdata*)ptr;
  CURL *curl;

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    return NULL;
  }

  headers = sethost(NULL);
  curl_easy_setopt(curl, CURLOPT_VERBOSE,    1L);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_URL,        tdata->url);
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
  printf("CURLOPT_SHARE\n");
  curl_easy_setopt(curl, CURLOPT_SHARE, tdata->share);

  printf("PERFORM\n");
  code = curl_easy_perform(curl);
  if(code) {
    int i = 0;
    fprintf(stderr, "perform url '%s' repeat %d failed, curlcode %d\n",
            tdata->url, i, (int)code);
  }

  printf("CLEANUP\n");
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);

  return NULL;
}


/* build request url */
static char *suburl(const char *base, int i)
{
  return curl_maprintf("%s%.4d", base, i);
}


/* test function */
int test(char *URL)
{
  int res;
  CURLSHcode scode = CURLSHE_OK;
  CURLcode code = CURLE_OK;
  char *url = NULL;
  struct Tdata tdata;
  CURL *curl;
  CURLSH *share;
  struct curl_slist *headers = NULL;
  struct curl_slist *cookies = NULL;
  struct curl_slist *next_cookie = NULL;
  int i;
  struct userdata user;

  user.text = "Pigs in space";
  user.counter = 0;

  printf("GLOBAL_INIT\n");
  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* prepare share */
  printf("SHARE_INIT\n");
  share = curl_share_init();
  if(!share) {
    fprintf(stderr, "curl_share_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  if(CURLSHE_OK == scode) {
    printf("CURLSHOPT_LOCKFUNC\n");
    scode = curl_share_setopt(share, CURLSHOPT_LOCKFUNC, my_lock);
  }
  if(CURLSHE_OK == scode) {
    printf("CURLSHOPT_UNLOCKFUNC\n");
    scode = curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, my_unlock);
  }
  if(CURLSHE_OK == scode) {
    printf("CURLSHOPT_USERDATA\n");
    scode = curl_share_setopt(share, CURLSHOPT_USERDATA, &user);
  }
  if(CURLSHE_OK == scode) {
    printf("CURL_LOCK_DATA_COOKIE\n");
    scode = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
  }
  if(CURLSHE_OK == scode) {
    printf("CURL_LOCK_DATA_DNS\n");
    scode = curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
  }

  if(CURLSHE_OK != scode) {
    fprintf(stderr, "curl_share_setopt() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* initial cookie manipulation */
  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  printf("CURLOPT_SHARE\n");
  test_setopt(curl, CURLOPT_SHARE,      share);
  printf("CURLOPT_COOKIELIST injected_and_clobbered\n");
  test_setopt(curl, CURLOPT_COOKIELIST,
               "Set-Cookie: injected_and_clobbered=yes; "
               "domain=host.foo.com; expires=Sat Feb 2 11:56:27 GMT 2030");
  printf("CURLOPT_COOKIELIST ALL\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "ALL");
  printf("CURLOPT_COOKIELIST session\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "Set-Cookie: session=elephants");
  printf("CURLOPT_COOKIELIST injected\n");
  test_setopt(curl, CURLOPT_COOKIELIST,
               "Set-Cookie: injected=yes; domain=host.foo.com; "
               "expires=Sat Feb 2 11:56:27 GMT 2030");
  printf("CURLOPT_COOKIELIST SESS\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "SESS");
  printf("CLEANUP\n");
  curl_easy_cleanup(curl);


  res = 0;

  /* start treads */
  for(i = 1; i <= THREADS; i++) {

    /* set thread data */
    tdata.url   = suburl(URL, i); /* must be curl_free()d */
    tdata.share = share;

    /* simulate thread, direct call of "thread" function */
    printf("*** run %d\n",i);
    fire(&tdata);

    curl_free(tdata.url);
  }


  /* fetch a another one and save cookies */
  printf("*** run %d\n", i);
  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  url = suburl(URL, i);
  headers = sethost(NULL);
  test_setopt(curl, CURLOPT_HTTPHEADER, headers);
  test_setopt(curl, CURLOPT_URL,        url);
  printf("CURLOPT_SHARE\n");
  test_setopt(curl, CURLOPT_SHARE,      share);
  printf("CURLOPT_COOKIEJAR\n");
  test_setopt(curl, CURLOPT_COOKIEJAR,  JAR);
  printf("CURLOPT_COOKIELIST FLUSH\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "FLUSH");

  printf("PERFORM\n");
  curl_easy_perform(curl);

  printf("CLEANUP\n");
  curl_easy_cleanup(curl);
  curl_free(url);
  curl_slist_free_all(headers);

  /* load cookies */
  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_share_cleanup(share);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  url = suburl(URL, i);
  headers = sethost(NULL);
  test_setopt(curl, CURLOPT_HTTPHEADER, headers);
  test_setopt(curl, CURLOPT_URL,        url);
  printf("CURLOPT_SHARE\n");
  test_setopt(curl, CURLOPT_SHARE,      share);
  printf("CURLOPT_COOKIELIST ALL\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "ALL");
  printf("CURLOPT_COOKIEJAR\n");
  test_setopt(curl, CURLOPT_COOKIEFILE, JAR);
  printf("CURLOPT_COOKIELIST RELOAD\n");
  test_setopt(curl, CURLOPT_COOKIELIST, "RELOAD");

  code = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
  if(code != CURLE_OK) {
    fprintf(stderr, "curl_easy_getinfo() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  printf("loaded cookies:\n");
  if(!cookies) {
    fprintf(stderr, "  reloading cookies from '%s' failed\n", JAR);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  printf("-----------------\n");
  next_cookie = cookies;
  while(next_cookie) {
    printf("  %s\n", next_cookie->data);
    next_cookie = next_cookie->next;
  }
  printf("-----------------\n");
  curl_slist_free_all(cookies);

  /* try to free share, expect to fail because share is in use */
  printf("try SHARE_CLEANUP...\n");
  scode = curl_share_cleanup(share);
  if(scode == CURLSHE_OK) {
    fprintf(stderr, "curl_share_cleanup succeed but error expected\n");
    share = NULL;
  }
  else {
    printf("SHARE_CLEANUP failed, correct\n");
  }

test_cleanup:

  /* clean up last handle */
  printf("CLEANUP\n");
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);
  curl_free(url);

  /* free share */
  printf("SHARE_CLEANUP\n");
  scode = curl_share_cleanup(share);
  if(scode != CURLSHE_OK)
    fprintf(stderr, "curl_share_cleanup failed, code errno %d\n",
            (int)scode);

  printf("GLOBAL_CLEANUP\n");
  curl_global_cleanup();

  return res;
}
