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

#if !defined(HAVE_POLL) && !defined(USE_WINSOCK) && !defined(FD_SETSIZE)
#error "this test requires FD_SETSIZE"
#endif

#define T537_SAFETY_MARGIN (11)

#if defined(_WIN32) || defined(MSDOS)
#define DEV_NULL "NUL"
#else
#define DEV_NULL "/dev/null"
#endif

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)

static int *t537_testfd = NULL;
static struct rlimit t537_num_open;
static char t537_msgbuff[256];

static void t537_store_errmsg(const char *msg, int err)
{
  if(!err)
    curl_msnprintf(t537_msgbuff, sizeof(t537_msgbuff), "%s", msg);
  else
    curl_msnprintf(t537_msgbuff, sizeof(t537_msgbuff), "%s, errno %d, %s", msg,
                   err, strerror(err));
}

static void t537_close_file_descriptors(void)
{
  for(t537_num_open.rlim_cur = 0;
      t537_num_open.rlim_cur < t537_num_open.rlim_max;
      t537_num_open.rlim_cur++)
    if(t537_testfd[t537_num_open.rlim_cur] > 0)
      close(t537_testfd[t537_num_open.rlim_cur]);
  free(t537_testfd);
  t537_testfd = NULL;
}

static int t537_fopen_works(void)
{
  FILE *fpa[3];
  int i;
  int ret = 1;

  for(i = 0; i < 3; i++) {
    fpa[i] = NULL;
  }
  for(i = 0; i < 3; i++) {
    fpa[i] = fopen(DEV_NULL, FOPEN_READTEXT);
    if(!fpa[i]) {
      t537_store_errmsg("fopen failed", errno);
      curl_mfprintf(stderr, "%s\n", t537_msgbuff);
      ret = 0;
      break;
    }
  }
  for(i = 0; i < 3; i++) {
    if(fpa[i])
      fclose(fpa[i]);
  }
  return ret;
}

static int t537_test_rlimit(int keep_open)
{
  int *tmpfd;
  rlim_t nitems, i;
  int *memchunk = NULL;
  struct rlimit rl;
  char strbuff[256];
  char strbuff1[81];

  /* get initial open file limits */

  if(getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    t537_store_errmsg("getrlimit() failed", errno);
    curl_mfprintf(stderr, "%s\n", t537_msgbuff);
    return -1;
  }

  /* show initial open file limits */

  tutil_rlim2str(strbuff, sizeof(strbuff), rl.rlim_cur);
  curl_mfprintf(stderr, "initial soft limit: %s\n", strbuff);

  tutil_rlim2str(strbuff, sizeof(strbuff), rl.rlim_max);
  curl_mfprintf(stderr, "initial hard limit: %s\n", strbuff);

  /* If the OS allows a HUGE number of open files, we do not run.
   * Modern debian sid reports a limit of 134217724 and this tests
   * takes minutes. */
#define LIMIT_CAP     (256*1024)
  if(rl.rlim_cur > LIMIT_CAP) {
    curl_mfprintf(stderr, "soft limit above %ld, not running\n",
                  (long)LIMIT_CAP);
    return -2;
  }

  /*
   * if soft limit and hard limit are different we ask the
   * system to raise soft limit all the way up to the hard
   * limit. Due to some other system limit the soft limit
   * might not be raised up to the hard limit. So from this
   * point the resulting soft limit is our limit. Trying to
   * open more than soft limit file descriptors will fail.
   */

  if(rl.rlim_cur != rl.rlim_max) {

#ifdef OPEN_MAX
    if((rl.rlim_cur > 0) &&
       (rl.rlim_cur < OPEN_MAX)) {
      curl_mfprintf(stderr, "raising soft limit up to OPEN_MAX\n");
      rl.rlim_cur = OPEN_MAX;
      if(setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        /* on failure don't abort just issue a warning */
        t537_store_errmsg("setrlimit() failed", errno);
        curl_mfprintf(stderr, "%s\n", t537_msgbuff);
        t537_msgbuff[0] = '\0';
      }
    }
#endif

    curl_mfprintf(stderr, "raising soft limit up to hard limit\n");
    rl.rlim_cur = rl.rlim_max;
    if(setrlimit(RLIMIT_NOFILE, &rl) != 0) {
      /* on failure don't abort just issue a warning */
      t537_store_errmsg("setrlimit() failed", errno);
      curl_mfprintf(stderr, "%s\n", t537_msgbuff);
      t537_msgbuff[0] = '\0';
    }

    /* get current open file limits */

    if(getrlimit(RLIMIT_NOFILE, &rl) != 0) {
      t537_store_errmsg("getrlimit() failed", errno);
      curl_mfprintf(stderr, "%s\n", t537_msgbuff);
      return -3;
    }

    /* show current open file limits */

    tutil_rlim2str(strbuff, sizeof(strbuff), rl.rlim_cur);
    curl_mfprintf(stderr, "current soft limit: %s\n", strbuff);

    tutil_rlim2str(strbuff, sizeof(strbuff), rl.rlim_max);
    curl_mfprintf(stderr, "current hard limit: %s\n", strbuff);

  } /* (rl.rlim_cur != rl.rlim_max) */

  /*
   * test 537 is all about testing libcurl functionality
   * when the system has nearly exhausted the number of
   * available file descriptors. Test 537 will try to run
   * with a very small number of file descriptors available.
   * This implies that any file descriptor which is open
   * when the test runs will have a number in the high range
   * of whatever the system supports.
   */

  /*
   * reserve a chunk of memory before opening file descriptors to
   * avoid a low memory condition once the file descriptors are
   * open. System conditions that could make the test fail should
   * be addressed in the precheck phase. This chunk of memory shall
   * be always free()ed before exiting the t537_test_rlimit() function so
   * that it becomes available to the test.
   */

  for(nitems = i = 1; nitems <= i; i *= 2)
    nitems = i;
  if(nitems > 0x7fff)
    nitems = 0x40000;
  do {
    t537_num_open.rlim_max = sizeof(*memchunk) * nitems;
    tutil_rlim2str(strbuff, sizeof(strbuff), t537_num_open.rlim_max);
    curl_mfprintf(stderr, "allocating memchunk %s byte array\n", strbuff);
    memchunk = malloc(sizeof(*memchunk) * (size_t)nitems);
    if(!memchunk) {
      curl_mfprintf(stderr, "memchunk, malloc() failed\n");
      nitems /= 2;
    }
  } while(nitems && !memchunk);
  if(!memchunk) {
    t537_store_errmsg("memchunk, malloc() failed", errno);
    curl_mfprintf(stderr, "%s\n", t537_msgbuff);
    return -4;
  }

  /* initialize it to fight lazy allocation */

  curl_mfprintf(stderr, "initializing memchunk array\n");

  for(i = 0; i < nitems; i++)
    memchunk[i] = -1;

  /* set the number of file descriptors we will try to open */

#ifdef RLIM_INFINITY
  if((rl.rlim_cur > 0) && (rl.rlim_cur != RLIM_INFINITY)) {
#else
  if(rl.rlim_cur > 0) {
#endif
    /* soft limit minus T537_SAFETY_MARGIN */
    t537_num_open.rlim_max = rl.rlim_cur - T537_SAFETY_MARGIN;
  }
  else {
    /* a huge number of file descriptors */
    for(nitems = i = 1; nitems <= i; i *= 2)
      nitems = i;
    if(nitems > 0x7fff)
      nitems = 0x40000;
    t537_num_open.rlim_max = nitems;
  }

  /* verify that we won't overflow size_t in malloc() */

  if((size_t)(t537_num_open.rlim_max) > ((size_t)-1) / sizeof(*t537_testfd)) {
    tutil_rlim2str(strbuff1, sizeof(strbuff1), t537_num_open.rlim_max);
    curl_msnprintf(strbuff, sizeof(strbuff),
                   "unable to allocate an array for %s "
                   "file descriptors, would overflow size_t", strbuff1);
    t537_store_errmsg(strbuff, 0);
    curl_mfprintf(stderr, "%s\n", t537_msgbuff);
    free(memchunk);
    return -5;
  }

  /* allocate array for file descriptors */

  do {
    tutil_rlim2str(strbuff, sizeof(strbuff), t537_num_open.rlim_max);
    curl_mfprintf(stderr, "allocating array for %s file descriptors\n",
                  strbuff);

    t537_testfd = malloc(sizeof(*t537_testfd) *
                         (size_t)(t537_num_open.rlim_max));
    if(!t537_testfd) {
      curl_mfprintf(stderr, "testfd, malloc() failed\n");
      t537_num_open.rlim_max /= 2;
    }
  } while(t537_num_open.rlim_max && !t537_testfd);
  if(!t537_testfd) {
    t537_store_errmsg("testfd, malloc() failed", errno);
    curl_mfprintf(stderr, "%s\n", t537_msgbuff);
    free(memchunk);
    return -6;
  }

  /* initialize it to fight lazy allocation */

  curl_mfprintf(stderr, "initializing testfd array\n");

  for(t537_num_open.rlim_cur = 0;
      t537_num_open.rlim_cur < t537_num_open.rlim_max;
      t537_num_open.rlim_cur++)
    t537_testfd[t537_num_open.rlim_cur] = -1;

  tutil_rlim2str(strbuff, sizeof(strbuff), t537_num_open.rlim_max);
  curl_mfprintf(stderr, "trying to open %s file descriptors\n", strbuff);

  /* open a dummy descriptor */

  t537_testfd[0] = open(DEV_NULL, O_RDONLY);
  if(t537_testfd[0] < 0) {
    curl_msnprintf(strbuff, sizeof(strbuff), "opening of %s failed", DEV_NULL);
    t537_store_errmsg(strbuff, errno);
    curl_mfprintf(stderr, "%s\n", t537_msgbuff);
    free(t537_testfd);
    t537_testfd = NULL;
    free(memchunk);
    return -7;
  }

  /* create a bunch of file descriptors */

  for(t537_num_open.rlim_cur = 1;
      t537_num_open.rlim_cur < t537_num_open.rlim_max;
      t537_num_open.rlim_cur++) {

    t537_testfd[t537_num_open.rlim_cur] = dup(t537_testfd[0]);

    if(t537_testfd[t537_num_open.rlim_cur] < 0) {

      t537_testfd[t537_num_open.rlim_cur] = -1;

      tutil_rlim2str(strbuff1, sizeof(strbuff1), t537_num_open.rlim_cur);
      curl_msnprintf(strbuff, sizeof(strbuff), "dup() attempt %s failed",
                     strbuff1);
      curl_mfprintf(stderr, "%s\n", strbuff);

      tutil_rlim2str(strbuff1, sizeof(strbuff1), t537_num_open.rlim_cur);
      curl_msnprintf(strbuff, sizeof(strbuff),
                     "fds system limit seems close to %s", strbuff1);
      curl_mfprintf(stderr, "%s\n", strbuff);

      t537_num_open.rlim_max = t537_num_open.rlim_cur - T537_SAFETY_MARGIN;

      t537_num_open.rlim_cur -= t537_num_open.rlim_max;
      tutil_rlim2str(strbuff1, sizeof(strbuff1), t537_num_open.rlim_cur);
      curl_msnprintf(strbuff, sizeof(strbuff), "closing %s file descriptors",
                     strbuff1);
      curl_mfprintf(stderr, "%s\n", strbuff);

      for(t537_num_open.rlim_cur = t537_num_open.rlim_max;
          t537_testfd[t537_num_open.rlim_cur] >= 0;
          t537_num_open.rlim_cur++) {
        close(t537_testfd[t537_num_open.rlim_cur]);
        t537_testfd[t537_num_open.rlim_cur] = -1;
      }

      tutil_rlim2str(strbuff, sizeof(strbuff), t537_num_open.rlim_max);
      curl_mfprintf(stderr, "shrinking array for %s file descriptors\n",
                    strbuff);

      /* we don't care if we can't shrink it */

      tmpfd = realloc(t537_testfd,
                      sizeof(*t537_testfd) * (size_t)(t537_num_open.rlim_max));
      if(tmpfd) {
        t537_testfd = tmpfd;
        tmpfd = NULL;
      }

      break;
    }
  }

  tutil_rlim2str(strbuff, sizeof(strbuff), t537_num_open.rlim_max);
  curl_mfprintf(stderr, "%s file descriptors open\n", strbuff);

#if !defined(HAVE_POLL) && !defined(USE_WINSOCK)

  /*
   * when using select() instead of poll() we cannot test
   * libcurl functionality with a socket number equal or
   * greater than FD_SETSIZE. In any case, macro VERIFY_SOCK
   * in lib/select.c enforces this check and protects libcurl
   * from a possible crash. The effect of this protection
   * is that test 537 will always fail, since the actual
   * call to select() never takes place. We skip test 537
   * with an indication that select limit would be exceeded.
   */

  t537_num_open.rlim_cur = FD_SETSIZE - T537_SAFETY_MARGIN;
  if(t537_num_open.rlim_max > t537_num_open.rlim_cur) {
    curl_msnprintf(strbuff, sizeof(strbuff), "select limit is FD_SETSIZE %d",
                   FD_SETSIZE);
    t537_store_errmsg(strbuff, 0);
    curl_mfprintf(stderr, "%s\n", t537_msgbuff);
    t537_close_file_descriptors();
    free(memchunk);
    return -8;
  }

  t537_num_open.rlim_cur = FD_SETSIZE - T537_SAFETY_MARGIN;
  for(rl.rlim_cur = 0;
      rl.rlim_cur < t537_num_open.rlim_max;
      rl.rlim_cur++) {
    if((t537_testfd[rl.rlim_cur] > 0) &&
       ((unsigned int)t537_testfd[rl.rlim_cur] > t537_num_open.rlim_cur)) {
      curl_msnprintf(strbuff, sizeof(strbuff), "select limit is FD_SETSIZE %d",
                     FD_SETSIZE);
      t537_store_errmsg(strbuff, 0);
      curl_mfprintf(stderr, "%s\n", t537_msgbuff);
      t537_close_file_descriptors();
      free(memchunk);
      return -9;
    }
  }

#endif /* using an FD_SETSIZE bound select() */

  /*
   * Old or 'backwards compatible' implementations of stdio do not allow
   * handling of streams with an underlying file descriptor number greater
   * than 255, even when allowing high numbered file descriptors for sockets.
   * At this point we have a big number of file descriptors which have been
   * opened using dup(), so lets test the stdio implementation and discover
   * if it is capable of fopen()ing some additional files.
   */

  if(!t537_fopen_works()) {
    tutil_rlim2str(strbuff1, sizeof(strbuff1), t537_num_open.rlim_max);
    curl_msnprintf(strbuff, sizeof(strbuff), "fopen fails with %s fds open",
                   strbuff1);
    curl_mfprintf(stderr, "%s\n", t537_msgbuff);
    curl_msnprintf(strbuff, sizeof(strbuff),
                   "fopen fails with lots of fds open");
    t537_store_errmsg(strbuff, 0);
    t537_close_file_descriptors();
    free(memchunk);
    return -10;
  }

  /* free the chunk of memory we were reserving so that it
     becomes available to the test */

  free(memchunk);

  /* close file descriptors unless instructed to keep them */

  if(!keep_open) {
    t537_close_file_descriptors();
  }

  return 0;
}

static CURLcode test_lib537(const char *URL)
{
  CURLcode res;
  CURL *curl;

  if(!strcmp(URL, "check")) {
    /* used by the test script to ask if we can run this test or not */
    if(t537_test_rlimit(FALSE)) {
      curl_mfprintf(stdout, "test_rlimit problem: %s\n", t537_msgbuff);
      return TEST_ERR_FAILURE;
    }
    return CURLE_OK; /* sure, run this! */
  }

  if(t537_test_rlimit(TRUE)) {
    /* failure */
    return TEST_ERR_MAJOR_BAD;
  }

  /* run the test with the bunch of open file descriptors
     and close them all once the test is over */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    t537_close_file_descriptors();
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    t537_close_file_descriptors();
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HEADER, 1L);

  res = curl_easy_perform(curl);

test_cleanup:

  t537_close_file_descriptors();
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}

#else /* HAVE_GETRLIMIT && HAVE_SETRLIMIT */

static CURLcode test_lib537(const char *URL)
{
  (void)URL;
  curl_mprintf("system lacks necessary system function(s)");
  return TEST_ERR_MAJOR_BAD; /* skip test */
}

#endif /* HAVE_GETRLIMIT && HAVE_SETRLIMIT */
