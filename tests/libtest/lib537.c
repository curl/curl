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

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <limits.h>

#include "warnless.h"
#include "memdebug.h"

#if !defined(HAVE_POLL) && !defined(USE_WINSOCK) && !defined(FD_SETSIZE)
#error "this test requires FD_SETSIZE"
#endif

#define SAFETY_MARGIN (11)

#if defined(_WIN32) || defined(MSDOS)
#define DEV_NULL "NUL"
#else
#define DEV_NULL "/dev/null"
#endif

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)

static int *testfd = NULL;
static struct rlimit num_open;
static char msgbuff[256];

static void store_errmsg(const char *msg, int err)
{
  if(!err)
    msnprintf(msgbuff, sizeof(msgbuff), "%s", msg);
  else
    msnprintf(msgbuff, sizeof(msgbuff), "%s, errno %d, %s", msg,
              err, strerror(err));
}

static void close_file_descriptors(void)
{
  for(num_open.rlim_cur = 0;
      num_open.rlim_cur < num_open.rlim_max;
      num_open.rlim_cur++)
    if(testfd[num_open.rlim_cur] > 0)
      close(testfd[num_open.rlim_cur]);
  free(testfd);
  testfd = NULL;
}

static int fopen_works(void)
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
      store_errmsg("fopen failed", errno);
      fprintf(stderr, "%s\n", msgbuff);
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

static void rlim2str(char *buf, size_t len, rlim_t val)
{
#ifdef RLIM_INFINITY
  if(val == RLIM_INFINITY) {
    msnprintf(buf, len, "INFINITY");
    return;
  }
#endif
#ifdef HAVE_LONGLONG
  if(sizeof(rlim_t) > sizeof(long))
    msnprintf(buf, len, "%llu", (unsigned long long)val);
  else
#endif
  {
    if(sizeof(rlim_t) < sizeof(long))
      msnprintf(buf, len, "%u", (unsigned int)val);
    else
      msnprintf(buf, len, "%lu", (unsigned long)val);
  }
}

static int test_rlimit(int keep_open)
{
  int *tmpfd;
  rlim_t nitems, i;
  int *memchunk = NULL;
  struct rlimit rl;
  char strbuff[256];
  char strbuff1[81];

  /* get initial open file limits */

  if(getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    store_errmsg("getrlimit() failed", errno);
    fprintf(stderr, "%s\n", msgbuff);
    return -1;
  }

  /* show initial open file limits */

  rlim2str(strbuff, sizeof(strbuff), rl.rlim_cur);
  fprintf(stderr, "initial soft limit: %s\n", strbuff);

  rlim2str(strbuff, sizeof(strbuff), rl.rlim_max);
  fprintf(stderr, "initial hard limit: %s\n", strbuff);

  /* If the OS allows a HUGE number of open files, we do not run.
   * Modern debian sid reports a limit of 134217724 and this tests
   * takes minutes. */
#define LIMIT_CAP     (256*1024)
  if(rl.rlim_cur > LIMIT_CAP) {
    fprintf(stderr, "soft limit above %ld, not running\n", (long)LIMIT_CAP);
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
      fprintf(stderr, "raising soft limit up to OPEN_MAX\n");
      rl.rlim_cur = OPEN_MAX;
      if(setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        /* on failure don't abort just issue a warning */
        store_errmsg("setrlimit() failed", errno);
        fprintf(stderr, "%s\n", msgbuff);
        msgbuff[0] = '\0';
      }
    }
#endif

    fprintf(stderr, "raising soft limit up to hard limit\n");
    rl.rlim_cur = rl.rlim_max;
    if(setrlimit(RLIMIT_NOFILE, &rl) != 0) {
      /* on failure don't abort just issue a warning */
      store_errmsg("setrlimit() failed", errno);
      fprintf(stderr, "%s\n", msgbuff);
      msgbuff[0] = '\0';
    }

    /* get current open file limits */

    if(getrlimit(RLIMIT_NOFILE, &rl) != 0) {
      store_errmsg("getrlimit() failed", errno);
      fprintf(stderr, "%s\n", msgbuff);
      return -3;
    }

    /* show current open file limits */

    rlim2str(strbuff, sizeof(strbuff), rl.rlim_cur);
    fprintf(stderr, "current soft limit: %s\n", strbuff);

    rlim2str(strbuff, sizeof(strbuff), rl.rlim_max);
    fprintf(stderr, "current hard limit: %s\n", strbuff);

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
   * be always free()ed before exiting the test_rlimit() function so
   * that it becomes available to the test.
   */

  for(nitems = i = 1; nitems <= i; i *= 2)
    nitems = i;
  if(nitems > 0x7fff)
    nitems = 0x40000;
  do {
    num_open.rlim_max = sizeof(*memchunk) * nitems;
    rlim2str(strbuff, sizeof(strbuff), num_open.rlim_max);
    fprintf(stderr, "allocating memchunk %s byte array\n", strbuff);
    memchunk = malloc(sizeof(*memchunk) * (size_t)nitems);
    if(!memchunk) {
      fprintf(stderr, "memchunk, malloc() failed\n");
      nitems /= 2;
    }
  } while(nitems && !memchunk);
  if(!memchunk) {
    store_errmsg("memchunk, malloc() failed", errno);
    fprintf(stderr, "%s\n", msgbuff);
    return -4;
  }

  /* initialize it to fight lazy allocation */

  fprintf(stderr, "initializing memchunk array\n");

  for(i = 0; i < nitems; i++)
    memchunk[i] = -1;

  /* set the number of file descriptors we will try to open */

#ifdef RLIM_INFINITY
  if((rl.rlim_cur > 0) && (rl.rlim_cur != RLIM_INFINITY)) {
#else
  if(rl.rlim_cur > 0) {
#endif
    /* soft limit minus SAFETY_MARGIN */
    num_open.rlim_max = rl.rlim_cur - SAFETY_MARGIN;
  }
  else {
    /* a huge number of file descriptors */
    for(nitems = i = 1; nitems <= i; i *= 2)
      nitems = i;
    if(nitems > 0x7fff)
      nitems = 0x40000;
    num_open.rlim_max = nitems;
  }

  /* verify that we won't overflow size_t in malloc() */

  if((size_t)(num_open.rlim_max) > ((size_t)-1) / sizeof(*testfd)) {
    rlim2str(strbuff1, sizeof(strbuff1), num_open.rlim_max);
    msnprintf(strbuff, sizeof(strbuff), "unable to allocate an array for %s "
              "file descriptors, would overflow size_t", strbuff1);
    store_errmsg(strbuff, 0);
    fprintf(stderr, "%s\n", msgbuff);
    free(memchunk);
    return -5;
  }

  /* allocate array for file descriptors */

  do {
    rlim2str(strbuff, sizeof(strbuff), num_open.rlim_max);
    fprintf(stderr, "allocating array for %s file descriptors\n", strbuff);

    testfd = malloc(sizeof(*testfd) * (size_t)(num_open.rlim_max));
    if(!testfd) {
      fprintf(stderr, "testfd, malloc() failed\n");
      num_open.rlim_max /= 2;
    }
  } while(num_open.rlim_max && !testfd);
  if(!testfd) {
    store_errmsg("testfd, malloc() failed", errno);
    fprintf(stderr, "%s\n", msgbuff);
    free(memchunk);
    return -6;
  }

  /* initialize it to fight lazy allocation */

  fprintf(stderr, "initializing testfd array\n");

  for(num_open.rlim_cur = 0;
      num_open.rlim_cur < num_open.rlim_max;
      num_open.rlim_cur++)
    testfd[num_open.rlim_cur] = -1;

  rlim2str(strbuff, sizeof(strbuff), num_open.rlim_max);
  fprintf(stderr, "trying to open %s file descriptors\n", strbuff);

  /* open a dummy descriptor */

  testfd[0] = open(DEV_NULL, O_RDONLY);
  if(testfd[0] < 0) {
    msnprintf(strbuff, sizeof(strbuff), "opening of %s failed", DEV_NULL);
    store_errmsg(strbuff, errno);
    fprintf(stderr, "%s\n", msgbuff);
    free(testfd);
    testfd = NULL;
    free(memchunk);
    return -7;
  }

  /* create a bunch of file descriptors */

  for(num_open.rlim_cur = 1;
      num_open.rlim_cur < num_open.rlim_max;
      num_open.rlim_cur++) {

    testfd[num_open.rlim_cur] = dup(testfd[0]);

    if(testfd[num_open.rlim_cur] < 0) {

      testfd[num_open.rlim_cur] = -1;

      rlim2str(strbuff1, sizeof(strbuff1), num_open.rlim_cur);
      msnprintf(strbuff, sizeof(strbuff), "dup() attempt %s failed", strbuff1);
      fprintf(stderr, "%s\n", strbuff);

      rlim2str(strbuff1, sizeof(strbuff1), num_open.rlim_cur);
      msnprintf(strbuff, sizeof(strbuff), "fds system limit seems close to %s",
                strbuff1);
      fprintf(stderr, "%s\n", strbuff);

      num_open.rlim_max = num_open.rlim_cur - SAFETY_MARGIN;

      num_open.rlim_cur -= num_open.rlim_max;
      rlim2str(strbuff1, sizeof(strbuff1), num_open.rlim_cur);
      msnprintf(strbuff, sizeof(strbuff), "closing %s file descriptors",
                strbuff1);
      fprintf(stderr, "%s\n", strbuff);

      for(num_open.rlim_cur = num_open.rlim_max;
          testfd[num_open.rlim_cur] >= 0;
          num_open.rlim_cur++) {
        close(testfd[num_open.rlim_cur]);
        testfd[num_open.rlim_cur] = -1;
      }

      rlim2str(strbuff, sizeof(strbuff), num_open.rlim_max);
      fprintf(stderr, "shrinking array for %s file descriptors\n", strbuff);

      /* we don't care if we can't shrink it */

      tmpfd = realloc(testfd, sizeof(*testfd) * (size_t)(num_open.rlim_max));
      if(tmpfd) {
        testfd = tmpfd;
        tmpfd = NULL;
      }

      break;
    }
  }

  rlim2str(strbuff, sizeof(strbuff), num_open.rlim_max);
  fprintf(stderr, "%s file descriptors open\n", strbuff);

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

  num_open.rlim_cur = FD_SETSIZE - SAFETY_MARGIN;
  if(num_open.rlim_max > num_open.rlim_cur) {
    msnprintf(strbuff, sizeof(strbuff), "select limit is FD_SETSIZE %d",
              FD_SETSIZE);
    store_errmsg(strbuff, 0);
    fprintf(stderr, "%s\n", msgbuff);
    close_file_descriptors();
    free(memchunk);
    return -8;
  }

  num_open.rlim_cur = FD_SETSIZE - SAFETY_MARGIN;
  for(rl.rlim_cur = 0;
      rl.rlim_cur < num_open.rlim_max;
      rl.rlim_cur++) {
    if((testfd[rl.rlim_cur] > 0) &&
       ((unsigned int)testfd[rl.rlim_cur] > num_open.rlim_cur)) {
      msnprintf(strbuff, sizeof(strbuff), "select limit is FD_SETSIZE %d",
                FD_SETSIZE);
      store_errmsg(strbuff, 0);
      fprintf(stderr, "%s\n", msgbuff);
      close_file_descriptors();
      free(memchunk);
      return -9;
    }
  }

#endif /* using a FD_SETSIZE bound select() */

  /*
   * Old or 'backwards compatible' implementations of stdio do not allow
   * handling of streams with an underlying file descriptor number greater
   * than 255, even when allowing high numbered file descriptors for sockets.
   * At this point we have a big number of file descriptors which have been
   * opened using dup(), so lets test the stdio implementation and discover
   * if it is capable of fopen()ing some additional files.
   */

  if(!fopen_works()) {
    rlim2str(strbuff1, sizeof(strbuff1), num_open.rlim_max);
    msnprintf(strbuff, sizeof(strbuff), "fopen fails with %s fds open",
              strbuff1);
    fprintf(stderr, "%s\n", msgbuff);
    msnprintf(strbuff, sizeof(strbuff), "fopen fails with lots of fds open");
    store_errmsg(strbuff, 0);
    close_file_descriptors();
    free(memchunk);
    return -10;
  }

  /* free the chunk of memory we were reserving so that it
     becomes available to the test */

  free(memchunk);

  /* close file descriptors unless instructed to keep them */

  if(!keep_open) {
    close_file_descriptors();
  }

  return 0;
}

CURLcode test(char *URL)
{
  CURLcode res;
  CURL *curl;

  if(!strcmp(URL, "check")) {
    /* used by the test script to ask if we can run this test or not */
    if(test_rlimit(FALSE)) {
      fprintf(stdout, "test_rlimit problem: %s\n", msgbuff);
      return (CURLcode)1;
    }
    return CURLE_OK; /* sure, run this! */
  }

  if(test_rlimit(TRUE)) {
    /* failure */
    return TEST_ERR_MAJOR_BAD;
  }

  /* run the test with the bunch of open file descriptors
     and close them all once the test is over */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    close_file_descriptors();
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    close_file_descriptors();
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HEADER, 1L);

  res = curl_easy_perform(curl);

test_cleanup:

  close_file_descriptors();
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}

#else /* defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT) */

CURLcode test(char *URL)
{
  (void)URL;
  printf("system lacks necessary system function(s)");
  return (CURLcode)1; /* skip test */
}

#endif /* defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT) */
