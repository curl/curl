/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

/*
 * This source code is used for lib518 and lib537.
 */

#include "test.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define _MPRINTF_REPLACE /* use our functions only */
#include <mprintf.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if defined(LIB518) && !defined(FD_SETSIZE)
#error "this test requires FD_SETSIZE"
#endif

#ifdef LIB518
#define SAFETY_MARGIN 16
#define NUM_OPEN (FD_SETSIZE + 10)
#define NUM_NEEDED (NUM_OPEN + SAFETY_MARGIN)
#endif

#ifdef LIB537
#define SAFETY_MARGIN 5
#endif

#define MEMCHUNK_NITEMS 32000

#if defined(WIN32) || defined(_WIN32) || defined(MSDOS)
#define DEV_NULL "NUL"
#else
#define DEV_NULL "/dev/null"
#endif

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)

static int *fd = NULL;
static struct rlimit num_open;
static char msgbuff[256];

/*
 * our_errno() returns the NOT *socket-related* errno (or equivalent)
 * on this platform to hide platform specific for the calling function.
 */

static int our_errno(void)
{
#ifdef WIN32
  return (int)GetLastError();
#else
  return errno;
#endif
}

static void store_errmsg(const char *msg, int err)
{
  if (!err)
    snprintf(msgbuff, sizeof(msgbuff), "%s", msg);
  else
    snprintf(msgbuff, sizeof(msgbuff), "%s, errno %d, %s",
             msg, err, strerror(err));
}

static void close_file_descriptors(void)
{
  fprintf(stderr, "closing file descriptors\n");
  for (num_open.rlim_cur = 0;
       num_open.rlim_cur < num_open.rlim_max;
       num_open.rlim_cur++)
    close(fd[num_open.rlim_cur]);
  free(fd);
  fd = NULL;
  fprintf(stderr, "file descriptors closed\n");
}

static int rlimit(int keep_open)
{
#ifdef LIB537
  int *tmpfd;
#endif
  int i;
  int *memchunk = NULL;
  char *fmt;
  struct rlimit rl;
  char strbuff[256];
  char strbuff1[81];
  char strbuff2[81];
  char fmt_u[] = "%u";
  char fmt_lu[] = "%lu";
#ifdef HAVE_LONGLONG
  char fmt_llu[] = "%llu";

  if (sizeof(rl.rlim_max) > sizeof(long))
    fmt = fmt_llu;
  else
#endif
    fmt = (sizeof(rl.rlim_max) < sizeof(long))?fmt_u:fmt_lu;

  /* get initial open file limits */

  if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    store_errmsg("getrlimit() failed", our_errno());
    fprintf(stderr, "%s\n", msgbuff);
    return -1;
  }

  /* show initial open file limits */

#ifdef RLIM_INFINITY
  if (rl.rlim_cur == RLIM_INFINITY)
    strcpy(strbuff, "INFINITY");
  else
#endif
    snprintf(strbuff, sizeof(strbuff), fmt, rl.rlim_cur);
  fprintf(stderr, "initial soft limit: %s\n", strbuff);

#ifdef RLIM_INFINITY
  if (rl.rlim_max == RLIM_INFINITY)
    strcpy(strbuff, "INFINITY");
  else
#endif
    snprintf(strbuff, sizeof(strbuff), fmt, rl.rlim_max);
  fprintf(stderr, "initial hard limit: %s\n", strbuff);

#ifdef LIB518
  /* show our constants */

  fprintf(stderr, "test518 FD_SETSIZE: %d\n", FD_SETSIZE);
  fprintf(stderr, "test518 NUM_OPEN  : %d\n", NUM_OPEN);
  fprintf(stderr, "test518 NUM_NEEDED: %d\n", NUM_NEEDED);
#endif

  /*
   * if soft limit and hard limit are different we ask the
   * system to raise soft limit all the way up to the hard
   * limit. Due to some other system limit the soft limit
   * might not be raised up to the hard limit. So from this
   * point the resulting soft limit is our limit. Trying to
   * open more than soft limit file descriptors will fail.
   */

  if (rl.rlim_cur != rl.rlim_max) {
    fprintf(stderr, "raising soft limit up to hard limit\n");
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
      store_errmsg("setrlimit() failed", our_errno());
      fprintf(stderr, "%s\n", msgbuff);
      return -2;
    }
  }

  /* get current open file limits */

  if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    store_errmsg("getrlimit() failed", our_errno());
    fprintf(stderr, "%s\n", msgbuff);
    return -3;
  }

  /* show current open file limits */

#ifdef RLIM_INFINITY
  if (rl.rlim_cur == RLIM_INFINITY)
    strcpy(strbuff, "INFINITY");
  else
#endif
    snprintf(strbuff, sizeof(strbuff), fmt, rl.rlim_cur);
  fprintf(stderr, "current soft limit: %s\n", strbuff);

#ifdef RLIM_INFINITY
  if (rl.rlim_max == RLIM_INFINITY)
    strcpy(strbuff, "INFINITY");
  else
#endif
    snprintf(strbuff, sizeof(strbuff), fmt, rl.rlim_max);
  fprintf(stderr, "current hard limit: %s\n", strbuff);

  /*
   * test 518 is all about testing libcurl functionality
   * when more than FD_SETSIZE file descriptors are open.
   * This means that if for any reason we are not able to
   * open more than FD_SETSIZE file descriptors then test
   * 518 should not be run.
   *
   * test 537 is all about testing libcurl functionality
   * when the system has nearly exhausted the number of
   * free file descriptors. Test 537 will try to run with 
   * very few free file descriptors.
   */

#ifdef LIB518

  /* verify that soft limit is higher than FD_SETSIZE */

  num_open.rlim_cur = FD_SETSIZE;

  if ((rl.rlim_cur > 0) &&
#ifdef RLIM_INFINITY
     (rl.rlim_cur != RLIM_INFINITY) &&
#endif
     (rl.rlim_cur <= num_open.rlim_cur)) {
    snprintf(strbuff2, sizeof(strbuff2), fmt, rl.rlim_cur);
    snprintf(strbuff1, sizeof(strbuff1), fmt, num_open.rlim_cur);
    snprintf(strbuff, sizeof(strbuff), "system does not support opening %s "
             "files, soft limit is %s", strbuff1, strbuff2);
    store_errmsg(strbuff, 0);
    fprintf(stderr, "%s\n", msgbuff);
    return -4;
  }

  /*
   * verify that soft limit is higher than NUM_OPEN,
   * number of file descriptors we would try to open
   */

  num_open.rlim_cur = NUM_OPEN;

  if ((rl.rlim_cur > 0) &&
#ifdef RLIM_INFINITY
     (rl.rlim_cur != RLIM_INFINITY) &&
#endif
     (rl.rlim_cur <= num_open.rlim_cur)) {
    snprintf(strbuff2, sizeof(strbuff2), fmt, rl.rlim_cur);
    snprintf(strbuff1, sizeof(strbuff1), fmt, num_open.rlim_cur);
    snprintf(strbuff, sizeof(strbuff), "system does not support opening %s "
             "files, soft limit is %s", strbuff1, strbuff2);
    store_errmsg(strbuff, 0);
    fprintf(stderr, "%s\n", msgbuff);
    return -5;
  }

  /*
   * verify that soft limit is higher than NUM_NEEDED,
   * number of file descriptors we would try to open
   * plus SAFETY_MARGIN to not exhaust file pool
   */

  num_open.rlim_cur = NUM_NEEDED;

  if ((rl.rlim_cur > 0) &&
#ifdef RLIM_INFINITY
     (rl.rlim_cur != RLIM_INFINITY) &&
#endif
     (rl.rlim_cur <= num_open.rlim_cur)) {
    snprintf(strbuff2, sizeof(strbuff2), fmt, rl.rlim_cur);
    snprintf(strbuff1, sizeof(strbuff1), fmt, num_open.rlim_cur);
    snprintf(strbuff, sizeof(strbuff), "system does not support opening %s "
             "files, soft limit is %s", strbuff1, strbuff2);
    store_errmsg(strbuff, 0);
    fprintf(stderr, "%s\n", msgbuff);
    return -6;
  }

#endif /* LIB518 */

  /*
   * reserve a chunk of memory before opening file descriptors to
   * avoid a low memory condition once the file descriptors are
   * open. System conditions that could make the test fail should
   * be addressed in the precheck phase. This chunk of memory shall
   * be always free()ed before exiting the rlimit() function so
   * that it becomes available to the test.
   */

  memchunk = malloc(sizeof(*memchunk) * MEMCHUNK_NITEMS);
  if (!memchunk) {
    store_errmsg("memchunk, malloc() failed", our_errno());
    fprintf(stderr, "%s\n", msgbuff);
    return -7;
  }

  /* initialize it to fight lazy allocation */

  for (i = 0; i < MEMCHUNK_NITEMS; i++)
    memchunk[i] = -1;

  /* set the number of file descriptors we will try to open to ... */

#ifdef LIB518
  /* NUM_OPEN */
  num_open.rlim_max = NUM_OPEN;
#endif

#ifdef LIB537
#ifdef RLIM_INFINITY
  if ((rl.rlim_cur > 0) && (rl.rlim_cur != RLIM_INFINITY)) {
#else
  if (rl.rlim_cur > 0) {
#endif
    /* soft limit minus SAFETY_MARGIN */
    num_open.rlim_max = rl.rlim_cur - SAFETY_MARGIN;
  }
  else {
    /* biggest file descriptor array size */
    num_open.rlim_max = ((size_t)-1) / sizeof(*fd);
  }
#endif /* LIB537 */

  /* verify that we won't overflow size_t in malloc() */

  if (num_open.rlim_max > ((size_t)-1) / sizeof(*fd)) {
    snprintf(strbuff1, sizeof(strbuff1), fmt, num_open.rlim_max);
    snprintf(strbuff, sizeof(strbuff), "unable to allocate an array for %s "
             "file descriptors, would overflow size_t", strbuff1);
    store_errmsg(strbuff, 0);
    fprintf(stderr, "%s\n", msgbuff);
    free(memchunk);
    return -8;
  }

  snprintf(strbuff, sizeof(strbuff), fmt, num_open.rlim_max);
  fprintf(stderr, "allocating array for %s file descriptors\n", strbuff);

  fd = malloc(sizeof(*fd) * (size_t)(num_open.rlim_max));
  if (!fd) {
    store_errmsg("fd, malloc() failed", our_errno());
    fprintf(stderr, "%s\n", msgbuff);
    free(memchunk);
    return -9;
  }

  /* initialize it to fight lazy allocation */

  for (num_open.rlim_cur = 0;
       num_open.rlim_cur < num_open.rlim_max;
       num_open.rlim_cur++)
    fd[num_open.rlim_cur] = -1;

  snprintf(strbuff, sizeof(strbuff), fmt, num_open.rlim_max);
  fprintf(stderr, "trying to open %s file descriptors\n", strbuff);

  /* open a dummy descriptor */

  fd[0] = open(DEV_NULL, O_RDONLY);
  if (fd[0] < 0) {
    snprintf(strbuff, sizeof(strbuff), "opening of %s failed", DEV_NULL);
    store_errmsg(strbuff, our_errno());
    fprintf(stderr, "%s\n", msgbuff);
    free(fd);
    fd = NULL;
    free(memchunk);
    return -10;
  }

  /* create a bunch of file descriptors */

#ifdef LIB518

  for (num_open.rlim_cur = 1; 
       num_open.rlim_cur < num_open.rlim_max; 
       num_open.rlim_cur++) {

    fd[num_open.rlim_cur] = dup(fd[0]);

    if (fd[num_open.rlim_cur] < 0) {

      fd[num_open.rlim_cur] = -1;

      snprintf(strbuff1, sizeof(strbuff1), fmt, num_open.rlim_cur);
      snprintf(strbuff, sizeof(strbuff), "dup() attempt %s failed", strbuff1);
      store_errmsg(strbuff, our_errno());
      fprintf(stderr, "%s\n", msgbuff);

      fprintf(stderr, "closing file descriptors\n");
      for (num_open.rlim_cur = 0;
           fd[num_open.rlim_cur] >= 0;
           num_open.rlim_cur++)
        close(fd[num_open.rlim_cur]);
      fprintf(stderr, "file descriptors closed\n");
      free(fd);
      fd = NULL;
      free(memchunk);
      return -11;

    }

  }

#endif /* LIB518 */

#ifdef LIB537

  for (num_open.rlim_cur = 1; 
       num_open.rlim_cur < num_open.rlim_max; 
       num_open.rlim_cur++) {

    fd[num_open.rlim_cur] = dup(fd[0]);

    if (fd[num_open.rlim_cur] < 0) {

      fd[num_open.rlim_cur] = -1;

      snprintf(strbuff1, sizeof(strbuff1), fmt, num_open.rlim_cur);
      snprintf(strbuff, sizeof(strbuff), "dup() attempt %s failed", strbuff1);
      fprintf(stderr, "%s\n", strbuff);

      snprintf(strbuff1, sizeof(strbuff1), fmt, num_open.rlim_cur + 2);
      snprintf(strbuff, sizeof(strbuff), "system does not support opening "
               "more than %s files" , strbuff1);
      fprintf(stderr, "%s\n", strbuff);

      num_open.rlim_max = num_open.rlim_cur + 2 - SAFETY_MARGIN;

      num_open.rlim_cur -= num_open.rlim_max;
      snprintf(strbuff1, sizeof(strbuff1), fmt, num_open.rlim_cur);
      snprintf(strbuff, sizeof(strbuff), "closing %s files", strbuff1);
      fprintf(stderr, "%s\n", strbuff);

      for (num_open.rlim_cur = num_open.rlim_max;
           fd[num_open.rlim_cur] >= 0;
           num_open.rlim_cur++) {
        close(fd[num_open.rlim_cur]);
        fd[num_open.rlim_cur] = -1;
      }

      snprintf(strbuff, sizeof(strbuff1), fmt, num_open.rlim_max);
      fprintf(stderr, "shrinking array for %s file descriptors\n", strbuff);

      tmpfd = realloc(fd, sizeof(*fd) * (size_t)(num_open.rlim_max));
      if (!tmpfd) {
        snprintf(strbuff, sizeof(strbuff), "fd, realloc() failed, "
                 "errno %d, %s", our_errno(), strerror(our_errno()));
        fprintf(stderr, "%s\n", strbuff);
      }
      else {
        fd = tmpfd;
        tmpfd = NULL;
      }

    }

  }

#endif /* LIB537 */

  snprintf(strbuff, sizeof(strbuff), fmt, num_open.rlim_max);
  fprintf(stderr, "%s file descriptors open\n", strbuff);

  /* free the chunk of memory we were reserving so that it
     becomes becomes available to the test */

  free(memchunk);

  /* close file descriptors unless instructed to keep them */
  if (!keep_open) {
    close_file_descriptors();
  }

  return 0;
}

int test(char *URL)
{
  CURLcode res;
  CURL *curl;

  if(!strcmp(URL, "check")) {
    /* used by the test script to ask if we can run this test or not */
    if(rlimit(FALSE)) {
      fprintf(stderr, "Previous condition prevents running this test\n");
      fprintf(stdout, "rlimit problem: %s\n", msgbuff);
      return 1;
    }
    return 0; /* sure, run this! */
  }

  if (rlimit(TRUE)) {
    /* failure */
    fprintf(stderr, "Previous condition aborts this test\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fprintf(stderr, "running test...\n");

  /* run the test with the bunch of open file descriptors 
     and close them all once the test is over */

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    close_file_descriptors();
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    close_file_descriptors();
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);

  res = curl_easy_perform(curl);

  close_file_descriptors();
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
#else
/* system lacks getrlimit() and/or setrlimit() */
int test(char *URL)
{
  (void)URL;
  printf("system lacks necessary system function(s)");
  return 1;
}
#endif
