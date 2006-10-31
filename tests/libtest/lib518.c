/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
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
#ifdef UNISTD_H
#include <unistd.h>
#endif

#include <mprintf.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifndef FD_SETSIZE
#error "this test requires FD_SETSIZE"
#endif

#define SAFETY_MARGIN 16
#define NUM_OPEN (FD_SETSIZE + 10)
#define NUM_NEEDED (NUM_OPEN + SAFETY_MARGIN)

#if defined(WIN32) || defined(_WIN32) || defined(MSDOS)
#define DEV_NULL "NUL"
#else
#define DEV_NULL "/dev/null"
#endif

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)

static int *fd = NULL;
static struct rlimit num_open;

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
  char *fmt;
  struct rlimit rl;
  char strbuff[81];
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
    fprintf(stderr, "warning: getrlimit: failed to get RLIMIT_NOFILE "
            "with errno %d\n", our_errno());
    return -1;
  }

  /* show initial open file limits */

#ifdef RLIM_INFINITY
  if (rl.rlim_cur == RLIM_INFINITY)
    strcpy(strbuff, "INFINITY");
  else
#endif
    sprintf(strbuff, fmt, rl.rlim_cur);
  fprintf(stderr, "initial SOFT_LIMIT: %s\n", strbuff);

#ifdef RLIM_INFINITY
  if (rl.rlim_max == RLIM_INFINITY)
    strcpy(strbuff, "INFINITY");
  else
#endif
    sprintf(strbuff, fmt, rl.rlim_max);
  fprintf(stderr, "initial HARD_LIMIT: %s\n", strbuff);

  /* show our constants */

  fprintf(stderr, "test518 FD_SETSIZE: %d\n", FD_SETSIZE);
  fprintf(stderr, "test518 NUM_OPEN  : %d\n", NUM_OPEN);
  fprintf(stderr, "test518 NUM_NEEDED: %d\n", NUM_NEEDED);

  /* increase soft limit up to hard limit if different */

  if (rl.rlim_cur != rl.rlim_max) {
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
      fprintf(stderr, "warning: setrlimit: failed to set RLIMIT_NOFILE "
              "with errno %d\n", our_errno());
      return -2;
    }
  }

  /* get current open file limits */

  if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    fprintf(stderr, "warning: getrlimit: failed to get RLIMIT_NOFILE "
            "with errno %d\n", our_errno());
    return -3;
  }

  /* if soft limit has not been increased all the way up to hard
     limit, warn about it but continue since it may be high enough */

  if (rl.rlim_cur != rl.rlim_max) {
    fprintf(stderr, "warning: setrlimit: did not raise soft limit "
            "up to hard limit\n");
  }

  /* show current open file limits */

#ifdef RLIM_INFINITY
  if (rl.rlim_cur == RLIM_INFINITY)
    strcpy(strbuff, "INFINITY");
  else
#endif
    sprintf(strbuff, fmt, rl.rlim_cur);
  fprintf(stderr, "current SOFT_LIMIT: %s\n", strbuff);

#ifdef RLIM_INFINITY
  if (rl.rlim_max == RLIM_INFINITY)
    strcpy(strbuff, "INFINITY");
  else
#endif
    sprintf(strbuff, fmt, rl.rlim_max);
  fprintf(stderr, "current HARD_LIMIT: %s\n", strbuff);

  /* 
  ** Our extreme test target is to open more than FD_SETSIZE files but
  ** it could happen that it would exceed the limit of allowed open
  ** files and we would not be able to test libcurl functionality. In 
  ** this case we will open the maximum allowed minus our safety margin,
  ** which will run the test under this stress condition.
  */

  num_open.rlim_cur = FD_SETSIZE;
  num_open.rlim_max = NUM_OPEN;
  if (num_open.rlim_cur > num_open.rlim_max)
    num_open.rlim_max = num_open.rlim_cur;

#ifdef RLIM_INFINITY
  if ((rl.rlim_cur > 0) && (rl.rlim_cur != RLIM_INFINITY)) {
#else
  if (rl.rlim_cur > 0) {
#endif
    if (num_open.rlim_max > rl.rlim_cur - SAFETY_MARGIN) {
      num_open.rlim_max = rl.rlim_cur - SAFETY_MARGIN;
    }
  }

  sprintf(strbuff, fmt, num_open.rlim_max);
  fprintf(stderr, "allocating array for %s file descriptors\n", strbuff);

  /* verify that we won't overflow size_t in malloc() */

  if (num_open.rlim_max > ((size_t)-1) / sizeof(*fd)) {
    fprintf(stderr, "is not possible, we would overflow size_t in malloc()\n");
    num_open.rlim_max = ((size_t)-1) / sizeof(*fd);
    sprintf(strbuff, fmt, num_open.rlim_max);
    fprintf(stderr, "allocating array for %s file descriptors\n", strbuff);
  }

  fd = malloc(sizeof(*fd) * (size_t)(num_open.rlim_max));
  if (!fd) {
    fprintf(stderr, "warning: memory allocation failed "
            "with errno %d\n", our_errno());
    return -4;
  }

  /* initialize fighting lazy allocation */

  for (num_open.rlim_cur = 0;
       num_open.rlim_cur < num_open.rlim_max;
       num_open.rlim_cur++)
    fd[num_open.rlim_cur] = -1;

  sprintf(strbuff, fmt, num_open.rlim_max);
  fprintf(stderr, "opening %s file descriptors\n", strbuff);

  /* open a dummy descriptor */
  fd[0] = open(DEV_NULL, O_RDONLY);
  if (fd[0] < 0) {
    fprintf(stderr, "open: failed to open %s "
            "with errno %d\n", DEV_NULL, our_errno());
    free(fd);
    fd = NULL;
    return -5;
  }

  /* create a bunch of file descriptors */
  for (num_open.rlim_cur = 1; 
       num_open.rlim_cur < num_open.rlim_max; 
       num_open.rlim_cur++) {
    fd[num_open.rlim_cur] = dup(fd[0]);
    if (fd[num_open.rlim_cur] < 0) {
      sprintf(strbuff, fmt, num_open.rlim_cur);
      fprintf(stderr, "dup: attempt #%s failed "
              "with errno %d\n", strbuff, our_errno());
      for (num_open.rlim_cur = 0;
           fd[num_open.rlim_cur] >= 0;
           num_open.rlim_cur++)
        close(fd[num_open.rlim_cur]);
      free(fd);
      fd = NULL;
      return -6;
    }
  }

  sprintf(strbuff, fmt, num_open.rlim_max);
  fprintf(stderr, "%s file descriptors open\n", strbuff);

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
      printf("rlimit problems\n");
      return 1;
    }
    return 0; /* sure, run this! */
  }

  if (rlimit(TRUE)) {
    /* failure */
    fprintf(stderr, "Previous condition aborts this test\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* run the test with more than FD_SETSIZE or max allowed open
     file descriptors and close them all once the test is over */

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
