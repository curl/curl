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

#define NUM_OPEN (FD_SETSIZE + 10)
#define NUM_NEEDED (NUM_OPEN + 16)

#if defined(WIN32) || defined(_WIN32) || defined(MSDOS)
#define DEV_NULL "NUL"
#else
#define DEV_NULL "/dev/null"
#endif

#if defined(HAVE_GETRLIMIT) && defined(HAVE_SETRLIMIT)

static int fd[NUM_OPEN];

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
  int i;

  for (i = 0; i < NUM_OPEN; i++) {
    close(fd[i]);
    fd[i] = -1;
  }
}

static int rlimit(int keep_open)
{
  int i;
  struct rlimit rl;
  char strbuff[81];
  char fmt_d[] = "%d";
  char fmt_ld[] = "%ld";
  char fmt_lld[] = "%lld";
  char *fmt;

  if (sizeof(rl.rlim_max) < sizeof(long))
    fmt = fmt_d;
  else if (sizeof(rl.rlim_max) == sizeof(long))
    fmt = fmt_ld;
  else
    fmt = fmt_lld;

  fprintf(stderr, "NUM_OPEN: %d\n", NUM_OPEN);
  fprintf(stderr, "NUM_NEEDED: %d\n", NUM_NEEDED);

  /* get open file limits */
  if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
    fprintf(stderr, "warning: getrlimit: failed to get RLIMIT_NOFILE "
            "with errno %d\n", our_errno());
    return -1;
  }

  /* check that hard limit is high enough */
#ifdef RLIM_INFINITY
  if (rl.rlim_max != RLIM_INFINITY) 
#endif
    if ((rl.rlim_max > 0) && (rl.rlim_max < NUM_NEEDED)) {
      sprintf(strbuff, fmt, rl.rlim_max);
      fprintf(stderr, "warning: RLIMIT_NOFILE hard limit %s < %d\n",
              strbuff, NUM_NEEDED);
      return -2;
    }

  /* increase soft limit if needed */
#ifdef RLIM_INFINITY
  if (rl.rlim_cur != RLIM_INFINITY) 
#endif
    if ((rl.rlim_cur > 0) && (rl.rlim_cur < NUM_NEEDED)) {
      rl.rlim_cur = NUM_NEEDED;
      if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "warning: setrlimit: failed to set RLIMIT_NOFILE "
                "with errno %d\n", our_errno());
        return -3;
      }
      /* verify that it has been increased */
      if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "warning: getrlimit: failed to get RLIMIT_NOFILE "
                "with errno %d\n", our_errno());
        return -4;
      }
      if ((rl.rlim_cur > 0) && (rl.rlim_cur < NUM_NEEDED)) {
        sprintf(strbuff, fmt, rl.rlim_cur);
        fprintf(stderr, "warning: RLIMIT_NOFILE soft limit %s < %d\n",
                strbuff, NUM_NEEDED);
        return -5;
      }
    }

#ifdef RLIM_INFINITY
  if (rl.rlim_cur == RLIM_INFINITY)
    fprintf(stderr, "SOFT_LIMIT: INFINITY\n");
  else
#endif
  {
    sprintf(strbuff, fmt, rl.rlim_cur);
    fprintf(stderr, "SOFT_LIMIT: %s\n", strbuff);
  }

#ifdef RLIM_INFINITY
  if (rl.rlim_max == RLIM_INFINITY)
    fprintf(stderr, "HARD_LIMIT: INFINITY\n");
  else
#endif
  {
    sprintf(strbuff, fmt, rl.rlim_max);
    fprintf(stderr, "HARD_LIMIT: %s\n", strbuff);
  }

  /* open a dummy descriptor */
  fd[0] = open(DEV_NULL, O_RDONLY);
  if (fd[0] < 0) {
    fprintf(stderr, "open: failed to open %s "
            "with errno %d\n", DEV_NULL, our_errno());
    return -6;
  }

  /* create a bunch of file descriptors */
  for (i = 1; i < NUM_OPEN; i++) {
    fd[i] = dup(fd[0]);
    if (fd[i] < 0) {
      fprintf(stderr, "dup: attempt #%d failed "
              "with errno %d\n", i, our_errno());
      for (i--; i >= 0; i--)
        close(fd[i]);
      return -7;
    }
  }

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
      printf("rlimit problems\n");
      return 1;
    }
    return 0; /* sure, run this! */
  }

  if(rlimit(TRUE))
    /* failure */
    return 100;

  /* now run the test with NUM_OPEN open file descriptors
     and close them all once this test is over */

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
