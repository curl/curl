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

static int rlimit(void)
{
  int i;
  struct rlimit rl;

  fprintf(stderr, "NUM_OPEN: %d\n", NUM_OPEN);
  fprintf(stderr, "NUM_NEEDED: %d\n", NUM_NEEDED);

  /* get open file limits */
  if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
    fprintf(stderr, "warning: getrlimit: failed to get RLIMIT_NOFILE\n");
    return -1;
  }

  /* check that hard limit is high enough */
  if (rl.rlim_max < NUM_NEEDED) {
    fprintf(stderr, "warning: RLIMIT_NOFILE hard limit %d < %d\n",
            (int)rl.rlim_max, NUM_NEEDED);
    return -2;
  }

  /* increase soft limit if needed */
  if (rl.rlim_cur < NUM_NEEDED) {
    rl.rlim_cur = NUM_NEEDED;
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
      fprintf(stderr, "warning: setrlimit: failed to set RLIMIT_NOFILE\n");
      return -3;
    }
  }

  /* open a dummy descriptor */
  fd[0] = open(DEV_NULL, O_RDONLY);
  if (fd[0] == -1) {
    fprintf(stderr, "open: failed to open %s\n", DEV_NULL);
    return -4;
  }

  /* create a bunch of file descriptors */
  for (i = 1; i < NUM_OPEN; i++) {
    fd[i] = dup(fd[0]);
    if (fd[i] == -1) {
      fprintf(stderr, "dup: attempt #%i failed\n", i);
      for (i--; i >= 0; i--)
        close(fd[i]);
      return -5;
    }
  }

  return 0;
}

int test(char *URL)
{
  CURLcode res;
  CURL *curl;

  if(!strcmp(URL, "check")) {
    /* used by the test script to ask if we can run this test or not */
    if(rlimit()) {
      printf("rlimit problems\n");
      return 1;
    }
    return 0; /* sure, run this! */
  }

  if(rlimit())
    /* failure */
    return 100;

  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);
  res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);

  /* we never close the file descriptors */

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
