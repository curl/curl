/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * Little tool to raise the amount of maximum file descriptor and then run the
 * given command line (using the hard-coded uid/gid).
 *
 */

#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <string.h> /* for errno translation */

/* ulimiter
 *
 * Source code inspiration from:
 *  http://www.cs.wisc.edu/condor/condorg/linux_scalability.html
 */

#define UID 1000 /* the user who must run this */

#define GID 1000 /* group id to run the program as */

/* Number of open files to increase to */
#define NEW_MAX 10000

int main(int argc, char *argv[])
{
  int ret;
  struct rlimit rl;
  char *brgv[20];
  int brgc=argc-1;
  int i;

  for(i=1; i< argc; i++)
    brgv[i-1]=argv[i];
  brgv[i-1]=NULL; /* terminate the list */

  if(getuid() != UID) {
    fprintf(stderr, "Only uid %d is allowed to run this\n", UID);
    return 1;
  }

  ret = getrlimit(RLIMIT_NOFILE, &rl);
  if(ret != 0) {
    fprintf(stderr, "Unable to read open file limit.\n"
            "(getrlimit(RLIMIT_NOFILE, &rl) failed)\n"
            "(%d, %s)", errno, strerror(errno));
    return 1;
  }

  fprintf(stderr, "Limit was %d (max %d), setting to %d\n",
          rl.rlim_cur, rl.rlim_max, NEW_MAX);

  rl.rlim_cur = rl.rlim_max = NEW_MAX;
  ret = setrlimit(RLIMIT_NOFILE, &rl);
  if(ret != 0) {
    fprintf(stderr, "Unable to set open file limit.\n"
            "(setrlimit(RLIMIT_NOFILE, &rl) failed)\n"
            "(%d, %s)", errno, strerror(errno));
    return 1;
  }

  ret = getrlimit(RLIMIT_NOFILE, &rl);
  if(ret != 0) {
    fprintf(stderr, "Unable to read new open file limit.\n"
            "(getrlimit(RLIMIT_NOFILE, &rl) failed)\n"
            "(%d, %s)", errno, strerror(errno));
    return 1;
  }
  if(rl.rlim_cur < NEW_MAX) {
    fprintf(stderr, "Failed to set new open file limit.\n"
            "Limit is %d, expected %d\n",
            rl.rlim_cur, NEW_MAX);
    return 1;
  }

  if(setgid(GID) != 0) {
    fprintf(stderr, "setgid failed (%d, %s)\n", errno, strerror(errno));
    return 1;
  }
  if(setuid(UID) != 0) {
    fprintf(stderr, "setuid failed (%d, %s)\n", errno, strerror(errno));
    return 1;
  }

  ret = execv(brgv[0], brgv);

  fprintf(stderr, "execl returned, failure\n"
          "returned %d, errno is %d (%s)\n",
          ret, errno, strerror(errno));
  return 1;
}
