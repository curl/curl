/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

/* Now include the setup.h file from libcurl's private libdir (the source
   version, but that might include "curl_config.h" from the build dir so we
   need both of them in the include path), so that we get good in-depth
   knowledge about the system we're building this on */

#define CURL_NO_OLDIES

#include "setup.h"

#include <curl/curl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_SELECT_H
/* since so many tests use select(), we can just as well include it here */
#include <sys/select.h>
#endif
#ifdef HAVE_UNISTD_H
/* at least somewhat oldish FreeBSD systems need this for select() */
#include <unistd.h>
#endif

#ifdef TPF
#  include "select.h"
#endif

#define TEST_ERR_MAJOR_BAD     100
#define TEST_ERR_RUNS_FOREVER   99

#define test_setopt(A,B,C) \
  if((res = curl_easy_setopt((A),(B),(C))) != CURLE_OK) goto test_cleanup

extern char *libtest_arg2; /* set by first.c to the argv[2] or NULL */
extern char *libtest_arg3; /* set by first.c to the argv[3] or NULL */

/* argc and argv as passed in to the main() function */
extern int test_argc;
extern char **test_argv;

extern int select_test(int num_fds, fd_set *rd, fd_set *wr, fd_set *exc,
                       struct timeval *tv);

extern int test(char *URL); /* the actual test function provided by each
                               individual libXXX.c file */

