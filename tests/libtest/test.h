#ifdef HAVE_CONFIG_H
/* Now include the setup.h file from libcurl's private libdir (the source
   version, but that might include "config.h" from the build dir so we need
   both of them in the include path), so that we get good in-depth knowledge
   about the system we're building this on */
#include "setup.h"
#endif

#include <curl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

extern char *arg2; /* set by first.c to the argv[2] or NULL */
int test(char *URL); /* the actual test function provided by each individual
                        libXXX.c file */
