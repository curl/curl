#ifdef HAVE_CONFIG_H
/* Now include the config.h file from libcurl's private libdir, so that we
   get good in-depth knowledge about the system we're building this on */
#include "config.h"
#endif

#include <curl.h>
#include <stdio.h>
#include <string.h>

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

extern char *arg2; /* set by first.c to the argv[2] or NULL */

