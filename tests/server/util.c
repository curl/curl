/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/
#include "setup.h" /* portability help from the lib directory */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _XOPEN_SOURCE_EXTENDED
/* This define is "almost" required to build on HPUX 11 */
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "util.h"

/*
 * ourerrno() returns the errno (or equivalent) on this platform to
 * hide platform specific for the function that calls this.
 */
int ourerrno(void)
{
#ifdef WIN32
  return (int)GetLastError();
#else
  return errno;
#endif
}

/* someone else must set this properly */
extern const char *serverlogfile;

void logmsg(const char *msg, ...)
{
  va_list ap;
  char buffer[256]; /* possible overflow if you pass in a huge string */
  FILE *logfp;

  struct timeval tv = curlx_tvnow();
  struct tm *now =
    localtime(&tv.tv_sec); /* not multithread safe but we don't care */

  char timebuf[12];
  snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%02ld",
           now->tm_hour, now->tm_min, now->tm_sec,
           tv.tv_usec/10000);

  va_start(ap, msg);
  vsprintf(buffer, msg, ap);
  va_end(ap);

  logfp = fopen(serverlogfile, "a");
  fprintf(logfp?logfp:stderr, /* write to stderr if the logfile doesn't open */
          "%s %s\n", timebuf, buffer);
  if(logfp)
    fclose(logfp);
}
