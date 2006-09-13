/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "util.h"

#if defined(ENABLE_IPV6) && defined(__MINGW32__)
const struct in6_addr in6addr_any = {{ IN6ADDR_ANY_INIT }};
#endif

/*
 * ourerrno() returns the errno (or equivalent) on this platform to
 * hide platform specific for the function that calls this.
 */
int ourerrno(void)
{
#if defined(WIN32) && !defined(__CYGWIN__)
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
  time_t sec = tv.tv_sec;
  struct tm *now =
    localtime(&sec); /* not multithread safe but we don't care */

  char timebuf[20];
  snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
           now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);

  va_start(ap, msg);
  vsprintf(buffer, msg, ap);
  va_end(ap);

  logfp = fopen(serverlogfile, "a");
  if(logfp) {
    fprintf(logfp, "%s %s\n", timebuf, buffer);
    fclose(logfp);
  }
}

#if defined(REAL_WIN32)
/* use instead of perror() on generic windows */
void win32_perror (const char *msg)
{
  char buf[256];
  DWORD err = WSAGetLastError();

  if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                     LANG_NEUTRAL, buf, sizeof(buf), NULL))
     snprintf(buf, sizeof(buf), "Unknown error %lu (%#lx)", err, err);
  if (msg)
     fprintf(stderr, "%s: ", msg);
  fprintf(stderr, "%s\n", buf);
}

void win32_init(void)
{
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;
  wVersionRequested = MAKEWORD(2, 0);

  err = WSAStartup(wVersionRequested, &wsaData);

  if (err != 0) {
    perror("Winsock init failed");
    logmsg("Error initialising winsock -- aborting\n");
    exit(1);
  }

  if ( LOBYTE( wsaData.wVersion ) != 2 ||
       HIBYTE( wsaData.wVersion ) != 0 ) {

    WSACleanup();
    perror("Winsock init failed");
    logmsg("No suitable winsock.dll found -- aborting\n");
    exit(1);
  }
}

void win32_cleanup(void)
{
  WSACleanup();
}
#endif  /* REAL_WIN32 */

/* set by the main code to point to where the test dir is */
const char *path=".";

char *test2file(long testno)
{
  static char filename[256];
  snprintf(filename, sizeof(filename), TEST_DATA_PATH, path, testno);
  return filename;
}
