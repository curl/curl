/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#define CURL_NO_OLDIES

#include "setup.h" /* portability help from the lib directory */

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
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
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#elif defined(HAVE_POLL_H)
#include <poll.h>
#endif

#define ENABLE_CURLX_PRINTF
/* make the curlx header define all printf() functions to use the curlx_*
   versions instead */
#include "curlx.h" /* from the private lib dir */
#include "getpart.h"
#include "util.h"
#include "timeval.h"

#if defined(ENABLE_IPV6) && defined(__MINGW32__)
const struct in6_addr in6addr_any = {{ IN6ADDR_ANY_INIT }};
#endif

void logmsg(const char *msg, ...)
{
  va_list ap;
  char buffer[2048 + 1];
  FILE *logfp;
  int error;
  struct timeval tv;
  time_t sec;
  struct tm *now;
  char timebuf[20];
  static time_t epoch_offset;
  static int    known_offset;

  if (!serverlogfile) {
    fprintf(stderr, "Error: serverlogfile not set\n");
    return;
  }

  tv = curlx_tvnow();
  if(!known_offset) {
    epoch_offset = time(NULL) - tv.tv_sec;
    known_offset = 1;
  }
  sec = epoch_offset + tv.tv_sec;
  now = localtime(&sec); /* not thread safe but we don't care */

  snprintf(timebuf, sizeof(timebuf), "%02d:%02d:%02d.%06ld",
    (int)now->tm_hour, (int)now->tm_min, (int)now->tm_sec, (long)tv.tv_usec);

  va_start(ap, msg);
  vsnprintf(buffer, sizeof(buffer), msg, ap);
  va_end(ap);

  logfp = fopen(serverlogfile, "ab");
  if(logfp) {
    fprintf(logfp, "%s %s\n", timebuf, buffer);
    fclose(logfp);
  }
  else {
    error = ERRNO;
    fprintf(stderr, "fopen() failed with error: %d %s\n",
            error, strerror(error));
    fprintf(stderr, "Error opening file: %s\n", serverlogfile);
    fprintf(stderr, "Msg not logged: %s %s\n", timebuf, buffer);
  }
}

#ifdef WIN32
/* use instead of perror() on generic windows */
void win32_perror (const char *msg)
{
  char buf[512];
  DWORD err = SOCKERRNO;

  if (!FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                     LANG_NEUTRAL, buf, sizeof(buf), NULL))
     snprintf(buf, sizeof(buf), "Unknown error %lu (%#lx)", err, err);
  if (msg)
     fprintf(stderr, "%s: ", msg);
  fprintf(stderr, "%s\n", buf);
}
#endif  /* WIN32 */

#ifdef USE_WINSOCK
void win32_init(void)
{
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;
  wVersionRequested = MAKEWORD(USE_WINSOCK, USE_WINSOCK);

  err = WSAStartup(wVersionRequested, &wsaData);

  if (err != 0) {
    perror("Winsock init failed");
    logmsg("Error initialising winsock -- aborting");
    exit(1);
  }

  if ( LOBYTE( wsaData.wVersion ) != USE_WINSOCK ||
       HIBYTE( wsaData.wVersion ) != USE_WINSOCK ) {

    WSACleanup();
    perror("Winsock init failed");
    logmsg("No suitable winsock.dll found -- aborting");
    exit(1);
  }
}

void win32_cleanup(void)
{
  WSACleanup();
}
#endif  /* USE_WINSOCK */

/* set by the main code to point to where the test dir is */
const char *path=".";

char *test2file(long testno)
{
  static char filename[256];
  snprintf(filename, sizeof(filename), TEST_DATA_PATH, path, testno);
  return filename;
}

/*
 * Portable function used for waiting a specific amount of ms.
 * Waiting indefinitely with this function is not allowed, a
 * zero or negative timeout value will return immediately.
 *
 * Return values:
 *   -1 = system call error, or invalid timeout value
 *    0 = specified timeout has elapsed
 */
int wait_ms(int timeout_ms)
{
#if !defined(MSDOS) && !defined(USE_WINSOCK)
#ifndef HAVE_POLL_FINE
  struct timeval pending_tv;
#endif
  struct timeval initial_tv;
  int pending_ms;
  int error;
#endif
  int r = 0;

  if(!timeout_ms)
    return 0;
  if(timeout_ms < 0) {
    SET_SOCKERRNO(EINVAL);
    return -1;
  }
#if defined(MSDOS)
  delay(timeout_ms);
#elif defined(USE_WINSOCK)
  Sleep(timeout_ms);
#else
  pending_ms = timeout_ms;
  initial_tv = curlx_tvnow();
  do {
#if defined(HAVE_POLL_FINE)
    r = poll(NULL, 0, pending_ms);
#else
    pending_tv.tv_sec = pending_ms / 1000;
    pending_tv.tv_usec = (pending_ms % 1000) * 1000;
    r = select(0, NULL, NULL, NULL, &pending_tv);
#endif /* HAVE_POLL_FINE */
    if(r != -1)
      break;
    error = SOCKERRNO;
    if(error && (error != EINTR))
      break;
    pending_ms = timeout_ms - (int)curlx_tvdiff(curlx_tvnow(), initial_tv);
    if(pending_ms <= 0)
      break;
  } while(r == -1);
#endif /* USE_WINSOCK */
  if(r)
    r = -1;
  return r;
}

int write_pidfile(const char *filename)
{
  FILE *pidfile;
  long pid;

  pid = (long)getpid();
  pidfile = fopen(filename, "wb");
  if(!pidfile) {
    logmsg("Couldn't write pid file: %s %s", filename, strerror(ERRNO));
    return 0; /* fail */
  }
  fprintf(pidfile, "%ld\n", pid);
  fclose(pidfile);
  logmsg("Wrote pid %ld to %s", pid, filename);
  return 1; /* success */
}

void set_advisor_read_lock(const char *filename)
{
  FILE *lockfile;
  int error = 0;
  int res;

  do {
    lockfile = fopen(filename, "wb");
  } while((lockfile == NULL) && ((error = ERRNO) == EINTR));
  if(lockfile == NULL) {
    logmsg("Error creating lock file %s error: %d %s",
           filename, error, strerror(error));
    return;
  }

  do {
    res = fclose(lockfile);
  } while(res && ((error = ERRNO) == EINTR));
  if(res)
    logmsg("Error closing lock file %s error: %d %s",
           filename, error, strerror(error));
}

void clear_advisor_read_lock(const char *filename)
{
  int error = 0;
  int res;

  /*
  ** Log all removal failures. Even those due to file not existing.
  ** This allows to detect if unexpectedly the file has already been
  ** removed by a process different than the one that should do this.
  */

  do {
    res = unlink(filename);
  } while(res && ((error = ERRNO) == EINTR));
  if(res)
    logmsg("Error removing lock file %s error: %d %s",
           filename, error, strerror(error));
}
