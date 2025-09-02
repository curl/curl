/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#ifdef HAVE_FCNTL_O_NONBLOCK
/* headers for FCNTL_O_NONBLOCK test */
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
/* */
#if defined(sun) || defined(__sun__) || \
    defined(__SUNPRO_C) || defined(__SUNPRO_CC)
#  if defined(__SVR4) || defined(__srv4__)
#    define PLATFORM_SOLARIS
#  else
#    define PLATFORM_SUNOS4
#  endif
#endif
#if (defined(_AIX) || defined(__xlC__)) && !defined(_AIX41)
#  define PLATFORM_AIX_V3
#endif
/* */
#if defined(PLATFORM_SUNOS4) || defined(PLATFORM_AIX_V3)
#error "O_NONBLOCK does not work on this platform"
#endif

int main(void)
{
  /* O_NONBLOCK source test */
  int flags = 0;
  if(0 != fcntl(0, F_SETFL, flags | O_NONBLOCK))
    return 1;
  return 0;
}
#endif

/* tests for gethostbyname_r */
#if defined(HAVE_GETHOSTBYNAME_R_3) || \
    defined(HAVE_GETHOSTBYNAME_R_3_REENTRANT) || \
    defined(HAVE_GETHOSTBYNAME_R_5) || \
    defined(HAVE_GETHOSTBYNAME_R_5_REENTRANT) || \
    defined(HAVE_GETHOSTBYNAME_R_6) || \
    defined(HAVE_GETHOSTBYNAME_R_6_REENTRANT)
#include <sys/types.h>
#include <netdb.h>
int main(void)
{
  const char *address = "example.com";
  struct hostent h;
  int rc = 0;
#if   defined(HAVE_GETHOSTBYNAME_R_3) || \
      defined(HAVE_GETHOSTBYNAME_R_3_REENTRANT)
  struct hostent_data hdata;
#elif defined(HAVE_GETHOSTBYNAME_R_5) || \
      defined(HAVE_GETHOSTBYNAME_R_5_REENTRANT) || \
      defined(HAVE_GETHOSTBYNAME_R_6) || \
      defined(HAVE_GETHOSTBYNAME_R_6_REENTRANT)
  char buffer[8192];
  struct hostent *hp;
  int h_errnop;
#endif

#if   defined(HAVE_GETHOSTBYNAME_R_3) || \
      defined(HAVE_GETHOSTBYNAME_R_3_REENTRANT)
  rc = gethostbyname_r(address, &h, &hdata);
  (void)hdata;
#elif defined(HAVE_GETHOSTBYNAME_R_5) || \
      defined(HAVE_GETHOSTBYNAME_R_5_REENTRANT)
  rc = gethostbyname_r(address, &h, buffer, 8192, &h_errnop);
  (void)hp;
  (void)h_errnop;
#elif defined(HAVE_GETHOSTBYNAME_R_6) || \
      defined(HAVE_GETHOSTBYNAME_R_6_REENTRANT)
  rc = gethostbyname_r(address, &h, buffer, 8192, &hp, &h_errnop);
  (void)hp;
  (void)h_errnop;
#endif
  (void)h;
  (void)rc;
  return 0;
}
#endif

#ifdef HAVE_BOOL_T
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
int main(void)
{
  return (int)sizeof(bool *);
}
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <float.h>
int main(void) { return 0; }
#endif

#ifdef HAVE_FILE_OFFSET_BITS
#include <sys/types.h>
/* Check that off_t can represent 2**63 - 1 correctly.
   We cannot simply define LARGE_OFF_T to be 9223372036854775807,
   since some C++ compilers masquerading as C compilers
   incorrectly reject 9223372036854775807. */
#define LARGE_OFF_T (((off_t) 1 << 62) - 1 + ((off_t) 1 << 62))
static int off_t_is_large[(LARGE_OFF_T % 2147483629 == 721 &&
                           LARGE_OFF_T % 2147483647 == 1)
                          ? 1 : -1];
int main(void)
{
  (void)off_t_is_large;
  return 0;
}
#endif

#ifdef HAVE_IOCTLSOCKET
#ifdef _WIN32
#  include <winsock2.h>
#endif
int main(void)
{
  /* ioctlsocket source code */
  int socket = -1;
  unsigned long flags = ioctlsocket(socket, FIONBIO, &flags);
  (void)flags;
  return 0;
}

#endif

#ifdef HAVE_IOCTLSOCKET_CAMEL
#include <proto/bsdsocket.h>
int main(void)
{
  /* IoctlSocket source code */
  if(0 != IoctlSocket(0, 0, 0))
    return 1;
  return 0;
}
#endif

#ifdef HAVE_IOCTLSOCKET_CAMEL_FIONBIO
#include <proto/bsdsocket.h>
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
int main(void)
{
  /* IoctlSocket source code */
  long flags = 0;
  if(0 != IoctlSocket(0, FIONBIO, &flags))
    return 1;
  (void)flags;
  return 0;
}
#endif

#ifdef HAVE_IOCTLSOCKET_FIONBIO
#ifdef _WIN32
#  include <winsock2.h>
#endif
int main(void)
{
  unsigned long flags = 0;
  if(0 != ioctlsocket(0, FIONBIO, &flags))
    return 1;
  (void)flags;
  return 0;
}
#endif

#ifdef HAVE_IOCTL_FIONBIO
/* headers for FIONBIO test */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifndef _WIN32
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef HAVE_STROPTS_H
#  include <stropts.h>
#endif
int main(void)
{
  int flags = 0;
  if(0 != ioctl(0, FIONBIO, &flags))
    return 1;
  (void)flags;
  return 0;
}
#endif

#ifdef HAVE_IOCTL_SIOCGIFADDR
/* headers for FIONBIO test */
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifndef _WIN32
#  include <sys/socket.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
#ifdef HAVE_STROPTS_H
#  include <stropts.h>
#endif
#include <net/if.h>
int main(void)
{
  struct ifreq ifr;
  if(0 != ioctl(0, SIOCGIFADDR, &ifr))
    return 1;
  (void)ifr;
  return 0;
}
#endif

#ifdef HAVE_SETSOCKOPT_SO_NONBLOCK
#ifdef _WIN32
#  include <winsock2.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifndef _WIN32
#  include <sys/socket.h>
#endif
int main(void)
{
  if(0 != setsockopt(0, SOL_SOCKET, SO_NONBLOCK, 0, 0))
    return 1;
  return 0;
}
#endif

#ifdef HAVE_GLIBC_STRERROR_R
#include <string.h>
#include <errno.h>

static void check(char c) { (void)c; }

int main(void)
{
  char buffer[1024];
  /* This will not compile if strerror_r does not return a char* */
  /* !checksrc! disable ERRNOVAR 1 */
  check(strerror_r(EACCES, buffer, sizeof(buffer))[0]);
  return 0;
}
#endif

#ifdef HAVE_POSIX_STRERROR_R
#include <string.h>
#include <errno.h>

/* Float, because a pointer cannot be implicitly cast to float */
static void check(float f) { (void)f; }

int main(void)
{
  char buffer[1024];
  /* This will not compile if strerror_r does not return an int */
  /* !checksrc! disable ERRNOVAR 1 */
  check(strerror_r(EACCES, buffer, sizeof(buffer)));
  return 0;
}
#endif

#ifdef HAVE_FSETXATTR_6
#include <sys/xattr.h> /* header from libc, not from libattr */
int main(void)
{
  fsetxattr(0, 0, 0, 0, 0, 0);
  return 0;
}
#endif

#ifdef HAVE_FSETXATTR_5
#include <sys/xattr.h> /* header from libc, not from libattr */
int main(void)
{
  fsetxattr(0, "", 0, 0, 0);
  return 0;
}
#endif

#ifdef HAVE_CLOCK_GETTIME_MONOTONIC
#include <time.h>
int main(void)
{
  struct timespec ts;
  (void)clock_gettime(CLOCK_MONOTONIC, &ts);
  (void)ts;
  return 0;
}
#endif

#ifdef HAVE_BUILTIN_AVAILABLE
int main(void)
{
  if(__builtin_available(macOS 10.12, iOS 5.0, *)) {}
  return 0;
}
#endif

#ifdef HAVE_ATOMIC
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif
#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#endif
int main(void)
{
  _Atomic int i = 1;
  i = 0;  /* Force an atomic-write operation. */
  return i;
}
#endif

#ifdef HAVE_WIN32_WINNT
#ifdef _WIN32
#  ifndef NOGDI
#  define NOGDI
#  endif
#  include <windows.h>
#endif

#define enquote(x) #x
#define expand(x) enquote(x)
#pragma message("_WIN32_WINNT=" expand(_WIN32_WINNT))

int main(void)
{
  return 0;
}
#endif

#ifdef MINGW64_VERSION
#ifdef __MINGW32__
#  include <_mingw.h>
#endif

#define enquote(x) #x
#define expand(x) enquote(x)
#pragma message("MINGW64_VERSION=" \
  expand(__MINGW64_VERSION_MAJOR) "." \
  expand(__MINGW64_VERSION_MINOR))

int main(void)
{
  return 0;
}
#endif
