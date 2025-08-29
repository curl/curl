#ifndef HEADER_CURL_SETUP_ONCE_H
#define HEADER_CURL_SETUP_ONCE_H
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

/*
 * Inclusion of common header files.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#ifndef UNDER_CE
#include <errno.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <sys/stat.h>

#if !defined(_WIN32) || defined(__MINGW32__)
#include <sys/time.h>
#endif

#ifdef HAVE_IO_H
#include <io.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if defined(HAVE_STDBOOL_H) && defined(HAVE_BOOL_T)
#include <stdbool.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

/* Macro to strip 'const' without triggering a compiler warning.
   Use it for APIs that do not or cannot support the const qualifier. */
#ifdef HAVE_STDINT_H
#  define CURL_UNCONST(p) ((void *)(uintptr_t)(const void *)(p))
#elif defined(_WIN32)  /* for VS2008 */
#  define CURL_UNCONST(p) ((void *)(ULONG_PTR)(const void *)(p))
#else
#  define CURL_UNCONST(p) ((void *)(p))  /* Fall back to simple cast */
#endif

#ifdef USE_SCHANNEL
/* Must set this before <schannel.h> is included directly or indirectly by
   another Windows header. */
#  define SCHANNEL_USE_BLACKLISTS 1
#endif

#ifdef __hpux
#  if !defined(_XOPEN_SOURCE_EXTENDED) || defined(_KERNEL)
#    ifdef _APP32_64BIT_OFF_T
#      define OLD_APP32_64BIT_OFF_T _APP32_64BIT_OFF_T
#      undef _APP32_64BIT_OFF_T
#    else
#      undef OLD_APP32_64BIT_OFF_T
#    endif
#  endif
#endif

#ifndef _WIN32
#include <sys/socket.h>
#endif

#include "functypes.h"

#ifdef __hpux
#  if !defined(_XOPEN_SOURCE_EXTENDED) || defined(_KERNEL)
#    ifdef OLD_APP32_64BIT_OFF_T
#      define _APP32_64BIT_OFF_T OLD_APP32_64BIT_OFF_T
#      undef OLD_APP32_64BIT_OFF_T
#    endif
#  endif
#endif

/*
 * Definition of timeval struct for platforms that do not have it.
 */

#ifndef HAVE_STRUCT_TIMEVAL
struct timeval {
  long tv_sec;
  long tv_usec;
};
#endif


/*
 * If we have the MSG_NOSIGNAL define, make sure we use
 * it as the fourth argument of function send()
 */

#ifdef HAVE_MSG_NOSIGNAL
#define SEND_4TH_ARG MSG_NOSIGNAL
#else
#define SEND_4TH_ARG 0
#endif


#ifdef __minix
/* Minix does not support recv on TCP sockets */
#define sread(x,y,z) (ssize_t)read((RECV_TYPE_ARG1)(x), \
                                   (RECV_TYPE_ARG2)(y), \
                                   (RECV_TYPE_ARG3)(z))

#elif defined(HAVE_RECV)
/*
 * The definitions for the return type and arguments types
 * of functions recv() and send() belong and come from the
 * configuration file. Do not define them in any other place.
 *
 * HAVE_RECV is defined if you have a function named recv()
 * which is used to read incoming data from sockets. If your
 * function has another name then do not define HAVE_RECV.
 *
 * If HAVE_RECV is defined then RECV_TYPE_ARG1, RECV_TYPE_ARG2,
 * RECV_TYPE_ARG3, RECV_TYPE_ARG4 and RECV_TYPE_RETV must also
 * be defined.
 *
 * HAVE_SEND is defined if you have a function named send()
 * which is used to write outgoing data on a connected socket.
 * If yours has another name then do not define HAVE_SEND.
 *
 * If HAVE_SEND is defined then SEND_TYPE_ARG1, SEND_QUAL_ARG2,
 * SEND_TYPE_ARG2, SEND_TYPE_ARG3, SEND_TYPE_ARG4 and
 * SEND_TYPE_RETV must also be defined.
 */

#define sread(x,y,z) (ssize_t)recv((RECV_TYPE_ARG1)(x), \
                                   (RECV_TYPE_ARG2)(y), \
                                   (RECV_TYPE_ARG3)(z), \
                                   (RECV_TYPE_ARG4)(0))
#else /* HAVE_RECV */
#ifndef sread
#error "Missing definition of macro sread!"
#endif
#endif /* HAVE_RECV */


#ifdef __minix
/* Minix does not support send on TCP sockets */
#define swrite(x,y,z) (ssize_t)write((SEND_TYPE_ARG1)(x), \
                                     (SEND_TYPE_ARG2)CURL_UNCONST(y), \
                                     (SEND_TYPE_ARG3)(z))
#elif defined(HAVE_SEND)
#define swrite(x,y,z) (ssize_t)send((SEND_TYPE_ARG1)(x), \
                              (SEND_QUAL_ARG2 SEND_TYPE_ARG2)CURL_UNCONST(y), \
                                    (SEND_TYPE_ARG3)(z), \
                                    (SEND_TYPE_ARG4)(SEND_4TH_ARG))
#else /* HAVE_SEND */
#ifndef swrite
#error "Missing definition of macro swrite!"
#endif
#endif /* HAVE_SEND */


/*
 * Function-like macro definition used to close a socket.
 */

#ifdef HAVE_CLOSESOCKET
#  define CURL_SCLOSE(x)  closesocket((x))
#elif defined(HAVE_CLOSESOCKET_CAMEL)
#  define CURL_SCLOSE(x)  CloseSocket((x))
#elif defined(MSDOS)  /* Watt-32 */
#  define CURL_SCLOSE(x)  close_s((x))
#elif defined(USE_LWIPSOCK)
#  define CURL_SCLOSE(x)  lwip_close((x))
#else
#  define CURL_SCLOSE(x)  close((x))
#endif

/*
 * Stack-independent version of fcntl() on sockets:
 */
#ifdef USE_LWIPSOCK
#  define sfcntl  lwip_fcntl
#else
#  define sfcntl  fcntl
#endif

/*
 * 'bool' stuff compatible with HP-UX headers.
 */

#if defined(__hpux) && !defined(HAVE_BOOL_T)
   typedef int bool;
#  define false 0
#  define true 1
#  define HAVE_BOOL_T
#endif


/*
 * 'bool' exists on platforms with <stdbool.h>, i.e. C99 platforms.
 * On non-C99 platforms there is no bool, so define an enum for that.
 * On C99 platforms 'false' and 'true' also exist. Enum uses a
 * global namespace though, so use bool_false and bool_true.
 */

#ifndef HAVE_BOOL_T
  typedef enum {
    bool_false = 0,
    bool_true  = 1
  } bool;

/*
 * Use a define to let 'true' and 'false' use those enums. There
 * are currently no use of true and false in libcurl proper, but
 * there are some in the examples. This will cater for any later
 * code happening to use true and false.
 */
#  define false bool_false
#  define true  bool_true
#  define HAVE_BOOL_T
#endif

/* the type we use for storing a single boolean bit */
#ifdef _MSC_VER
typedef bool bit;
#define BIT(x) bool x
#else
typedef unsigned int bit;
#define BIT(x) bit x:1
#endif

/*
 * Redefine TRUE and FALSE too, to catch current use. With this
 * change, 'bool found = 1' will give a warning on MIPSPro, but
 * 'bool found = TRUE' will not. Change tested on IRIX/MIPSPro,
 * AIX 5.1/Xlc, Tru64 5.1/cc, w/make test too.
 */

#ifndef TRUE
#define TRUE true
#endif
#ifndef FALSE
#define FALSE false
#endif

#include "curl_ctype.h"


/*
 * Macro used to include code only in debug builds.
 */

#ifdef DEBUGBUILD
#define DEBUGF(x) x
#else
#define DEBUGF(x) do { } while(0)
#endif


/*
 * Macro used to include assertion code only in debug builds.
 */

#undef DEBUGASSERT
#ifdef DEBUGBUILD
#define DEBUGASSERT(x) assert(x)
#else
#define DEBUGASSERT(x) do { } while(0)
#endif


/*
 * Macro SOCKERRNO / SET_SOCKERRNO() returns / sets the *socket-related* errno
 * (or equivalent) on this platform to hide platform details to code using it.
 */

#ifdef USE_WINSOCK
#define SOCKERRNO         ((int)WSAGetLastError())
#define SET_SOCKERRNO(x)  (WSASetLastError((int)(x)))
#else
#define SOCKERRNO         (errno)
#define SET_SOCKERRNO(x)  (errno = (x))
#endif


/*
 * Portable error number symbolic names defined to Winsock error codes.
 */

#ifdef USE_WINSOCK
#define SOCKEACCES        WSAEACCES
#define SOCKEADDRINUSE    WSAEADDRINUSE
#define SOCKEADDRNOTAVAIL WSAEADDRNOTAVAIL
#define SOCKEAFNOSUPPORT  WSAEAFNOSUPPORT
#define SOCKEBADF         WSAEBADF
#define SOCKECONNREFUSED  WSAECONNREFUSED
#define SOCKECONNRESET    WSAECONNRESET
#define SOCKEINPROGRESS   WSAEINPROGRESS
#define SOCKEINTR         WSAEINTR
#define SOCKEINVAL        WSAEINVAL
#define SOCKEISCONN       WSAEISCONN
#define SOCKEMSGSIZE      WSAEMSGSIZE
#define SOCKENOMEM        WSA_NOT_ENOUGH_MEMORY
#define SOCKETIMEDOUT     WSAETIMEDOUT
#define SOCKEWOULDBLOCK   WSAEWOULDBLOCK
#else
#define SOCKEACCES        EACCES
#define SOCKEADDRINUSE    EADDRINUSE
#define SOCKEADDRNOTAVAIL EADDRNOTAVAIL
#define SOCKEAFNOSUPPORT  EAFNOSUPPORT
#define SOCKEBADF         EBADF
#define SOCKECONNREFUSED  ECONNREFUSED
#define SOCKECONNRESET    ECONNRESET
#define SOCKEINPROGRESS   EINPROGRESS
#define SOCKEINTR         EINTR
#define SOCKEINVAL        EINVAL
#define SOCKEISCONN       EISCONN
#define SOCKEMSGSIZE      EMSGSIZE
#define SOCKENOMEM        ENOMEM
#ifdef ETIMEDOUT
#define SOCKETIMEDOUT     ETIMEDOUT
#endif
#define SOCKEWOULDBLOCK   EWOULDBLOCK
#endif

/*
 * Macro argv_item_t hides platform details to code using it.
 */

#ifdef __VMS
#define argv_item_t  __char_ptr32
#elif defined(_UNICODE) && !defined(UNDER_CE)
#define argv_item_t  wchar_t *
#else
#define argv_item_t  char *
#endif


/*
 * We use this ZERO_NULL to avoid picky compiler warnings,
 * when assigning a NULL pointer to a function pointer var.
 */

#define ZERO_NULL 0


#endif /* HEADER_CURL_SETUP_ONCE_H */
