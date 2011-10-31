#ifndef HEADER_CURL_SRC_SETUP_H
#define HEADER_CURL_SRC_SETUP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/*
 * Define WIN32 when build target is Win32 API
 */

#if (defined(_WIN32) || defined(__WIN32__)) && !defined(WIN32) && \
  !defined(__SYMBIAN32__)
#define WIN32
#endif

/*
 * Include configuration script results or hand-crafted
 * configuration file for platforms which lack config tool.
 */

#ifdef HAVE_CONFIG_H
#include "curl_config.h"
#else

#ifdef WIN32
#include "config-win32.h"
#endif

#if defined(macintosh) && defined(__MRC__)
#  include "config-mac.h"
#endif

#ifdef __riscos__
#include "config-riscos.h"
#endif

#ifdef __AMIGA__
#include "config-amigaos.h"
#endif

#ifdef __SYMBIAN32__
#include "config-symbian.h"
#endif

#ifdef TPF
#include "config-tpf.h"
#endif

#endif /* HAVE_CONFIG_H */

/*
 * AIX 4.3 and newer needs _THREAD_SAFE defined to build
 * proper reentrant code. Others may also need it.
 */

#ifdef NEED_THREAD_SAFE
#  ifndef _THREAD_SAFE
#    define _THREAD_SAFE
#  endif
#endif

/*
 * Tru64 needs _REENTRANT set for a few function prototypes and
 * things to appear in the system header files. Unixware needs it
 * to build proper reentrant code. Others may also need it.
 */

#ifdef NEED_REENTRANT
#  ifndef _REENTRANT
#    define _REENTRANT
#  endif
#endif

/*
 * Include header files for windows builds before redefining anything.
 * Use this preproessor block only to include or exclude windows.h,
 * winsock2.h, ws2tcpip.h or winsock.h. Any other windows thing belongs
 * to any other further and independent block.  Under Cygwin things work
 * just as under linux (e.g. <sys/socket.h>) and the winsock headers should
 * never be included when __CYGWIN__ is defined.  configure script takes
 * care of this, not defining HAVE_WINDOWS_H, HAVE_WINSOCK_H, HAVE_WINSOCK2_H,
 * neither HAVE_WS2TCPIP_H when __CYGWIN__ is defined.
 */

#ifdef HAVE_WINDOWS_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  ifdef HAVE_WINSOCK2_H
#    include <winsock2.h>
#    ifdef HAVE_WS2TCPIP_H
#       include <ws2tcpip.h>
#    endif
#  else
#    ifdef HAVE_WINSOCK_H
#      include <winsock.h>
#    endif
#  endif
#endif

/*
 * Define USE_WINSOCK to 2 if we have and use WINSOCK2 API, else
 * define USE_WINSOCK to 1 if we have and use WINSOCK  API, else
 * undefine USE_WINSOCK.
 */

#undef USE_WINSOCK

#ifdef HAVE_WINSOCK2_H
#  define USE_WINSOCK 2
#else
#  ifdef HAVE_WINSOCK_H
#    define USE_WINSOCK 1
#  endif
#endif

#ifdef USE_LWIPSOCK
#  include <lwip/sockets.h>
#  include <lwip/netdb.h>
#endif

#ifdef TPF
#  include <sys/socket.h>
   /* change which select is used for the curl command line tool */
#  define select(a,b,c,d,e) tpf_select_bsd(a,b,c,d,e)
   /* and turn off the progress meter */
#  define CONF_DEFAULT (0|CONF_NOPROGRESS)
#endif

#include <stdio.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif


#ifdef __TANDEM
#include <floss.h>
#endif

/*
 * Large file (>2Gb) support using WIN32 functions.
 */

#ifdef USE_WIN32_LARGE_FILES
#  include <io.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  undef  lseek
#  define lseek(fdes,offset,whence)  _lseeki64(fdes, offset, whence)
#  define fstat(fdes,stp)            _fstati64(fdes, stp)
#  define stat(fname,stp)            _stati64(fname, stp)
#  define struct_stat                struct _stati64
#  define LSEEK_ERROR                (__int64)-1
#endif

/*
 * Small file (<2Gb) support using WIN32 functions.
 */

#ifdef USE_WIN32_SMALL_FILES
#  include <io.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  undef  lseek
#  define lseek(fdes,offset,whence)  _lseek(fdes, (long)offset, whence)
#  define fstat(fdes,stp)            _fstat(fdes, stp)
#  define stat(fname,stp)            _stat(fname, stp)
#  define struct_stat                struct _stat
#  define LSEEK_ERROR                (long)-1
#endif

#ifndef struct_stat
#  define struct_stat struct stat
#endif

#ifndef LSEEK_ERROR
#  define LSEEK_ERROR (off_t)-1
#endif

#ifndef OS
#define OS "unknown"
#endif

#if !defined(fileno) && !defined(WIN32) /* sunos 4 have this as a macro! */
int fileno( FILE *stream);
#endif

#ifdef WIN32
#define DIR_CHAR      "\\"
#define DOT_CHAR      "_"
#else
#ifdef __EMX__
/* 20000318 mgs
 * OS/2 supports leading dots in filenames if the volume is formatted
 * with JFS or HPFS. */
#define DIR_CHAR      "\\"
#define DOT_CHAR      "."
#else

#ifdef DJGPP
#include <tcp.h>
#ifdef word
#undef word
#endif
#define DIR_CHAR      "/"
#define DOT_CHAR      "_"
#else

#define DIR_CHAR      "/"
#define DOT_CHAR      "."

#endif /* !DJGPP */
#endif /* !__EMX__ */
#endif /* !WIN32 */

#ifdef __riscos__
#define USE_ENVIRONMENT
#endif

#ifdef __BEOS__
#define typedef_bool
#endif

#if (defined(NETWARE) && !defined(__NOVELL_LIBC__))
#include <sys/timeval.h>
#endif

#ifndef UNPRINTABLE_CHAR
/* define what to use for unprintable characters */
#define UNPRINTABLE_CHAR '.'
#endif

#ifndef HAVE_STRDUP
#include "strdup.h"
#define strdup(ptr) curlx_strdup(ptr)
#endif

/* Define S_ISREG if not defined by system headers, f.e. MSVC */
#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

/*
 * Include macros and defines that should only be processed once.
 */

#ifndef __SETUP_ONCE_H
#include "setup_once.h"
#endif

/*
 * Definition of our NOP statement Object-like macro
 */

#ifndef Curl_nop_stmt
#  define Curl_nop_stmt do { } WHILE_FALSE
#endif

/*
 * Ensure that Winsock and lwIP TCP/IP stacks are not mixed.
 */

#if defined(__LWIP_OPT_H__)
#  if defined(SOCKET) || \
     defined(USE_WINSOCK) || \
     defined(HAVE_ERRNO_H) || \
     defined(HAVE_WINSOCK_H) || \
     defined(HAVE_WINSOCK2_H) || \
     defined(HAVE_WS2TCPIP_H)
#    error "Winsock and lwIP TCP/IP stack definitions shall not coexist!"
#  endif
#endif

#endif /* HEADER_CURL_SRC_SETUP_H */

