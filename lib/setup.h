#ifndef __SETUP_H
#define __SETUP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HTTP_ONLY
#define CURL_DISABLE_FTP
#define CURL_DISABLE_LDAP
#define CURL_DISABLE_TELNET
#define CURL_DISABLE_DICT
#define CURL_DISABLE_FILE
#define CURL_DISABLE_GOPHER
#endif

#if !defined(WIN32) && defined(__WIN32__)
/* This should be a good Borland fix. Alexander J. Oss told us! */
#define WIN32
#endif

#ifdef HAVE_CONFIG_H
#include "config.h" /* the configure script results */
#else
#ifdef _WIN32_WCE
#include "config-win32ce.h"
#else
#ifdef WIN32
/* hand-modified win32 config.h! */
#include "config-win32.h"
#endif
#endif
#endif

#ifdef macintosh
/* hand-modified MacOS config.h! */
#include "config-mac.h"
#endif
#ifdef AMIGA
/* hand-modified AmigaOS config.h! */
#include "amigaos.h"
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#if !defined(__cplusplus) && !defined(__BEOS__) && !defined(typedef_bool)
typedef unsigned char bool;
#define typedef_bool
#endif

#ifdef HAVE_LONGLONG
#define LONG_LONG long long
#define ENABLE_64BIT
#else
#ifdef _MSC_VER
#define LONG_LONG __int64
#define ENABLE_64BIT
#endif
#endif /* HAVE_LONGLONG */

#ifndef SIZEOF_CURL_OFF_T
/* If we don't know the size here, we assume a conservative size: 4. When
   building libcurl, the actual size of this variable should be define in the
   config*.h file. */
#define SIZEOF_CURL_OFF_T 4
#endif

/* We set up our internal prefered (CURL_)FORMAT_OFF_T here */
#if SIZEOF_CURL_OFF_T > 4
#define FORMAT_OFF_T "lld"
#else
#define FORMAT_OFF_T "ld"
#endif

/*#ifdef NEED_REENTRANT*/
/* Solaris needs _REENTRANT set for a few function prototypes and things to
   appear in the #include files. We need to #define it before all #include
   files. Unixware needs it to build proper reentrant code. Others may also
   need it. */
#define _REENTRANT
/*#endif */

#include <stdio.h>
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#include <errno.h>

#ifdef __TANDEM /* for nsr-tandem-nsk systems */
#include <floss.h>
#endif

#ifndef STDC_HEADERS /* no standard C headers! */
#include <curl/stdcheaders.h>
#endif

#if defined(CURLDEBUG) && defined(HAVE_ASSERT_H)
#define curlassert(x) assert(x)
#else
/* does nothing without CURLDEBUG defined */
#define curlassert(x)
#endif

#ifdef MSG_NOSIGNAL
/* If we have the MSG_NOSIGNAL define, we make sure to use that in the forth
   argument to send() and recv() */
#define SEND_4TH_ARG MSG_NOSIGNAL
#define HAVE_MSG_NOSIGNAL 1 /* we have MSG_NOSIGNAL */
#else
#define SEND_4TH_ARG 0
#endif

/* To make large file support transparent even on Windows */
#if defined(WIN32) && (SIZEOF_CURL_OFF_T > 4)
#include <sys/stat.h>   /* must come first before we redefine stat() */
#include <io.h>
#define lseek(x,y,z) _lseeki64(x, y, z)
#define struct_stat struct _stati64
#define stat(file,st) _stati64(file,st)
#define fstat(fd,st) _fstati64(fd,st)
#else
#define struct_stat struct stat
#endif

/* Below we define four functions. They should
   1. close a socket
   2. read from a socket
   3. write to a socket

   4. set the SIGALRM signal timeout
   5. set dir/file naming defines
   */

#ifdef WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN  /* Prevent including <winsock*.h> in <windows.h> */
#endif

#if (defined(ENABLE_IPV6) || defined(CURLDEBUG)) && defined(_MSC_VER) && \
    (!defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0500)
/*
 * Needed to pull in the real getaddrinfo() and not the inline version
 * in <wspiAPI.H> which doesn't support IPv6 (IPv4 only). <wspiAPI.H> is
 * included from <ws2tcpip.h> for <= 0x0500 SDKs.
 */
#undef  _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#if HAVE_WINSOCK2_H
#include <winsock2.h>        /* required by telnet.c */
#endif

#if defined(ENABLE_IPV6) || defined(USE_SSLEAY)
#include <ws2tcpip.h>
#endif

#if !defined(__GNUC__) || defined(__MINGW32__)
#define sclose(x) closesocket(x)
#define sread(x,y,z) recv(x,y,z, SEND_4TH_ARG)
#define swrite(x,y,z) (size_t)send(x,y,z, SEND_4TH_ARG)
#undef HAVE_ALARM
#else
     /* gcc-for-win is still good :) */
#define sclose(x) close(x)
#define sread(x,y,z) recv(x,y,z, SEND_4TH_ARG)
#define swrite(x,y,z) send(x,y,z, SEND_4TH_ARG)
#define HAVE_ALARM
#endif

#define DIR_CHAR      "\\"
#define DOT_CHAR      "_"

#else

#ifdef DJGPP
#define sclose(x)         close_s(x)
#define sread(x,y,z)      read_s(x,y,z)
#define swrite(x,y,z)     write_s(x,y,z)
#define select(n,r,w,x,t) select_s(n,r,w,x,t)
#define IOCTL_3_ARGS
#include <tcp.h>
#ifdef word
#undef word
#endif

#else

#ifdef __BEOS__
#define sclose(x) closesocket(x)
#define sread(x,y,z) (ssize_t)recv(x,y,z, SEND_4TH_ARG)
#define swrite(x,y,z) (ssize_t)send(x,y,z, SEND_4TH_ARG)
#else
#define sclose(x) close(x)
#define sread(x,y,z) recv(x,y,z, SEND_4TH_ARG)
#define swrite(x,y,z) send(x,y,z, SEND_4TH_ARG)
#endif

#define HAVE_ALARM

#endif

#ifdef _AMIGASF
#undef HAVE_ALARM
#undef sclose
#define sclose(x) CloseSocket(x)
#endif

#define DIR_CHAR      "/"
#define DOT_CHAR      "."

#ifdef DJGPP
#undef DOT_CHAR
#define DOT_CHAR      "_"
#endif

#ifndef fileno /* sunos 4 have this as a macro! */
int fileno( FILE *stream);
#endif

#endif

/* now typedef our socket type */
#ifdef WIN32
typedef SOCKET curl_socket_t;
#define CURL_SOCKET_BAD INVALID_SOCKET
#else
typedef int curl_socket_t;
#define CURL_SOCKET_BAD -1
#endif

#if defined(ENABLE_IPV6) && defined(USE_ARES)
#error "ares does not yet support IPv6. Disable IPv6 or ares and rebuild"
#endif

#if defined(WIN32) && !defined(__CYGWIN__) && !defined(USE_ARES) && \
    !defined(__LCC__)  /* lcc-win32 doesn't have _beginthreadex() */
#ifdef ENABLE_IPV6
#define USE_THREADING_GETADDRINFO
#else
#define USE_THREADING_GETHOSTBYNAME  /* Cygwin uses alarm() function */
#endif
#endif

#ifdef mpeix
#define IOCTL_3_ARGS
#endif

#ifdef NETWARE
#undef HAVE_ALARM
#endif

#if defined(HAVE_LIBIDN) && defined(HAVE_TLD_H)
/* The lib was present and the tld.h header (which is missing in libidn 0.3.X
   but we only work with libidn 0.4.1 or later) */
#define USE_LIBIDN
#endif

#ifndef SIZEOF_TIME_T
/* assume default size of time_t to be 32 bit */
#define SIZEOF_TIME_T 4
#endif

#define LIBIDN_REQUIRED_VERSION "0.4.1"

#endif /* __CONFIG_H */
