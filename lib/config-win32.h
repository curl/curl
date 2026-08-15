#ifndef HEADER_CURL_CONFIG_WIN32_H
#define HEADER_CURL_CONFIG_WIN32_H
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

/* ======================================================================== */
/* Handcrafted config file for building via Visual Studio IDE Project Files */
/* ======================================================================== */

#if !defined(_MSC_VER) || _MSC_VER > 1800
#error This manual configuration requires MSVC 2010-2013 (IDE Project builds)
#endif

/* ---------------------------------------------------------------- */
/*                          HEADER FILES                            */
/* ---------------------------------------------------------------- */

#define HAVE_FCNTL_H 1
#define HAVE_IO_H 1
#define HAVE_LOCALE_H 1
#if _MSC_VER >= 1800
#define HAVE_STDBOOL_H 1
#endif
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_UTIME_H 1

/* ---------------------------------------------------------------- */
/*                        OTHER HEADER INFO                         */
/* ---------------------------------------------------------------- */

/* Define to 1 if bool is an available type. */
#if _MSC_VER >= 1800
#define HAVE_BOOL_T 1
#endif

/* ---------------------------------------------------------------- */
/*                             FUNCTIONS                            */
/* ---------------------------------------------------------------- */

#define HAVE_CLOSESOCKET 1
#define HAVE_FREEADDRINFO 1
#define HAVE_GETADDRINFO 1
#define HAVE_GETADDRINFO_THREADSAFE 1
#define HAVE_GETHOSTNAME 1
#define HAVE_GETPEERNAME 1
#define HAVE_GETSOCKNAME 1
#define HAVE_IOCTLSOCKET 1
#define HAVE_IOCTLSOCKET_FIONBIO 1
#define HAVE_SETLOCALE 1
#define HAVE_SOCKET 1
#define HAVE_UTIME 1
#define HAVE_RECV 1
#define RECV_TYPE_ARG1 SOCKET
#define RECV_TYPE_ARG2 char *
#define RECV_TYPE_ARG3 int
#define RECV_TYPE_ARG4 int
#define RECV_TYPE_RETV int
#define HAVE_SEND 1
#define SEND_TYPE_ARG1 SOCKET
#define SEND_TYPE_ARG2 char *
#define SEND_TYPE_ARG3 int
#define SEND_TYPE_ARG4 int
#define SEND_TYPE_RETV int
#define HAVE_SIGNAL 1

/* ---------------------------------------------------------------- */
/*                       TYPEDEF REPLACEMENTS                       */
/* ---------------------------------------------------------------- */

/* Define if ssize_t is not an available 'typedefed' type. */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
#ifdef _WIN64
#  define ssize_t __int64
#else
#  define ssize_t int
#endif
#endif

/* ---------------------------------------------------------------- */
/*                            TYPE SIZES                            */
/* ---------------------------------------------------------------- */

#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#ifdef _WIN64
#  define SIZEOF_SIZE_T 8
#else
#  define SIZEOF_SIZE_T 4
#endif
#define SIZEOF_CURL_OFF_T 8
/* Default to 64-bit time_t unless _USE_32BIT_TIME_T is defined */
#ifndef _USE_32BIT_TIME_T
#  define SIZEOF_TIME_T 8
#else
#  define SIZEOF_TIME_T 4
#endif
#define SIZEOF_OFF_T 4

/* ---------------------------------------------------------------- */
/*                          STRUCT RELATED                          */
/* ---------------------------------------------------------------- */

/* Define if you have struct sockaddr_storage. */
#define HAVE_STRUCT_SOCKADDR_STORAGE 1

/* Define if you have struct timeval. */
#define HAVE_STRUCT_TIMEVAL 1

/* Define if struct sockaddr_in6 has the sin6_scope_id member. */
#define HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1

/* ---------------------------------------------------------------- */
/*                       DNS RESOLVER SPECIALTY                     */
/* ---------------------------------------------------------------- */

/*
 * Undefine both USE_ARES and USE_RESOLV_THREADED for synchronous DNS.
 */

/* Default define to enable threaded asynchronous DNS lookups. */
#if !defined(USE_SYNC_DNS) && !defined(USE_ARES) && \
  !defined(USE_RESOLV_THREADED)
#  define USE_RESOLV_THREADED 1
#endif

#if defined(USE_ARES) && defined(USE_RESOLV_THREADED)
#  error "Only one DNS lookup specialty may be defined at most"
#endif

/* ---------------------------------------------------------------- */
/*                           LDAP SUPPORT                           */
/* ---------------------------------------------------------------- */

#ifndef CURL_WINDOWS_UWP
#define HAVE_LDAP_SSL  1
#define USE_WIN32_LDAP 1

/* Define to use the Windows crypto library. */
#define USE_WIN32_CRYPTO
#endif /* CURL_WINDOWS_UWP */

/* Define to use Unix sockets. */
#define USE_UNIX_SOCKETS

/* ---------------------------------------------------------------- */
/*                       ADDITIONAL DEFINITIONS                     */
/* ---------------------------------------------------------------- */

/* Define cpu-machine-OS */
#ifndef CURL_OS
#  ifdef _M_IX86 /* x86 */
#  define CURL_OS "i386-pc-win32"
#  elif defined(_M_X64) /* x86_64 */
#  define CURL_OS "x86_64-pc-win32"
#  else
#  define CURL_OS "unknown-pc-win32"
#  endif
#endif /* !CURL_OS */

#endif /* HEADER_CURL_CONFIG_WIN32_H */
