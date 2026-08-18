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

/* Handcrafted config file for building via Visual Studio IDE Project Files */

#if !defined(_MSC_VER) || _MSC_VER > 1800
#error This manual configuration requires MSVC 2010-2013 (IDE Project builds)
#endif

/*
 * Headers and functions
 */

#define HAVE_FCNTL_H 1
#define HAVE_IO_H 1
#define HAVE_LOCALE_H 1
#if _MSC_VER >= 1800
#define HAVE_STDBOOL_H 1
#define HAVE_BOOL_T 1
#endif
#define HAVE_SYS_TYPES_H 1
#define HAVE_SYS_UTIME_H 1

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

/*
 * Types and sizes
 */

#define SIZEOF_INT 4
#define SIZEOF_LONG 4
#ifdef _WIN64
#  define SIZEOF_SIZE_T 8
#  define ssize_t __int64
#else
#  define SIZEOF_SIZE_T 4
#  define ssize_t int
#endif
#define SIZEOF_CURL_OFF_T 8
/* Default to 64-bit time_t unless _USE_32BIT_TIME_T is defined */
#ifndef _USE_32BIT_TIME_T
#  define SIZEOF_TIME_T 8
#else
#  define SIZEOF_TIME_T 4
#endif
#define SIZEOF_OFF_T 4

#define HAVE_STRUCT_SOCKADDR_STORAGE 1
#define HAVE_STRUCT_TIMEVAL 1
#define HAVE_SOCKADDR_IN6_SIN6_SCOPE_ID 1

/*
 * Additional definitions
 */

/* Default define to enable threaded asynchronous DNS lookups. */
#if !defined(USE_RESOLV_THREADED) && !defined(USE_SYNC_DNS)
#  define USE_RESOLV_THREADED 1
#endif

#define HAVE_LDAP_SSL 1
#define USE_WIN32_LDAP 1
#define USE_WIN32_CRYPTO 1
#define USE_UNIX_SOCKETS 1

#ifndef CURL_OS
#  ifdef _M_IX86
#  define CURL_OS "i386-pc-win32"
#  elif defined(_M_X64)
#  define CURL_OS "x86_64-pc-win32"
#  else
#  define CURL_OS "unknown-pc-win32"
#  endif
#endif

#endif /* HEADER_CURL_CONFIG_WIN32_H */
