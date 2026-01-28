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

/* ================================================================ */
/*               Hand crafted config file for Windows               */
/* ================================================================ */

/* ---------------------------------------------------------------- */
/*                          HEADER FILES                            */
/* ---------------------------------------------------------------- */

/* Define if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define if you have the <io.h> header file. */
#define HAVE_IO_H 1

/* Define if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the <stdbool.h> header file. */
#if (defined(_MSC_VER) && (_MSC_VER >= 1800)) || defined(__MINGW32__)
#define HAVE_STDBOOL_H 1
#endif

/* Define if you have the <sys/param.h> header file. */
#ifdef __MINGW32__
#define HAVE_SYS_PARAM_H 1
#endif

/* Define if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <sys/utime.h> header file. */
#define HAVE_SYS_UTIME_H 1

/* Define if you have the <unistd.h> header file. */
#ifdef __MINGW32__
#define HAVE_UNISTD_H 1
#endif

/* Define to 1 if you have the <libgen.h> header file. */
#ifdef __MINGW32__
#define HAVE_LIBGEN_H 1
#endif

/* ---------------------------------------------------------------- */
/*                        OTHER HEADER INFO                         */
/* ---------------------------------------------------------------- */

/* Define if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to 1 if bool is an available type. */
#if (defined(_MSC_VER) && (_MSC_VER >= 1800)) || defined(__MINGW32__)
#define HAVE_BOOL_T 1
#endif

/* ---------------------------------------------------------------- */
/*                             FUNCTIONS                            */
/* ---------------------------------------------------------------- */

/* Define if you have the closesocket function. */
#define HAVE_CLOSESOCKET 1

/* Define if you have the ftruncate function. */
#ifdef __MINGW32__
#define HAVE_FTRUNCATE 1
#endif

/* Define to 1 if you have the `getpeername' function. */
#define HAVE_GETPEERNAME 1

/* Define to 1 if you have the getsockname function. */
#define HAVE_GETSOCKNAME 1

/* Define if you have the gethostname function. */
#define HAVE_GETHOSTNAME 1

/* Define if you have the gettimeofday function. */
#ifdef __MINGW32__
#define HAVE_GETTIMEOFDAY 1
#endif

/* Define if you have the ioctlsocket function. */
#define HAVE_IOCTLSOCKET 1

/* Define if you have a working ioctlsocket FIONBIO function. */
#define HAVE_IOCTLSOCKET_FIONBIO 1

/* Define if you have the select function. */
#define HAVE_SELECT 1

/* Define if you have the setlocale function. */
#define HAVE_SETLOCALE 1

/* Define if you have the setmode function. */
#define HAVE_SETMODE 1

/* Define if you have the _setmode function. */
#define HAVE__SETMODE 1

/* Define if you have the socket function. */
#define HAVE_SOCKET 1

/* Define if you have the strdup function. */
#define HAVE_STRDUP 1

/* Define if you have the utime function. */
#define HAVE_UTIME 1

/* Define if you have the recv function. */
#define HAVE_RECV 1

/* Define to the type of arg 1 for recv. */
#define RECV_TYPE_ARG1 SOCKET

/* Define to the type of arg 2 for recv. */
#define RECV_TYPE_ARG2 char *

/* Define to the type of arg 3 for recv. */
#define RECV_TYPE_ARG3 int

/* Define to the type of arg 4 for recv. */
#define RECV_TYPE_ARG4 int

/* Define to the function return type for recv. */
#define RECV_TYPE_RETV int

/* Define if you have the send function. */
#define HAVE_SEND 1

/* Define to the type of arg 1 for send. */
#define SEND_TYPE_ARG1 SOCKET

/* Define to the type of arg 2 for send. */
#define SEND_TYPE_ARG2 char *

/* Define to the type of arg 3 for send. */
#define SEND_TYPE_ARG3 int

/* Define to the type of arg 4 for send. */
#define SEND_TYPE_ARG4 int

/* Define to the function return type for send. */
#define SEND_TYPE_RETV int

/* Define to 1 if you have the snprintf function. */
#if (defined(_MSC_VER) && (_MSC_VER >= 1900)) || defined(__MINGW32__)
#define HAVE_SNPRINTF 1
#endif

/* Must always use local implementations on Windows. */
/* Define to 1 if you have an IPv6 capable working inet_ntop function. */
/* #undef HAVE_INET_NTOP */
/* Define to 1 if you have an IPv6 capable working inet_pton function. */
/* #undef HAVE_INET_PTON */

/* Define to 1 if you have the `basename' function. */
#ifdef __MINGW32__
#define HAVE_BASENAME 1
#endif

/* Define to 1 if you have the signal function. */
#define HAVE_SIGNAL 1

/* ---------------------------------------------------------------- */
/*                       TYPEDEF REPLACEMENTS                       */
/* ---------------------------------------------------------------- */

/* Define if ssize_t is not an available 'typedefed' type. */
#ifndef _SSIZE_T_DEFINED
#  ifdef __MINGW32__
#  elif defined(_WIN64)
#    define _SSIZE_T_DEFINED
#    define ssize_t __int64
#  else
#    define _SSIZE_T_DEFINED
#    define ssize_t int
#  endif
#endif

/* ---------------------------------------------------------------- */
/*                            TYPE SIZES                            */
/* ---------------------------------------------------------------- */

/* Define to the size of `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* Define to the size of `long', as computed by sizeof. */
#define SIZEOF_LONG 4

/* Define to the size of `size_t', as computed by sizeof. */
#ifdef _WIN64
#  define SIZEOF_SIZE_T 8
#else
#  define SIZEOF_SIZE_T 4
#endif

/* Define to the size of `curl_off_t', as computed by sizeof. */
#define SIZEOF_CURL_OFF_T 8

/* ---------------------------------------------------------------- */
/*                        COMPILER SPECIFIC                         */
/* ---------------------------------------------------------------- */

/* Default to 64-bit time_t unless _USE_32BIT_TIME_T is defined */
#if defined(_MSC_VER) || defined(__MINGW32__)
#  ifndef _USE_32BIT_TIME_T
#    define SIZEOF_TIME_T 8
#  else
#    define SIZEOF_TIME_T 4
#  endif
#endif

/* Windows XP is required for freeaddrinfo, getaddrinfo */
#define HAVE_FREEADDRINFO           1
#define HAVE_GETADDRINFO            1
#define HAVE_GETADDRINFO_THREADSAFE 1

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
/*                        LARGE FILE SUPPORT                        */
/* ---------------------------------------------------------------- */

/* Number of bits in a file offset, on hosts where this is settable. */
#ifdef __MINGW32__
#  undef _FILE_OFFSET_BITS
#  define _FILE_OFFSET_BITS 64
#endif

/* Define to the size of `off_t', as computed by sizeof. */
#ifdef __MINGW32__
#  define SIZEOF_OFF_T 8
#else
#  define SIZEOF_OFF_T 4
#endif

/* ---------------------------------------------------------------- */
/*                       DNS RESOLVER SPECIALTY                     */
/* ---------------------------------------------------------------- */

/*
 * Undefine both USE_ARES and USE_THREADS_WIN32 for synchronous DNS.
 */

/* Default define to enable threaded asynchronous DNS lookups. */
#if !defined(USE_SYNC_DNS) && !defined(USE_ARES) && \
    !defined(USE_THREADS_WIN32)
#  define USE_THREADS_WIN32 1
#endif

#if defined(USE_ARES) && defined(USE_THREADS_WIN32)
#  error "Only one DNS lookup specialty may be defined at most"
#endif

/* ---------------------------------------------------------------- */
/*                           LDAP SUPPORT                           */
/* ---------------------------------------------------------------- */

#ifndef CURL_WINDOWS_UWP
#undef HAVE_LDAP_URL_PARSE
#define HAVE_LDAP_SSL 1
#define USE_WIN32_LDAP 1
#endif

/* Define to use the Windows crypto library. */
#ifndef CURL_WINDOWS_UWP
#define USE_WIN32_CRYPTO
#endif

/* Define to use Unix sockets. */
#define USE_UNIX_SOCKETS

/* ---------------------------------------------------------------- */
/*                       ADDITIONAL DEFINITIONS                     */
/* ---------------------------------------------------------------- */

/* Define cpu-machine-OS */
#ifndef CURL_OS
#  if defined(_M_IX86) || defined(__i386__) /* x86 (MSVC or gcc) */
#  define CURL_OS "i386-pc-win32"
#  elif defined(_M_X64) || defined(__x86_64__) /* x86_64 (VS2005+ or gcc) */
#  define CURL_OS "x86_64-pc-win32"
#  elif defined(_M_IA64) || defined(__ia64__) /* Itanium */
#  define CURL_OS "ia64-pc-win32"
#  elif defined(_M_ARM_NT) || defined(__arm__) /* ARMv7-Thumb2 */
#  define CURL_OS "thumbv7a-pc-win32"
#  elif defined(_M_ARM64) || defined(__aarch64__) /* ARM64 (Windows 10) */
#  define CURL_OS "aarch64-pc-win32"
#  else
#  define CURL_OS "unknown-pc-win32"
#  endif
#endif /* !CURL_OS */

#endif /* HEADER_CURL_CONFIG_WIN32_H */
