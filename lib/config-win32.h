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

#ifndef UNDER_CE

/* Define some minimum and default build targets for Visual Studio */
#ifdef _MSC_VER
   /* VS2012 default target settings and minimum build target check. */
#  if _MSC_VER >= 1700
     /* The minimum and default build targets for VS2012 are Vista and 8,
        respectively, unless Update 1 is installed and the v110_xp toolset
        is chosen. */
#    ifdef _USING_V110_SDK71_
#      define VS2012_MIN_TARGET 0x0501  /* XP */
#      define VS2012_DEF_TARGET 0x0501  /* XP */
#    else
#      define VS2012_MIN_TARGET 0x0600  /* Vista */
#      define VS2012_DEF_TARGET 0x0602  /* 8 */
#    endif

#    ifndef _WIN32_WINNT
#    define _WIN32_WINNT VS2012_DEF_TARGET
#    endif
#    ifndef WINVER
#    define WINVER VS2012_DEF_TARGET
#    endif
#    if (_WIN32_WINNT < VS2012_MIN_TARGET) || (WINVER < VS2012_MIN_TARGET)
#      ifdef _USING_V110_SDK71_
#        error VS2012 does not support build targets prior to Windows XP
#      else
#        error VS2012 does not support build targets prior to Windows Vista
#      endif
#    endif
   /* Default target settings and minimum build target check for
      VS2008 and VS2010 */
#  else
#    define VS2008_MIN_TARGET 0x0501  /* XP */
     /* VS2008 default build target is Windows Vista (0x0600).
        We override default target to be Windows XP. */
#    define VS2008_DEF_TARGET 0x0501  /* XP */

#    ifndef _WIN32_WINNT
#    define _WIN32_WINNT VS2008_DEF_TARGET
#    endif
#    ifndef WINVER
#    define WINVER VS2008_DEF_TARGET
#    endif
#    if (_WIN32_WINNT < VS2008_MIN_TARGET) || (WINVER < VS2008_MIN_TARGET)
#      error VS2008 does not support build targets prior to Windows XP
#    endif
#  endif
#endif /* _MSC_VER */

#endif /* UNDER_CE */

/* ---------------------------------------------------------------- */
/*                          HEADER FILES                            */
/* ---------------------------------------------------------------- */

/* Define if you have the <arpa/inet.h> header file. */
/* #define HAVE_ARPA_INET_H 1 */

#ifndef UNDER_CE

/* Define if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1  /* exists on __MINGW32CE__ */

/* Define if you have the <io.h> header file. */
#define HAVE_IO_H 1  /* exists on __MINGW32CE__ */

/* Define if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

#endif

/* Define if you have the <netdb.h> header file. */
/* #define HAVE_NETDB_H 1 */

/* Define if you have the <netinet/in.h> header file. */
/* #define HAVE_NETINET_IN_H 1 */

/* Define to 1 if you have the <stdbool.h> header file. */
#ifndef UNDER_CE
#if (defined(_MSC_VER) && (_MSC_VER >= 1800)) || defined(__MINGW32__)
#define HAVE_STDBOOL_H 1  /* exists on __MINGW32CE__ */
#endif
#endif

/* Define to 1 if you have the <stdint.h> header file. */
#if (defined(_MSC_VER) && (_MSC_VER >= 1600)) || defined(__MINGW32__)
#define HAVE_STDINT_H 1
#endif

/* Define if you have the <sys/param.h> header file. */
#ifdef __MINGW32__
#define HAVE_SYS_PARAM_H 1
#endif

/* Define if you have the <sys/select.h> header file. */
/* #define HAVE_SYS_SELECT_H 1 */

/* Define if you have the <sys/sockio.h> header file. */
/* #define HAVE_SYS_SOCKIO_H 1 */

/* Define if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <sys/utime.h> header file. */
#define HAVE_SYS_UTIME_H 1

/* Define if you have the <termio.h> header file. */
/* #define HAVE_TERMIO_H 1 */

/* Define if you have the <termios.h> header file. */
/* #define HAVE_TERMIOS_H 1 */

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
#ifndef UNDER_CE
#if (defined(_MSC_VER) && (_MSC_VER >= 1800)) || defined(__MINGW32__)
#define HAVE_BOOL_T 1  /* exists on __MINGW32CE__ */
#endif
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

#ifndef UNDER_CE
/* Define if you have the setlocale function. */
#define HAVE_SETLOCALE 1

/* Define if you have the setmode function. */
#define HAVE_SETMODE 1

/* Define if you have the _setmode function. */
#define HAVE__SETMODE 1
#endif

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

/* Define to the type qualifier of arg 2 for send. */
#define SEND_QUAL_ARG2 const

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
#ifndef UNDER_CE
#define HAVE_SIGNAL 1
#endif

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

/* Define to the size of `long long', as computed by sizeof. */
/* #define SIZEOF_LONG_LONG 8 */

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

/* Define to nothing if compiler does not support 'const' qualifier. */
/* #define const */

/* Define to nothing if compiler does not support 'volatile' qualifier. */
/* #define volatile */

/* Windows should not have HAVE_GMTIME_R defined */
/* #undef HAVE_GMTIME_R */

/* Define if the compiler supports the 'long long' data type. */
#if defined(_MSC_VER) || defined(__MINGW32__)
#define HAVE_LONGLONG 1
#endif

/* Default to 64-bit time_t unless _USE_32BIT_TIME_T is defined */
#if defined(_MSC_VER) || defined(__MINGW32__)
#  ifndef _USE_32BIT_TIME_T
#    define SIZEOF_TIME_T 8
#  else
#    define SIZEOF_TIME_T 4
#  endif
#endif

/* Windows XP is required for freeaddrinfo, getaddrinfo */
#ifndef UNDER_CE
#define HAVE_FREEADDRINFO           1
#define HAVE_GETADDRINFO            1
#define HAVE_GETADDRINFO_THREADSAFE 1
#endif

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

#ifndef UNDER_CE

#if defined(_MSC_VER) || defined(__MINGW32__)
#  define USE_WIN32_LARGE_FILES
/* Number of bits in a file offset, on hosts where this is settable. */
#  ifdef __MINGW32__
#    ifndef _FILE_OFFSET_BITS
#    define _FILE_OFFSET_BITS 64
#    endif
#  endif
#endif

/* Define to the size of `off_t', as computed by sizeof. */
#if defined(__MINGW32__) && \
  defined(_FILE_OFFSET_BITS) && (_FILE_OFFSET_BITS == 64)
#  define SIZEOF_OFF_T 8
#else
#  define SIZEOF_OFF_T 4
#endif

#endif /* UNDER_CE */

/* ---------------------------------------------------------------- */
/*                       DNS RESOLVER SPECIALTY                     */
/* ---------------------------------------------------------------- */

/*
 * Undefine both USE_ARES and USE_THREADS_WIN32 for synchronous DNS.
 */

/* Define to enable c-ares asynchronous DNS lookups. */
/* #define USE_ARES 1 */

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

#ifdef CURL_HAS_OPENLDAP_LDAPSDK
#undef USE_WIN32_LDAP
#define HAVE_LDAP_URL_PARSE 1
#elif !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
#undef HAVE_LDAP_URL_PARSE
#define HAVE_LDAP_SSL 1
#define USE_WIN32_LDAP 1
#endif

/* Define to use the Windows crypto library. */
#ifndef CURL_WINDOWS_UWP
#define USE_WIN32_CRYPTO
#endif

/* Define to use Unix sockets. */
#ifndef UNDER_CE
#define USE_UNIX_SOCKETS
#endif

/* ---------------------------------------------------------------- */
/*                       ADDITIONAL DEFINITIONS                     */
/* ---------------------------------------------------------------- */

/* Define cpu-machine-OS */
#ifndef CURL_OS
#  ifdef UNDER_CE
#    ifdef _M_ARM
#    define CURL_OS "arm-pc-win32ce"
#    else
#    define CURL_OS "i386-pc-win32ce"
#    endif
#  else /* !UNDER_CE */
#    if defined(_M_IX86) || defined(__i386__) /* x86 (MSVC or gcc) */
#    define CURL_OS "i386-pc-win32"
#    elif defined(_M_X64) || defined(__x86_64__) /* x86_64 (VS2005+ or gcc) */
#    define CURL_OS "x86_64-pc-win32"
#    elif defined(_M_IA64) || defined(__ia64__) /* Itanium */
#    define CURL_OS "ia64-pc-win32"
#    elif defined(_M_ARM_NT) || defined(__arm__) /* ARMv7-Thumb2 */
#    define CURL_OS "thumbv7a-pc-win32"
#    elif defined(_M_ARM64) || defined(__aarch64__) /* ARM64 (Windows 10) */
#    define CURL_OS "aarch64-pc-win32"
#    else
#    define CURL_OS "unknown-pc-win32"
#    endif
#  endif /* UNDER_CE */
#endif /* !CURL_OS */

/* ---------------------------------------------------------------- */
/*                            Windows CE                            */
/* ---------------------------------------------------------------- */

#ifdef UNDER_CE

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#define CURL_DISABLE_FILE 1
#define CURL_DISABLE_TELNET 1
#define CURL_DISABLE_LDAP 1

#ifndef _MSC_VER
extern int stat(const char *path, struct stat *buffer);
#endif

#endif /* UNDER_CE */

#endif /* HEADER_CURL_CONFIG_WIN32_H */
