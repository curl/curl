#ifndef HEADER_CURL_SETUP_H
#define HEADER_CURL_SETUP_H
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

#if defined(BUILDING_LIBCURL) && !defined(CURL_NO_OLDIES)
#define CURL_NO_OLDIES
#endif

/* FIXME: Delete this once the warnings have been fixed. */
#if !defined(CURL_WARN_SIGN_CONVERSION)
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif
#endif

/* Set default _WIN32_WINNT */
#ifdef __MINGW32__
#include <_mingw.h>
#endif

/*
 * Disable Visual Studio warnings:
 * 4127 "conditional expression is constant"
 */
#ifdef _MSC_VER
#pragma warning(disable:4127)
#endif

#ifdef _WIN32
/*
 * Don't include unneeded stuff in Windows headers to avoid compiler
 * warnings and macro clashes.
 * Make sure to define this macro before including any Windows headers.
 */
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOGDI
#    define NOGDI
#  endif
/* Detect Windows App environment which has a restricted access
 * to the Win32 APIs. */
# if (defined(_WIN32_WINNT) && (_WIN32_WINNT >= 0x0602)) || \
  defined(WINAPI_FAMILY)
#  include <winapifamily.h>
#  if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP) &&  \
     !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#    define CURL_WINDOWS_APP
#  endif
# endif
#endif

/*
 * Include configuration script results or hand-crafted
 * configuration file for platforms which lack config tool.
 */

#ifdef HAVE_CONFIG_H

#include "curl_config.h"

#else /* HAVE_CONFIG_H */

#ifdef _WIN32_WCE
#  include "config-win32ce.h"
#else
#  ifdef _WIN32
#    include "config-win32.h"
#  endif
#endif

#ifdef macintosh
#  include "config-mac.h"
#endif

#ifdef __riscos__
#  include "config-riscos.h"
#endif

#ifdef __AMIGA__
#  include "config-amigaos.h"
#endif

#ifdef __OS400__
#  include "config-os400.h"
#endif

#ifdef __PLAN9__
#  include "config-plan9.h"
#endif

#ifdef MSDOS
#  include "config-dos.h"
#endif

#endif /* HAVE_CONFIG_H */

/* ================================================================ */
/* Definition of preprocessor macros/symbols which modify compiler  */
/* behavior or generated code characteristics must be done here,   */
/* as appropriate, before any system header file is included. It is */
/* also possible to have them defined in the config file included   */
/* before this point. As a result of all this we frown inclusion of */
/* system header files in our config files, avoid this at any cost. */
/* ================================================================ */

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

/* Solaris needs this to get a POSIX-conformant getpwuid_r */
#if defined(sun) || defined(__sun)
#  ifndef _POSIX_PTHREAD_SEMANTICS
#    define _POSIX_PTHREAD_SEMANTICS 1
#  endif
#endif

/* ================================================================ */
/*  If you need to include a system header file for your platform,  */
/*  please, do it beyond the point further indicated in this file.  */
/* ================================================================ */

/*
 * Disable other protocols when http is the only one desired.
 */

#ifdef HTTP_ONLY
#  ifndef CURL_DISABLE_DICT
#    define CURL_DISABLE_DICT
#  endif
#  ifndef CURL_DISABLE_FILE
#    define CURL_DISABLE_FILE
#  endif
#  ifndef CURL_DISABLE_FTP
#    define CURL_DISABLE_FTP
#  endif
#  ifndef CURL_DISABLE_GOPHER
#    define CURL_DISABLE_GOPHER
#  endif
#  ifndef CURL_DISABLE_IMAP
#    define CURL_DISABLE_IMAP
#  endif
#  ifndef CURL_DISABLE_LDAP
#    define CURL_DISABLE_LDAP
#  endif
#  ifndef CURL_DISABLE_LDAPS
#    define CURL_DISABLE_LDAPS
#  endif
#  ifndef CURL_DISABLE_MQTT
#    define CURL_DISABLE_MQTT
#  endif
#  ifndef CURL_DISABLE_POP3
#    define CURL_DISABLE_POP3
#  endif
#  ifndef CURL_DISABLE_RTSP
#    define CURL_DISABLE_RTSP
#  endif
#  ifndef CURL_DISABLE_SMB
#    define CURL_DISABLE_SMB
#  endif
#  ifndef CURL_DISABLE_SMTP
#    define CURL_DISABLE_SMTP
#  endif
#  ifndef CURL_DISABLE_TELNET
#    define CURL_DISABLE_TELNET
#  endif
#  ifndef CURL_DISABLE_TFTP
#    define CURL_DISABLE_TFTP
#  endif
#endif

/*
 * When http is disabled rtsp is not supported.
 */

#if defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_RTSP)
#  define CURL_DISABLE_RTSP
#endif

/*
 * When HTTP is disabled, disable HTTP-only features
 */

#if defined(CURL_DISABLE_HTTP)
#  define CURL_DISABLE_ALTSVC 1
#  define CURL_DISABLE_COOKIES 1
#  define CURL_DISABLE_BASIC_AUTH 1
#  define CURL_DISABLE_BEARER_AUTH 1
#  define CURL_DISABLE_AWS 1
#  define CURL_DISABLE_DOH 1
#  define CURL_DISABLE_FORM_API 1
#  define CURL_DISABLE_HEADERS_API 1
#  define CURL_DISABLE_HSTS 1
#  define CURL_DISABLE_HTTP_AUTH 1
#endif

/* ================================================================ */
/* No system header file shall be included in this file before this */
/* point.                                                           */
/* ================================================================ */

/*
 * OS/400 setup file includes some system headers.
 */

#ifdef __OS400__
#  include "setup-os400.h"
#endif

/*
 * VMS setup file includes some system headers.
 */

#ifdef __VMS
#  include "setup-vms.h"
#endif

/*
 * Windows setup file includes some system headers.
 */

#ifdef _WIN32
#  include "setup-win32.h"
#endif

#include <curl/system.h>

/* curl uses its own printf() function internally. It understands the GNU
 * format. Use this format, so that is matches the GNU format attribute we
 * use with the mingw compiler, allowing it to verify them at compile-time.
 */
#ifdef  __MINGW32__
#  undef CURL_FORMAT_CURL_OFF_T
#  undef CURL_FORMAT_CURL_OFF_TU
#  define CURL_FORMAT_CURL_OFF_T   "lld"
#  define CURL_FORMAT_CURL_OFF_TU  "llu"
#endif

/* based on logic in "curl/mprintf.h" */

#if (defined(__GNUC__) || defined(__clang__)) &&                        \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) &&         \
  !defined(CURL_NO_FMT_CHECKS)
#if defined(__MINGW32__) && !defined(__clang__)
#define CURL_PRINTF(fmt, arg) \
  __attribute__((format(gnu_printf, fmt, arg)))
#else
#define CURL_PRINTF(fmt, arg) \
  __attribute__((format(__printf__, fmt, arg)))
#endif
#else
#define CURL_PRINTF(fmt, arg)
#endif

/*
 * Use getaddrinfo to resolve the IPv4 address literal. If the current network
 * interface doesn't support IPv4, but supports IPv6, NAT64, and DNS64,
 * performing this task will result in a synthesized IPv6 address.
 */
#if defined(__APPLE__) && !defined(USE_ARES)
#include <TargetConditionals.h>
#define USE_RESOLVE_ON_IPS 1
#  if TARGET_OS_MAC && !(defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE) && \
     defined(ENABLE_IPV6)
#    define CURL_MACOS_CALL_COPYPROXIES 1
#  endif
#endif

#ifdef USE_LWIPSOCK
#  include <lwip/init.h>
#  include <lwip/sockets.h>
#  include <lwip/netdb.h>
#endif

#ifdef HAVE_EXTRA_STRICMP_H
#  include <extra/stricmp.h>
#endif

#ifdef HAVE_EXTRA_STRDUP_H
#  include <extra/strdup.h>
#endif

#ifdef __AMIGA__
#  ifdef __amigaos4__
#    define __USE_INLINE__
     /* use our own resolver which uses runtime feature detection */
#    define CURLRES_AMIGA
     /* getaddrinfo() currently crashes bsdsocket.library, so disable */
#    undef HAVE_GETADDRINFO
#    if !(defined(__NEWLIB__) || \
          (defined(__CLIB2__) && defined(__THREAD_SAFE)))
       /* disable threaded resolver with clib2 - requires newlib or clib-ts */
#      undef USE_THREADS_POSIX
#    endif
#  endif
#  include <exec/types.h>
#  include <exec/execbase.h>
#  include <proto/exec.h>
#  include <proto/dos.h>
#  include <unistd.h>
#  if defined(HAVE_PROTO_BSDSOCKET_H) && \
    (!defined(__amigaos4__) || defined(USE_AMISSL))
     /* use bsdsocket.library directly, instead of libc networking functions */
#    define _SYS_MBUF_H /* m_len define clashes with curl */
#    include <proto/bsdsocket.h>
#    ifdef __amigaos4__
       int Curl_amiga_select(int nfds, fd_set *readfds, fd_set *writefds,
                             fd_set *errorfds, struct timeval *timeout);
#      define select(a,b,c,d,e) Curl_amiga_select(a,b,c,d,e)
#    else
#      define select(a,b,c,d,e) WaitSelect(a,b,c,d,e,0)
#    endif
     /* must not use libc's fcntl() on bsdsocket.library sockfds! */
#    undef HAVE_FCNTL
#    undef HAVE_FCNTL_O_NONBLOCK
#  else
     /* use libc networking and hence close() and fnctl() */
#    undef HAVE_CLOSESOCKET_CAMEL
#    undef HAVE_IOCTLSOCKET_CAMEL
#  endif
/*
 * In clib2 arpa/inet.h warns that some prototypes may clash
 * with bsdsocket.library. This avoids the definition of those.
 */
#  define __NO_NET_API
#endif

#include <stdio.h>
#include <assert.h>

#ifdef __TANDEM /* for ns*-tandem-nsk systems */
# if ! defined __LP64
#  include <floss.h> /* FLOSS is only used for 32-bit builds. */
# endif
#endif

#ifndef STDC_HEADERS /* no standard C headers! */
#include <curl/stdcheaders.h>
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
#  undef  fstat
#  define fstat(fdes,stp)            _fstati64(fdes, stp)
#  undef  stat
#  define stat(fname,stp)            curlx_win32_stat(fname, stp)
#  define struct_stat                struct _stati64
#  define LSEEK_ERROR                (__int64)-1
#  define open                       curlx_win32_open
#  define fopen(fname,mode)          curlx_win32_fopen(fname, mode)
#  define access(fname,mode)         curlx_win32_access(fname, mode)
   int curlx_win32_open(const char *filename, int oflag, ...);
   int curlx_win32_stat(const char *path, struct_stat *buffer);
   FILE *curlx_win32_fopen(const char *filename, const char *mode);
   int curlx_win32_access(const char *path, int mode);
#endif

/*
 * Small file (<2Gb) support using WIN32 functions.
 */

#ifdef USE_WIN32_SMALL_FILES
#  include <io.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  ifndef _WIN32_WCE
#    undef  lseek
#    define lseek(fdes,offset,whence)  _lseek(fdes, (long)offset, whence)
#    define fstat(fdes,stp)            _fstat(fdes, stp)
#    define stat(fname,stp)            curlx_win32_stat(fname, stp)
#    define struct_stat                struct _stat
#    define open                       curlx_win32_open
#    define fopen(fname,mode)          curlx_win32_fopen(fname, mode)
#    define access(fname,mode)         curlx_win32_access(fname, mode)
     int curlx_win32_stat(const char *path, struct_stat *buffer);
     int curlx_win32_open(const char *filename, int oflag, ...);
     FILE *curlx_win32_fopen(const char *filename, const char *mode);
     int curlx_win32_access(const char *path, int mode);
#  endif
#  define LSEEK_ERROR                (long)-1
#endif

#ifndef struct_stat
#  define struct_stat struct stat
#endif

#ifndef LSEEK_ERROR
#  define LSEEK_ERROR (off_t)-1
#endif

#ifndef SIZEOF_TIME_T
/* assume default size of time_t to be 32 bit */
#define SIZEOF_TIME_T 4
#endif

#ifndef SIZEOF_CURL_SOCKET_T
/* configure and cmake check and set the define */
#  ifdef _WIN64
#    define SIZEOF_CURL_SOCKET_T 8
#  else
/* default guess */
#    define SIZEOF_CURL_SOCKET_T 4
#  endif
#endif

#if SIZEOF_CURL_SOCKET_T < 8
#  define CURL_FORMAT_SOCKET_T "d"
#elif defined(__MINGW32__)
#  define CURL_FORMAT_SOCKET_T "zd"
#else
#  define CURL_FORMAT_SOCKET_T "qd"
#endif

/*
 * Default sizeof(off_t) in case it hasn't been defined in config file.
 */

#ifndef SIZEOF_OFF_T
#  if defined(__VMS) && !defined(__VAX)
#    if defined(_LARGEFILE)
#      define SIZEOF_OFF_T 8
#    endif
#  elif defined(__OS400__) && defined(__ILEC400__)
#    if defined(_LARGE_FILES)
#      define SIZEOF_OFF_T 8
#    endif
#  elif defined(__MVS__) && defined(__IBMC__)
#    if defined(_LP64) || defined(_LARGE_FILES)
#      define SIZEOF_OFF_T 8
#    endif
#  elif defined(__370__) && defined(__IBMC__)
#    if defined(_LP64) || defined(_LARGE_FILES)
#      define SIZEOF_OFF_T 8
#    endif
#  endif
#  ifndef SIZEOF_OFF_T
#    define SIZEOF_OFF_T 4
#  endif
#endif

#if (SIZEOF_CURL_OFF_T < 8)
#error "too small curl_off_t"
#else
   /* assume SIZEOF_CURL_OFF_T == 8 */
#  define CURL_OFF_T_MAX CURL_OFF_T_C(0x7FFFFFFFFFFFFFFF)
#endif
#define CURL_OFF_T_MIN (-CURL_OFF_T_MAX - CURL_OFF_T_C(1))

#if (SIZEOF_TIME_T == 4)
#  ifdef HAVE_TIME_T_UNSIGNED
#  define TIME_T_MAX UINT_MAX
#  define TIME_T_MIN 0
#  else
#  define TIME_T_MAX INT_MAX
#  define TIME_T_MIN INT_MIN
#  endif
#else
#  ifdef HAVE_TIME_T_UNSIGNED
#  define TIME_T_MAX 0xFFFFFFFFFFFFFFFF
#  define TIME_T_MIN 0
#  else
#  define TIME_T_MAX 0x7FFFFFFFFFFFFFFF
#  define TIME_T_MIN (-TIME_T_MAX - 1)
#  endif
#endif

#ifndef SIZE_T_MAX
/* some limits.h headers have this defined, some don't */
#if defined(SIZEOF_SIZE_T) && (SIZEOF_SIZE_T > 4)
#define SIZE_T_MAX 18446744073709551615U
#else
#define SIZE_T_MAX 4294967295U
#endif
#endif

#ifndef SSIZE_T_MAX
/* some limits.h headers have this defined, some don't */
#if defined(SIZEOF_SIZE_T) && (SIZEOF_SIZE_T > 4)
#define SSIZE_T_MAX 9223372036854775807
#else
#define SSIZE_T_MAX 2147483647
#endif
#endif

/*
 * Arg 2 type for gethostname in case it hasn't been defined in config file.
 */

#ifndef GETHOSTNAME_TYPE_ARG2
#  ifdef USE_WINSOCK
#    define GETHOSTNAME_TYPE_ARG2 int
#  else
#    define GETHOSTNAME_TYPE_ARG2 size_t
#  endif
#endif

/* Below we define some functions. They should

   4. set the SIGALRM signal timeout
   5. set dir/file naming defines
   */

#ifdef _WIN32

#  define DIR_CHAR      "\\"

#else /* _WIN32 */

#  ifdef MSDOS  /* Watt-32 */

#    include <sys/ioctl.h>
#    define select(n,r,w,x,t) select_s(n,r,w,x,t)
#    define ioctl(x,y,z) ioctlsocket(x,y,(char *)(z))
#    include <tcp.h>
#    ifdef word
#      undef word
#    endif
#    ifdef byte
#      undef byte
#    endif

#  endif /* MSDOS */

#  ifdef __minix
     /* Minix 3 versions up to at least 3.1.3 are missing these prototypes */
     extern char *strtok_r(char *s, const char *delim, char **last);
     extern struct tm *gmtime_r(const time_t * const timep, struct tm *tmp);
#  endif

#  define DIR_CHAR      "/"

#endif /* _WIN32 */

/* ---------------------------------------------------------------- */
/*             resolver specialty compile-time defines              */
/*         CURLRES_* defines to use in the host*.c sources          */
/* ---------------------------------------------------------------- */

/*
 * MSVC threads support requires a multi-threaded runtime library.
 * _beginthreadex() is not available in single-threaded ones.
 */

#if defined(_MSC_VER) && !defined(_MT)
#  undef USE_THREADS_POSIX
#  undef USE_THREADS_WIN32
#endif

/*
 * Mutually exclusive CURLRES_* definitions.
 */

#if defined(ENABLE_IPV6) && defined(HAVE_GETADDRINFO)
#  define CURLRES_IPV6
#elif defined(ENABLE_IPV6) && (defined(_WIN32) || defined(__CYGWIN__))
/* assume on Windows that IPv6 without getaddrinfo is a broken build */
#  error "Unexpected build: IPv6 is enabled but getaddrinfo was not found."
#else
#  define CURLRES_IPV4
#endif

#ifdef USE_ARES
#  define CURLRES_ASYNCH
#  define CURLRES_ARES
/* now undef the stock libc functions just to avoid them being used */
#  undef HAVE_GETADDRINFO
#  undef HAVE_FREEADDRINFO
#elif defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)
#  define CURLRES_ASYNCH
#  define CURLRES_THREADED
#else
#  define CURLRES_SYNCH
#endif

/* ---------------------------------------------------------------- */

#if defined(HAVE_LIBIDN2) && defined(HAVE_IDN2_H) && !defined(USE_WIN32_IDN)
/* The lib and header are present */
#define USE_LIBIDN2
#endif

#if defined(USE_LIBIDN2) && defined(USE_WIN32_IDN)
#error "Both libidn2 and WinIDN are enabled, choose one."
#endif

#define LIBIDN_REQUIRED_VERSION "0.4.1"

#if defined(USE_GNUTLS) || defined(USE_OPENSSL) || defined(USE_MBEDTLS) || \
  defined(USE_WOLFSSL) || defined(USE_SCHANNEL) || defined(USE_SECTRANSP) || \
  defined(USE_BEARSSL) || defined(USE_RUSTLS)
#define USE_SSL    /* SSL support has been enabled */
#endif

/* Single point where USE_SPNEGO definition might be defined */
#if !defined(CURL_DISABLE_NEGOTIATE_AUTH) && \
    (defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI))
#define USE_SPNEGO
#endif

/* Single point where USE_KERBEROS5 definition might be defined */
#if !defined(CURL_DISABLE_KERBEROS_AUTH) && \
    (defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI))
#define USE_KERBEROS5
#endif

/* Single point where USE_NTLM definition might be defined */
#if !defined(CURL_DISABLE_NTLM)
#  if defined(USE_OPENSSL) || defined(USE_MBEDTLS) ||                   \
  defined(USE_GNUTLS) || defined(USE_SECTRANSP) ||                      \
  defined(USE_OS400CRYPTO) || defined(USE_WIN32_CRYPTO) ||              \
  (defined(USE_WOLFSSL) && defined(HAVE_WOLFSSL_DES_ECB_ENCRYPT))
#    define USE_CURL_NTLM_CORE
#  endif
#  if defined(USE_CURL_NTLM_CORE) || defined(USE_WINDOWS_SSPI)
#    define USE_NTLM
#  endif
#endif

#ifdef CURL_WANTS_CA_BUNDLE_ENV
#error "No longer supported. Set CURLOPT_CAINFO at runtime instead."
#endif

#if defined(USE_LIBSSH2) || defined(USE_LIBSSH) || defined(USE_WOLFSSH)
#define USE_SSH
#endif

/*
 * Provide a mechanism to silence picky compilers, such as gcc 4.6+.
 * Parameters should of course normally not be unused, but for example when
 * we have multiple implementations of the same interface it may happen.
 */

#if defined(__GNUC__) && ((__GNUC__ >= 3) || \
  ((__GNUC__ == 2) && defined(__GNUC_MINOR__) && (__GNUC_MINOR__ >= 7)))
#  define UNUSED_PARAM __attribute__((__unused__))
#  define WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#  define UNUSED_PARAM /* NOTHING */
#  define WARN_UNUSED_RESULT
#endif

/* noreturn attribute */

#if !defined(CURL_NORETURN)
#if (defined(__GNUC__) && (__GNUC__ >= 3)) || defined(__clang__)
#  define CURL_NORETURN  __attribute__((__noreturn__))
#elif defined(_MSC_VER) && (_MSC_VER >= 1200)
#  define CURL_NORETURN  __declspec(noreturn)
#else
#  define CURL_NORETURN
#endif
#endif

/* fallthrough attribute */

#if !defined(FALLTHROUGH)
#if (defined(__GNUC__) && __GNUC__ >= 7) || \
    (defined(__clang__) && __clang_major__ >= 10)
#  define FALLTHROUGH()  __attribute__((fallthrough))
#else
#  define FALLTHROUGH()  do {} while (0)
#endif
#endif

/*
 * Include macros and defines that should only be processed once.
 */

#ifndef HEADER_CURL_SETUP_ONCE_H
#include "curl_setup_once.h"
#endif

/*
 * Definition of our NOP statement Object-like macro
 */

#ifndef Curl_nop_stmt
#  define Curl_nop_stmt do { } while(0)
#endif

/*
 * Ensure that Winsock and lwIP TCP/IP stacks are not mixed.
 */

#if defined(__LWIP_OPT_H__) || defined(LWIP_HDR_OPT_H)
#  if defined(SOCKET) || defined(USE_WINSOCK)
#    error "WinSock and lwIP TCP/IP stack definitions shall not coexist!"
#  endif
#endif

/*
 * shutdown() flags for systems that don't define them
 */

#ifndef SHUT_RD
#define SHUT_RD 0x00
#endif

#ifndef SHUT_WR
#define SHUT_WR 0x01
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 0x02
#endif

/* Define S_ISREG if not defined by system headers, e.g. MSVC */
#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

/* Define S_ISDIR if not defined by system headers, e.g. MSVC */
#if !defined(S_ISDIR) && defined(S_IFMT) && defined(S_IFDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

/* In Windows the default file mode is text but an application can override it.
Therefore we specify it explicitly. https://github.com/curl/curl/pull/258
*/
#if defined(_WIN32) || defined(MSDOS)
#define FOPEN_READTEXT "rt"
#define FOPEN_WRITETEXT "wt"
#define FOPEN_APPENDTEXT "at"
#elif defined(__CYGWIN__)
/* Cygwin has specific behavior we need to address when WIN32 is not defined.
https://cygwin.com/cygwin-ug-net/using-textbinary.html
For write we want our output to have line endings of LF and be compatible with
other Cygwin utilities. For read we want to handle input that may have line
endings either CRLF or LF so 't' is appropriate.
*/
#define FOPEN_READTEXT "rt"
#define FOPEN_WRITETEXT "w"
#define FOPEN_APPENDTEXT "a"
#else
#define FOPEN_READTEXT "r"
#define FOPEN_WRITETEXT "w"
#define FOPEN_APPENDTEXT "a"
#endif

/* for systems that don't detect this in configure */
#ifndef CURL_SA_FAMILY_T
#  if defined(HAVE_SA_FAMILY_T)
#    define CURL_SA_FAMILY_T sa_family_t
#  elif defined(HAVE_ADDRESS_FAMILY)
#    define CURL_SA_FAMILY_T ADDRESS_FAMILY
#  else
/* use a sensible default */
#    define CURL_SA_FAMILY_T unsigned short
#  endif
#endif

/* Some convenience macros to get the larger/smaller value out of two given.
   We prefix with CURL to prevent name collisions. */
#define CURLMAX(x,y) ((x)>(y)?(x):(y))
#define CURLMIN(x,y) ((x)<(y)?(x):(y))

/* A convenience macro to provide both the string literal and the length of
   the string literal in one go, useful for functions that take "string,len"
   as their argument */
#define STRCONST(x) x,sizeof(x)-1

/* Some versions of the Android SDK is missing the declaration */
#if defined(HAVE_GETPWUID_R) && defined(HAVE_DECL_GETPWUID_R_MISSING)
struct passwd;
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf,
               size_t buflen, struct passwd **result);
#endif

#ifdef DEBUGBUILD
#define UNITTEST
#else
#define UNITTEST static
#endif

/* Hyper supports HTTP2 also, but Curl's integration with Hyper does not */
#if defined(USE_NGHTTP2)
#define USE_HTTP2
#endif

#if (defined(USE_NGTCP2) && defined(USE_NGHTTP3)) || \
    (defined(USE_OPENSSL_QUIC) && defined(USE_NGHTTP3)) || \
    defined(USE_QUICHE) || defined(USE_MSH3)

#ifdef CURL_WITH_MULTI_SSL
#error "Multi-SSL combined with QUIC is not supported"
#endif

#define ENABLE_QUIC
#define USE_HTTP3
#endif

/* Certain Windows implementations are not aligned with what curl expects,
   so always use the local one on this platform. E.g. the mingw-w64
   implementation can return wrong results for non-ASCII inputs. */
#if defined(HAVE_BASENAME) && defined(_WIN32)
#undef HAVE_BASENAME
#endif

#if defined(USE_UNIX_SOCKETS) && defined(_WIN32)
#  if !defined(UNIX_PATH_MAX)
     /* Replicating logic present in afunix.h
        (distributed with newer Windows 10 SDK versions only) */
#    define UNIX_PATH_MAX 108
     /* !checksrc! disable TYPEDEFSTRUCT 1 */
     typedef struct sockaddr_un {
       ADDRESS_FAMILY sun_family;
       char sun_path[UNIX_PATH_MAX];
     } SOCKADDR_UN, *PSOCKADDR_UN;
#    define WIN32_SOCKADDR_UN
#  endif
#endif

/* OpenSSLv3 marks DES, MD5 and ENGINE functions deprecated but we have no
   replacements (yet) so tell the compiler to not warn for them. */
#ifdef USE_OPENSSL
#define OPENSSL_SUPPRESS_DEPRECATED
#endif

#endif /* HEADER_CURL_SETUP_H */
