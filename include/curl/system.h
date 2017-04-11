#ifndef __CURL_SYSTEM_H
#define __CURL_SYSTEM_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * This header is supposed to eventually replace curlbuild.h. This little one
 * is still learning.  During the experimental phase, this header files
 * defines symbols using the prefixes CURLSYS_ or curlsys_. When we feel
 * confident enough, we replace curlbuild.h with this file and rename all
 * prefixes to CURL_ and curl_.
 */

/*
 * Try to keep one section per platform, compiler and architecture, otherwise,
 * if an existing section is reused for a different one and later on the
 * original is adjusted, probably the piggybacking one can be adversely
 * changed.
 *
 * In order to differentiate between platforms/compilers/architectures use
 * only compiler built in predefined preprocessor symbols.
 *
 * curl_off_t
 * ----------
 *
 * For any given platform/compiler curl_off_t must be typedef'ed to a 64-bit
 * wide signed integral data type. The width of this data type must remain
 * constant and independent of any possible large file support settings.
 *
 * As an exception to the above, curl_off_t shall be typedef'ed to a 32-bit
 * wide signed integral data type if there is no 64-bit type.
 *
 * As a general rule, curl_off_t shall not be mapped to off_t. This rule shall
 * only be violated if off_t is the only 64-bit data type available and the
 * size of off_t is independent of large file support settings. Keep your
 * build on the safe side avoiding an off_t gating.  If you have a 64-bit
 * off_t then take for sure that another 64-bit data type exists, dig deeper
 * and you will find it.
 *
 */

#if defined(__DJGPP__) || defined(__GO32__)
#  if defined(__DJGPP__) && (__DJGPP__ > 1)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long long
#    define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     LL
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  else
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long
#    define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     4
#    define CURLSYS_SUFFIX_CURL_OFF_T     L
#    define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  endif
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__SALFORDC__)
#  define CURLSYS_SIZEOF_LONG           4
#  define CURLSYS_TYPEOF_CURL_OFF_T     long
#  define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#  define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#  define CURLSYS_SIZEOF_CURL_OFF_T     4
#  define CURLSYS_SUFFIX_CURL_OFF_T     L
#  define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__BORLANDC__)
#  if (__BORLANDC__ < 0x520)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long
#    define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     4
#    define CURLSYS_SUFFIX_CURL_OFF_T     L
#    define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  else
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     __int64
#    define CURLSYS_FORMAT_CURL_OFF_T     "I64d"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "I64u"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     i64
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ui64
#  endif
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__TURBOC__)
#  define CURLSYS_SIZEOF_LONG           4
#  define CURLSYS_TYPEOF_CURL_OFF_T     long
#  define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#  define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#  define CURLSYS_SIZEOF_CURL_OFF_T     4
#  define CURLSYS_SUFFIX_CURL_OFF_T     L
#  define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__WATCOMC__)
#  if defined(__386__)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     __int64
#    define CURLSYS_FORMAT_CURL_OFF_T     "I64d"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "I64u"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     i64
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ui64
#  else
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long
#    define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     4
#    define CURLSYS_SUFFIX_CURL_OFF_T     L
#    define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  endif
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__POCC__)
#  if (__POCC__ < 280)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long
#    define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     4
#    define CURLSYS_SUFFIX_CURL_OFF_T     L
#    define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  elif defined(_MSC_VER)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     __int64
#    define CURLSYS_FORMAT_CURL_OFF_T     "I64d"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "I64u"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     i64
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ui64
#  else
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long long
#    define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     LL
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  endif
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__LCC__)
#  define CURLSYS_SIZEOF_LONG           4
#  define CURLSYS_TYPEOF_CURL_OFF_T     long
#  define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#  define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#  define CURLSYS_SIZEOF_CURL_OFF_T     4
#  define CURLSYS_SUFFIX_CURL_OFF_T     L
#  define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__SYMBIAN32__)
#  if defined(__EABI__)  /* Treat all ARM compilers equally */
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long long
#    define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     LL
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  elif defined(__CW32__)
#    pragma longlong on
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long long
#    define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     LL
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  elif defined(__VC32__)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     __int64
#    define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     LL
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  endif
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T unsigned int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__MWERKS__)
#  define CURLSYS_SIZEOF_LONG           4
#  define CURLSYS_TYPEOF_CURL_OFF_T     long long
#  define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#  define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#  define CURLSYS_SIZEOF_CURL_OFF_T     8
#  define CURLSYS_SUFFIX_CURL_OFF_T     LL
#  define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(_WIN32_WCE)
#  define CURLSYS_SIZEOF_LONG           4
#  define CURLSYS_TYPEOF_CURL_OFF_T     __int64
#  define CURLSYS_FORMAT_CURL_OFF_T     "I64d"
#  define CURLSYS_FORMAT_CURL_OFF_TU    "I64u"
#  define CURLSYS_SIZEOF_CURL_OFF_T     8
#  define CURLSYS_SUFFIX_CURL_OFF_T     i64
#  define CURLSYS_SUFFIX_CURL_OFF_TU    ui64
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__MINGW32__)
#  define CURLSYS_SIZEOF_LONG           4
#  define CURLSYS_TYPEOF_CURL_OFF_T     long long
#  define CURLSYS_FORMAT_CURL_OFF_T     "I64d"
#  define CURLSYS_FORMAT_CURL_OFF_TU    "I64u"
#  define CURLSYS_SIZEOF_CURL_OFF_T     8
#  define CURLSYS_SUFFIX_CURL_OFF_T     LL
#  define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T socklen_t
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4
#  define CURLSYS_PULL_SYS_TYPES_H      1
#  define CURLSYS_PULL_WS2TCPIP_H       1

#elif defined(__VMS)
#  if defined(__VAX)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long
#    define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     4
#    define CURLSYS_SUFFIX_CURL_OFF_T     L
#    define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  else
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long long
#    define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     LL
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  endif
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T unsigned int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__OS400__)
#  if defined(__ILEC400__)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long long
#    define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     LL
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#    define CURLSYS_TYPEOF_CURL_SOCKLEN_T socklen_t
#    define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4
#    define CURLSYS_PULL_SYS_TYPES_H      1
#    define CURLSYS_PULL_SYS_SOCKET_H     1
#  endif

#elif defined(__MVS__)
#  if defined(__IBMC__) || defined(__IBMCPP__)
#    if defined(_ILP32)
#      define CURLSYS_SIZEOF_LONG           4
#    elif defined(_LP64)
#      define CURLSYS_SIZEOF_LONG           8
#    endif
#    if defined(_LONG_LONG)
#      define CURLSYS_TYPEOF_CURL_OFF_T     long long
#      define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#      define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#      define CURLSYS_SIZEOF_CURL_OFF_T     8
#      define CURLSYS_SUFFIX_CURL_OFF_T     LL
#      define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#    elif defined(_LP64)
#      define CURLSYS_TYPEOF_CURL_OFF_T     long
#      define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#      define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#      define CURLSYS_SIZEOF_CURL_OFF_T     8
#      define CURLSYS_SUFFIX_CURL_OFF_T     L
#      define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#    else
#      define CURLSYS_TYPEOF_CURL_OFF_T     long
#      define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#      define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#      define CURLSYS_SIZEOF_CURL_OFF_T     4
#      define CURLSYS_SUFFIX_CURL_OFF_T     L
#      define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#    endif
#    define CURLSYS_TYPEOF_CURL_SOCKLEN_T socklen_t
#    define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4
#    define CURLSYS_PULL_SYS_TYPES_H      1
#    define CURLSYS_PULL_SYS_SOCKET_H     1
#  endif

#elif defined(__370__)
#  if defined(__IBMC__) || defined(__IBMCPP__)
#    if defined(_ILP32)
#      define CURLSYS_SIZEOF_LONG           4
#    elif defined(_LP64)
#      define CURLSYS_SIZEOF_LONG           8
#    endif
#    if defined(_LONG_LONG)
#      define CURLSYS_TYPEOF_CURL_OFF_T     long long
#      define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#      define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#      define CURLSYS_SIZEOF_CURL_OFF_T     8
#      define CURLSYS_SUFFIX_CURL_OFF_T     LL
#      define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#    elif defined(_LP64)
#      define CURLSYS_TYPEOF_CURL_OFF_T     long
#      define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#      define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#      define CURLSYS_SIZEOF_CURL_OFF_T     8
#      define CURLSYS_SUFFIX_CURL_OFF_T     L
#      define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#    else
#      define CURLSYS_TYPEOF_CURL_OFF_T     long
#      define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#      define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#      define CURLSYS_SIZEOF_CURL_OFF_T     4
#      define CURLSYS_SUFFIX_CURL_OFF_T     L
#      define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#    endif
#    define CURLSYS_TYPEOF_CURL_SOCKLEN_T socklen_t
#    define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4
#    define CURLSYS_PULL_SYS_TYPES_H      1
#    define CURLSYS_PULL_SYS_SOCKET_H     1
#  endif

#elif defined(TPF)
#  define CURLSYS_SIZEOF_LONG           8
#  define CURLSYS_TYPEOF_CURL_OFF_T     long
#  define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#  define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#  define CURLSYS_SIZEOF_CURL_OFF_T     8
#  define CURLSYS_SUFFIX_CURL_OFF_T     L
#  define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

#elif defined(__TINYC__) /* also known as tcc */

#  define CURLSYS_SIZEOF_LONG           4
#  define CURLSYS_TYPEOF_CURL_OFF_T     long long
#  define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#  define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#  define CURLSYS_SIZEOF_CURL_OFF_T     8
#  define CURLSYS_SUFFIX_CURL_OFF_T     LL
#  define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T socklen_t
#  define CURLSYS_PULL_SYS_TYPES_H      1
#  define CURLSYS_PULL_SYS_SOCKET_H     1

/* ===================================== */
/*    KEEP MSVC THE PENULTIMATE ENTRY    */
/* ===================================== */

#elif defined(_MSC_VER)
#  if (_MSC_VER >= 900) && (_INTEGRAL_MAX_BITS >= 64)
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     __int64
#    define CURLSYS_FORMAT_CURL_OFF_T     "I64d"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "I64u"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     i64
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ui64
#  else
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long
#    define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     4
#    define CURLSYS_SUFFIX_CURL_OFF_T     L
#    define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  endif
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4

/* ===================================== */
/*    KEEP GENERIC GCC THE LAST ENTRY    */
/* ===================================== */

#elif defined(__GNUC__)
#  if !defined(__LP64__) && (defined(__ILP32__) || \
      defined(__i386__) || defined(__ppc__) || defined(__arm__) || \
      defined(__sparc__) || defined(__mips__) || defined(__sh__))
#    define CURLSYS_SIZEOF_LONG           4
#    define CURLSYS_TYPEOF_CURL_OFF_T     long long
#    define CURLSYS_FORMAT_CURL_OFF_T     "lld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "llu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     LL
#    define CURLSYS_SUFFIX_CURL_OFF_TU    ULL
#  elif defined(__LP64__) || \
        defined(__x86_64__) || defined(__ppc64__) || defined(__sparc64__)
#    define CURLSYS_SIZEOF_LONG           8
#    define CURLSYS_TYPEOF_CURL_OFF_T     long
#    define CURLSYS_FORMAT_CURL_OFF_T     "ld"
#    define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
#    define CURLSYS_SIZEOF_CURL_OFF_T     8
#    define CURLSYS_SUFFIX_CURL_OFF_T     L
#    define CURLSYS_SUFFIX_CURL_OFF_TU    UL
#  endif
#  define CURLSYS_TYPEOF_CURL_SOCKLEN_T socklen_t
#  define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4
#  define CURLSYS_PULL_SYS_TYPES_H      1
#  define CURLSYS_PULL_SYS_SOCKET_H     1

#else
/* generic "safe guess" on old 32 bit style */
# define CURLSYS_SIZEOF_LONG 4
# define CURLSYS_SIZEOF_CURL_SOCKLEN_T 4
# define CURLSYS_SIZEOF_CURL_OFF_T 4
# define CURLSYS_TYPEOF_CURL_OFF_T     long
# define CURLSYS_FORMAT_CURL_OFF_T     "ld"
# define CURLSYS_FORMAT_CURL_OFF_TU    "lu"
# define CURLSYS_SUFFIX_CURL_OFF_T     L
# define CURLSYS_SUFFIX_CURL_OFF_TU    UL
# define CURLSYS_TYPEOF_CURL_SOCKLEN_T int
#endif

/* CURLSYS_PULL_WS2TCPIP_H is defined above when inclusion of header file  */
/* ws2tcpip.h is required here to properly make type definitions below. */
#ifdef CURLSYS_PULL_WS2TCPIP_H
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

/* CURLSYS_PULL_SYS_TYPES_H is defined above when inclusion of header file  */
/* sys/types.h is required here to properly make type definitions below. */
#ifdef CURLSYS_PULL_SYS_TYPES_H
#  include <sys/types.h>
#endif

/* CURLSYS_PULL_SYS_SOCKET_H is defined above when inclusion of header file  */
/* sys/socket.h is required here to properly make type definitions below. */
#ifdef CURLSYS_PULL_SYS_SOCKET_H
#  include <sys/socket.h>
#endif

/* Data type definition of curl_socklen_t. */
#ifdef CURLSYS_TYPEOF_CURL_SOCKLEN_T
  typedef CURLSYS_TYPEOF_CURL_SOCKLEN_T curlsys_socklen_t;
#endif

/* Data type definition of curl_off_t. */

#ifdef CURLSYS_TYPEOF_CURL_OFF_T
  typedef CURLSYS_TYPEOF_CURL_OFF_T curlsys_off_t;
#endif

#endif /* __CURL_SYSTEM_H */

