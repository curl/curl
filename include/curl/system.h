#ifndef FETCHINC_SYSTEM_H
#define FETCHINC_SYSTEM_H
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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/*
 * Try to keep one section per platform, compiler and architecture, otherwise,
 * if an existing section is reused for a different one and later on the
 * original is adjusted, probably the piggybacking one can be adversely
 * changed.
 *
 * In order to differentiate between platforms/compilers/architectures use
 * only compiler built-in predefined preprocessor symbols.
 *
 * fetch_off_t
 * ----------
 *
 * For any given platform/compiler fetch_off_t must be typedef'ed to a 64-bit
 * wide signed integral data type. The width of this data type must remain
 * constant and independent of any possible large file support settings.
 *
 * As an exception to the above, fetch_off_t shall be typedef'ed to a 32-bit
 * wide signed integral data type if there is no 64-bit type.
 *
 * As a general rule, fetch_off_t shall not be mapped to off_t. This rule shall
 * only be violated if off_t is the only 64-bit data type available and the
 * size of off_t is independent of large file support settings. Keep your
 * build on the safe side avoiding an off_t gating. If you have a 64-bit
 * off_t then take for sure that another 64-bit data type exists, dig deeper
 * and you will find it.
 *
 */

#if defined(__DJGPP__)
#  define FETCH_TYPEOF_FETCH_OFF_T     long long
#  define FETCH_FORMAT_FETCH_OFF_T     "lld"
#  define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#  define FETCH_SUFFIX_FETCH_OFF_T     LL
#  define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T int

#elif defined(__BORLANDC__)
#  define FETCH_TYPEOF_FETCH_OFF_T     __int64
#  define FETCH_FORMAT_FETCH_OFF_T     "I64d"
#  define FETCH_FORMAT_FETCH_OFF_TU    "I64u"
#  define FETCH_SUFFIX_FETCH_OFF_T     i64
#  define FETCH_SUFFIX_FETCH_OFF_TU    ui64
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T int

#elif defined(__POCC__)
#  if defined(_MSC_VER)
#    define FETCH_TYPEOF_FETCH_OFF_T     __int64
#    define FETCH_FORMAT_FETCH_OFF_T     "I64d"
#    define FETCH_FORMAT_FETCH_OFF_TU    "I64u"
#    define FETCH_SUFFIX_FETCH_OFF_T     i64
#    define FETCH_SUFFIX_FETCH_OFF_TU    ui64
#  else
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  endif
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T int

#elif defined(__LCC__)
#  if defined(__MCST__) /* MCST eLbrus Compiler Collection */
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#    define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#    define FETCH_PULL_SYS_TYPES_H      1
#    define FETCH_PULL_SYS_SOCKET_H     1
#  else                /* Local (or Little) C Compiler */
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#    define FETCH_TYPEOF_FETCH_SOCKLEN_T int
#  endif

#elif defined(macintosh)
#  include <ConditionalMacros.h>
#  if TYPE_LONGLONG
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  else
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  endif
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T unsigned int

#elif defined(__TANDEM)
#  if !defined(__LP64)
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#    define FETCH_TYPEOF_FETCH_SOCKLEN_T int
#  else
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#    define FETCH_TYPEOF_FETCH_SOCKLEN_T unsigned int
#  endif

#elif defined(_WIN32_WCE)
#  define FETCH_TYPEOF_FETCH_OFF_T     __int64
#  define FETCH_FORMAT_FETCH_OFF_T     "I64d"
#  define FETCH_FORMAT_FETCH_OFF_TU    "I64u"
#  define FETCH_SUFFIX_FETCH_OFF_T     i64
#  define FETCH_SUFFIX_FETCH_OFF_TU    ui64
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T int

#elif defined(__MINGW32__)
#  include <inttypes.h>
#  define FETCH_TYPEOF_FETCH_OFF_T     long long
#  define FETCH_FORMAT_FETCH_OFF_T     PRId64
#  define FETCH_FORMAT_FETCH_OFF_TU    PRIu64
#  define FETCH_SUFFIX_FETCH_OFF_T     LL
#  define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T int
#  define FETCH_PULL_SYS_TYPES_H      1

#elif defined(__VMS)
#  if defined(__VAX)
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  else
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  endif
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T unsigned int

#elif defined(__OS400__)
#  define FETCH_TYPEOF_FETCH_OFF_T     long long
#  define FETCH_FORMAT_FETCH_OFF_T     "lld"
#  define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#  define FETCH_SUFFIX_FETCH_OFF_T     LL
#  define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#  define FETCH_PULL_SYS_TYPES_H      1
#  define FETCH_PULL_SYS_SOCKET_H     1

#elif defined(__MVS__)
#  if defined(_LONG_LONG)
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  else /* _LP64 and default */
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  endif
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#  define FETCH_PULL_SYS_TYPES_H      1
#  define FETCH_PULL_SYS_SOCKET_H     1

#elif defined(__370__)
#  if defined(__IBMC__) || defined(__IBMCPP__)
#    if defined(_LONG_LONG)
#      define FETCH_TYPEOF_FETCH_OFF_T     long long
#      define FETCH_FORMAT_FETCH_OFF_T     "lld"
#      define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#      define FETCH_SUFFIX_FETCH_OFF_T     LL
#      define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#    else /* _LP64 and default */
#      define FETCH_TYPEOF_FETCH_OFF_T     long
#      define FETCH_FORMAT_FETCH_OFF_T     "ld"
#      define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#      define FETCH_SUFFIX_FETCH_OFF_T     L
#      define FETCH_SUFFIX_FETCH_OFF_TU    UL
#    endif
#    define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#    define FETCH_PULL_SYS_TYPES_H      1
#    define FETCH_PULL_SYS_SOCKET_H     1
#  endif

#elif defined(TPF)
#  define FETCH_TYPEOF_FETCH_OFF_T     long
#  define FETCH_FORMAT_FETCH_OFF_T     "ld"
#  define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#  define FETCH_SUFFIX_FETCH_OFF_T     L
#  define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T int

#elif defined(__TINYC__) /* also known as tcc */
#  define FETCH_TYPEOF_FETCH_OFF_T     long long
#  define FETCH_FORMAT_FETCH_OFF_T     "lld"
#  define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#  define FETCH_SUFFIX_FETCH_OFF_T     LL
#  define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#  define FETCH_PULL_SYS_TYPES_H      1
#  define FETCH_PULL_SYS_SOCKET_H     1

#elif defined(__SUNPRO_C) || defined(__SUNPRO_CC) /* Oracle Solaris Studio */
#  if !defined(__LP64) && (defined(__ILP32) ||                          \
                           defined(__i386) ||                           \
                           defined(__sparcv8) ||                        \
                           defined(__sparcv8plus))
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  elif defined(__LP64) || \
        defined(__amd64) || defined(__sparcv9)
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  endif
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#  define FETCH_PULL_SYS_TYPES_H      1
#  define FETCH_PULL_SYS_SOCKET_H     1

#elif defined(__xlc__) /* IBM xlc compiler */
#  if !defined(_LP64)
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  else
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  endif
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#  define FETCH_PULL_SYS_TYPES_H      1
#  define FETCH_PULL_SYS_SOCKET_H     1

#elif defined(__hpux) /* HP aCC compiler */
#  if !defined(_LP64)
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  else
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  endif
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#  define FETCH_PULL_SYS_TYPES_H      1
#  define FETCH_PULL_SYS_SOCKET_H     1

/* ===================================== */
/*    KEEP MSVC THE PENULTIMATE ENTRY    */
/* ===================================== */

#elif defined(_MSC_VER)
#  if (_MSC_VER >= 1800)
#    include <inttypes.h>
#    define FETCH_FORMAT_FETCH_OFF_T     PRId64
#    define FETCH_FORMAT_FETCH_OFF_TU    PRIu64
#  else
#    define FETCH_FORMAT_FETCH_OFF_T     "I64d"
#    define FETCH_FORMAT_FETCH_OFF_TU    "I64u"
#  endif
#  define FETCH_TYPEOF_FETCH_OFF_T     __int64
#  define FETCH_SUFFIX_FETCH_OFF_T     i64
#  define FETCH_SUFFIX_FETCH_OFF_TU    ui64
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T int

/* ===================================== */
/*    KEEP GENERIC GCC THE LAST ENTRY    */
/* ===================================== */

#elif defined(__GNUC__) && !defined(_SCO_DS)
#  if !defined(__LP64__) &&                                             \
  (defined(__ILP32__) || defined(__i386__) || defined(__hppa__) ||      \
   defined(__ppc__) || defined(__powerpc__) || defined(__arm__) ||      \
   defined(__sparc__) || defined(__mips__) || defined(__sh__) ||        \
   defined(__XTENSA__) ||                                               \
   (defined(__SIZEOF_LONG__) && __SIZEOF_LONG__ == 4)  ||               \
   (defined(__LONG_MAX__) && __LONG_MAX__ == 2147483647L))
#    define FETCH_TYPEOF_FETCH_OFF_T     long long
#    define FETCH_FORMAT_FETCH_OFF_T     "lld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "llu"
#    define FETCH_SUFFIX_FETCH_OFF_T     LL
#    define FETCH_SUFFIX_FETCH_OFF_TU    ULL
#  elif defined(__LP64__) || \
        defined(__x86_64__) || defined(__ppc64__) || defined(__sparc64__) || \
        defined(__e2k__) || \
        (defined(__SIZEOF_LONG__) && __SIZEOF_LONG__ == 8) || \
        (defined(__LONG_MAX__) && __LONG_MAX__ == 9223372036854775807L)
#    define FETCH_TYPEOF_FETCH_OFF_T     long
#    define FETCH_FORMAT_FETCH_OFF_T     "ld"
#    define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#    define FETCH_SUFFIX_FETCH_OFF_T     L
#    define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  endif
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T socklen_t
#  define FETCH_PULL_SYS_TYPES_H      1
#  define FETCH_PULL_SYS_SOCKET_H     1

#else
/* generic "safe guess" on old 32-bit style */
#  define FETCH_TYPEOF_FETCH_OFF_T     long
#  define FETCH_FORMAT_FETCH_OFF_T     "ld"
#  define FETCH_FORMAT_FETCH_OFF_TU    "lu"
#  define FETCH_SUFFIX_FETCH_OFF_T     L
#  define FETCH_SUFFIX_FETCH_OFF_TU    UL
#  define FETCH_TYPEOF_FETCH_SOCKLEN_T int
#endif

#ifdef _AIX
/* AIX needs <sys/poll.h> */
#define FETCH_PULL_SYS_POLL_H
#endif

/* FETCH_PULL_SYS_TYPES_H is defined above when inclusion of header file  */
/* sys/types.h is required here to properly make type definitions below. */
#ifdef FETCH_PULL_SYS_TYPES_H
#  include <sys/types.h>
#endif

/* FETCH_PULL_SYS_SOCKET_H is defined above when inclusion of header file  */
/* sys/socket.h is required here to properly make type definitions below. */
#ifdef FETCH_PULL_SYS_SOCKET_H
#  include <sys/socket.h>
#endif

/* FETCH_PULL_SYS_POLL_H is defined above when inclusion of header file    */
/* sys/poll.h is required here to properly make type definitions below.   */
#ifdef FETCH_PULL_SYS_POLL_H
#  include <sys/poll.h>
#endif

/* Data type definition of fetch_socklen_t. */
#ifdef FETCH_TYPEOF_FETCH_SOCKLEN_T
  typedef FETCH_TYPEOF_FETCH_SOCKLEN_T fetch_socklen_t;
#endif

/* Data type definition of fetch_off_t. */

#ifdef FETCH_TYPEOF_FETCH_OFF_T
  typedef FETCH_TYPEOF_FETCH_OFF_T fetch_off_t;
#endif

/*
 * FETCH_ISOCPP and FETCH_OFF_T_C definitions are done here in order to allow
 * these to be visible and exported by the external libfetch interface API,
 * while also making them visible to the library internals, simply including
 * fetch_setup.h, without actually needing to include fetch.h internally.
 * If some day this section would grow big enough, all this should be moved
 * to its own header file.
 */

/*
 * Figure out if we can use the ## preprocessor operator, which is supported
 * by ISO/ANSI C and C++. Some compilers support it without setting __STDC__
 * or  __cplusplus so we need to carefully check for them too.
 */

#if defined(__STDC__) || defined(_MSC_VER) || defined(__cplusplus) || \
  defined(__HP_aCC) || defined(__BORLANDC__) || defined(__LCC__) || \
  defined(__POCC__) || defined(__HIGHC__) || \
  defined(__ILEC400__)
  /* This compiler is believed to have an ISO compatible preprocessor */
#define FETCH_ISOCPP
#else
  /* This compiler is believed NOT to have an ISO compatible preprocessor */
#undef FETCH_ISOCPP
#endif

/*
 * Macros for minimum-width signed and unsigned fetch_off_t integer constants.
 */

#if defined(__BORLANDC__) && (__BORLANDC__ == 0x0551)
#  define FETCHINC_OFF_T_C_HLPR2(x) x
#  define FETCHINC_OFF_T_C_HLPR1(x) FETCHINC_OFF_T_C_HLPR2(x)
#  define FETCH_OFF_T_C(Val)  FETCHINC_OFF_T_C_HLPR1(Val) ## \
                             FETCHINC_OFF_T_C_HLPR1(FETCH_SUFFIX_FETCH_OFF_T)
#  define FETCH_OFF_TU_C(Val) FETCHINC_OFF_T_C_HLPR1(Val) ## \
                             FETCHINC_OFF_T_C_HLPR1(FETCH_SUFFIX_FETCH_OFF_TU)
#else
#  ifdef FETCH_ISOCPP
#    define FETCHINC_OFF_T_C_HLPR2(Val,Suffix) Val ## Suffix
#  else
#    define FETCHINC_OFF_T_C_HLPR2(Val,Suffix) Val/**/Suffix
#  endif
#  define FETCHINC_OFF_T_C_HLPR1(Val,Suffix) FETCHINC_OFF_T_C_HLPR2(Val,Suffix)
#  define FETCH_OFF_T_C(Val)  FETCHINC_OFF_T_C_HLPR1(Val,FETCH_SUFFIX_FETCH_OFF_T)
#  define FETCH_OFF_TU_C(Val) FETCHINC_OFF_T_C_HLPR1(Val,FETCH_SUFFIX_FETCH_OFF_TU)
#endif

#endif /* FETCHINC_SYSTEM_H */
