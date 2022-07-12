/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#define GLOBAL_INIT_IS_THREADSAFE

#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x600

#ifdef __MINGW32__
#ifndef __MINGW64_VERSION_MAJOR
#if (__MINGW32_MAJOR_VERSION < 5) || \
    (__MINGW32_MAJOR_VERSION == 5 && __MINGW32_MINOR_VERSION == 0)
/* mingw >= 5.0.1 defines SRWLOCK, and slightly different from MS define */
typedef PVOID SRWLOCK, *PSRWLOCK;
#endif
#endif
#ifndef SRWLOCK_INIT
#define SRWLOCK_INIT NULL
#endif
#endif /* __MINGW32__ */

#define curl_simple_lock SRWLOCK
#define CURL_SIMPLE_LOCK_INIT SRWLOCK_INIT

#define curl_simple_lock_lock(m) AcquireSRWLockExclusive(m)
#define curl_simple_lock_unlock(m) ReleaseSRWLockExclusive(m)

#elif defined (HAVE_ATOMIC)
#include <stdatomic.h>
#if defined(HAVE_SCHED_YIELD)
#include <sched.h>
#endif

#define curl_simple_lock atomic_int
#define CURL_SIMPLE_LOCK_INIT 0

/* a clang-thing */
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#ifndef __INTEL_COMPILER
/* The Intel compiler tries to look like GCC *and* clang *and* lies in its
   __has_builtin() function, so override it. */

/* if GCC on i386/x86_64 or if the built-in is present */
#if ( (defined(__GNUC__) && !defined(__clang__)) &&     \
      (defined(__i386__) || defined(__x86_64__))) ||    \
  __has_builtin(__builtin_ia32_pause)
#define HAVE_BUILTIN_IA32_PAUSE
#endif

#endif

static inline void curl_simple_lock_lock(curl_simple_lock *lock)
{
  for(;;) {
    if(!atomic_exchange_explicit(lock, true, memory_order_acquire))
      break;
    /* Reduce cache coherency traffic */
    while(atomic_load_explicit(lock, memory_order_relaxed)) {
      /* Reduce load (not mandatory) */
#ifdef HAVE_BUILTIN_IA32_PAUSE
      __builtin_ia32_pause();
#elif defined(__aarch64__)
      __asm__ volatile("yield" ::: "memory");
#elif defined(HAVE_SCHED_YIELD)
      sched_yield();
#endif
    }
  }
}

static inline void curl_simple_lock_unlock(curl_simple_lock *lock)
{
  atomic_store_explicit(lock, false, memory_order_release);
}

#else

#undef  GLOBAL_INIT_IS_THREADSAFE

#endif
