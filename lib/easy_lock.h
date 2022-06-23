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

#define curl_simple_lock SRWLOCK
#define CURL_SIMPLE_LOCK_INIT SRWLOCK_INIT

#define curl_simple_lock_lock(m) AcquireSRWLockExclusive(m)
#define curl_simple_lock_unlock(m) ReleaseSRWLockExclusive(m)

#elif defined (HAVE_ATOMIC)
#include <stdatomic.h>

#define curl_simple_lock atomic_bool
#define CURL_SIMPLE_LOCK_INIT false

static inline void curl_simple_lock_lock(curl_simple_lock *lock)
{
  for(;;) {
    if(!atomic_exchange_explicit(lock, true, memory_order_acquire))
      break;
    /* Reduce cache coherency traffic */
    while(atomic_load_explicit(lock, memory_order_relaxed)) {
      /* Reduce load (not mandatory) */
#if defined(__i386__) || defined(__x86_64__)
      __builtin_ia32_pause();
#elif defined(__aarch64__)
      asm volatile("yield" ::: "memory");
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
