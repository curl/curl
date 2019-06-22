/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#include "lazylock.h"
#include <curl/curl.h>
#include "select.h"
#include "system_win32.h"
#include "warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
 * Lazy locking for thread synchronization.
 *
 * This is a type of lock that needs no allocated resources, to avoid the
 * chicken-and-egg problem we'd have with thread-safe init/deinit of the lock
 * itself during global init/deinit.
 *
 * The lock is an atomic compare-and-swap with a full memory barrier. Rather
 * than aggressive spin to acquire the lock or efficiently wait in a queue it
 * will wait to lock by sleeping instead. Acquisition is not ordered.
 *
 * The lock is not re-entrant since for our purposes locking global init/deinit
 * that is not needed. Re-entrancy could be implemented but it would limit
 * support to builds that have thread support or some system function to get
 * the current thread id.
 *
 * The implementation of this lock does not (and should not) require libcurl to
 * be built with any threading support.
 */

#ifdef HAVE_LAZYLOCK

typedef enum {
  LAZYLOCK_UNLOCKED,
  /* LAZYLOCK_TRANSIENT, */
  LAZYLOCK_LOCKED
} lockstate;

curl_lazylock_obj curl_initlock;

/* atomic compare-and-swap with full memory barrier */
static long compare_and_swap(LAZYLOCK_ATOMIC_TYPENAME long *target,
                             long oldval, long newval)
{
#ifdef WIN32
  return InterlockedCompareExchange(target, newval, oldval);
#elif defined(__clang__)
  /* C11's atomic_compare_exchange_strong with memory_order_seq_cst */
  __c11_atomic_compare_exchange_strong(target, &oldval, newval,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  return oldval;
#elif defined(__GNUC__)
  /* gcc says intel is unclear on whether or not __sync_val_compare_and_swap
     gives a full memory barrier so play it safe and call __sync_synchronize.
     https://gcc.gnu.org/onlinedocs/gcc-4.1.2/gcc/Atomic-Builtins.html */
  __sync_synchronize();
  return __sync_val_compare_and_swap(target, oldval, newval);
#else
#error "compare-and-swap function not implemented"
#endif
}

void Curl_lazylock_lock(curl_lazylock_obj *lock)
{
  int milliseconds = 1;

  for(;;) {
    long prev = compare_and_swap(lock, LAZYLOCK_UNLOCKED, LAZYLOCK_LOCKED);

    /* if the previous state was UNLOCKED then we own LOCKED */
    if(prev == LAZYLOCK_UNLOCKED)
      return;

    Curl_wait_ms(milliseconds);

    if(milliseconds < 1024)
      milliseconds *= 2;
  }
}

void Curl_lazylock_unlock(curl_lazylock_obj *lock)
{
  long prev = compare_and_swap(lock, LAZYLOCK_LOCKED, LAZYLOCK_UNLOCKED);
  /* the previous state should always be LOCKED */
  DEBUGASSERT(prev == LAZYLOCK_LOCKED);
  (void)prev;
  return;
}

#endif /* HAVE_LAZYLOCK */
