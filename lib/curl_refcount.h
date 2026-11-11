#ifndef HEADER_CURL_REFCOUNT_H
#define HEADER_CURL_REFCOUNT_H
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
#include "curl_setup.h"

/* Reference counter for objects that an easy handle shares with
 * connections, like `struct Curl_peer` and `struct Curl_creds`. Once a
 * transfer has been removed from its multi handle, the application may use
 * the easy handle in another thread (libcurl-thread(3)) while the multi
 * handle keeps using the connection, so the counter is updated atomically.
 * Without atomics, curl_refcount.c updates it under a lock from easy_lock.h,
 * so it is thread-safe whenever libcurl reports CURL_VERSION_THREADSAFE.
 *
 * Curl_refcount_decr() returns the new value of the counter.
 */

#ifdef _WIN32

typedef LONG volatile curl_refcount;

#define Curl_refcount_init(c, v) (*(c) = (LONG)(v))
#define Curl_refcount_get(c)     ((uint32_t)*(c))
#define Curl_refcount_incr(c)    ((void)InterlockedIncrement(c))
#define Curl_refcount_decr(c)    ((uint32_t)InterlockedDecrement(c))

#elif defined(HAVE_ATOMIC) && defined(HAVE_STDATOMIC_H)
#include <stdatomic.h>

typedef atomic_uint curl_refcount;

#define Curl_refcount_init(c, v) atomic_init(c, v)
#define Curl_refcount_get(c)     atomic_load_explicit(c, memory_order_relaxed)
#define Curl_refcount_incr(c) \
  ((void)atomic_fetch_add_explicit(c, 1U, memory_order_relaxed))
#define Curl_refcount_decr(c) \
  (atomic_fetch_sub_explicit(c, 1U, memory_order_acq_rel) - 1U)

#else /* see curl_refcount.c */

typedef uint32_t curl_refcount;

#define Curl_refcount_init(c, v) (*(c) = (v))
uint32_t Curl_refcount_get(curl_refcount *c);
void Curl_refcount_incr(curl_refcount *c);
uint32_t Curl_refcount_decr(curl_refcount *c);

#endif

#endif /* HEADER_CURL_REFCOUNT_H */
