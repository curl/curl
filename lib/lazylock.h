#ifndef HEADER_LAZYLOCK_H
#define HEADER_LAZYLOCK_H
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

#if defined(WIN32) || defined(__clang__) || defined(__GNUC__)
#define HAVE_LAZYLOCK
#endif

#ifdef HAVE_LAZYLOCK

/* lazylock object is just the state. type long due to Windows CAS type. */
#ifdef __clang__
#define LAZYLOCK_ATOMIC_TYPENAME _Atomic
#else
#define LAZYLOCK_ATOMIC_TYPENAME
#endif

typedef LAZYLOCK_ATOMIC_TYPENAME long curl_lazylock_obj;

extern curl_lazylock_obj curl_initlock;

/* lazylock is not re-entrant */
void Curl_lazylock_lock(curl_lazylock_obj *lock);
void Curl_lazylock_unlock(curl_lazylock_obj *lock);

#define LOCK_GLOBAL_INIT() Curl_lazylock_lock(&curl_initlock)
#define UNLOCK_GLOBAL_INIT() Curl_lazylock_unlock(&curl_initlock)

#else
#define LOCK_GLOBAL_INIT()
#define UNLOCK_GLOBAL_INIT()
#endif /* HAVE_LAZYLOCK */

#endif /* HEADER_LAZYLOCK_H */
