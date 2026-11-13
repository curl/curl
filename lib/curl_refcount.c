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

#include "curl_refcount.h"

#if !defined(_WIN32) && !(defined(HAVE_ATOMIC) && defined(HAVE_STDATOMIC_H))

#include "easy_lock.h"

#ifdef GLOBAL_INIT_IS_THREADSAFE
static curl_simple_lock s_refcount_lock = CURL_SIMPLE_LOCK_INIT;
#define refcount_lock()   curl_simple_lock_lock(&s_refcount_lock)
#define refcount_unlock() curl_simple_lock_unlock(&s_refcount_lock)
#else
#define refcount_lock()   Curl_nop_stmt
#define refcount_unlock() Curl_nop_stmt
#endif

uint32_t Curl_refcount_get(curl_refcount *c)
{
  uint32_t value;
  refcount_lock();
  value = *c;
  refcount_unlock();
  return value;
}

void Curl_refcount_incr(curl_refcount *c)
{
  refcount_lock();
  ++(*c);
  refcount_unlock();
}

uint32_t Curl_refcount_decr(curl_refcount *c)
{
  uint32_t value;
  refcount_lock();
  value = --(*c);
  refcount_unlock();
  return value;
}

#endif
