#ifndef HEADER_CURL_THREADS_H
#define HEADER_CURL_THREADS_H
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

#ifdef USE_THREADS_POSIX
#  define CURL_THREAD_RETURN_T   unsigned int
#  define CURL_STDCALL
#  define curl_mutex_t           pthread_mutex_t
#  define curl_thread_t          pthread_t *
#  define curl_thread_t_null     (pthread_t *)0
#  define Curl_mutex_init(m)     pthread_mutex_init(m, NULL)
#  define Curl_mutex_acquire(m)  pthread_mutex_lock(m)
#  define Curl_mutex_release(m)  pthread_mutex_unlock(m)
#  define Curl_mutex_destroy(m)  pthread_mutex_destroy(m)
#  define curl_thread_id         pthread_t
#  define curl_thread_self       pthread_self
#  define curl_thread_equal(a,b) pthread_equal(a, b)
#elif defined(USE_THREADS_WIN32)
#  define CURL_THREAD_RETURN_T   DWORD
#  define CURL_STDCALL           WINAPI
#  define curl_mutex_t           CRITICAL_SECTION
#  define curl_thread_t          HANDLE
#  define curl_thread_t_null     (HANDLE)0
#  if !defined(_WIN32_WINNT) || (_WIN32_WINNT < _WIN32_WINNT_VISTA)
#    define Curl_mutex_init(m)   InitializeCriticalSection(m)
#  else
#    define Curl_mutex_init(m)   InitializeCriticalSectionEx(m, 0, 1)
#  endif
#  define Curl_mutex_acquire(m)  EnterCriticalSection(m)
#  define Curl_mutex_release(m)  LeaveCriticalSection(m)
#  define Curl_mutex_destroy(m)  DeleteCriticalSection(m)
#  define curl_thread_id         HANDLE
#  define curl_thread_self       GetCurrentThread
#  define curl_thread_equal(a,b) ((a) == (b))
#endif

#if defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)

curl_thread_t Curl_thread_create(CURL_THREAD_RETURN_T
                                 (CURL_STDCALL *func) (void *), void *arg);

void Curl_thread_destroy(curl_thread_t *hnd);

int Curl_thread_join(curl_thread_t *hnd);

#endif /* USE_THREADS_POSIX || USE_THREADS_WIN32 */


#ifdef USE_THREAD_GUARDS

struct Curl_easy;

struct curl_tguard {
  curl_mutex_t mutx;
  curl_thread_id tid;
  int depth;
  BIT(initialised);
};

void Curl_tguard_init(struct curl_tguard *tguard);
void Curl_tguard_destroy(struct curl_tguard *tguard);
/* Return FALSE if called from another thread during an active call.
 * Otherwise, remember the calling thread. */
bool Curl_tguard_enter(struct curl_tguard *tguard);
/* End a recorded thread call */
void Curl_tguard_leave(struct curl_tguard *tguard);

#endif /* USE_THREAD_GUARDS */

#endif /* HEADER_CURL_THREADS_H */
