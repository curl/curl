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
#  define CURL_STDCALL
#  define curl_mutex_t           pthread_mutex_t
#  define curl_thread_t          pthread_t *
#  define curl_thread_t_null     (pthread_t *)0
#  define Curl_mutex_init(m)     pthread_mutex_init(m, NULL)
#  define Curl_mutex_acquire(m)  pthread_mutex_lock(m)
#  define Curl_mutex_release(m)  pthread_mutex_unlock(m)
#  define Curl_mutex_destroy(m)  pthread_mutex_destroy(m)
#elif defined(USE_THREADS_WIN32)
#  define CURL_STDCALL           __stdcall
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
#else
#  define CURL_STDCALL
#endif

#if defined(CURL_WINDOWS_UWP) || defined(UNDER_CE)
#define CURL_THREAD_RETURN_T DWORD
#else
#define CURL_THREAD_RETURN_T unsigned int
#endif

#if defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)

curl_thread_t Curl_thread_create(CURL_THREAD_RETURN_T
                                 (CURL_STDCALL *func) (void *), void *arg);

void Curl_thread_destroy(curl_thread_t *hnd);

int Curl_thread_join(curl_thread_t *hnd);

int Curl_thread_cancel(curl_thread_t *hnd);

#if defined(USE_THREADS_POSIX) && defined(PTHREAD_CANCEL_ENABLE)
#define Curl_thread_push_cleanup(a,b)   pthread_cleanup_push(a,b)
#define Curl_thread_pop_cleanup()       pthread_cleanup_pop(0)
#define Curl_thread_enable_cancel()     \
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)
#define Curl_thread_disable_cancel()     \
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)
#else
#define Curl_thread_push_cleanup(a,b)   ((void)a,(void)b)
#define Curl_thread_pop_cleanup()       Curl_nop_stmt
#define Curl_thread_enable_cancel()     Curl_nop_stmt
#define Curl_thread_disable_cancel()    Curl_nop_stmt
#endif

#endif /* USE_THREADS_POSIX || USE_THREADS_WIN32 */

#endif /* HEADER_CURL_THREADS_H */
