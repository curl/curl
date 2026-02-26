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

#ifdef USE_THREADS

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
#  define curl_cond_t            pthread_cond_t
#  define Curl_cond_init(c)      pthread_cond_init(c, NULL)
#  define Curl_cond_destroy(c)   pthread_cond_destroy(c)
#elif defined(USE_THREADS_WIN32)
#  define CURL_THREAD_RETURN_T   DWORD
#  define CURL_STDCALL           WINAPI
#  define curl_mutex_t           CRITICAL_SECTION
#  define curl_thread_t          HANDLE
#  define curl_thread_t_null     (HANDLE)0
#  define Curl_mutex_init(m)     InitializeCriticalSectionEx(m, 0, 1)
#  define Curl_mutex_acquire(m)  EnterCriticalSection(m)
#  define Curl_mutex_release(m)  LeaveCriticalSection(m)
#  define Curl_mutex_destroy(m)  DeleteCriticalSection(m)
#  define curl_cond_t            CONDITION_VARIABLE
#  define Curl_cond_init(c)      InitializeConditionVariable(c)
#  define Curl_cond_destroy(c)   (void)(c)
#endif

curl_thread_t Curl_thread_create(CURL_THREAD_RETURN_T
                                 (CURL_STDCALL *func) (void *), void *arg);

void Curl_thread_destroy(curl_thread_t *hnd);

int Curl_thread_join(curl_thread_t *hnd);

void Curl_cond_signal(curl_cond_t *c);
void Curl_cond_wait(curl_cond_t *c, curl_mutex_t *m);
/* Returns CURLE_OPERATION_TIMEDOUT on timeout */
CURLcode Curl_cond_timedwait(curl_cond_t *c, curl_mutex_t *m,
                             uint32_t timeout_ms);

#endif /* USE_THREADS */

#endif /* HEADER_CURL_THREADS_H */
