/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Hoi-Ho Chan, <hoiho.chan@gmail.com>
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
#include "../curl_setup.h"

#if defined(USE_MBEDTLS) && \
  ((defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)) || defined(_WIN32))

#if defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)
#  include <pthread.h>
#  define MBEDTLS_MUTEX_T pthread_mutex_t
#elif defined(_WIN32)
#  define MBEDTLS_MUTEX_T HANDLE
#endif

#include "mbedtls_threadlock.h"

/* This array stores the mutexes available to mbedTLS */
static MBEDTLS_MUTEX_T mutex_buf[2];

int Curl_mbedtlsthreadlock_thread_setup(void)
{
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(mutex_buf); i++) {
#if defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)
    if(pthread_mutex_init(&mutex_buf[i], NULL))
      return 0; /* pthread_mutex_init failed */
#elif defined(_WIN32)
    mutex_buf[i] = CreateMutex(0, FALSE, 0);
    if(mutex_buf[i] == 0)
      return 0;  /* CreateMutex failed */
#endif /* USE_THREADS_POSIX && HAVE_PTHREAD_H */
  }

  return 1; /* OK */
}

int Curl_mbedtlsthreadlock_thread_cleanup(void)
{
  size_t i;

  for(i = 0; i < CURL_ARRAYSIZE(mutex_buf); i++) {
#if defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)
    if(pthread_mutex_destroy(&mutex_buf[i]))
      return 0; /* pthread_mutex_destroy failed */
#elif defined(_WIN32)
    if(!CloseHandle(mutex_buf[i]))
      return 0; /* CloseHandle failed */
#endif /* USE_THREADS_POSIX && HAVE_PTHREAD_H */
  }

  return 1; /* OK */
}

int Curl_mbedtlsthreadlock_lock_function(size_t n)
{
  if(n < CURL_ARRAYSIZE(mutex_buf)) {
#if defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)
    if(pthread_mutex_lock(&mutex_buf[n])) {
      DEBUGF(curl_mfprintf(stderr, "Error: "
                           "mbedtlsthreadlock_lock_function failed\n"));
      return 0; /* pthread_mutex_lock failed */
    }
#elif defined(_WIN32)
    if(WaitForSingleObject(mutex_buf[n], INFINITE) == WAIT_FAILED) {
      DEBUGF(curl_mfprintf(stderr, "Error: "
                           "mbedtlsthreadlock_lock_function failed\n"));
      return 0; /* pthread_mutex_lock failed */
    }
#endif /* USE_THREADS_POSIX && HAVE_PTHREAD_H */
  }
  return 1; /* OK */
}

int Curl_mbedtlsthreadlock_unlock_function(size_t n)
{
  if(n < CURL_ARRAYSIZE(mutex_buf)) {
#if defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)
    if(pthread_mutex_unlock(&mutex_buf[n])) {
      DEBUGF(curl_mfprintf(stderr, "Error: "
                           "mbedtlsthreadlock_unlock_function failed\n"));
      return 0; /* pthread_mutex_unlock failed */
    }
#elif defined(_WIN32)
    if(!ReleaseMutex(mutex_buf[n])) {
      DEBUGF(curl_mfprintf(stderr, "Error: "
                           "mbedtlsthreadlock_unlock_function failed\n"));
      return 0; /* pthread_mutex_lock failed */
    }
#endif /* USE_THREADS_POSIX && HAVE_PTHREAD_H */
  }
  return 1; /* OK */
}

#endif /* USE_MBEDTLS */
