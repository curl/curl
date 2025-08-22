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

#include <curl/curl.h>

#ifdef USE_THREADS_POSIX
#  ifdef HAVE_PTHREAD_H
#    include <pthread.h>
#  endif
#elif defined(USE_THREADS_WIN32)
#  include <process.h>
#endif

#include "curl_threads.h"
#include "curl_memory.h"
/* The last #include FILE should be: */
#include "memdebug.h"

#ifdef USE_THREADS_POSIX

struct Curl_actual_call {
  unsigned int (*func)(void *);
  void *arg;
};

static void *curl_thread_create_thunk(void *arg)
{
  struct Curl_actual_call *ac = arg;
  unsigned int (*func)(void *) = ac->func;
  void *real_arg = ac->arg;

  free(ac);

  (*func)(real_arg);

  return 0;
}

curl_thread_t Curl_thread_create(CURL_THREAD_RETURN_T
                                 (CURL_STDCALL *func) (void *), void *arg)
{
  curl_thread_t t = malloc(sizeof(pthread_t));
  struct Curl_actual_call *ac = malloc(sizeof(struct Curl_actual_call));
  if(!(ac && t))
    goto err;

  ac->func = func;
  ac->arg = arg;

  if(pthread_create(t, NULL, curl_thread_create_thunk, ac) != 0)
    goto err;

  return t;

err:
  free(t);
  free(ac);
  return curl_thread_t_null;
}

void Curl_thread_destroy(curl_thread_t *hnd)
{
  if(*hnd != curl_thread_t_null) {
    pthread_detach(**hnd);
    free(*hnd);
    *hnd = curl_thread_t_null;
  }
}

int Curl_thread_join(curl_thread_t *hnd)
{
  int ret = (pthread_join(**hnd, NULL) == 0);

  free(*hnd);
  *hnd = curl_thread_t_null;

  return ret;
}

/* do not use pthread_cancel if:
 * - pthread_cancel seems to be absent
 * - on FreeBSD, as we see hangers in CI testing
 * - this is a -fsanitize=thread build
 *   (clang sanitizer reports false positive when functions to not return)
 */
#if defined(PTHREAD_CANCEL_ENABLE) && !defined(__FreeBSD__)
#if defined(__has_feature)
#  if !__has_feature(thread_sanitizer)
#define USE_PTHREAD_CANCEL
#  endif
#else /* __has_feature */
#define USE_PTHREAD_CANCEL
#endif /* !__has_feature */
#endif /* PTHREAD_CANCEL_ENABLE && !__FreeBSD__ */

int Curl_thread_cancel(curl_thread_t *hnd)
{
  (void)hnd;
  if(*hnd != curl_thread_t_null)
#ifdef USE_PTHREAD_CANCEL
    return pthread_cancel(**hnd);
#else
    return 1; /* not supported */
#endif
  return 0;
}

#elif defined(USE_THREADS_WIN32)

curl_thread_t Curl_thread_create(CURL_THREAD_RETURN_T
                                 (CURL_STDCALL *func) (void *), void *arg)
{
#if defined(CURL_WINDOWS_UWP) || defined(UNDER_CE)
  typedef HANDLE curl_win_thread_handle_t;
#else
  typedef uintptr_t curl_win_thread_handle_t;
#endif
  curl_thread_t t;
  curl_win_thread_handle_t thread_handle;
#if defined(CURL_WINDOWS_UWP) || defined(UNDER_CE)
  thread_handle = CreateThread(NULL, 0, func, arg, 0, NULL);
#else
  thread_handle = _beginthreadex(NULL, 0, func, arg, 0, NULL);
#endif
  t = (curl_thread_t)thread_handle;
  if((t == 0) || (t == LongToHandle(-1L))) {
#ifdef UNDER_CE
    DWORD gle = GetLastError();
    /* !checksrc! disable ERRNOVAR 1 */
    int err = (gle == ERROR_ACCESS_DENIED ||
               gle == ERROR_NOT_ENOUGH_MEMORY) ?
               EACCES : EINVAL;
    CURL_SETERRNO(err);
#endif
    return curl_thread_t_null;
  }
  return t;
}

void Curl_thread_destroy(curl_thread_t *hnd)
{
  if(*hnd != curl_thread_t_null) {
    CloseHandle(*hnd);
    *hnd = curl_thread_t_null;
  }
}

int Curl_thread_join(curl_thread_t *hnd)
{
#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < _WIN32_WINNT_VISTA)
  int ret = (WaitForSingleObject(*hnd, INFINITE) == WAIT_OBJECT_0);
#else
  int ret = (WaitForSingleObjectEx(*hnd, INFINITE, FALSE) == WAIT_OBJECT_0);
#endif

  Curl_thread_destroy(hnd);


  return ret;
}

int Curl_thread_cancel(curl_thread_t *hnd)
{
  if(*hnd != curl_thread_t_null) {
    return 1; /* not supported */
  }
  return 0;
}

#endif /* USE_THREADS_* */
