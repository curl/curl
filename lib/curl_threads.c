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

#if defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "curl_threads.h"

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

  curlx_free(ac);

  (*func)(real_arg);

  return 0;
}

curl_thread_t Curl_thread_create(CURL_THREAD_RETURN_T
                                 (CURL_STDCALL *func) (void *), void *arg)
{
  curl_thread_t t = curlx_malloc(sizeof(pthread_t));
  struct Curl_actual_call *ac = NULL;
  int rc;

  if(t)
    ac = curlx_malloc(sizeof(struct Curl_actual_call));
  if(!(ac && t))
    goto err;

  ac->func = func;
  ac->arg = arg;

  rc = pthread_create(t, NULL, curl_thread_create_thunk, ac);
  if(rc) {
    errno = rc;
    goto err;
  }

  return t;

err:
  curlx_free(t);
  curlx_free(ac);
  return curl_thread_t_null;
}

void Curl_thread_destroy(curl_thread_t *hnd)
{
  if(*hnd != curl_thread_t_null) {
    pthread_detach(**hnd);
    curlx_free(*hnd);
    *hnd = curl_thread_t_null;
  }
}

int Curl_thread_join(curl_thread_t *hnd)
{
  int ret = (pthread_join(**hnd, NULL) == 0);

  curlx_free(*hnd);
  *hnd = curl_thread_t_null;

  return ret;
}

#elif defined(USE_THREADS_WIN32)

curl_thread_t Curl_thread_create(CURL_THREAD_RETURN_T
                                 (CURL_STDCALL *func) (void *), void *arg)
{
  curl_thread_t t = CreateThread(NULL, 0, func, arg, 0, NULL);
  if(!t) {
    DWORD gle = GetLastError();
    /* !checksrc! disable ERRNOVAR 1 */
    errno = (gle == ERROR_ACCESS_DENIED ||
             gle == ERROR_NOT_ENOUGH_MEMORY) ?
             EACCES : EINVAL;
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
  int ret = (WaitForSingleObjectEx(*hnd, INFINITE, FALSE) == WAIT_OBJECT_0);

  Curl_thread_destroy(hnd);

  return ret;
}

#endif /* USE_THREADS_* */
