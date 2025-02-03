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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "test.h"

#include "testutil.h"
#include "warnless.h"

#define NUM_THREADS 100

#ifdef _WIN32
#if defined(_WIN32_WCE) || defined(FETCH_WINDOWS_UWP)
static DWORD WINAPI run_thread(LPVOID ptr)
#else
#include <process.h>
static unsigned int WINAPI run_thread(void *ptr)
#endif
{
  FETCHcode *result = ptr;

  *result = fetch_global_init(FETCH_GLOBAL_ALL);
  if(*result == FETCHE_OK)
    fetch_global_cleanup();

  return 0;
}

FETCHcode test(char *URL)
{
#if defined(_WIN32_WCE) || defined(FETCH_WINDOWS_UWP)
  typedef HANDLE fetch_win_thread_handle_t;
#else
  typedef uintptr_t fetch_win_thread_handle_t;
#endif
  FETCHcode results[NUM_THREADS];
  fetch_win_thread_handle_t ths[NUM_THREADS];
  unsigned tid_count = NUM_THREADS, i;
  int test_failure = 0;
  fetch_version_info_data *ver;
  (void) URL;

  ver = fetch_version_info(FETCHVERSION_NOW);
  if((ver->features & FETCH_VERSION_THREADSAFE) == 0) {
    fprintf(stderr, "%s:%d On Windows but the "
            "FETCH_VERSION_THREADSAFE feature flag is not set\n",
            __FILE__, __LINE__);
    return (FETCHcode)-1;
  }

  /* On Windows libfetch global init/cleanup calls LoadLibrary/FreeLibrary for
     secur32.dll and iphlpapi.dll. Here we load them beforehand so that when
     libfetch calls LoadLibrary/FreeLibrary it only increases/decreases the
     library's refcount rather than actually loading/unloading the library,
     which would affect the test runtime. */
  (void)win32_load_system_library(TEXT("secur32.dll"));
  (void)win32_load_system_library(TEXT("iphlpapi.dll"));

  for(i = 0; i < tid_count; i++) {
    fetch_win_thread_handle_t th;
    results[i] = FETCH_LAST; /* initialize with invalid value */
#if defined(_WIN32_WCE) || defined(FETCH_WINDOWS_UWP)
    th = CreateThread(NULL, 0, run_thread, &results[i], 0, NULL);
#else
    th = _beginthreadex(NULL, 0, run_thread, &results[i], 0, NULL);
#endif
    if(!th) {
      fprintf(stderr, "%s:%d Couldn't create thread, errno %lu\n",
              __FILE__, __LINE__, GetLastError());
      tid_count = i;
      test_failure = -1;
      goto cleanup;
    }
    ths[i] = th;
  }

cleanup:
  for(i = 0; i < tid_count; i++) {
    WaitForSingleObject((HANDLE)ths[i], INFINITE);
    CloseHandle((HANDLE)ths[i]);
    if(results[i] != FETCHE_OK) {
      fprintf(stderr, "%s:%d thread[%u]: fetch_global_init() failed,"
              "with code %d (%s)\n", __FILE__, __LINE__,
              i, (int) results[i], fetch_easy_strerror(results[i]));
      test_failure = -1;
    }
  }

  return (FETCHcode)test_failure;
}

#elif defined(HAVE_PTHREAD_H)
#include <pthread.h>
#include <unistd.h>

static void *run_thread(void *ptr)
{
  FETCHcode *result = ptr;

  *result = fetch_global_init(FETCH_GLOBAL_ALL);
  if(*result == FETCHE_OK)
    fetch_global_cleanup();

  return NULL;
}

FETCHcode test(char *URL)
{
  FETCHcode results[NUM_THREADS];
  pthread_t tids[NUM_THREADS];
  unsigned tid_count = NUM_THREADS, i;
  FETCHcode test_failure = FETCHE_OK;
  fetch_version_info_data *ver;
  (void) URL;

  ver = fetch_version_info(FETCHVERSION_NOW);
  if((ver->features & FETCH_VERSION_THREADSAFE) == 0) {
    fprintf(stderr, "%s:%d Have pthread but the "
            "FETCH_VERSION_THREADSAFE feature flag is not set\n",
            __FILE__, __LINE__);
    return (FETCHcode)-1;
  }

  for(i = 0; i < tid_count; i++) {
    int res;
    results[i] = FETCH_LAST; /* initialize with invalid value */
    res = pthread_create(&tids[i], NULL, run_thread, &results[i]);
    if(res) {
      fprintf(stderr, "%s:%d Couldn't create thread, errno %d\n",
              __FILE__, __LINE__, res);
      tid_count = i;
      test_failure = (FETCHcode)-1;
      goto cleanup;
    }
  }

cleanup:
  for(i = 0; i < tid_count; i++) {
    pthread_join(tids[i], NULL);
    if(results[i] != FETCHE_OK) {
      fprintf(stderr, "%s:%d thread[%u]: fetch_global_init() failed,"
              "with code %d (%s)\n", __FILE__, __LINE__,
              i, (int) results[i], fetch_easy_strerror(results[i]));
      test_failure = (FETCHcode)-1;
    }
  }

  return test_failure;
}

#else /* without pthread or Windows, this test doesn't work */
FETCHcode test(char *URL)
{
  fetch_version_info_data *ver;
  (void)URL;

  ver = fetch_version_info(FETCHVERSION_NOW);
  if((ver->features & FETCH_VERSION_THREADSAFE) != 0) {
    fprintf(stderr, "%s:%d No pthread but the "
            "FETCH_VERSION_THREADSAFE feature flag is set\n",
            __FILE__, __LINE__);
    return (FETCHcode)-1;
  }
  return FETCHE_OK;
}
#endif
