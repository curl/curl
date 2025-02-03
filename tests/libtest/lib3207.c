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
#include "memdebug.h"

#include <stdio.h>

#if defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)
#if defined(USE_THREADS_POSIX)
#include <pthread.h>
#endif
#include "fetch_threads.h"
#endif

#define CAINFO libtest_arg2
#define THREAD_SIZE 16
#define PER_THREAD_SIZE 8

struct Ctx
{
  const char *URL;
  FETCHSH *share;
  int result;
  int thread_id;
  struct fetch_slist *contents;
};

static size_t write_memory_callback(char *contents, size_t size,
                                    size_t nmemb, void *userp)
{
  /* append the data to contents */
  size_t realsize = size * nmemb;
  struct Ctx *mem = (struct Ctx *)userp;
  char *data = (char *)malloc(realsize + 1);
  struct fetch_slist *item_append = NULL;
  if (!data)
  {
    printf("not enough memory (malloc returned NULL)\n");
    return 0;
  }
  memcpy(data, contents, realsize);
  data[realsize] = '\0';
  item_append = fetch_slist_append(mem->contents, data);
  free(data);
  if (item_append)
  {
    mem->contents = item_append;
  }
  else
  {
    printf("not enough memory (fetch_slist_append returned NULL)\n");
    return 0;
  }
  return realsize;
}

static
#if defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)
#if defined(_WIN32_WCE) || defined(FETCH_WINDOWS_UWP)
    DWORD
#else
    unsigned int
#endif
        FETCH_STDCALL
#else
    unsigned int
#endif
        test_thread(void *ptr)
{
  struct Ctx *ctx = (struct Ctx *)ptr;
  FETCHcode res = FETCHE_OK;

  int i;

  /* Loop the transfer and cleanup the handle properly every lap. This will
     still reuse ssl session since the pool is in the shared object! */
  for (i = 0; i < PER_THREAD_SIZE; i++)
  {
    FETCH *fetch = fetch_easy_init();
    if (fetch)
    {
      fetch_easy_setopt(fetch, FETCHOPT_URL, (char *)ctx->URL);

      /* use the share object */
      fetch_easy_setopt(fetch, FETCHOPT_SHARE, ctx->share);
      fetch_easy_setopt(fetch, FETCHOPT_CAINFO, CAINFO);

      fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, write_memory_callback);
      fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, ptr);
      fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1);

      /* Perform the request, res will get the return code */
      res = fetch_easy_perform(fetch);

      /* always cleanup */
      fetch_easy_cleanup(fetch);
      /* Check for errors */
      if (res != FETCHE_OK)
      {
        fprintf(stderr, "fetch_easy_perform() failed: %s\n",
                fetch_easy_strerror(res));
        goto test_cleanup;
      }
    }
  }

test_cleanup:
  ctx->result = (int)res;
  return 0;
}

#if defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)

static void test_lock(FETCH *handle, fetch_lock_data data,
                      fetch_lock_access laccess, void *useptr)
{
  fetch_mutex_t *mutexes = (fetch_mutex_t *)useptr;
  (void)handle;
  (void)laccess;
  Fetch_mutex_acquire(&mutexes[data]);
}

static void test_unlock(FETCH *handle, fetch_lock_data data, void *useptr)
{
  fetch_mutex_t *mutexes = (fetch_mutex_t *)useptr;
  (void)handle;
  Fetch_mutex_release(&mutexes[data]);
}

static void execute(FETCHSH *share, struct Ctx *ctx)
{
  int i;
  fetch_mutex_t mutexes[FETCH_LOCK_DATA_LAST - 1];
  fetch_thread_t thread[THREAD_SIZE];
  for (i = 0; i < FETCH_LOCK_DATA_LAST - 1; i++)
  {
    Fetch_mutex_init(&mutexes[i]);
  }
  fetch_share_setopt(share, FETCHSHOPT_LOCKFUNC, test_lock);
  fetch_share_setopt(share, FETCHSHOPT_UNLOCKFUNC, test_unlock);
  fetch_share_setopt(share, FETCHSHOPT_USERDATA, (void *)mutexes);
  fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_SSL_SESSION);

  for (i = 0; i < THREAD_SIZE; i++)
  {
    thread[i] = Fetch_thread_create(test_thread, (void *)&ctx[i]);
  }
  for (i = 0; i < THREAD_SIZE; i++)
  {
    if (thread[i])
    {
      Fetch_thread_join(&thread[i]);
      Fetch_thread_destroy(thread[i]);
    }
  }
  fetch_share_setopt(share, FETCHSHOPT_LOCKFUNC, NULL);
  fetch_share_setopt(share, FETCHSHOPT_UNLOCKFUNC, NULL);
  for (i = 0; i < FETCH_LOCK_DATA_LAST - 1; i++)
  {
    Fetch_mutex_destroy(&mutexes[i]);
  }
}

#else /* without pthread, run serially */

static void execute(FETCHSH *share, struct Ctx *ctx)
{
  int i;
  (void)share;
  for (i = 0; i < THREAD_SIZE; i++)
  {
    test_thread((void *)&ctx[i]);
  }
}

#endif

FETCHcode test(char *URL)
{
  int res = 0;
  int i;
  FETCHSH *share;
  struct Ctx ctx[THREAD_SIZE];

  fetch_global_init(FETCH_GLOBAL_ALL);

  share = fetch_share_init();
  if (!share)
  {
    fprintf(stderr, "fetch_share_init() failed\n");
    goto test_cleanup;
  }

  for (i = 0; i < THREAD_SIZE; i++)
  {
    ctx[i].share = share;
    ctx[i].URL = URL;
    ctx[i].thread_id = i;
    ctx[i].result = 0;
    ctx[i].contents = NULL;
  }

  execute(share, ctx);

  for (i = 0; i < THREAD_SIZE; i++)
  {
    if (ctx[i].result)
    {
      res = ctx[i].result;
    }
    else
    {
      struct fetch_slist *item = ctx[i].contents;
      while (item)
      {
        printf("%s", item->data);
        item = item->next;
      }
    }
    fetch_slist_free_all(ctx[i].contents);
  }

test_cleanup:
  if (share)
    fetch_share_cleanup(share);
  fetch_global_cleanup();
  return (FETCHcode)res;
}
