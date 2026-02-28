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

#if defined(USE_THREADS) && defined(CURLRES_THREADED)

#if defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)
#include <pthread.h>
#endif

#include "llist.h"
#include "curl_threads.h"
#include "curlx/timeval.h"
#include "thrdpool.h"
#ifdef CURLVERBOSE
#include "curl_trc.h"
#include "urldata.h"
#endif


struct thrdslot {
  struct Curl_llist_node node;
  struct curl_thrdpool *tpool;
  curl_thread_t thread;
  curl_cond_t await;
  struct curltime starttime;
  const char *work_description;
  timediff_t work_timeout_ms;
  uint32_t id;
  BIT(running);
  BIT(idle);
};

struct curl_thrdpool {
  char *name;
  uint64_t refcount;
  curl_mutex_t lock;
  curl_cond_t await;
  struct Curl_llist slots;
  struct Curl_llist zombies;
  Curl_thrdpool_take_item_cb *fn_take;
  Curl_thrdpool_process_item_cb *fn_process;
  Curl_thrdpool_return_item_cb *fn_return;
  void *fn_user_data;
  CURLcode fatal_err;
  uint32_t min_threads;
  uint32_t max_threads;
  uint32_t idle_time_ms;
  uint32_t next_id;
  BIT(aborted);
  BIT(detached);
};

static void thrdpool_join_zombies(struct curl_thrdpool *tpool);
static bool thrdpool_unlink(struct curl_thrdpool *tpool, bool locked);

static void thrdslot_destroy(struct thrdslot *tslot)
{
  DEBUGASSERT(tslot->thread == curl_thread_t_null);
  DEBUGASSERT(!tslot->running);
  Curl_cond_destroy(&tslot->await);
  curlx_free(tslot);
}

static void thrdslot_done(struct thrdslot *tslot)
{
  struct curl_thrdpool *tpool = tslot->tpool;

  DEBUGASSERT(Curl_node_llist(&tslot->node) == &tpool->slots);
  Curl_node_remove(&tslot->node);
  tslot->running = FALSE;
  Curl_llist_append(&tpool->zombies, tslot, &tslot->node);
  Curl_cond_signal(&tpool->await);
}

static CURL_THREAD_RETURN_T CURL_STDCALL thrdslot_run(void *arg)
{
  struct thrdslot *tslot = arg;
  struct curl_thrdpool *tpool = tslot->tpool;
  void *item;

  Curl_mutex_acquire(&tpool->lock);
  DEBUGASSERT(Curl_node_llist(&tslot->node) == &tpool->slots);
  for(;;) {
    while(!tpool->aborted) {
      tslot->work_description = NULL;
      tslot->work_timeout_ms = 0;
      item = tpool->fn_take(tpool->fn_user_data, &tslot->work_description,
                            &tslot->work_timeout_ms);
      if(!item)
        break;
      tslot->starttime = curlx_now();
      Curl_mutex_release(&tpool->lock);

      tpool->fn_process(item);

      Curl_mutex_acquire(&tpool->lock);
      tslot->work_description = NULL;
      tpool->fn_return(item, tpool->aborted ? NULL : tpool->fn_user_data);
    }

    if(tpool->aborted)
      goto out;

    tslot->idle = TRUE;
    tslot->starttime = curlx_now();
    thrdpool_join_zombies(tpool);
    Curl_cond_signal(&tpool->await);
    /* Only wait with idle timeout when we are above the minimum
     * number of threads. Otherwise short idle timeouts will keep
     * on activating threads that have no means to shut down. */
    if((tpool->idle_time_ms > 0) &&
       (Curl_llist_count(&tpool->slots) > tpool->min_threads)) {
      CURLcode r = Curl_cond_timedwait(&tslot->await, &tpool->lock,
                                       tpool->idle_time_ms);
      if((r == CURLE_OPERATION_TIMEDOUT) &&
         (Curl_llist_count(&tpool->slots) > tpool->min_threads)) {
        goto out;
      }
    }
    else {
      Curl_cond_wait(&tslot->await, &tpool->lock);
    }
    tslot->idle = FALSE;
  }

out:
  thrdslot_done(tslot);
  if(!thrdpool_unlink(tslot->tpool, TRUE)) {
    /* tpool not destroyed */
    Curl_mutex_release(&tpool->lock);
  }
  return 0;
}

static CURLcode thrdslot_start(struct curl_thrdpool *tpool)
{
  struct thrdslot *tslot;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  tslot = curlx_calloc(1, sizeof(*tslot));
  if(!tslot)
    goto out;
  tslot->id = tpool->next_id++;
  tslot->tpool = tpool;
  tslot->thread = curl_thread_t_null;
  Curl_cond_init(&tslot->await);

  tpool->refcount++;
  tslot->running = TRUE;
  tslot->thread = Curl_thread_create(thrdslot_run, tslot);
  if(tslot->thread == curl_thread_t_null) { /* never started */
    tslot->running = FALSE;
    thrdpool_unlink(tpool, TRUE);
    result = CURLE_FAILED_INIT;
    goto out;
  }

  Curl_llist_append(&tpool->slots, tslot, &tslot->node);
  tslot = NULL;
  result = CURLE_OK;

out:
  if(tslot)
    thrdslot_destroy(tslot);
  return result;
}

static void thrdpool_wake_all(struct curl_thrdpool *tpool)
{
  struct Curl_llist_node *e;
  for(e = Curl_llist_head(&tpool->slots); e; e = Curl_node_next(e)) {
    struct thrdslot *tslot = Curl_node_elem(e);
    Curl_cond_signal(&tslot->await);
  }
}

static void thrdpool_join_zombies(struct curl_thrdpool *tpool)
{
  struct Curl_llist_node *e;

  for(e = Curl_llist_head(&tpool->zombies); e;
      e = Curl_llist_head(&tpool->zombies)) {
    struct thrdslot *tslot = Curl_node_elem(e);

    Curl_node_remove(&tslot->node);
    if(tslot->thread != curl_thread_t_null) {
      Curl_mutex_release(&tpool->lock);
      Curl_thread_join(&tslot->thread);
      Curl_mutex_acquire(&tpool->lock);
      tslot->thread = curl_thread_t_null;
    }
    thrdslot_destroy(tslot);
  }
}

static bool thrdpool_unlink(struct curl_thrdpool *tpool, bool locked)
{
  DEBUGASSERT(tpool->refcount);
  if(tpool->refcount)
    tpool->refcount--;
  if(tpool->refcount)
    return FALSE;

  /* no more references, free */
  DEBUGASSERT(tpool->aborted);
  thrdpool_join_zombies(tpool);
  if(locked)
    Curl_mutex_release(&tpool->lock);
  curlx_free(tpool->name);
  Curl_cond_destroy(&tpool->await);
  Curl_mutex_destroy(&tpool->lock);
  curlx_free(tpool);
  return TRUE;
}

CURLcode Curl_thrdpool_create(struct curl_thrdpool **ptpool,
                              const char *name,
                              uint32_t min_threads,
                              uint32_t max_threads,
                              uint32_t idle_time_ms,
                              Curl_thrdpool_take_item_cb *fn_take,
                              Curl_thrdpool_process_item_cb *fn_process,
                              Curl_thrdpool_return_item_cb *fn_return,
                              void *user_data)
{
  struct curl_thrdpool *tpool;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  tpool = curlx_calloc(1, sizeof(*tpool));
  if(!tpool)
    goto out;
  tpool->refcount = 1;

  Curl_mutex_init(&tpool->lock);
  Curl_cond_init(&tpool->await);
  Curl_llist_init(&tpool->slots, NULL);
  Curl_llist_init(&tpool->zombies, NULL);
  tpool->min_threads = min_threads;
  tpool->max_threads = max_threads;
  tpool->idle_time_ms = idle_time_ms;
  tpool->fn_take = fn_take;
  tpool->fn_process = fn_process;
  tpool->fn_return = fn_return;
  tpool->fn_user_data = user_data;

  tpool->name = curlx_strdup(name);
  if(!tpool->name)
    goto out;

  if(tpool->min_threads)
    result = Curl_thrdpool_signal(tpool, tpool->min_threads);
  else
    result = CURLE_OK;

out:
  if(result && tpool) {
    tpool->aborted = TRUE;
    thrdpool_unlink(tpool, FALSE);
    tpool = NULL;
  }
  *ptpool = tpool;
  return result;
}

void Curl_thrdpool_destroy(struct curl_thrdpool *tpool, bool join)
{
  Curl_mutex_acquire(&tpool->lock);

  tpool->aborted = TRUE;

  while(join && Curl_llist_count(&tpool->slots)) {
    thrdpool_wake_all(tpool);
    Curl_cond_wait(&tpool->await, &tpool->lock);
  }

  thrdpool_join_zombies(tpool);

  /* detach all still running threads */
  if(Curl_llist_count(&tpool->slots)) {
    struct Curl_llist_node *e;
    for(e = Curl_llist_head(&tpool->slots); e; e = Curl_node_next(e)) {
      struct thrdslot *tslot = Curl_node_elem(e);
      if(tslot->thread != curl_thread_t_null)
        Curl_thread_destroy(&tslot->thread);
    }
    tpool->detached = TRUE;
  }

  if(!thrdpool_unlink(tpool, TRUE)) {
    /* tpool not destroyed */
    Curl_mutex_release(&tpool->lock);
  }
}

CURLcode Curl_thrdpool_signal(struct curl_thrdpool *tpool, uint32_t nthreads)
{
  struct Curl_llist_node *e, *n;
  CURLcode result = CURLE_OK;

  Curl_mutex_acquire(&tpool->lock);
  DEBUGASSERT(!tpool->aborted);

  thrdpool_join_zombies(tpool);

  for(e = Curl_llist_head(&tpool->slots); e && nthreads; e = n) {
    struct thrdslot *tslot = Curl_node_elem(e);
    n = Curl_node_next(e);
    if(tslot->idle) {
      Curl_cond_signal(&tslot->await);
      --nthreads;
    }
  }

  while(nthreads && !result &&
        Curl_llist_count(&tpool->slots) < tpool->max_threads) {
    result = thrdslot_start(tpool);
    if(result)
      break;
    --nthreads;
  }

  Curl_mutex_release(&tpool->lock);
  return result;
}

static bool thrdpool_all_idle(struct curl_thrdpool *tpool)
{
  struct Curl_llist_node *e;
  for(e = Curl_llist_head(&tpool->slots); e; e = Curl_node_next(e)) {
    struct thrdslot *tslot = Curl_node_elem(e);
    if(!tslot->idle)
      return FALSE;
  }
  return TRUE;
}

CURLcode Curl_thrdpool_await_idle(struct curl_thrdpool *tpool,
                                  uint32_t timeout_ms)
{
  CURLcode result = CURLE_OK;
  struct curltime end = { 0 };

  Curl_mutex_acquire(&tpool->lock);
  DEBUGASSERT(!tpool->aborted);
  if(tpool->aborted) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  while(!thrdpool_all_idle(tpool)) {
    if(timeout_ms) {
      timediff_t remain_ms;
      CURLcode r;

      if(!end.tv_sec && !end.tv_usec) {
        end = curlx_now();
        end.tv_sec += (time_t)(timeout_ms / 1000);
        end.tv_usec += (int)(timeout_ms % 1000) * 1000;
        if(end.tv_usec >= 1000000) {
          end.tv_sec++;
          end.tv_usec -= 1000000;
        }
      }
      remain_ms = curlx_timediff_ms(curlx_now(), end);
      if(remain_ms <= 0)
        r = CURLE_OPERATION_TIMEDOUT;
      else
        r = Curl_cond_timedwait(&tpool->await, &tpool->lock,
                                (uint32_t)remain_ms);
      if(r == CURLE_OPERATION_TIMEDOUT) {
        result = r;
        break;
      }
    }
    else {
      Curl_cond_wait(&tpool->await, &tpool->lock);
    }
  }

out:
  thrdpool_join_zombies(tpool);
  Curl_mutex_release(&tpool->lock);
  return result;
}

#ifdef CURLVERBOSE
void Curl_thrdpool_trace(struct curl_thrdpool *tpool,
                         struct Curl_easy *data,
                         struct curl_trc_feat *feat)
{
  if(Curl_trc_ft_is_verbose(data, feat)) {
    struct Curl_llist_node *e;
    struct curltime now = curlx_now();

    Curl_mutex_acquire(&tpool->lock);
    if(!Curl_llist_count(&tpool->slots)) {
      Curl_trc_feat_infof(data, feat, "[%s] [TPOOL] no threads running",
                          tpool->name);
    }
    for(e = Curl_llist_head(&tpool->slots); e; e = Curl_node_next(e)) {
      struct thrdslot *tslot = Curl_node_elem(e);
      timediff_t elapsed_ms = curlx_ptimediff_ms(&now, &tslot->starttime);
      if(tslot->idle) {
        Curl_trc_feat_infof(data, feat, "[%s] [TPOOL] [%u]: idle for %"
                            FMT_TIMEDIFF_T "ms",
                            tpool->name, tslot->id, elapsed_ms);
      }
      else {
        timediff_t remain_ms = tslot->work_timeout_ms ?
          (tslot->work_timeout_ms - elapsed_ms) : 0;
        Curl_trc_feat_infof(data, feat, "[%s] [TPOOL] [%u]: busy %"
                            FMT_TIMEDIFF_T "ms, timeout in %" FMT_TIMEDIFF_T
                            "ms: %s",
                            tpool->name, tslot->id, elapsed_ms, remain_ms,
                            tslot->work_description);
      }
    }
    Curl_mutex_release(&tpool->lock);
  }
}
#endif

#endif /* USE_THREADS && CURLRES_THREADED */
