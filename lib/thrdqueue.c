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
#include "thrdpool.h"
#include "thrdqueue.h"
#include "curlx/timeval.h"
#ifdef CURLVERBOSE
#include "curl_trc.h"
#include "urldata.h"
#endif


struct curl_thrdq {
  char *name;
  curl_mutex_t lock;
  curl_cond_t await;
  struct Curl_llist sendq;
  struct Curl_llist recvq;
  struct curl_thrdpool *tpool;
  Curl_thrdq_item_free_cb *fn_free;
  Curl_thrdq_item_process_cb *fn_process;
  Curl_thrdq_ev_cb *fn_event;
  void *fn_user_data;
  uint64_t nscheduled;
  uint64_t nprocessed;
  uint32_t send_max_len;
  BIT(aborted);
};

struct thrdq_item {
  struct Curl_llist_node node;
  Curl_thrdq_item_free_cb *fn_free;
  Curl_thrdq_item_process_cb *fn_process;
  void *item;
  struct curltime start;
  timediff_t timeout_ms;
  const char *description;
};

static struct thrdq_item *thrdq_item_create(struct curl_thrdq *tqueue,
                                            void *item,
                                            const char *description,
                                            timediff_t timeout_ms)
{
  struct thrdq_item *qitem;

  qitem = curlx_calloc(1, sizeof(*qitem));
  if(!qitem)
    return NULL;
  qitem->item = item;
  qitem->description = description;
  qitem->fn_free = tqueue->fn_free;
  qitem->fn_process = tqueue->fn_process;
  if(timeout_ms) {
    qitem->start = curlx_now();
    qitem->timeout_ms = timeout_ms;
  }
  return qitem;
}

static void thrdq_item_destroy(struct thrdq_item *qitem)
{
  if(qitem->item)
    qitem->fn_free(qitem->item);
  curlx_free(qitem);
}

static void thrdq_item_list_dtor(void *user_data, void *elem)
{
  (void)user_data;
  thrdq_item_destroy(elem);
}

static void *thrdq_tpool_take(void *user_data, const char **pdescription,
                              timediff_t *ptimeout_ms)
{
  struct curl_thrdq *tqueue = user_data;
  struct thrdq_item *qitem = NULL;
  struct Curl_llist_node *e;
  Curl_thrdq_ev_cb *fn_event = NULL;
  void *fn_user_data = NULL;

  Curl_mutex_acquire(&tqueue->lock);
  *pdescription = NULL;
  if(!tqueue->aborted) {
    e = Curl_llist_head(&tqueue->sendq);
    if(e) {
      struct curltime now = curlx_now();
      timediff_t timeout_ms;
      while(e) {
        qitem = Curl_node_take_elem(e);
        timeout_ms = (!qitem->timeout_ms) ? 0 :
          (qitem->timeout_ms - curlx_ptimediff_ms(&now, &qitem->start));
        if(timeout_ms < 0) {
          /* timed out while queued, place on receive queue */
          Curl_llist_append(&tqueue->recvq, qitem, &qitem->node);
          tqueue->nprocessed++;
          fn_event = tqueue->fn_event;
          fn_user_data = tqueue->fn_user_data;
          qitem = NULL;
          e = Curl_llist_head(&tqueue->sendq);
          continue;
        }
        else {
          *pdescription = qitem->description;
          *ptimeout_ms = timeout_ms;
          break;
        }
      }
    }
  }
  Curl_mutex_release(&tqueue->lock);
  /* avoiding deadlocks */
  if(fn_event)
    fn_event(tqueue, CURL_THRDQ_EV_ITEM_DONE, fn_user_data);
  return qitem;
}

static void thrdq_tpool_return(void *item, void *user_data)
{
  struct curl_thrdq *tqueue = user_data;
  struct thrdq_item *qitem = item;
  Curl_thrdq_ev_cb *fn_event = NULL;
  void *fn_user_data = NULL;

  if(!tqueue) {
    thrdq_item_destroy(item);
    return;
  }

  Curl_mutex_acquire(&tqueue->lock);
  if(tqueue->aborted) {
    thrdq_item_destroy(qitem);
  }
  else {
    DEBUGASSERT(!Curl_node_llist(&qitem->node));
    Curl_llist_append(&tqueue->recvq, qitem, &qitem->node);
    tqueue->nprocessed++;
    fn_event = tqueue->fn_event;
    fn_user_data = tqueue->fn_user_data;
  }
  Curl_mutex_release(&tqueue->lock);
  /* avoiding deadlocks */
  if(fn_event)
    fn_event(tqueue, CURL_THRDQ_EV_ITEM_DONE, fn_user_data);
}

static void thrdq_tpool_process(void *item)
{
  struct thrdq_item *qitem = item;
  qitem->fn_process(qitem->item);
}

static void thrdq_unlink(struct curl_thrdq *tqueue, bool locked, bool join)
{
  DEBUGASSERT(tqueue->aborted);
  if(tqueue->tpool) {
    if(locked)
      Curl_mutex_release(&tqueue->lock);
    Curl_thrdpool_destroy(tqueue->tpool, join);
    tqueue->tpool = NULL;
    if(locked)
      Curl_mutex_acquire(&tqueue->lock);
  }

  Curl_llist_destroy(&tqueue->sendq, NULL);
  Curl_llist_destroy(&tqueue->recvq, NULL);
  curlx_free(tqueue->name);
  Curl_cond_destroy(&tqueue->await);
  if(locked)
    Curl_mutex_release(&tqueue->lock);
  Curl_mutex_destroy(&tqueue->lock);
  curlx_free(tqueue);
}

CURLcode Curl_thrdq_create(struct curl_thrdq **ptqueue,
                           const char *name,
                           uint32_t max_len,
                           uint32_t min_threads,
                           uint32_t max_threads,
                           uint32_t idle_time_ms,
                           Curl_thrdq_item_free_cb *fn_free,
                           Curl_thrdq_item_process_cb *fn_process,
                           Curl_thrdq_ev_cb *fn_event,
                           void *user_data)
{
  struct curl_thrdq *tqueue;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  tqueue = curlx_calloc(1, sizeof(*tqueue));
  if(!tqueue)
    goto out;

  Curl_mutex_init(&tqueue->lock);
  Curl_cond_init(&tqueue->await);
  Curl_llist_init(&tqueue->sendq, thrdq_item_list_dtor);
  Curl_llist_init(&tqueue->recvq, thrdq_item_list_dtor);
  tqueue->fn_free = fn_free;
  tqueue->fn_process = fn_process;
  tqueue->fn_event = fn_event;
  tqueue->fn_user_data = user_data;
  tqueue->send_max_len = max_len;

  tqueue->name = curlx_strdup(name);
  if(!tqueue->name)
    goto out;

  result = Curl_thrdpool_create(&tqueue->tpool, name,
                                min_threads, max_threads, idle_time_ms,
                                thrdq_tpool_take,
                                thrdq_tpool_process,
                                thrdq_tpool_return,
                                tqueue);

out:
  if(result && tqueue) {
    tqueue->aborted = TRUE;
    thrdq_unlink(tqueue, FALSE, TRUE);
    tqueue = NULL;
  }
  *ptqueue = tqueue;
  return result;
}

void Curl_thrdq_destroy(struct curl_thrdq *tqueue, bool join)
{
  Curl_mutex_acquire(&tqueue->lock);
  DEBUGASSERT(!tqueue->aborted);
  tqueue->aborted = TRUE;
  thrdq_unlink(tqueue, TRUE, join);
}

void Curl_thrdq_stat(struct curl_thrdq *tqueue,
                     uint32_t *pnsend,
                     uint32_t *pnrecv,
                     uint64_t *pnscheduled,
                     uint64_t *pnprocessed)
{
  Curl_mutex_acquire(&tqueue->lock);
  DEBUGASSERT(!tqueue->aborted);
  if(pnsend)
    *pnsend = (uint32_t)Curl_llist_count(&tqueue->sendq);
  if(pnrecv)
    *pnrecv = (uint32_t)Curl_llist_count(&tqueue->recvq);
  if(pnscheduled)
    *pnscheduled = tqueue->nscheduled;
  if(pnprocessed)
    *pnprocessed = tqueue->nprocessed;
  Curl_mutex_release(&tqueue->lock);
}

CURLcode Curl_thrdq_send(struct curl_thrdq *tqueue, void *item,
                         const char *description, timediff_t timeout_ms)
{
  CURLcode result = CURLE_AGAIN;

  Curl_mutex_acquire(&tqueue->lock);
  if(tqueue->aborted) {
    DEBUGASSERT(0);
    result = CURLE_SEND_ERROR;
    goto out;
  }
  if(timeout_ms < 0) {
    result = CURLE_OPERATION_TIMEDOUT;
    goto out;
  }

  if(!tqueue->send_max_len ||
     (Curl_llist_count(&tqueue->sendq) < tqueue->send_max_len)) {
    struct thrdq_item *qitem = thrdq_item_create(tqueue, item, description,
                                                 timeout_ms);
    if(!qitem) {
      result = CURLE_OUT_OF_MEMORY;
      goto out;
    }
    Curl_llist_append(&tqueue->sendq, qitem, &qitem->node);
    result = CURLE_OK;
  }

out:
  Curl_mutex_release(&tqueue->lock);
  /* Signal thread pool unlocked to void deadlocks */
  if(!result)
    result = Curl_thrdpool_signal(tqueue->tpool, 1);
  return result;
}

CURLcode Curl_thrdq_recv(struct curl_thrdq *tqueue, void **pitem)
{
  CURLcode result = CURLE_AGAIN;
  struct Curl_llist_node *e;

  *pitem = NULL;
  Curl_mutex_acquire(&tqueue->lock);
  if(tqueue->aborted) {
    DEBUGASSERT(0);
    result = CURLE_RECV_ERROR;
    goto out;
  }

  e = Curl_llist_head(&tqueue->recvq);
  if(e) {
    struct thrdq_item *qitem = Curl_node_take_elem(e);
    *pitem = qitem->item;
    qitem->item = NULL;
    thrdq_item_destroy(qitem);
    result = CURLE_OK;
  }
out:
  Curl_mutex_release(&tqueue->lock);
  return result;
}

static void thrdq_llist_clean_matches(struct Curl_llist *llist,
                                      Curl_thrdq_item_match_cb *fn_match,
                                      void *match_data)
{
  struct Curl_llist_node *e, *n;
  struct thrdq_item *qitem;

  for(e = Curl_llist_head(llist); e; e = n) {
    n = Curl_node_next(e);
    qitem = Curl_node_elem(e);
    if(fn_match(qitem->item, match_data))
      Curl_node_remove(e);
  }
}

void Curl_thrdq_clear(struct curl_thrdq *tqueue,
                      Curl_thrdq_item_match_cb *fn_match,
                      void *match_data)
{
  Curl_mutex_acquire(&tqueue->lock);
  if(tqueue->aborted) {
    DEBUGASSERT(0);
    goto out;
  }
  thrdq_llist_clean_matches(&tqueue->sendq, fn_match, match_data);
  thrdq_llist_clean_matches(&tqueue->recvq, fn_match, match_data);
out:
  Curl_mutex_release(&tqueue->lock);
}

CURLcode Curl_thrdq_await_done(struct curl_thrdq *tqueue,
                               uint32_t timeout_ms)
{
  return Curl_thrdpool_await_idle(tqueue->tpool, timeout_ms);
}

#ifdef CURLVERBOSE
void Curl_thrdq_trace(struct curl_thrdq *tqueue,
                      struct Curl_easy *data,
                      struct curl_trc_feat *feat)
{
  if(Curl_trc_ft_is_verbose(data, feat)) {
    struct Curl_llist_node *e;
    struct thrdq_item *qitem;

    Curl_thrdpool_trace(tqueue->tpool, data, feat);
    Curl_mutex_acquire(&tqueue->lock);
    if(!Curl_llist_count(&tqueue->sendq) &&
       !Curl_llist_count(&tqueue->recvq)) {
      Curl_trc_feat_infof(data, feat, "[%s] [QUEUE] empty", tqueue->name);
    }
    for(e = Curl_llist_head(&tqueue->sendq); e; e = Curl_node_next(e)) {
      qitem = Curl_node_elem(e);
      Curl_trc_feat_infof(data, feat, "[%s] [QUEUE] in: %s",
                          tqueue->name, qitem->description);
    }
    for(e = Curl_llist_head(&tqueue->recvq); e; e = Curl_node_next(e)) {
      qitem = Curl_node_elem(e);
      Curl_trc_feat_infof(data, feat, "[%s] [QUEUE] out: %s",
                          tqueue->name, qitem->description);
    }
    Curl_mutex_release(&tqueue->lock);
  }
}
#endif

#endif /* USE_THREADS && CURLRES_THREADED */
