#ifndef HEADER_CURL_THRDQUEUE_H
#define HEADER_CURL_THRDQUEUE_H
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

struct curl_thrdq;

typedef enum {
  CURL_THRDQ_EV_ITEM_DONE /* an item has been processed and is ready */
} Curl_thrdq_event;

/* Notification callback when "events" happen in the queue. May be
 * call from any thread, tqueue is not locked. */
typedef void Curl_thrdq_ev_cb(const struct curl_thrdq *tqueue,
                              Curl_thrdq_event ev,
                              void *user_data);

/* Process a queued item. Maybe call from any thread. Queue is
 * not locked. */
typedef void Curl_thrdq_item_process_cb(void *item);

/* Free an item. May be called from any thread at any time for an
 * item that is in the queue (either before or after processing). */
typedef void Curl_thrdq_item_free_cb(void *item);

/* Create a new queue processing "items" by a thread pool.
 */
CURLcode Curl_thrdq_create(struct curl_thrdq **ptqueue,
                           const char *name,
                           uint32_t max_len, /* 0 for unlimited */
                           uint32_t min_threads,
                           uint32_t max_threads,
                           uint32_t idle_time_ms,
                           Curl_thrdq_item_free_cb *fn_free,
                           Curl_thrdq_item_process_cb *fn_process,
                           Curl_thrdq_ev_cb *fn_event, /* optional */
                           void *user_data);

/* Destroy the queue, free all queued items unprocessed and destroy
 * the thread pool used.
 * @param join TRUE when thread pool shall be joined. FALSE for
 *             detaching any running threads.
 */
void Curl_thrdq_destroy(struct curl_thrdq *tqueue, bool join);

/* Get information about the current queue state. Parameters may be
 * passed as NULL if caller is not interested. */
void Curl_thrdq_stat(struct curl_thrdq *tqueue,
                     uint32_t *pnsend, /* # of items awaitting processing */
                     uint32_t *pnrecv, /* # of items ready for recv */
                     uint64_t *pnscheduled, /* total items added */
                     uint64_t *pnprocessed); /* total items processed */

/* Send "item" onto the queue. The caller needs to clear any reference
 * to "item" on success, e.g. the queue takes ownership.
 * Returns CURLE_AGAIN when the queue has already been full.
 */
CURLcode Curl_thrdq_send(struct curl_thrdq *tqueue, void *item);

/* Receive the oldest, processed item from the queue again, if there is one.
 * The caller takes ownership of the item received, e.g. the queue
 * relinquishes all references to item.
 * Returns CURLE_AGAIN when there is no processed item, setting `pitem`
 * to NULL.
 */
CURLcode Curl_thrdq_recv(struct curl_thrdq *tqueue, void **pitem);

/* Return TRUE if the passed "item" matches. */
typedef bool Curl_thrdq_item_match_cb(void *item, void *match_data);

/* Clear all scheduled/processed items that match from the queue. This
 * will *not* be able to clear items that are being processed.
 */
void Curl_thrdq_clear(struct curl_thrdq *tqueue,
                      Curl_thrdq_item_match_cb *fn_match,
                      void *match_data);

CURLcode Curl_thrdq_await_done(struct curl_thrdq *tqueue,
                               uint32_t timeout_ms);

#endif /* USE_THREADS */

#endif /* HEADER_CURL_THRDQUEUE_H */
