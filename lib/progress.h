#ifndef HEADER_CURL_PROGRESS_H
#define HEADER_CURL_PROGRESS_H
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

#include "curlx/timeval.h"

struct Curl_easy;

typedef enum {
  TIMER_NONE,
  TIMER_STARTOP,
  TIMER_STARTSINGLE, /* start of transfer, might get queued */
  TIMER_POSTQUEUE,   /* start, immediately after dequeue */
  TIMER_NAMELOOKUP,
  TIMER_CONNECT,
  TIMER_APPCONNECT,
  TIMER_PRETRANSFER,
  TIMER_STARTTRANSFER,
  TIMER_POSTRANSFER,
  TIMER_STARTACCEPT,
  TIMER_REDIRECT,
  TIMER_LAST /* must be last */
} timerid;

#define CURL_PGRS_NOW_MONOTONIC

/* Set current time in data->progress.now */
void Curl_pgrs_now_set(struct Curl_easy *data);
/* Advance `now` timestamp at least to given timestamp.
 * No effect it data's `now` is already later than `pts`. */
void Curl_pgrs_now_at_least(struct Curl_easy *data, struct curltime *pts);
/* `data` progressing continues after `other` processing. Advance `data`s
 * now timestamp to at least `other's` timestamp. */
void Curl_pgrs_now_update(struct Curl_easy *data, struct Curl_easy *other);

int Curl_pgrsDone(struct Curl_easy *data);
void Curl_pgrsStartNow(struct Curl_easy *data);
void Curl_pgrsSetDownloadSize(struct Curl_easy *data, curl_off_t size);
void Curl_pgrsSetUploadSize(struct Curl_easy *data, curl_off_t size);

void Curl_pgrs_download_inc(struct Curl_easy *data, size_t delta);
void Curl_pgrs_upload_inc(struct Curl_easy *data, size_t delta);
void Curl_pgrsSetUploadCounter(struct Curl_easy *data, curl_off_t size);

/* perform progress update, invoking callbacks at intervals */
CURLcode Curl_pgrsUpdate(struct Curl_easy *data);
/* perform progress update, no callbacks invoked */
void Curl_pgrsUpdate_nometer(struct Curl_easy *data);
/* perform progress update with callbacks and speed checks */
CURLcode Curl_pgrsCheck(struct Curl_easy *data);

/* Inform progress/speedcheck about receive/send pausing */
void Curl_pgrsRecvPause(struct Curl_easy *data, bool enable);
void Curl_pgrsSendPause(struct Curl_easy *data, bool enable);

/* Reset sizes and couners for up- and download. */
void Curl_pgrsReset(struct Curl_easy *data);
/* Reset sizes for up- and download. */
void Curl_pgrsResetTransferSizes(struct Curl_easy *data);

void Curl_pgrsTime(struct Curl_easy *data, timerid timer);
/**
 * Update progress timer with the elapsed time from its start to `timestamp`.
 * This allows updating timers later and is used by happy eyeballing, where
 * we only want to record the winner's times.
 */
void Curl_pgrsTimeWas(struct Curl_easy *data, timerid timer,
                      struct curltime timestamp);

void Curl_pgrsEarlyData(struct Curl_easy *data, curl_off_t sent);

#ifdef UNITTESTS
UNITTEST CURLcode pgrs_speedcheck(struct Curl_easy *data,
                                  struct curltime *pnow);
#endif

#endif /* HEADER_CURL_PROGRESS_H */
