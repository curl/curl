#ifndef HEADER_FETCH_PROGRESS_H
#define HEADER_FETCH_PROGRESS_H
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

#include "timeval.h"

typedef enum
{
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

int Fetch_pgrsDone(struct Fetch_easy *data);
void Fetch_pgrsStartNow(struct Fetch_easy *data);
void Fetch_pgrsSetDownloadSize(struct Fetch_easy *data, fetch_off_t size);
void Fetch_pgrsSetUploadSize(struct Fetch_easy *data, fetch_off_t size);

/* It is fine to not check the return code if 'size' is set to 0 */
FETCHcode Fetch_pgrsSetDownloadCounter(struct Fetch_easy *data, fetch_off_t size);

void Fetch_pgrsSetUploadCounter(struct Fetch_easy *data, fetch_off_t size);
void Fetch_ratelimit(struct Fetch_easy *data, struct fetchtime now);
int Fetch_pgrsUpdate(struct Fetch_easy *data);
void Fetch_pgrsUpdate_nometer(struct Fetch_easy *data);

void Fetch_pgrsResetTransferSizes(struct Fetch_easy *data);
struct fetchtime Fetch_pgrsTime(struct Fetch_easy *data, timerid timer);
timediff_t Fetch_pgrsLimitWaitTime(struct pgrs_dir *d,
                                  fetch_off_t speed_limit,
                                  struct fetchtime now);
/**
 * Update progress timer with the elapsed time from its start to `timestamp`.
 * This allows updating timers later and is used by happy eyeballing, where
 * we only want to record the winner's times.
 */
void Fetch_pgrsTimeWas(struct Fetch_easy *data, timerid timer,
                      struct fetchtime timestamp);

void Fetch_pgrsEarlyData(struct Fetch_easy *data, fetch_off_t sent);

#define PGRS_HIDE (1 << 4)
#define PGRS_UL_SIZE_KNOWN (1 << 5)
#define PGRS_DL_SIZE_KNOWN (1 << 6)
#define PGRS_HEADERS_OUT (1 << 7) /* set when the headers have been written */

#endif /* HEADER_FETCH_PROGRESS_H */
