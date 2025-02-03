#ifndef HEADER_FETCH_TOOL_CB_PRG_H
#define HEADER_FETCH_TOOL_CB_PRG_H
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "tool_setup.h"

#define FETCH_PROGRESS_STATS 0 /* default progress display */
#define FETCH_PROGRESS_BAR 1

struct ProgressData
{
  int calls;
  fetch_off_t prev;
  struct timeval prevtime;
  int width;
  FILE *out; /* where to write everything to */
  fetch_off_t initial_size;
  unsigned int tick;
  int bar;
  int barmove;
};

struct OperationConfig;

void progressbarinit(struct ProgressData *bar,
                     struct OperationConfig *config);

/*
** callback for FETCHOPT_PROGRESSFUNCTION
*/

int tool_progress_cb(void *clientp,
                     fetch_off_t dltotal, fetch_off_t dlnow,
                     fetch_off_t ultotal, fetch_off_t ulnow);

#endif /* HEADER_FETCH_TOOL_CB_PRG_H */
