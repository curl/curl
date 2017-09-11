/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "tool_setup.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_cb_prg.h"
#include "tool_util.h"

#include "memdebug.h" /* keep this as LAST include */

/*
** callback for CURLOPT_XFERINFOFUNCTION
*/

#define MAX_BARLENGTH 256

int tool_progress_cb(void *clientp,
                     curl_off_t dltotal, curl_off_t dlnow,
                     curl_off_t ultotal, curl_off_t ulnow)
{
  /* The original progress-bar source code was written for curl by Lars Aas,
     and this new edition inherits some of his concepts. */

  char line[MAX_BARLENGTH + 1];
  char format[40];
  double frac;
  double percent;
  int barwidth;
  int num;
  struct timeval now = tvnow();
  struct ProgressData *bar = (struct ProgressData *)clientp;
  curl_off_t total;
  curl_off_t point;

  /* expected transfer size */
  total = dltotal + ultotal + bar->initial_size;

  /* we've come this far */
  point = dlnow + ulnow + bar->initial_size;

  if(bar->calls && (tvdiff(now, bar->prevtime) < 100L) && point < total)
    /* after first call, limit progress-bar updating to 10 Hz */
    /* update when we're at 100% even if last update is less than 200ms ago */
    return 0;

  if(point > total)
    /* we have got more than the expected total! */
    total = point;

  /* simply count invokes */
  bar->calls++;

  if(total < 1) {
    curl_off_t prevblock = bar->prev / 1024;
    curl_off_t thisblock = point / 1024;
    while(thisblock > prevblock) {
      fprintf(bar->out, "#");
      prevblock++;
    }
  }
  else if(point != bar->prev) {
    frac = (double)point / (double)total;
    percent = frac * 100.0;
    barwidth = bar->width - 7;
    num = (int) (((double)barwidth) * frac);
    if(num > MAX_BARLENGTH)
      num = MAX_BARLENGTH;
    memset(line, '#', num);
    line[num] = '\0';
    snprintf(format, sizeof(format), "\r%%-%ds %%5.1f%%%%", barwidth);
    fprintf(bar->out, format, line, percent);
  }
  fflush(bar->out);
  bar->prev = point;
  bar->prevtime = now;

  return 0;
}

void progressbarinit(struct ProgressData *bar,
                     struct OperationConfig *config)
{
#ifdef __EMX__
  /* 20000318 mgs */
  int scr_size[2];
#endif
  char *colp;

  memset(bar, 0, sizeof(struct ProgressData));

  /* pass this through to progress function so
   * it can display progress towards total file
   * not just the part that's left. (21-may-03, dbyron) */
  if(config->use_resume)
    bar->initial_size = config->resume_from;

/* TODO: get terminal width through ansi escapes or something similar.
   try to update width when xterm is resized... - 19990617 larsa */
#ifndef __EMX__
  /* 20000318 mgs
   * OS/2 users most likely won't have this env var set, and besides that
   * we're using our own way to determine screen width */
  colp = curlx_getenv("COLUMNS");
  if(colp) {
    char *endptr;
    long num = strtol(colp, &endptr, 10);
    if((endptr != colp) && (endptr == colp + strlen(colp)) && (num > 0))
      bar->width = (int)num;
    else
      bar->width = 79;
    curl_free(colp);
  }
  else
    bar->width = 79;
#else
  /* 20000318 mgs
   * We use this emx library call to get the screen width, and subtract
   * one from what we got in order to avoid a problem with the cursor
   * advancing to the next line if we print a string that is as long as
   * the screen is wide. */

  _scrsize(scr_size);
  bar->width = scr_size[0] - 1;
#endif

  bar->out = config->global->errors;
}
