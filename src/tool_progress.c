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
#include "tool_setup.h"
#include "tool_operate.h"
#include "tool_progress.h"
#include "tool_util.h"

/* The point of this function would be to return a string of the input data,
   but never longer than 5 columns (+ one zero byte).
   Add suffix k, M, G when suitable... */
static char *max5data(curl_off_t bytes, char *max5)
{
  /* a signed 64-bit value is 8192 petabytes maximum */
  const char unit[] = { 'k', 'M', 'G', 'T', 'P', 0 };
  int k = 0;
  if(bytes < 100000) {
    curl_msnprintf(max5, 6, "%5" CURL_FORMAT_CURL_OFF_T, bytes);
    return max5;
  }

  do {
    curl_off_t nbytes = bytes / 1024;
    if(nbytes < 100) {
      /* display with a decimal */
      curl_msnprintf(max5, 6, "%2" CURL_FORMAT_CURL_OFF_T ".%0"
                     CURL_FORMAT_CURL_OFF_T "%c", bytes/1024,
                     (bytes%1024) / (1024/10), unit[k]);
      break;
    }
    else if(nbytes < 10000) {
      /* no decimals */
      curl_msnprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "%c", nbytes,
                     unit[k]);
      break;
    }
    bytes = nbytes;
    k++;
    DEBUGASSERT(unit[k]);
  } while(unit[k]);
  return max5;
}

int xferinfo_cb(void *clientp,
                curl_off_t dltotal,
                curl_off_t dlnow,
                curl_off_t ultotal,
                curl_off_t ulnow)
{
  struct per_transfer *per = clientp;
  struct OperationConfig *config = per->config;
  per->dltotal = dltotal;
  per->dlnow = dlnow;
  per->ultotal = ultotal;
  per->ulnow = ulnow;

  if(per->abort)
    return 1;

  if(config->readbusy) {
    config->readbusy = FALSE;
    curl_easy_pause(per->curl, CURLPAUSE_CONT);
  }

  return 0;
}

/* Provide a string that is 2 + 1 + 2 + 1 + 2 = 8 letters long (plus the zero
   byte) */
static void time2str(char *r, curl_off_t seconds)
{
  curl_off_t h;
  if(seconds <= 0) {
    strcpy(r, "--:--:--");
    return;
  }
  h = seconds / 3600;
  if(h <= 99) {
    curl_off_t m = (seconds - (h * 3600)) / 60;
    curl_off_t s = (seconds - (h * 3600)) - (m * 60);
    curl_msnprintf(r, 9, "%2" CURL_FORMAT_CURL_OFF_T
                   ":%02" CURL_FORMAT_CURL_OFF_T
                   ":%02" CURL_FORMAT_CURL_OFF_T, h, m, s);
  }
  else {
    /* this equals to more than 99 hours, switch to a more suitable output
       format to fit within the limits. */
    curl_off_t d = seconds / 86400;
    h = (seconds - (d * 86400)) / 3600;
    if(d <= 999)
      curl_msnprintf(r, 9, "%3" CURL_FORMAT_CURL_OFF_T
                     "d %02" CURL_FORMAT_CURL_OFF_T "h", d, h);
    else
      curl_msnprintf(r, 9, "%7" CURL_FORMAT_CURL_OFF_T "d", d);
  }
}

static curl_off_t all_dltotal = 0;
static curl_off_t all_ultotal = 0;
static curl_off_t all_dlalready = 0;
static curl_off_t all_ulalready = 0;

struct speedcount {
  curl_off_t dl;
  curl_off_t ul;
  struct curltime stamp;
};
#define SPEEDCNT 10
static unsigned int speedindex;
static bool indexwrapped;
static struct speedcount speedstore[SPEEDCNT];

static void add_offt(curl_off_t *val, curl_off_t add)
{
  if(CURL_OFF_T_MAX - *val < add)
    /* maxed out! */
    *val = CURL_OFF_T_MAX;
  else
    *val += add;
}

/*
  |DL% UL%  Dled  Uled  Xfers  Live Total     Current  Left    Speed
  |  6 --   9.9G     0     2     2   0:00:40  0:00:02  0:00:37 4087M
*/
bool progress_meter(CURLM *multi,
                    struct curltime *start,
                    bool final)
{
  static struct curltime stamp;
  static bool header = FALSE;
  struct curltime now;
  timediff_t diff;

  if(global->noprogress || global->silent)
    return FALSE;

  now = curlx_now();
  diff = curlx_timediff(now, stamp);

  if(!header) {
    header = TRUE;
    fputs("DL% UL%  Dled  Uled  Xfers  Live "
          "Total     Current  Left    Speed\n",
          tool_stderr);
  }
  if(final || (diff > 500)) {
    char time_left[10];
    char time_total[10];
    char time_spent[10];
    char buffer[3][6];
    curl_off_t spent = curlx_timediff(now, *start)/1000;
    char dlpercen[4]="--";
    char ulpercen[4]="--";
    struct per_transfer *per;
    curl_off_t all_dlnow = 0;
    curl_off_t all_ulnow = 0;
    curl_off_t xfers_added = 0;
    curl_off_t xfers_running = 0;
    bool dlknown = TRUE;
    bool ulknown = TRUE;
    curl_off_t speed = 0;
    unsigned int i;
    stamp = now;

    /* first add the amounts of the already completed transfers */
    add_offt(&all_dlnow, all_dlalready);
    add_offt(&all_ulnow, all_ulalready);

    for(per = transfers; per; per = per->next) {
      add_offt(&all_dlnow, per->dlnow);
      add_offt(&all_ulnow, per->ulnow);
      if(!per->dltotal)
        dlknown = FALSE;
      else if(!per->dltotal_added) {
        /* only add this amount once */
        add_offt(&all_dltotal, per->dltotal);
        per->dltotal_added = TRUE;
      }
      if(!per->ultotal)
        ulknown = FALSE;
      else if(!per->ultotal_added) {
        /* only add this amount once */
        add_offt(&all_ultotal, per->ultotal);
        per->ultotal_added = TRUE;
      }
    }
    if(dlknown && all_dltotal)
      curl_msnprintf(dlpercen, sizeof(dlpercen), "%3" CURL_FORMAT_CURL_OFF_T,
                     all_dlnow < (CURL_OFF_T_MAX/100) ?
                     (all_dlnow * 100 / all_dltotal) :
                     (all_dlnow / (all_dltotal/100)));

    if(ulknown && all_ultotal)
      curl_msnprintf(ulpercen, sizeof(ulpercen), "%3" CURL_FORMAT_CURL_OFF_T,
                     all_ulnow < (CURL_OFF_T_MAX/100) ?
                     (all_ulnow * 100 / all_ultotal) :
                     (all_ulnow / (all_ultotal/100)));

    /* get the transfer speed, the higher of the two */

    i = speedindex;
    speedstore[i].dl = all_dlnow;
    speedstore[i].ul = all_ulnow;
    speedstore[i].stamp = now;
    if(++speedindex >= SPEEDCNT) {
      indexwrapped = TRUE;
      speedindex = 0;
    }

    {
      timediff_t deltams;
      curl_off_t dl;
      curl_off_t ul;
      curl_off_t dls;
      curl_off_t uls;
      if(indexwrapped) {
        /* 'speedindex' is the oldest stored data */
        deltams = curlx_timediff(now, speedstore[speedindex].stamp);
        dl = all_dlnow - speedstore[speedindex].dl;
        ul = all_ulnow - speedstore[speedindex].ul;
      }
      else {
        /* since the beginning */
        deltams = curlx_timediff(now, *start);
        dl = all_dlnow;
        ul = all_ulnow;
      }
      if(!deltams) /* no division by zero please */
        deltams++;
      dls = (curl_off_t)((double)dl / ((double)deltams/1000.0));
      uls = (curl_off_t)((double)ul / ((double)deltams/1000.0));
      speed = dls > uls ? dls : uls;
    }


    if(dlknown && speed) {
      curl_off_t est = all_dltotal / speed;
      curl_off_t left = (all_dltotal - all_dlnow) / speed;
      time2str(time_left, left);
      time2str(time_total, est);
    }
    else {
      time2str(time_left, 0);
      time2str(time_total, 0);
    }
    time2str(time_spent, spent);

    (void)curl_multi_get_offt(multi, CURLMINFO_XFERS_ADDED, &xfers_added);
    (void)curl_multi_get_offt(multi, CURLMINFO_XFERS_RUNNING, &xfers_running);
    curl_mfprintf(tool_stderr,
                  "\r"
                  "%-3s " /* percent downloaded */
                  "%-3s " /* percent uploaded */
                  "%s " /* Dled */
                  "%s " /* Uled */
                  "%5" CURL_FORMAT_CURL_OFF_T " " /* Xfers */
                  "%5" CURL_FORMAT_CURL_OFF_T " " /* Live */
                  " %s "  /* Total time */
                  "%s "  /* Current time */
                  "%s "  /* Time left */
                  "%s "  /* Speed */
                  "%5s" /* final newline */,

                  dlpercen,  /* 3 letters */
                  ulpercen,  /* 3 letters */
                  max5data(all_dlnow, buffer[0]),
                  max5data(all_ulnow, buffer[1]),
                  xfers_added,
                  xfers_running,
                  time_total,
                  time_spent,
                  time_left,
                  max5data(speed, buffer[2]), /* speed */
                  final ? "\n" :"");
    return TRUE;
  }
  return FALSE;
}

void progress_finalize(struct per_transfer *per)
{
  /* get the numbers before this transfer goes away */
  add_offt(&all_dlalready, per->dlnow);
  add_offt(&all_ulalready, per->ulnow);
  if(!per->dltotal_added) {
    add_offt(&all_dltotal, per->dltotal);
    per->dltotal_added = TRUE;
  }
  if(!per->ultotal_added) {
    add_offt(&all_ultotal, per->ultotal);
    per->ultotal_added = TRUE;
  }
}
