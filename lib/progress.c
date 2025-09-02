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

#include "urldata.h"
#include "sendf.h"
#include "multiif.h"
#include "progress.h"
#include "curlx/timeval.h"
#include "curl_printf.h"

/* check rate limits within this many recent milliseconds, at minimum. */
#define MIN_RATE_LIMIT_PERIOD 3000

#ifndef CURL_DISABLE_PROGRESS_METER
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
    msnprintf(r, 9, "%2" FMT_OFF_T ":%02" FMT_OFF_T ":%02" FMT_OFF_T, h, m, s);
  }
  else {
    /* this equals to more than 99 hours, switch to a more suitable output
       format to fit within the limits. */
    curl_off_t d = seconds / 86400;
    h = (seconds - (d * 86400)) / 3600;
    if(d <= 999)
      msnprintf(r, 9, "%3" FMT_OFF_T "d %02" FMT_OFF_T "h", d, h);
    else
      msnprintf(r, 9, "%7" FMT_OFF_T "d", d);
  }
}

/* The point of this function would be to return a string of the input data,
   but never longer than 5 columns (+ one zero byte).
   Add suffix k, M, G when suitable... */
static char *max5data(curl_off_t bytes, char *max5)
{
#define ONE_KILOBYTE (curl_off_t)1024
#define ONE_MEGABYTE (1024 * ONE_KILOBYTE)
#define ONE_GIGABYTE (1024 * ONE_MEGABYTE)
#define ONE_TERABYTE (1024 * ONE_GIGABYTE)
#define ONE_PETABYTE (1024 * ONE_TERABYTE)

  if(bytes < 100000)
    msnprintf(max5, 6, "%5" FMT_OFF_T, bytes);

  else if(bytes < 10000 * ONE_KILOBYTE)
    msnprintf(max5, 6, "%4" FMT_OFF_T "k", bytes/ONE_KILOBYTE);

  else if(bytes < 100 * ONE_MEGABYTE)
    /* 'XX.XM' is good as long as we are less than 100 megs */
    msnprintf(max5, 6, "%2" FMT_OFF_T ".%0"
              FMT_OFF_T "M", bytes/ONE_MEGABYTE,
              (bytes%ONE_MEGABYTE) / (ONE_MEGABYTE/10) );

  else if(bytes < 10000 * ONE_MEGABYTE)
    /* 'XXXXM' is good until we are at 10000MB or above */
    msnprintf(max5, 6, "%4" FMT_OFF_T "M", bytes/ONE_MEGABYTE);

  else if(bytes < 100 * ONE_GIGABYTE)
    /* 10000 MB - 100 GB, we show it as XX.XG */
    msnprintf(max5, 6, "%2" FMT_OFF_T ".%0"
              FMT_OFF_T "G", bytes/ONE_GIGABYTE,
              (bytes%ONE_GIGABYTE) / (ONE_GIGABYTE/10) );

  else if(bytes < 10000 * ONE_GIGABYTE)
    /* up to 10000GB, display without decimal: XXXXG */
    msnprintf(max5, 6, "%4" FMT_OFF_T "G", bytes/ONE_GIGABYTE);

  else if(bytes < 10000 * ONE_TERABYTE)
    /* up to 10000TB, display without decimal: XXXXT */
    msnprintf(max5, 6, "%4" FMT_OFF_T "T", bytes/ONE_TERABYTE);

  else
    /* up to 10000PB, display without decimal: XXXXP */
    msnprintf(max5, 6, "%4" FMT_OFF_T "P", bytes/ONE_PETABYTE);

  /* 16384 petabytes (16 exabytes) is the maximum a 64-bit unsigned number can
     hold, but our data type is signed so 8192PB will be the maximum. */

  return max5;
}
#endif

/*

   New proposed interface, 9th of February 2000:

   pgrsStartNow() - sets start time
   pgrsSetDownloadSize(x) - known expected download size
   pgrsSetUploadSize(x) - known expected upload size
   pgrsSetDownloadCounter() - amount of data currently downloaded
   pgrsSetUploadCounter() - amount of data currently uploaded
   pgrsUpdate() - show progress
   pgrsDone() - transfer complete

*/

int Curl_pgrsDone(struct Curl_easy *data)
{
  int rc;
  data->progress.lastshow = 0;
  rc = Curl_pgrsUpdate(data); /* the final (forced) update */
  if(rc)
    return rc;

  if(!data->progress.hide && !data->progress.callback)
    /* only output if we do not use a progress callback and we are not
     * hidden */
    fprintf(data->set.err, "\n");

  data->progress.speeder_c = 0; /* reset the progress meter display */
  return 0;
}

/* reset the known transfer sizes */
void Curl_pgrsResetTransferSizes(struct Curl_easy *data)
{
  Curl_pgrsSetDownloadSize(data, -1);
  Curl_pgrsSetUploadSize(data, -1);
}

/*
 *
 * Curl_pgrsTimeWas(). Store the timestamp time at the given label.
 */
void Curl_pgrsTimeWas(struct Curl_easy *data, timerid timer,
                      struct curltime timestamp)
{
  timediff_t *delta = NULL;

  switch(timer) {
  default:
  case TIMER_NONE:
    /* mistake filter */
    break;
  case TIMER_STARTOP:
    /* This is set at the start of a transfer */
    data->progress.t_startop = timestamp;
    data->progress.t_startqueue = timestamp;
    data->progress.t_postqueue = 0;
    break;
  case TIMER_STARTSINGLE:
    /* This is set at the start of each single transfer */
    data->progress.t_startsingle = timestamp;
    data->progress.is_t_startransfer_set = FALSE;
    break;
  case TIMER_POSTQUEUE:
    /* Queue time is accumulative from all involved redirects */
    data->progress.t_postqueue +=
      curlx_timediff_us(timestamp, data->progress.t_startqueue);
    break;
  case TIMER_STARTACCEPT:
    data->progress.t_acceptdata = timestamp;
    break;
  case TIMER_NAMELOOKUP:
    delta = &data->progress.t_nslookup;
    break;
  case TIMER_CONNECT:
    delta = &data->progress.t_connect;
    break;
  case TIMER_APPCONNECT:
    delta = &data->progress.t_appconnect;
    break;
  case TIMER_PRETRANSFER:
    delta = &data->progress.t_pretransfer;
    break;
  case TIMER_STARTTRANSFER:
    delta = &data->progress.t_starttransfer;
    /* prevent updating t_starttransfer unless:
     *   1) this is the first time we are setting t_starttransfer
     *   2) a redirect has occurred since the last time t_starttransfer was set
     * This prevents repeated invocations of the function from incorrectly
     * changing the t_starttransfer time.
     */
    if(data->progress.is_t_startransfer_set) {
      return;
    }
    else {
      data->progress.is_t_startransfer_set = TRUE;
      break;
    }
  case TIMER_POSTRANSFER:
    delta = &data->progress.t_posttransfer;
    break;
  case TIMER_REDIRECT:
    data->progress.t_redirect = curlx_timediff_us(timestamp,
                                                 data->progress.start);
    data->progress.t_startqueue = timestamp;
    break;
  }
  if(delta) {
    timediff_t us = curlx_timediff_us(timestamp, data->progress.t_startsingle);
    if(us < 1)
      us = 1; /* make sure at least one microsecond passed */
    *delta += us;
  }
}

/*
 *
 * Curl_pgrsTime(). Store the current time at the given label. This fetches a
 * fresh "now" and returns it.
 *
 * @unittest: 1399
 */
struct curltime Curl_pgrsTime(struct Curl_easy *data, timerid timer)
{
  struct curltime now = curlx_now();

  Curl_pgrsTimeWas(data, timer, now);
  return now;
}

void Curl_pgrsStartNow(struct Curl_easy *data)
{
  struct Progress *p = &data->progress;
  p->speeder_c = 0; /* reset the progress meter display */
  p->start = curlx_now();
  p->is_t_startransfer_set = FALSE;
  p->ul.limit.start = p->start;
  p->dl.limit.start = p->start;
  p->ul.limit.start_size = 0;
  p->dl.limit.start_size = 0;
  p->dl.cur_size = 0;
  p->ul.cur_size = 0;
  /* the sizes are unknown at start */
  p->dl_size_known = FALSE;
  p->ul_size_known = FALSE;
  Curl_ratelimit(data, p->start);
}

/*
 * This is used to handle speed limits, calculating how many milliseconds to
 * wait until we are back under the speed limit, if needed.
 *
 * The way it works is by having a "starting point" (time & amount of data
 * transferred by then) used in the speed computation, to be used instead of
 * the start of the transfer. This starting point is regularly moved as
 * transfer goes on, to keep getting accurate values (instead of average over
 * the entire transfer).
 *
 * This function takes the current amount of data transferred, the amount at
 * the starting point, the limit (in bytes/s), the time of the starting point
 * and the current time.
 *
 * Returns 0 if no waiting is needed or when no waiting is needed but the
 * starting point should be reset (to current); or the number of milliseconds
 * to wait to get back under the speed limit.
 */
timediff_t Curl_pgrsLimitWaitTime(struct pgrs_dir *d,
                                  curl_off_t bytes_per_sec,
                                  struct curltime now)
{
  curl_off_t bytes = d->cur_size - d->limit.start_size;
  timediff_t should_ms;
  timediff_t took_ms;

  /* no limit or we did not get to any bytes yet */
  if(!bytes_per_sec || !bytes)
    return 0;

  /* The time it took us to have `bytes` */
  took_ms = curlx_timediff_ceil(now, d->limit.start);

  /* The time it *should* have taken us to have `bytes`
   * when obeying the bytes_per_sec speed_limit. */
  if(bytes < CURL_OFF_T_MAX/1000) {
    /* (1000 * bytes / (bytes / sec)) = 1000 * sec = ms */
    should_ms = (timediff_t) (1000 * bytes / bytes_per_sec);
  }
  else {
    /* very large `bytes`, first calc the seconds it should have taken.
     * if that is small enough, convert to milliseconds. */
    should_ms = (timediff_t) (bytes / bytes_per_sec);
    if(should_ms < TIMEDIFF_T_MAX/1000)
      should_ms *= 1000;
    else
      should_ms = TIMEDIFF_T_MAX;
  }

  if(took_ms < should_ms) {
    /* when gotten to `bytes` too fast, wait the difference */
    return should_ms - took_ms;
  }
  return 0;
}

/*
 * Set the number of downloaded bytes so far.
 */
CURLcode Curl_pgrsSetDownloadCounter(struct Curl_easy *data, curl_off_t size)
{
  data->progress.dl.cur_size = size;
  return CURLE_OK;
}

/*
 * Update the timestamp and sizestamp to use for rate limit calculations.
 */
void Curl_ratelimit(struct Curl_easy *data, struct curltime now)
{
  /* do not set a new stamp unless the time since last update is long enough */
  if(data->set.max_recv_speed) {
    if(curlx_timediff(now, data->progress.dl.limit.start) >=
       MIN_RATE_LIMIT_PERIOD) {
      data->progress.dl.limit.start = now;
      data->progress.dl.limit.start_size = data->progress.dl.cur_size;
    }
  }
  if(data->set.max_send_speed) {
    if(curlx_timediff(now, data->progress.ul.limit.start) >=
       MIN_RATE_LIMIT_PERIOD) {
      data->progress.ul.limit.start = now;
      data->progress.ul.limit.start_size = data->progress.ul.cur_size;
    }
  }
}

/*
 * Set the number of uploaded bytes so far.
 */
void Curl_pgrsSetUploadCounter(struct Curl_easy *data, curl_off_t size)
{
  data->progress.ul.cur_size = size;
}

void Curl_pgrsSetDownloadSize(struct Curl_easy *data, curl_off_t size)
{
  if(size >= 0) {
    data->progress.dl.total_size = size;
    data->progress.dl_size_known = TRUE;
  }
  else {
    data->progress.dl.total_size = 0;
    data->progress.dl_size_known = FALSE;
  }
}

void Curl_pgrsSetUploadSize(struct Curl_easy *data, curl_off_t size)
{
  if(size >= 0) {
    data->progress.ul.total_size = size;
    data->progress.ul_size_known = TRUE;
  }
  else {
    data->progress.ul.total_size = 0;
    data->progress.ul_size_known = FALSE;
  }
}

void Curl_pgrsEarlyData(struct Curl_easy *data, curl_off_t sent)
{
    data->progress.earlydata_sent = sent;
}

/* returns the average speed in bytes / second */
static curl_off_t trspeed(curl_off_t size, /* number of bytes */
                          curl_off_t us)   /* microseconds */
{
  if(us < 1)
    return size * 1000000;
  else if(size < CURL_OFF_T_MAX/1000000)
    return (size * 1000000) / us;
  else if(us >= 1000000)
    return size / (us / 1000000);
  else
    return CURL_OFF_T_MAX;
}

/* returns TRUE if it is time to show the progress meter */
static bool progress_calc(struct Curl_easy *data, struct curltime now)
{
  bool timetoshow = FALSE;
  struct Progress * const p = &data->progress;

  /* The time spent so far (from the start) in microseconds */
  p->timespent = curlx_timediff_us(now, p->start);
  p->dl.speed = trspeed(p->dl.cur_size, p->timespent);
  p->ul.speed = trspeed(p->ul.cur_size, p->timespent);

  /* Calculations done at most once a second, unless end is reached */
  if(p->lastshow != now.tv_sec) {
    int countindex; /* amount of seconds stored in the speeder array */
    int nowindex = p->speeder_c% CURR_TIME;
    p->lastshow = now.tv_sec;
    timetoshow = TRUE;

    /* Let's do the "current speed" thing, with the dl + ul speeds
       combined. Store the speed at entry 'nowindex'. */
    p->speeder[ nowindex ] = p->dl.cur_size + p->ul.cur_size;

    /* remember the exact time for this moment */
    p->speeder_time [ nowindex ] = now;

    /* advance our speeder_c counter, which is increased every time we get
       here and we expect it to never wrap as 2^32 is a lot of seconds! */
    p->speeder_c++;

    /* figure out how many index entries of data we have stored in our speeder
       array. With N_ENTRIES filled in, we have about N_ENTRIES-1 seconds of
       transfer. Imagine, after one second we have filled in two entries,
       after two seconds we have filled in three entries etc. */
    countindex = ((p->speeder_c >= CURR_TIME) ? CURR_TIME : p->speeder_c) - 1;

    /* first of all, we do not do this if there is no counted seconds yet */
    if(countindex) {
      int checkindex;
      timediff_t span_ms;
      curl_off_t amount;

      /* Get the index position to compare with the 'nowindex' position.
         Get the oldest entry possible. While we have less than CURR_TIME
         entries, the first entry will remain the oldest. */
      checkindex = (p->speeder_c >= CURR_TIME) ? p->speeder_c%CURR_TIME : 0;

      /* Figure out the exact time for the time span */
      span_ms = curlx_timediff(now, p->speeder_time[checkindex]);
      if(span_ms == 0)
        span_ms = 1; /* at least one millisecond MUST have passed */

      /* Calculate the average speed the last 'span_ms' milliseconds */
      amount = p->speeder[nowindex]- p->speeder[checkindex];

      if(amount > (0xffffffff/1000))
        /* the 'amount' value is bigger than would fit in 32 bits if
           multiplied with 1000, so we use the double math for this */
        p->current_speed = (curl_off_t)
          ((double)amount/((double)span_ms/1000.0));
      else
        /* the 'amount' value is small enough to fit within 32 bits even
           when multiplied with 1000 */
        p->current_speed = amount * 1000/span_ms;
    }
    else
      /* the first second we use the average */
      p->current_speed = p->ul.speed + p->dl.speed;

  } /* Calculations end */
  return timetoshow;
}

#ifndef CURL_DISABLE_PROGRESS_METER

struct pgrs_estimate {
  curl_off_t secs;
  curl_off_t percent;
};

static curl_off_t pgrs_est_percent(curl_off_t total, curl_off_t cur)
{
  if(total > 10000)
    return cur / (total / 100);
  else if(total > 0)
    return (cur*100) / total;
  return 0;
}

static void pgrs_estimates(struct pgrs_dir *d,
                           bool total_known,
                           struct pgrs_estimate *est)
{
  est->secs = 0;
  est->percent = 0;
  if(total_known && (d->speed > 0)) {
    est->secs = d->total_size / d->speed;
    est->percent = pgrs_est_percent(d->total_size, d->cur_size);
  }
}

static void progress_meter(struct Curl_easy *data)
{
  struct Progress *p = &data->progress;
  char max5[6][10];
  struct pgrs_estimate dl_estm;
  struct pgrs_estimate ul_estm;
  struct pgrs_estimate total_estm;
  curl_off_t total_cur_size;
  curl_off_t total_expected_size;
  curl_off_t dl_size;
  char time_left[10];
  char time_total[10];
  char time_spent[10];
  curl_off_t cur_secs = (curl_off_t)p->timespent/1000000; /* seconds */

  if(!p->headers_out) {
    if(data->state.resume_from) {
      fprintf(data->set.err,
              "** Resuming transfer from byte position %" FMT_OFF_T "\n",
              data->state.resume_from);
    }
    fprintf(data->set.err,
            "  %% Total    %% Received %% Xferd  Average Speed   "
            "Time    Time     Time  Current\n"
            "                                 Dload  Upload   "
            "Total   Spent    Left  Speed\n");
    p->headers_out = TRUE; /* headers are shown */
  }

  /* Figure out the estimated time of arrival for upload and download */
  pgrs_estimates(&p->ul, (bool)p->ul_size_known, &ul_estm);
  pgrs_estimates(&p->dl, (bool)p->dl_size_known, &dl_estm);

  /* Since both happen at the same time, total expected duration is max. */
  total_estm.secs = CURLMAX(ul_estm.secs, dl_estm.secs);
  /* create the three time strings */
  time2str(time_left, total_estm.secs > 0 ? (total_estm.secs - cur_secs) : 0);
  time2str(time_total, total_estm.secs);
  time2str(time_spent, cur_secs);

  /* Get the total amount of data expected to get transferred */
  total_expected_size =
    p->ul_size_known ? p->ul.total_size : p->ul.cur_size;

  dl_size =
    p->dl_size_known ? p->dl.total_size : p->dl.cur_size;

  /* integer overflow check */
  if((CURL_OFF_T_MAX - total_expected_size) < dl_size)
    total_expected_size = CURL_OFF_T_MAX; /* capped */
  else
    total_expected_size += dl_size;

  /* We have transferred this much so far */
  total_cur_size = p->dl.cur_size + p->ul.cur_size;

  /* Get the percentage of data transferred so far */
  total_estm.percent = pgrs_est_percent(total_expected_size, total_cur_size);

  fprintf(data->set.err,
          "\r"
          "%3" FMT_OFF_T " %s  "
          "%3" FMT_OFF_T " %s  "
          "%3" FMT_OFF_T " %s  %s  %s %s %s %s %s",
          total_estm.percent, /* 3 letters */           /* total % */
          max5data(total_expected_size, max5[2]),       /* total size */
          dl_estm.percent, /* 3 letters */              /* rcvd % */
          max5data(p->dl.cur_size, max5[0]),            /* rcvd size */
          ul_estm.percent, /* 3 letters */              /* xfer % */
          max5data(p->ul.cur_size, max5[1]),            /* xfer size */
          max5data(p->dl.speed, max5[3]),               /* avrg dl speed */
          max5data(p->ul.speed, max5[4]),               /* avrg ul speed */
          time_total,    /* 8 letters */                /* total time */
          time_spent,    /* 8 letters */                /* time spent */
          time_left,     /* 8 letters */                /* time left */
          max5data(p->current_speed, max5[5])
    );

  /* we flush the output stream to make it appear as soon as possible */
  fflush(data->set.err);
}
#else
 /* progress bar disabled */
#define progress_meter(x) Curl_nop_stmt
#endif


/*
 * Curl_pgrsUpdate() returns 0 for success or the value returned by the
 * progress callback!
 */
static int pgrsupdate(struct Curl_easy *data, bool showprogress)
{
  if(!data->progress.hide) {
    if(data->set.fxferinfo) {
      int result;
      /* There is a callback set, call that */
      Curl_set_in_callback(data, TRUE);
      result = data->set.fxferinfo(data->set.progress_client,
                                   data->progress.dl.total_size,
                                   data->progress.dl.cur_size,
                                   data->progress.ul.total_size,
                                   data->progress.ul.cur_size);
      Curl_set_in_callback(data, FALSE);
      if(result != CURL_PROGRESSFUNC_CONTINUE) {
        if(result)
          failf(data, "Callback aborted");
        return result;
      }
    }
    else if(data->set.fprogress) {
      int result;
      /* The older deprecated callback is set, call that */
      Curl_set_in_callback(data, TRUE);
      result = data->set.fprogress(data->set.progress_client,
                                   (double)data->progress.dl.total_size,
                                   (double)data->progress.dl.cur_size,
                                   (double)data->progress.ul.total_size,
                                   (double)data->progress.ul.cur_size);
      Curl_set_in_callback(data, FALSE);
      if(result != CURL_PROGRESSFUNC_CONTINUE) {
        if(result)
          failf(data, "Callback aborted");
        return result;
      }
    }

    if(showprogress)
      progress_meter(data);
  }

  return 0;
}

int Curl_pgrsUpdate(struct Curl_easy *data)
{
  struct curltime now = curlx_now(); /* what time is it */
  bool showprogress = progress_calc(data, now);
  return pgrsupdate(data, showprogress);
}

/*
 * Update all progress, do not do progress meter/callbacks.
 */
void Curl_pgrsUpdate_nometer(struct Curl_easy *data)
{
  struct curltime now = curlx_now(); /* what time is it */
  (void)progress_calc(data, now);
}
