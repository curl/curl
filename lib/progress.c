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
#include "transfer.h"
#include "curlx/timeval.h"

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
    curl_msnprintf(r, 9, "%2" FMT_OFF_T ":%02" FMT_OFF_T ":%02" FMT_OFF_T,
                   h, m, s);
  }
  else {
    /* this equals to more than 99 hours, switch to a more suitable output
       format to fit within the limits. */
    curl_off_t d = seconds / 86400;
    h = (seconds - (d * 86400)) / 3600;
    if(d <= 999)
      curl_msnprintf(r, 9, "%3" FMT_OFF_T "d %02" FMT_OFF_T "h", d, h);
    else
      curl_msnprintf(r, 9, "%7" FMT_OFF_T "d", d);
  }
}

/* The point of this function would be to return a string of the input data,
   but never longer than 6 columns (+ one zero byte).
   Add suffix k, M, G when suitable... */
static char *max6data(curl_off_t bytes, char *max6)
{
  /* a signed 64-bit value is 8192 petabytes maximum, shown as
     8.0E (exabytes)*/
  if(bytes < 100000)
    curl_msnprintf(max6, 7, "%6" CURL_FORMAT_CURL_OFF_T, bytes);
  else {
    const char unit[] = { 'k', 'M', 'G', 'T', 'P', 'E', 0 };
    int k = 0;
    curl_off_t nbytes;
    do {
      nbytes = bytes / 1024;
      if(nbytes < 1000)
        break;
      bytes = nbytes;
      k++;
      DEBUGASSERT(unit[k]);
    } while(unit[k]);
    /* xxx.yU */
    curl_msnprintf(max6, 7, "%3" CURL_FORMAT_CURL_OFF_T
                   ".%" CURL_FORMAT_CURL_OFF_T "%c", nbytes,
                   (bytes % 1024) / (1024 / 10), unit[k]);
  }
  return max6;
}
#endif

static void pgrs_speedinit(struct Curl_easy *data)
{
  memset(&data->state.keeps_speed, 0, sizeof(struct curltime));
}

/*
 * @unittest: 1606
 */
UNITTEST CURLcode pgrs_speedcheck(struct Curl_easy *data,
                                  struct curltime *pnow)
{
  if(!data->set.low_speed_time || !data->set.low_speed_limit ||
     Curl_xfer_recv_is_paused(data) || Curl_xfer_send_is_paused(data))
    /* A paused transfer is not qualified for speed checks */
    return CURLE_OK;

  if(data->progress.current_speed >= 0) {
    if(data->progress.current_speed < data->set.low_speed_limit) {
      if(!data->state.keeps_speed.tv_sec)
        /* under the limit at this moment */
        data->state.keeps_speed = *pnow;
      else {
        /* how long has it been under the limit */
        timediff_t howlong = curlx_timediff_ms(*pnow, data->state.keeps_speed);

        if(howlong >= data->set.low_speed_time * 1000) {
          /* too long */
          failf(data,
                "Operation too slow. "
                "Less than %ld bytes/sec transferred the last %ld seconds",
                data->set.low_speed_limit,
                data->set.low_speed_time);
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
    }
    else
      /* faster right now */
      data->state.keeps_speed.tv_sec = 0;
  }

  /* since low speed limit is enabled, set the expire timer to make this
     connection's speed get checked again in a second */
  Curl_expire(data, 1000, EXPIRE_SPEEDCHECK);

  return CURLE_OK;
}

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
    curl_mfprintf(data->set.err, "\n");

  return 0;
}

void Curl_pgrsReset(struct Curl_easy *data)
{
  Curl_pgrsSetUploadCounter(data, 0);
  Curl_pgrsSetDownloadCounter(data, 0);
  Curl_pgrsSetUploadSize(data, -1);
  Curl_pgrsSetDownloadSize(data, -1);
  data->progress.speeder_c = 0; /* reset speed records */
  pgrs_speedinit(data);
}

/* reset the known transfer sizes */
void Curl_pgrsResetTransferSizes(struct Curl_easy *data)
{
  Curl_pgrsSetDownloadSize(data, -1);
  Curl_pgrsSetUploadSize(data, -1);
}

void Curl_pgrsRecvPause(struct Curl_easy *data, bool enable)
{
  if(!enable) {
    data->progress.speeder_c = 0; /* reset speed records */
    pgrs_speedinit(data); /* reset low speed measurements */
  }
}

void Curl_pgrsSendPause(struct Curl_easy *data, bool enable)
{
  if(!enable) {
    data->progress.speeder_c = 0; /* reset speed records */
    pgrs_speedinit(data); /* reset low speed measurements */
  }
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
  p->dl.cur_size = 0;
  p->ul.cur_size = 0;
  /* the sizes are unknown at start */
  p->dl_size_known = FALSE;
  p->ul_size_known = FALSE;
}

/*
 * Set the number of downloaded bytes so far.
 */
void Curl_pgrsSetDownloadCounter(struct Curl_easy *data, curl_off_t size)
{
  data->progress.dl.cur_size = size;
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
  else if(size < CURL_OFF_T_MAX / 1000000)
    return (size * 1000000) / us;
  else if(us >= 1000000)
    return size / (us / 1000000);
  else
    return CURL_OFF_T_MAX;
}

/* returns TRUE if it is time to show the progress meter */
static bool progress_calc(struct Curl_easy *data, struct curltime *pnow)
{
  struct Progress * const p = &data->progress;
  int i_next, i_oldest, i_latest;
  timediff_t duration_ms;
  curl_off_t amount;

  /* The time spent so far (from the start) in microseconds */
  p->timespent = curlx_timediff_us(*pnow, p->start);
  p->dl.speed = trspeed(p->dl.cur_size, p->timespent);
  p->ul.speed = trspeed(p->ul.cur_size, p->timespent);

  if(!p->speeder_c) { /* no previous record exists */
    p->speed_amount[0] = p->dl.cur_size + p->ul.cur_size;
    p->speed_time[0] = *pnow;
    p->speeder_c++;
    /* use the overall average at the start */
    p->current_speed = p->ul.speed + p->dl.speed;
    p->lastshow = pnow->tv_sec;
    return TRUE;
  }
  /* We have at least one record now. Where to put the next and
   * where is the latest one? */
  i_next = p->speeder_c % CURL_SPEED_RECORDS;
  i_latest = (i_next > 0) ? (i_next - 1) : (CURL_SPEED_RECORDS - 1);

  /* Make a new record only when some time has passed.
   * Too frequent calls otherwise ruin the history. */
  if(curlx_timediff_ms(*pnow, p->speed_time[i_latest]) >= 1000) {
    p->speeder_c++;
    i_latest = i_next;
    p->speed_amount[i_latest] = p->dl.cur_size + p->ul.cur_size;
    p->speed_time[i_latest] = *pnow;
  }
  else if(data->req.done) {
    /* When a transfer is done, and we did not have a current speed
     * already, update the last record. Otherwise, stay at the speed
     * we have. The last chunk of data, when rate limiting, would increase
     * reported speed since it no longer measures a full second. */
    if(!p->current_speed) {
      p->speed_amount[i_latest] = p->dl.cur_size + p->ul.cur_size;
      p->speed_time[i_latest] = *pnow;
    }
  }
  else {
    /* transfer ongoing, wait for more time to pass. */
    return FALSE;
  }

  i_oldest = (p->speeder_c < CURL_SPEED_RECORDS) ? 0 :
             ((i_latest + 1) % CURL_SPEED_RECORDS);

  /* How much we transferred between oldest and current records */
  amount = p->speed_amount[i_latest] - p->speed_amount[i_oldest];
  /* How long this took */
  duration_ms = curlx_timediff_ms(p->speed_time[i_latest],
                                  p->speed_time[i_oldest]);
  if(duration_ms <= 0)
    duration_ms = 1;

  if(amount > (CURL_OFF_T_MAX / 1000)) {
    /* the 'amount' value is bigger than would fit in 64 bits if
       multiplied with 1000, so we use the double math for this */
    p->current_speed =
      (curl_off_t)(((double)amount * 1000.0) / (double)duration_ms);
  }
  else {
    /* the 'amount' value is small enough to fit within 32 bits even
       when multiplied with 1000 */
    p->current_speed = amount * 1000 / duration_ms;
  }

  if((p->lastshow == pnow->tv_sec) && !data->req.done)
    return FALSE;
  p->lastshow = pnow->tv_sec;
  return TRUE;
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
    return (cur * 100) / total;
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
  char max6[6][7];
  struct pgrs_estimate dl_estm;
  struct pgrs_estimate ul_estm;
  struct pgrs_estimate total_estm;
  curl_off_t total_cur_size;
  curl_off_t total_expected_size;
  curl_off_t dl_size;
  char time_left[10];
  char time_total[10];
  char time_spent[10];
  curl_off_t cur_secs = (curl_off_t)p->timespent / 1000000; /* seconds */

  if(!p->headers_out) {
    if(data->state.resume_from) {
      curl_mfprintf(data->set.err,
                    "** Resuming transfer from byte position %" FMT_OFF_T "\n",
                    data->state.resume_from);
    }
    curl_mfprintf(data->set.err,
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
  total_expected_size = p->ul_size_known ? p->ul.total_size : p->ul.cur_size;

  dl_size = p->dl_size_known ? p->dl.total_size : p->dl.cur_size;

  /* integer overflow check */
  if((CURL_OFF_T_MAX - total_expected_size) < dl_size)
    total_expected_size = CURL_OFF_T_MAX; /* capped */
  else
    total_expected_size += dl_size;

  /* We have transferred this much so far */
  total_cur_size = p->dl.cur_size + p->ul.cur_size;

  /* Get the percentage of data transferred so far */
  total_estm.percent = pgrs_est_percent(total_expected_size, total_cur_size);

  curl_mfprintf(data->set.err,
                "\r"
                "%3" FMT_OFF_T " %s "
                "%3" FMT_OFF_T " %s "
                "%3" FMT_OFF_T " %s %s %s  %s %s %s %s",
                total_estm.percent, /* 3 letters */         /* total % */
                max6data(total_expected_size, max6[2]),     /* total size */
                dl_estm.percent, /* 3 letters */            /* rcvd % */
                max6data(p->dl.cur_size, max6[0]),          /* rcvd size */
                ul_estm.percent, /* 3 letters */            /* xfer % */
                max6data(p->ul.cur_size, max6[1]),          /* xfer size */
                max6data(p->dl.speed, max6[3]),             /* avrg dl speed */
                max6data(p->ul.speed, max6[4]),             /* avrg ul speed */
                time_total,    /* 8 letters */              /* total time */
                time_spent,    /* 8 letters */              /* time spent */
                time_left,     /* 8 letters */              /* time left */
                max6data(p->current_speed, max6[5])
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
static CURLcode pgrsupdate(struct Curl_easy *data, bool showprogress)
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
        if(result) {
          failf(data, "Callback aborted");
          return CURLE_ABORTED_BY_CALLBACK;
        }
        return CURLE_OK;
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
        if(result) {
          failf(data, "Callback aborted");
          return CURLE_ABORTED_BY_CALLBACK;
        }
        return CURLE_OK;
      }
    }

    if(showprogress)
      progress_meter(data);
  }

  return CURLE_OK;
}

static CURLcode pgrs_update(struct Curl_easy *data, struct curltime *pnow)
{
  bool showprogress = progress_calc(data, pnow);
  return pgrsupdate(data, showprogress);
}

CURLcode Curl_pgrsUpdate(struct Curl_easy *data)
{
  struct curltime now = curlx_now(); /* what time is it */
  return pgrs_update(data, &now);
}

CURLcode Curl_pgrsCheck(struct Curl_easy *data)
{
  struct curltime now = curlx_now();
  CURLcode result;

  result = pgrs_update(data, &now);
  if(!result && !data->req.done)
    result = pgrs_speedcheck(data, &now);
  return result;
}

/*
 * Update all progress, do not do progress meter/callbacks.
 */
void Curl_pgrsUpdate_nometer(struct Curl_easy *data)
{
  struct curltime now = curlx_now(); /* what time is it */
  (void)progress_calc(data, &now);
}
