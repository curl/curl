/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#include "urldata.h"
#include "sendf.h"
#include "progress.h"
#include "curl_printf.h"

/* Provide a string that is 2 + 1 + 2 + 1 + 2 = 8 letters long (plus the zero
   byte) */
static void time2str(char *r, curl_off_t seconds)
{
  curl_off_t d, h, m, s;
  if(seconds <= 0) {
    strcpy(r, "--:--:--");
    return;
  }
  h = seconds / CURL_OFF_T_C(3600);
  if(h <= CURL_OFF_T_C(99)) {
    m = (seconds - (h*CURL_OFF_T_C(3600))) / CURL_OFF_T_C(60);
    s = (seconds - (h*CURL_OFF_T_C(3600))) - (m*CURL_OFF_T_C(60));
    snprintf(r, 9, "%2" CURL_FORMAT_CURL_OFF_T ":%02" CURL_FORMAT_CURL_OFF_T
             ":%02" CURL_FORMAT_CURL_OFF_T, h, m, s);
  }
  else {
    /* this equals to more than 99 hours, switch to a more suitable output
       format to fit within the limits. */
    d = seconds / CURL_OFF_T_C(86400);
    h = (seconds - (d*CURL_OFF_T_C(86400))) / CURL_OFF_T_C(3600);
    if(d <= CURL_OFF_T_C(999))
      snprintf(r, 9, "%3" CURL_FORMAT_CURL_OFF_T
               "d %02" CURL_FORMAT_CURL_OFF_T "h", d, h);
    else
      snprintf(r, 9, "%7" CURL_FORMAT_CURL_OFF_T "d", d);
  }
}

/* The point of this function would be to return a string of the input data,
   but never longer than 5 columns (+ one zero byte).
   Add suffix k, M, G when suitable... */
static char *max5data(curl_off_t bytes, char *max5)
{
#define ONE_KILOBYTE  CURL_OFF_T_C(1024)
#define ONE_MEGABYTE (CURL_OFF_T_C(1024) * ONE_KILOBYTE)
#define ONE_GIGABYTE (CURL_OFF_T_C(1024) * ONE_MEGABYTE)
#define ONE_TERABYTE (CURL_OFF_T_C(1024) * ONE_GIGABYTE)
#define ONE_PETABYTE (CURL_OFF_T_C(1024) * ONE_TERABYTE)

  if(bytes < CURL_OFF_T_C(100000))
    snprintf(max5, 6, "%5" CURL_FORMAT_CURL_OFF_T, bytes);

  else if(bytes < CURL_OFF_T_C(10000) * ONE_KILOBYTE)
    snprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "k", bytes/ONE_KILOBYTE);

  else if(bytes < CURL_OFF_T_C(100) * ONE_MEGABYTE)
    /* 'XX.XM' is good as long as we're less than 100 megs */
    snprintf(max5, 6, "%2" CURL_FORMAT_CURL_OFF_T ".%0"
             CURL_FORMAT_CURL_OFF_T "M", bytes/ONE_MEGABYTE,
             (bytes%ONE_MEGABYTE) / (ONE_MEGABYTE/CURL_OFF_T_C(10)) );

#if (CURL_SIZEOF_CURL_OFF_T > 4)

  else if(bytes < CURL_OFF_T_C(10000) * ONE_MEGABYTE)
    /* 'XXXXM' is good until we're at 10000MB or above */
    snprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "M", bytes/ONE_MEGABYTE);

  else if(bytes < CURL_OFF_T_C(100) * ONE_GIGABYTE)
    /* 10000 MB - 100 GB, we show it as XX.XG */
    snprintf(max5, 6, "%2" CURL_FORMAT_CURL_OFF_T ".%0"
             CURL_FORMAT_CURL_OFF_T "G", bytes/ONE_GIGABYTE,
             (bytes%ONE_GIGABYTE) / (ONE_GIGABYTE/CURL_OFF_T_C(10)) );

  else if(bytes < CURL_OFF_T_C(10000) * ONE_GIGABYTE)
    /* up to 10000GB, display without decimal: XXXXG */
    snprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "G", bytes/ONE_GIGABYTE);

  else if(bytes < CURL_OFF_T_C(10000) * ONE_TERABYTE)
    /* up to 10000TB, display without decimal: XXXXT */
    snprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "T", bytes/ONE_TERABYTE);

  else
    /* up to 10000PB, display without decimal: XXXXP */
    snprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "P", bytes/ONE_PETABYTE);

    /* 16384 petabytes (16 exabytes) is the maximum a 64 bit unsigned number
       can hold, but our data type is signed so 8192PB will be the maximum. */

#else

  else
    snprintf(max5, 6, "%4" CURL_FORMAT_CURL_OFF_T "M", bytes/ONE_MEGABYTE);

#endif

  return max5;
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

int Curl_pgrsDone(struct connectdata *conn)
{
  int rc;
  struct Curl_easy *data = conn->data;
  data->progress.lastshow=0;
  rc = Curl_pgrsUpdate(conn); /* the final (forced) update */
  if(rc)
    return rc;

  if(!(data->progress.flags & PGRS_HIDE) &&
     !data->progress.callback)
    /* only output if we don't use a progress callback and we're not
     * hidden */
    fprintf(data->set.err, "\n");

  data->progress.speeder_c = 0; /* reset the progress meter display */
  return 0;
}

/* reset all times except redirect, and reset the known transfer sizes */
void Curl_pgrsResetTimesSizes(struct Curl_easy *data)
{
  data->progress.t_nslookup = 0.0;
  data->progress.t_connect = 0.0;
  data->progress.t_pretransfer = 0.0;
  data->progress.t_starttransfer = 0.0;

  Curl_pgrsSetDownloadSize(data, -1);
  Curl_pgrsSetUploadSize(data, -1);
}

void Curl_pgrsTime(struct Curl_easy *data, timerid timer)
{
  struct timeval now = Curl_tvnow();

  switch(timer) {
  default:
  case TIMER_NONE:
    /* mistake filter */
    break;
  case TIMER_STARTOP:
    /* This is set at the start of a transfer */
    data->progress.t_startop = now;
    break;
  case TIMER_STARTSINGLE:
    /* This is set at the start of each single fetch */
    data->progress.t_startsingle = now;
    break;

  case TIMER_STARTACCEPT:
    data->progress.t_acceptdata = Curl_tvnow();
    break;

  case TIMER_NAMELOOKUP:
    data->progress.t_nslookup =
      Curl_tvdiff_secs(now, data->progress.t_startsingle);
    break;
  case TIMER_CONNECT:
    data->progress.t_connect =
      Curl_tvdiff_secs(now, data->progress.t_startsingle);
    break;
  case TIMER_APPCONNECT:
    data->progress.t_appconnect =
      Curl_tvdiff_secs(now, data->progress.t_startsingle);
    break;
  case TIMER_PRETRANSFER:
    data->progress.t_pretransfer =
      Curl_tvdiff_secs(now, data->progress.t_startsingle);
    break;
  case TIMER_STARTTRANSFER:
    data->progress.t_starttransfer =
      Curl_tvdiff_secs(now, data->progress.t_startsingle);
    break;
  case TIMER_POSTRANSFER:
    /* this is the normal end-of-transfer thing */
    break;
  case TIMER_REDIRECT:
    data->progress.t_redirect = Curl_tvdiff_secs(now, data->progress.start);
    break;
  }
}

void Curl_pgrsStartNow(struct Curl_easy *data)
{
  data->progress.speeder_c = 0; /* reset the progress meter display */
  data->progress.start = Curl_tvnow();
  data->progress.ul_limit_start.tv_sec = 0;
  data->progress.ul_limit_start.tv_usec = 0;
  data->progress.dl_limit_start.tv_sec = 0;
  data->progress.dl_limit_start.tv_usec = 0;
  /* clear all bits except HIDE and HEADERS_OUT */
  data->progress.flags &= PGRS_HIDE|PGRS_HEADERS_OUT;
}

/*
 * This is used to handle speed limits, calculating how much milliseconds we
 * need to wait until we're back under the speed limit, if needed.
 *
 * The way it works is by having a "starting point" (time & amount of data
 * transfered by then) used in the speed computation, to be used instead of the
 * start of the transfer.
 * This starting point is regularly moved as transfer goes on, to keep getting
 * accurate values (instead of average over the entire tranfer).
 *
 * This function takes the current amount of data transfered, the amount at the
 * starting point, the limit (in bytes/s), the time of the starting point and
 * the current time.
 *
 * Returns -1 if no waiting is needed (not enough data transfered since
 * starting point yet), 0 when no waiting is needed but the starting point
 * should be reset (to current), or the number of milliseconds to wait to get
 * back under the speed limit.
 */
long Curl_pgrsLimitWaitTime(curl_off_t cursize,
                            curl_off_t startsize,
                            curl_off_t limit,
                            struct timeval start,
                            struct timeval now)
{
  curl_off_t size = cursize - startsize;
  time_t minimum;
  time_t actual;

  /* we don't have a starting point yet -- return 0 so it gets (re)set */
  if(start.tv_sec == 0 && start.tv_usec == 0)
    return 0;

  /* not enough data yet */
  if(size < limit)
    return -1;

  minimum = (time_t) (CURL_OFF_T_C(1000) * size / limit);
  actual = Curl_tvdiff(now, start);

  if(actual < minimum)
    /* this is a conversion on some systems (64bit time_t => 32bit long) */
    return (long)(minimum - actual);
  else
    return 0;
}

void Curl_pgrsSetDownloadCounter(struct Curl_easy *data, curl_off_t size)
{
  struct timeval now = Curl_tvnow();

  data->progress.downloaded = size;

  /* download speed limit */
  if((data->set.max_recv_speed > 0) &&
     (Curl_pgrsLimitWaitTime(data->progress.downloaded,
                             data->progress.dl_limit_size,
                             data->set.max_recv_speed,
                             data->progress.dl_limit_start,
                             now) == 0)) {
    data->progress.dl_limit_start = now;
    data->progress.dl_limit_size = size;
  }
}

void Curl_pgrsSetUploadCounter(struct Curl_easy *data, curl_off_t size)
{
  struct timeval now = Curl_tvnow();

  data->progress.uploaded = size;

  /* upload speed limit */
  if((data->set.max_send_speed > 0) &&
     (Curl_pgrsLimitWaitTime(data->progress.uploaded,
                             data->progress.ul_limit_size,
                             data->set.max_send_speed,
                             data->progress.ul_limit_start,
                             now) == 0)) {
    data->progress.ul_limit_start = now;
    data->progress.ul_limit_size = size;
  }
}

void Curl_pgrsSetDownloadSize(struct Curl_easy *data, curl_off_t size)
{
  if(size >= 0) {
    data->progress.size_dl = size;
    data->progress.flags |= PGRS_DL_SIZE_KNOWN;
  }
  else {
    data->progress.size_dl = 0;
    data->progress.flags &= ~PGRS_DL_SIZE_KNOWN;
  }
}

void Curl_pgrsSetUploadSize(struct Curl_easy *data, curl_off_t size)
{
  if(size >= 0) {
    data->progress.size_ul = size;
    data->progress.flags |= PGRS_UL_SIZE_KNOWN;
  }
  else {
    data->progress.size_ul = 0;
    data->progress.flags &= ~PGRS_UL_SIZE_KNOWN;
  }
}

/*
 * Curl_pgrsUpdate() returns 0 for success or the value returned by the
 * progress callback!
 */
int Curl_pgrsUpdate(struct connectdata *conn)
{
  struct timeval now;
  int result;
  char max5[6][10];
  curl_off_t dlpercen=0;
  curl_off_t ulpercen=0;
  curl_off_t total_percen=0;
  curl_off_t total_transfer;
  curl_off_t total_expected_transfer;
  curl_off_t timespent;
  struct Curl_easy *data = conn->data;
  int nowindex = data->progress.speeder_c% CURR_TIME;
  int checkindex;
  int countindex; /* amount of seconds stored in the speeder array */
  char time_left[10];
  char time_total[10];
  char time_spent[10];
  curl_off_t ulestimate=0;
  curl_off_t dlestimate=0;
  curl_off_t total_estimate;
  bool shownow=FALSE;

  now = Curl_tvnow(); /* what time is it */

  /* The time spent so far (from the start) */
  data->progress.timespent = curlx_tvdiff_secs(now, data->progress.start);
  timespent = (curl_off_t)data->progress.timespent;

  /* The average download speed this far */
  data->progress.dlspeed = (curl_off_t)
    ((double)data->progress.downloaded/
     (data->progress.timespent>0?data->progress.timespent:1));

  /* The average upload speed this far */
  data->progress.ulspeed = (curl_off_t)
    ((double)data->progress.uploaded/
     (data->progress.timespent>0?data->progress.timespent:1));

  /* Calculations done at most once a second, unless end is reached */
  if(data->progress.lastshow != now.tv_sec) {
    shownow = TRUE;

    data->progress.lastshow = now.tv_sec;

    /* Let's do the "current speed" thing, which should use the fastest
       of the dl/ul speeds. Store the faster speed at entry 'nowindex'. */
    data->progress.speeder[ nowindex ] =
      data->progress.downloaded>data->progress.uploaded?
      data->progress.downloaded:data->progress.uploaded;

    /* remember the exact time for this moment */
    data->progress.speeder_time [ nowindex ] = now;

    /* advance our speeder_c counter, which is increased every time we get
       here and we expect it to never wrap as 2^32 is a lot of seconds! */
    data->progress.speeder_c++;

    /* figure out how many index entries of data we have stored in our speeder
       array. With N_ENTRIES filled in, we have about N_ENTRIES-1 seconds of
       transfer. Imagine, after one second we have filled in two entries,
       after two seconds we've filled in three entries etc. */
    countindex = ((data->progress.speeder_c>=CURR_TIME)?
                  CURR_TIME:data->progress.speeder_c) - 1;

    /* first of all, we don't do this if there's no counted seconds yet */
    if(countindex) {
      time_t span_ms;

      /* Get the index position to compare with the 'nowindex' position.
         Get the oldest entry possible. While we have less than CURR_TIME
         entries, the first entry will remain the oldest. */
      checkindex = (data->progress.speeder_c>=CURR_TIME)?
        data->progress.speeder_c%CURR_TIME:0;

      /* Figure out the exact time for the time span */
      span_ms = Curl_tvdiff(now,
                            data->progress.speeder_time[checkindex]);
      if(0 == span_ms)
        span_ms=1; /* at least one millisecond MUST have passed */

      /* Calculate the average speed the last 'span_ms' milliseconds */
      {
        curl_off_t amount = data->progress.speeder[nowindex]-
          data->progress.speeder[checkindex];

        if(amount > CURL_OFF_T_C(4294967) /* 0xffffffff/1000 */)
          /* the 'amount' value is bigger than would fit in 32 bits if
             multiplied with 1000, so we use the double math for this */
          data->progress.current_speed = (curl_off_t)
            ((double)amount/((double)span_ms/1000.0));
        else
          /* the 'amount' value is small enough to fit within 32 bits even
             when multiplied with 1000 */
          data->progress.current_speed = amount*CURL_OFF_T_C(1000)/span_ms;
      }
    }
    else
      /* the first second we use the main average */
      data->progress.current_speed =
        (data->progress.ulspeed>data->progress.dlspeed)?
        data->progress.ulspeed:data->progress.dlspeed;

  } /* Calculations end */

  if(!(data->progress.flags & PGRS_HIDE)) {
    /* progress meter has not been shut off */

    if(data->set.fxferinfo) {
      /* There's a callback set, call that */
      result= data->set.fxferinfo(data->set.progress_client,
                                  data->progress.size_dl,
                                  data->progress.downloaded,
                                  data->progress.size_ul,
                                  data->progress.uploaded);
      if(result)
        failf(data, "Callback aborted");
      return result;
    }
    else if(data->set.fprogress) {
      /* The older deprecated callback is set, call that */
      result= data->set.fprogress(data->set.progress_client,
                                  (double)data->progress.size_dl,
                                  (double)data->progress.downloaded,
                                  (double)data->progress.size_ul,
                                  (double)data->progress.uploaded);
      if(result)
        failf(data, "Callback aborted");
      return result;
    }

    if(!shownow)
      /* only show the internal progress meter once per second */
      return 0;

    /* If there's no external callback set, use internal code to show
       progress */

    if(!(data->progress.flags & PGRS_HEADERS_OUT)) {
      if(data->state.resume_from) {
        fprintf(data->set.err,
                "** Resuming transfer from byte position %"
                CURL_FORMAT_CURL_OFF_T "\n", data->state.resume_from);
      }
      fprintf(data->set.err,
              "  %% Total    %% Received %% Xferd  Average Speed   "
              "Time    Time     Time  Current\n"
              "                                 Dload  Upload   "
              "Total   Spent    Left  Speed\n");
      data->progress.flags |= PGRS_HEADERS_OUT; /* headers are shown */
    }

    /* Figure out the estimated time of arrival for the upload */
    if((data->progress.flags & PGRS_UL_SIZE_KNOWN) &&
       (data->progress.ulspeed > CURL_OFF_T_C(0))) {
      ulestimate = data->progress.size_ul / data->progress.ulspeed;

      if(data->progress.size_ul > CURL_OFF_T_C(10000))
        ulpercen = data->progress.uploaded /
          (data->progress.size_ul/CURL_OFF_T_C(100));
      else if(data->progress.size_ul > CURL_OFF_T_C(0))
        ulpercen = (data->progress.uploaded*100) /
          data->progress.size_ul;
    }

    /* ... and the download */
    if((data->progress.flags & PGRS_DL_SIZE_KNOWN) &&
       (data->progress.dlspeed > CURL_OFF_T_C(0))) {
      dlestimate = data->progress.size_dl / data->progress.dlspeed;

      if(data->progress.size_dl > CURL_OFF_T_C(10000))
        dlpercen = data->progress.downloaded /
          (data->progress.size_dl/CURL_OFF_T_C(100));
      else if(data->progress.size_dl > CURL_OFF_T_C(0))
        dlpercen = (data->progress.downloaded*100) /
          data->progress.size_dl;
    }

    /* Now figure out which of them is slower and use that one for the
       total estimate! */
    total_estimate = ulestimate>dlestimate?ulestimate:dlestimate;

    /* create the three time strings */
    time2str(time_left, total_estimate > 0?(total_estimate - timespent):0);
    time2str(time_total, total_estimate);
    time2str(time_spent, timespent);

    /* Get the total amount of data expected to get transferred */
    total_expected_transfer =
      (data->progress.flags & PGRS_UL_SIZE_KNOWN?
       data->progress.size_ul:data->progress.uploaded)+
      (data->progress.flags & PGRS_DL_SIZE_KNOWN?
       data->progress.size_dl:data->progress.downloaded);

    /* We have transferred this much so far */
    total_transfer = data->progress.downloaded + data->progress.uploaded;

    /* Get the percentage of data transferred so far */
    if(total_expected_transfer > CURL_OFF_T_C(10000))
      total_percen = total_transfer /
        (total_expected_transfer/CURL_OFF_T_C(100));
    else if(total_expected_transfer > CURL_OFF_T_C(0))
      total_percen = (total_transfer*100) / total_expected_transfer;

    fprintf(data->set.err,
            "\r"
            "%3" CURL_FORMAT_CURL_OFF_T " %s  "
            "%3" CURL_FORMAT_CURL_OFF_T " %s  "
            "%3" CURL_FORMAT_CURL_OFF_T " %s  %s  %s %s %s %s %s",
            total_percen,  /* 3 letters */                /* total % */
            max5data(total_expected_transfer, max5[2]),   /* total size */
            dlpercen,      /* 3 letters */                /* rcvd % */
            max5data(data->progress.downloaded, max5[0]), /* rcvd size */
            ulpercen,      /* 3 letters */                /* xfer % */
            max5data(data->progress.uploaded, max5[1]),   /* xfer size */
            max5data(data->progress.dlspeed, max5[3]),    /* avrg dl speed */
            max5data(data->progress.ulspeed, max5[4]),    /* avrg ul speed */
            time_total,    /* 8 letters */                /* total time */
            time_spent,    /* 8 letters */                /* time spent */
            time_left,     /* 8 letters */                /* time left */
            max5data(data->progress.current_speed, max5[5]) /* current speed */
            );

    /* we flush the output stream to make it appear as soon as possible */
    fflush(data->set.err);

  } /* !(data->progress.flags & PGRS_HIDE) */

  return 0;
}
