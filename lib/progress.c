/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 ***************************************************************************/

#include "setup.h"

#include <string.h>
#include <time.h>

#if defined(__EMX__)
#include <stdlib.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "progress.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* Provide a string that is 2 + 1 + 2 + 1 + 2 = 8 letters long (plus the zero
   byte) */
static void time2str(char *r, long t)
{
  long h;
  if(!t) {
    strcpy(r, "--:--:--");
    return;
  }
  h = (t/3600);
  if(h <= 99) {
    long m = (t-(h*3600))/60;
    long s = (t-(h*3600)-(m*60));
    snprintf(r, 9, "%2ld:%02ld:%02ld",h,m,s);
  }
  else {
    /* this equals to more than 99 hours, switch to a more suitable output
       format to fit within the limits. */
    if(h/24 <= 999)
      snprintf(r, 9, "%3ldd %02ldh", h/24, h-(h/24)*24);
    else
      snprintf(r, 9, "%7ldd", h/24);
  }
}

/* The point of this function would be to return a string of the input data,
   but never longer than 5 columns (+ one zero byte).
   Add suffix k, M, G when suitable... */
static char *max5data(curl_off_t bytes, char *max5)
{
#define ONE_KILOBYTE 1024
#define ONE_MEGABYTE (1024* ONE_KILOBYTE)
#define ONE_GIGABYTE (1024* ONE_MEGABYTE)
#define ONE_TERRABYTE ((curl_off_t)1024* ONE_GIGABYTE)
#define ONE_PETABYTE ((curl_off_t)1024* ONE_TERRABYTE)

  if(bytes < 100000) {
    snprintf(max5, 6, "%5" FORMAT_OFF_T, bytes);
  }
  else if(bytes < (10000*ONE_KILOBYTE)) {
    snprintf(max5, 6, "%4" FORMAT_OFF_T "k", (curl_off_t)(bytes/ONE_KILOBYTE));
  }
  else if(bytes < (100*ONE_MEGABYTE)) {
    /* 'XX.XM' is good as long as we're less than 100 megs */
    snprintf(max5, 6, "%2d.%0dM",
             (int)(bytes/ONE_MEGABYTE),
             (int)(bytes%ONE_MEGABYTE)/(ONE_MEGABYTE/10) );
  }
#if SIZEOF_CURL_OFF_T > 4
  else if(bytes < ( (curl_off_t)10000*ONE_MEGABYTE))
    /* 'XXXXM' is good until we're at 10000MB or above */
    snprintf(max5, 6, "%4" FORMAT_OFF_T "M", (curl_off_t)(bytes/ONE_MEGABYTE));

  else if(bytes < (curl_off_t)100*ONE_GIGABYTE)
    /* 10000 MB - 100 GB, we show it as XX.XG */
    snprintf(max5, 6, "%2d.%0dG",
             (int)(bytes/ONE_GIGABYTE),
             (int)(bytes%ONE_GIGABYTE)/(ONE_GIGABYTE/10) );

  else if(bytes < (curl_off_t)10000 * ONE_GIGABYTE)
    /* up to 10000GB, display without decimal: XXXXG */
    snprintf(max5, 6, "%4dG", (int)(bytes/ONE_GIGABYTE));

  else if(bytes < (curl_off_t)10000 * ONE_TERRABYTE)
    /* up to 10000TB, display without decimal: XXXXT */
    snprintf(max5, 6, "%4dT", (int)(bytes/ONE_TERRABYTE));
  else {
    /* up to 10000PB, display without decimal: XXXXP */
    snprintf(max5, 6, "%4dP", (int)(bytes/ONE_PETABYTE));

    /* 16384 petabytes (16 exabytes) is maximum a 64 bit number can hold,
       but this type is signed so 8192PB will be max.*/
  }

#else
  else
    snprintf(max5, 6, "%4" FORMAT_OFF_T "M", (curl_off_t)(bytes/ONE_MEGABYTE));
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

void Curl_pgrsDone(struct connectdata *conn)
{
  struct SessionHandle *data = conn->data;
  data->progress.lastshow=0;
  Curl_pgrsUpdate(conn); /* the final (forced) update */

  data->progress.speeder_c = 0; /* reset the progress meter display */
}

/* reset all times except redirect */
void Curl_pgrsResetTimes(struct SessionHandle *data)
{
  data->progress.t_nslookup = 0.0;
  data->progress.t_connect = 0.0;
  data->progress.t_pretransfer = 0.0;
  data->progress.t_starttransfer = 0.0;
}

void Curl_pgrsTime(struct SessionHandle *data, timerid timer)
{
  switch(timer) {
  default:
  case TIMER_NONE:
    /* mistake filter */
    break;
  case TIMER_STARTSINGLE:
    /* This is set at the start of a single fetch */
    data->progress.t_startsingle = Curl_tvnow();
    break;

  case TIMER_NAMELOOKUP:
    data->progress.t_nslookup =
      Curl_tvdiff_secs(Curl_tvnow(), data->progress.t_startsingle);
    break;
  case TIMER_CONNECT:
    data->progress.t_connect =
      Curl_tvdiff_secs(Curl_tvnow(), data->progress.t_startsingle);
    break;
  case TIMER_PRETRANSFER:
    data->progress.t_pretransfer =
      Curl_tvdiff_secs(Curl_tvnow(), data->progress.t_startsingle);
    break;
  case TIMER_STARTTRANSFER:
    data->progress.t_starttransfer =
      Curl_tvdiff_secs(Curl_tvnow(), data->progress.t_startsingle);
    break;
  case TIMER_POSTRANSFER:
    /* this is the normal end-of-transfer thing */
    break;
  case TIMER_REDIRECT:
    data->progress.t_redirect =
      Curl_tvdiff_secs(Curl_tvnow(), data->progress.start);
    break;
  }
}

void Curl_pgrsStartNow(struct SessionHandle *data)
{
  data->progress.speeder_c = 0; /* reset the progress meter display */
  data->progress.start = Curl_tvnow();
}

void Curl_pgrsSetDownloadCounter(struct SessionHandle *data, curl_off_t size)
{
  data->progress.downloaded = size;
}

void Curl_pgrsSetUploadCounter(struct SessionHandle *data, curl_off_t size)
{
  data->progress.uploaded = size;
}

void Curl_pgrsSetDownloadSize(struct SessionHandle *data, curl_off_t size)
{
  data->progress.size_dl = size;
  if(size > 0)
    data->progress.flags |= PGRS_DL_SIZE_KNOWN;
  else
    data->progress.flags &= ~PGRS_DL_SIZE_KNOWN;
}

void Curl_pgrsSetUploadSize(struct SessionHandle *data, curl_off_t size)
{
  data->progress.size_ul = size;
  if(size > 0)
    data->progress.flags |= PGRS_UL_SIZE_KNOWN;
  else
    data->progress.flags &= ~PGRS_UL_SIZE_KNOWN;
}

int Curl_pgrsUpdate(struct connectdata *conn)
{
  struct timeval now;
  int result;
  char max5[6][10];
  int dlpercen=0;
  int ulpercen=0;
  int total_percen=0;
  curl_off_t total_transfer;
  curl_off_t total_expected_transfer;
  long timespent;
  struct SessionHandle *data = conn->data;
  int nowindex = data->progress.speeder_c% CURR_TIME;
  int checkindex;
  int countindex; /* amount of seconds stored in the speeder array */
  char time_left[10];
  char time_total[10];
  char time_spent[10];
  long ulestimate=0;
  long dlestimate=0;
  long total_estimate;

  if(data->progress.flags & PGRS_HIDE)
    ; /* We do enter this function even if we don't wanna see anything, since
         this is were lots of the calculations are being made that will be used
         even when not displayed! */
  else if(!(data->progress.flags & PGRS_HEADERS_OUT)) {
    if (!data->progress.callback) {
      if(data->reqdata.resume_from)
        fprintf(data->set.err,
                "** Resuming transfer from byte position %" FORMAT_OFF_T
                "\n",
                data->reqdata.resume_from);
      fprintf(data->set.err,
              "  %% Total    %% Received %% Xferd  Average Speed   Time    Time     Time  Current\n"
              "                                 Dload  Upload   Total   Spent    Left  Speed\n");
    }
    data->progress.flags |= PGRS_HEADERS_OUT; /* headers are shown */
  }

  now = Curl_tvnow(); /* what time is it */

  /* The time spent so far (from the start) */
  data->progress.timespent = Curl_tvdiff_secs(now, data->progress.start);
  timespent = (long)data->progress.timespent;

  /* The average download speed this far */
  data->progress.dlspeed = (curl_off_t)
    ((double)data->progress.downloaded/
     (data->progress.timespent>0?data->progress.timespent:1));

  /* The average upload speed this far */
  data->progress.ulspeed = (curl_off_t)
    ((double)data->progress.uploaded/
     (data->progress.timespent>0?data->progress.timespent:1));

  if(data->progress.lastshow == Curl_tvlong(now))
    return 0; /* never update this more than once a second if the end isn't
                 reached */
  data->progress.lastshow = now.tv_sec;

  /* Let's do the "current speed" thing, which should use the fastest
     of the dl/ul speeds. Store the fasted speed at entry 'nowindex'. */
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
    long span_ms;

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

      if(amount > 4294967 /* 0xffffffff/1000 */)
        /* the 'amount' value is bigger than would fit in 32 bits if
           multiplied with 1000, so we use the double math for this */
        data->progress.current_speed = (curl_off_t)
          ((double)amount/((double)span_ms/1000.0));
      else
        /* the 'amount' value is small enough to fit within 32 bits even
           when multiplied with 1000 */
        data->progress.current_speed = amount*1000/span_ms;
    }
  }
  else
    /* the first second we use the main average */
    data->progress.current_speed =
      (data->progress.ulspeed>data->progress.dlspeed)?
      data->progress.ulspeed:data->progress.dlspeed;

  if(data->progress.flags & PGRS_HIDE)
    return 0;

  else if(data->set.fprogress) {
    /* There's a callback set, so we call that instead of writing
       anything ourselves. This really is the way to go. */
    result= data->set.fprogress(data->set.progress_client,
                                (double)data->progress.size_dl,
                                (double)data->progress.downloaded,
                                (double)data->progress.size_ul,
                                (double)data->progress.uploaded);
    if(result)
      failf(data, "Callback aborted");
    return result;
  }

  /* Figure out the estimated time of arrival for the upload */
  if((data->progress.flags & PGRS_UL_SIZE_KNOWN) &&
     (data->progress.ulspeed>0) &&
     (data->progress.size_ul > 100) ) {
    ulestimate = (long)(data->progress.size_ul / data->progress.ulspeed);
    ulpercen = (int)(100*(data->progress.uploaded/100) /
                      (data->progress.size_ul/100) );
  }

  /* ... and the download */
  if((data->progress.flags & PGRS_DL_SIZE_KNOWN) &&
     (data->progress.dlspeed>0) &&
     (data->progress.size_dl>100)) {
    dlestimate = (long)(data->progress.size_dl / data->progress.dlspeed);
    dlpercen = (int)(100*(data->progress.downloaded/100) /
                      (data->progress.size_dl/100));
  }

  /* Now figure out which of them that is slower and use for the for
     total estimate! */
  total_estimate = ulestimate>dlestimate?ulestimate:dlestimate;

  /* create the three time strings */
  time2str(time_left, total_estimate > 0?(total_estimate - timespent):0);
  time2str(time_total, total_estimate);
  time2str(time_spent, timespent);

  /* Get the total amount of data expected to get transfered */
  total_expected_transfer =
    (data->progress.flags & PGRS_UL_SIZE_KNOWN?
     data->progress.size_ul:data->progress.uploaded)+
    (data->progress.flags & PGRS_DL_SIZE_KNOWN?
     data->progress.size_dl:data->progress.downloaded);

  /* We have transfered this much so far */
  total_transfer = data->progress.downloaded + data->progress.uploaded;

  /* Get the percentage of data transfered so far */
  if(total_expected_transfer > 100)
    total_percen=(int)(100*(total_transfer/100) /
                       (total_expected_transfer/100) );

  fprintf(data->set.err,
          "\r%3d %s  %3d %s  %3d %s  %s  %s %s %s %s %s",
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

  return 0;
}
