/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#if defined(__MINGW32__)
#include <winsock.h>
#endif
#include <time.h>
#endif

/* 20000318 mgs
 * later we use _scrsize to determine the screen width, this emx library
 * function needs stdlib.h to be included */
#if defined(__EMX__)
#include <stdlib.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"

#include "progress.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>


static void time2str(char *r, int t)
{
  int h = (t/3600);
  int m = (t-(h*3600))/60;
  int s = (t-(h*3600)-(m*60));
  sprintf(r,"%2d:%02d:%02d",h,m,s);
}

/* The point of this function would be to return a string of the input data,
   but never longer than 5 columns. Add suffix k, M, G when suitable... */
static char *max5data(double bytes, char *max5)
{
#define ONE_KILOBYTE 1024
#define ONE_MEGABYTE (1024*1024)

  if(bytes < 100000) {
    sprintf(max5, "%5d", (int)bytes);
    return max5;
  }
  if(bytes < (9999*ONE_KILOBYTE)) {
    sprintf(max5, "%4dk", (int)bytes/ONE_KILOBYTE);
    return max5;
  }
  if(bytes < (100*ONE_MEGABYTE)) {
    /* 'XX.XM' is good as long as we're less than 100 megs */
    sprintf(max5, "%4.1fM", bytes/ONE_MEGABYTE);
    return max5;
  }
  sprintf(max5, "%4dM", (int)bytes/ONE_MEGABYTE);
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
  if(!(data->progress.flags & PGRS_HIDE)) {
    data->progress.lastshow=0;
    Curl_pgrsUpdate(conn); /* the final (forced) update */
    if(!data->progress.callback)
      /* only output if we don't use progress callback */
      fprintf(data->set.err, "\n");
  }
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
      (double)Curl_tvdiff(Curl_tvnow(), data->progress.t_startsingle)/1000.0;
    break;
  case TIMER_CONNECT:
    data->progress.t_connect =
      (double)Curl_tvdiff(Curl_tvnow(), data->progress.t_startsingle)/1000.0;
    break;
  case TIMER_PRETRANSFER:
    data->progress.t_pretransfer =
      (double)Curl_tvdiff(Curl_tvnow(), data->progress.t_startsingle)/1000.0;
    break;
  case TIMER_STARTTRANSFER:
    data->progress.t_starttransfer =
      (double)Curl_tvdiff(Curl_tvnow(), data->progress.t_startsingle)/1000.0;
    break;
  case TIMER_POSTRANSFER:
    /* this is the normal end-of-transfer thing */
    break;
  case TIMER_REDIRECT:
    data->progress.t_redirect =
      (double)Curl_tvdiff(Curl_tvnow(), data->progress.start)/1000.0;
    break;
  }
}

void Curl_pgrsStartNow(struct SessionHandle *data)
{
  data->progress.speeder_c = 0; /* reset the progress meter display */
  data->progress.start = Curl_tvnow();
}

void Curl_pgrsSetDownloadCounter(struct SessionHandle *data, double size)
{
  data->progress.downloaded = size;
}

void Curl_pgrsSetUploadCounter(struct SessionHandle *data, double size)
{
  data->progress.uploaded = size;
}

void Curl_pgrsSetDownloadSize(struct SessionHandle *data, double size)
{
  if(size > 0) {
    data->progress.size_dl = size;
    data->progress.flags |= PGRS_DL_SIZE_KNOWN;
  }
}

void Curl_pgrsSetUploadSize(struct SessionHandle *data, double size)
{
  if(size > 0) {
    data->progress.size_ul = size;
    data->progress.flags |= PGRS_UL_SIZE_KNOWN;
  }
}

/* EXAMPLE OUTPUT to follow:

  % Total    % Received % Xferd  Average Speed          Time             Curr.
                                 Dload  Upload Total    Current  Left    Speed
100 12345  100 12345  100 12345  12345  12345 12:12:12 12:12:12 12:12:12 12345

 */

int Curl_pgrsUpdate(struct connectdata *conn)
{
  struct timeval now;
  int result;

  char max5[6][10];
  double dlpercen=0;
  double ulpercen=0;
  double total_percen=0;

  double total_transfer;
  double total_expected_transfer;
  double timespent;

  struct SessionHandle *data = conn->data;

  int nowindex = data->progress.speeder_c% CURR_TIME;
  int checkindex;

  int countindex; /* amount of seconds stored in the speeder array */

  char time_left[10];
  char time_total[10];
  char time_current[10];
      
  double ulestimate=0;
  double dlestimate=0;
  
  double total_estimate;


  if(data->progress.flags & PGRS_HIDE)
    ; /* We do enter this function even if we don't wanna see anything, since
         this is were lots of the calculations are being made that will be used
         even when not displayed! */
  else if(!(data->progress.flags & PGRS_HEADERS_OUT)) {
    if (!data->progress.callback) {
      if(conn->resume_from)
        fprintf(data->set.err, "** Resuming transfer from byte position %d\n",
                conn->resume_from);
      fprintf(data->set.err,
              "  %% Total    %% Received %% Xferd  Average Speed          Time             Curr.\n"
              "                                 Dload  Upload Total    Current  Left    Speed\n");
    }
    data->progress.flags |= PGRS_HEADERS_OUT; /* headers are shown */
  }

  now = Curl_tvnow(); /* what time is it */

  /* The exact time spent so far (from the start) */
  timespent = (double)Curl_tvdiff (now, data->progress.start)/1000;

  data->progress.timespent = timespent;

  /* The average download speed this far */
  data->progress.dlspeed =
    data->progress.downloaded/(timespent>0.01?timespent:1);

  /* The average upload speed this far */
  data->progress.ulspeed =
    data->progress.uploaded/(timespent>0.01?timespent:1);

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

    /* Calculate the average speed the last 'countindex' seconds */
    data->progress.current_speed =
      (data->progress.speeder[nowindex]-
       data->progress.speeder[checkindex])/((double)span_ms/1000);
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
                                data->progress.size_dl,
                                data->progress.downloaded,
                                data->progress.size_ul,
                                data->progress.uploaded);
    if(result)
      failf(data, "Callback aborted");
    return result;
  }

  /* Figure out the estimated time of arrival for the upload */
  if((data->progress.flags & PGRS_UL_SIZE_KNOWN) && data->progress.ulspeed){
    ulestimate = data->progress.size_ul / data->progress.ulspeed;
    ulpercen = (data->progress.uploaded / data->progress.size_ul)*100;
  }

  /* ... and the download */
  if((data->progress.flags & PGRS_DL_SIZE_KNOWN) && data->progress.dlspeed) {
    dlestimate = data->progress.size_dl / data->progress.dlspeed;
    dlpercen = (data->progress.downloaded / data->progress.size_dl)*100;
  }
    
  /* Now figure out which of them that is slower and use for the for
     total estimate! */
  total_estimate = ulestimate>dlestimate?ulestimate:dlestimate;


  /* If we have a total estimate, we can display that and the expected
     time left */
  if(total_estimate) {
    time2str(time_left, (int)(total_estimate - data->progress.timespent)); 
    time2str(time_total, (int)total_estimate);
  }
  else {
    /* otherwise we blank those times */
    strcpy(time_left,  "--:--:--");
    strcpy(time_total, "--:--:--");
  }
  /* The time spent so far is always known */
  time2str(time_current, (int)data->progress.timespent);

  /* Get the total amount of data expected to get transfered */
  total_expected_transfer = 
    (data->progress.flags & PGRS_UL_SIZE_KNOWN?
     data->progress.size_ul:data->progress.uploaded)+
    (data->progress.flags & PGRS_DL_SIZE_KNOWN?
     data->progress.size_dl:data->progress.downloaded);
      
  /* We have transfered this much so far */
  total_transfer = data->progress.downloaded + data->progress.uploaded;

  /* Get the percentage of data transfered so far */
  if(total_expected_transfer)
    total_percen=(double)(total_transfer/total_expected_transfer)*100;

  fprintf(data->set.err,
          "\r%3d %s  %3d %s  %3d %s  %s  %s %s %s %s %s",
          (int)total_percen,                            /* total % */
          max5data(total_expected_transfer, max5[2]),   /* total size */
          (int)dlpercen,                                /* rcvd % */
          max5data(data->progress.downloaded, max5[0]), /* rcvd size */
          (int)ulpercen,                                /* xfer % */
          max5data(data->progress.uploaded, max5[1]),   /* xfer size */

          max5data(data->progress.dlspeed, max5[3]), /* avrg dl speed */
          max5data(data->progress.ulspeed, max5[4]), /* avrg ul speed */
          time_total,                           /* total time */
          time_current,                         /* current time */
          time_left,                            /* time left */
          max5data(data->progress.current_speed, max5[5]) /* current speed */
          );

  /* we flush the output stream to make it appear as soon as possible */
  fflush(data->set.err);

  return 0;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
