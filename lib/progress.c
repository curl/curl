/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <daniel@haxx.se>
 *
 * 	http://curl.haxx.se
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

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

void time2str(char *r, int t)
{
  int h = (t/3600);
  int m = (t-(h*3600))/60;
  int s = (t-(h*3600)-(m*60));
  sprintf(r,"%2d:%02d:%02d",h,m,s);
}

/* The point of this function would be to return a string of the input data,
   but never longer than 5 columns. Add suffix k, M, G when suitable... */
char *max5data(double bytes, char *max5)
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
    sprintf(max5, "%2.1fM", bytes/ONE_MEGABYTE);
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

void pgrsDone(struct UrlData *data)
{
  if(!(data->progress.flags & PGRS_HIDE)) {
    data->progress.lastshow=0;
    pgrsUpdate(data); /* the final (forced) update */
    fprintf(stderr, "\n");
  }
}

void pgrsTime(struct UrlData *data, timerid timer)
{
  switch(timer) {
  default:
  case TIMER_NONE:
    /* mistake filter */
    break;
  case TIMER_NAMELOOKUP:
    data->progress.t_nslookup = tvnow();
    break;
  case TIMER_CONNECT:
    data->progress.t_connect = tvnow();
    break;
  case TIMER_PRETRANSFER:
    data->progress.t_pretransfer = tvnow();
    break;
  case TIMER_POSTRANSFER:
    /* this is the normal end-of-transfer thing */
    break;
  }
}

void pgrsStartNow(struct UrlData *data)
{
  data->progress.start = tvnow();
}

void pgrsSetDownloadCounter(struct UrlData *data, double size)
{
  data->progress.downloaded = size;
}

void pgrsSetUploadCounter(struct UrlData *data, double size)
{
  data->progress.uploaded = size;
}

void pgrsSetDownloadSize(struct UrlData *data, double size)
{
  if(size > 0) {
    data->progress.size_dl = size;
    data->progress.flags |= PGRS_DL_SIZE_KNOWN;
  }
}

void pgrsSetUploadSize(struct UrlData *data, double size)
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

int pgrsUpdate(struct UrlData *data)
{
  struct timeval now;
  int result;

  char max5[6][10];
  double dlpercen=0;
  double ulpercen=0;
  double total_percen=0;

  double total_transfer;
  double total_expected_transfer;

  int nowindex = data->progress.speeder_c% CURR_TIME;
  int checkindex;
  int count;

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
      fprintf(data->err,
              "  %% Total    %% Received %% Xferd  Average Speed          Time             Curr.\n"
              "                                 Dload  Upload Total    Current  Left    Speed\n");
    }
    data->progress.flags |= PGRS_HEADERS_OUT; /* headers are shown */
  }

  now = tvnow(); /* what time is it */

  if(data->progress.lastshow == tvlong(now))
    return 0; /* never update this more than once a second if the end isn't 
                 reached */
  data->progress.lastshow = now.tv_sec;

  /* The exact time spent so far */
  data->progress.timespent = tvdiff (now, data->progress.start);

  /* The average download speed this far */
  data->progress.dlspeed = data->progress.downloaded/(data->progress.timespent!=0.0?data->progress.timespent:1.0);

  /* The average upload speed this far */
  data->progress.ulspeed = data->progress.uploaded/(data->progress.timespent!=0.0?data->progress.timespent:1.0);

  /* Let's do the "current speed" thing, which should use the fastest
         of the dl/ul speeds */

  data->progress.speeder[ nowindex ] =
    data->progress.downloaded>data->progress.uploaded?
    data->progress.downloaded:data->progress.uploaded;
  data->progress.speeder_c++; /* increase */
  count = ((data->progress.speeder_c>=CURR_TIME)?
           CURR_TIME:data->progress.speeder_c) - 1;
  checkindex = (data->progress.speeder_c>=CURR_TIME)?
    data->progress.speeder_c%CURR_TIME:0;

  /* find out the average speed the last CURR_TIME seconds */
  data->progress.current_speed =
    (data->progress.speeder[nowindex]-
     data->progress.speeder[checkindex])/(count?count:1);

  if(data->progress.flags & PGRS_HIDE)
    return 0;
  else if(data->fprogress) {
    result= data->fprogress(data->progress_client,
                            data->progress.size_dl,
                            data->progress.downloaded,
                            data->progress.size_ul,
                            data->progress.uploaded);
    if(result)
      failf(data, "Callback aborted");
    return result;
  }

      /* Figure out the estimated time of arrival for the upload */
  if(data->progress.flags & PGRS_UL_SIZE_KNOWN) {
    if(!data->progress.ulspeed)
      data->progress.ulspeed=1;
    ulestimate = data->progress.size_ul / data->progress.ulspeed;
    ulpercen = (data->progress.uploaded / data->progress.size_ul)*100;
  }

  /* ... and the download */
  if(data->progress.flags & PGRS_DL_SIZE_KNOWN) {
    if(!data->progress.dlspeed)
      data->progress.dlspeed=1;
    dlestimate = data->progress.size_dl / data->progress.dlspeed;
    dlpercen = (data->progress.downloaded / data->progress.size_dl)*100;
  }
    
  /* Now figure out which of them that is slower and use for the for
         total estimate! */
  total_estimate = ulestimate>dlestimate?ulestimate:dlestimate;


  /* If we have a total estimate, we can display that and the expected
         time left */
  if(total_estimate) {
    time2str(time_left, total_estimate-(int) data->progress.timespent); 
    time2str(time_total, total_estimate);
  }
  else {
    /* otherwise we blank those times */
    strcpy(time_left,  "--:--:--");
    strcpy(time_total, "--:--:--");
  }
  /* The time spent so far is always known */
  time2str(time_current, data->progress.timespent);

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

  fprintf(stderr,
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

  return 0;
}
