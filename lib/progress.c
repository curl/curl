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
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
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

#include <string.h>
#include "setup.h"

#if defined(WIN32) && !defined(__GNUC__) || defined(__MINGW32__)
#if defined(__MINGW32__)
#include <winsock.h>
#endif
#include <time.h>
#endif

#include <curl/curl.h>
#include "urldata.h"

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
  if(bytes < 100000) {
    sprintf(max5, "%5d", (int)bytes);
    return max5;
  }
  if(bytes < (9999*1024)) {
    sprintf(max5, "%4dk", (int)bytes/1024);
    return max5;
  }
  sprintf(max5, "%4dM", (int)bytes/(1024*1024));
  return max5;
}

/* 

   New proposed interface, 9th of February 2000:

   pgrsStartNow() - sets start time
   pgrsMode(type) - kind of display
   pgrsSetDownloadSize(x) - known expected download size
   pgrsSetUploadSize(x) - known expected upload size
   pgrsSetDownloadCounter() - amount of data currently downloaded
   pgrsSetUploadCounter() - amount of data currently uploaded
   pgrsUpdate() - show progress
   pgrsDone() - transfer complete

*/
#if 1
void pgrsDone(struct UrlData *data)
{
  if(!(data->progress.flags & PGRS_HIDE)) {
    data->progress.lastshow=0;
    pgrsUpdate(data); /* the final (forced) update */
    fprintf(stderr, "\n");
  }
}
void pgrsMode(struct UrlData *data, int mode)
{
  /* mode should include a hidden mode as well */
  if(data->conf&(CONF_NOPROGRESS|CONF_MUTE))
    data->progress.flags |= PGRS_HIDE; /* don't show anything */
  else {
    data->progress.mode = mode; /* store type */
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

void pgrsUpdate(struct UrlData *data)
{
  struct timeval now;

  if(data->progress.flags & PGRS_HIDE)
    ; /* We do enter this function even if we don't wanna see anything, since
         this is were lots of the calculations are being made that will be used
         even when not displayed! */
  else if(!(data->progress.flags & PGRS_HEADERS_OUT)) {
    if ( data->progress.mode == CURL_PROGRESS_STATS ) {
      fprintf(data->err,
              "  %% Total    %% Received %% Xferd  Average Speed          Time             Curr.\n"
              "                                 Dload  Upload Total    Current  Left    Speed\n");
    }
    data->progress.flags |= PGRS_HEADERS_OUT; /* headers are shown */
  }

  now = tvnow(); /* what time is it */

  switch(data->progress.mode) {
  case CURL_PROGRESS_STATS:
  default:
    {
      char max5[6][6];
      double dlpercen=0;
      double ulpercen=0;
      double total_percen=0;

      double total_transfer;
      double total_expected_transfer;

#define CURR_TIME 5

      static double speeder[ CURR_TIME ];
      static int speeder_c=0;

      int nowindex = speeder_c% CURR_TIME;
      int checkindex;
      int count;

      char time_left[10];
      char time_total[10];
      char time_current[10];

      double ulestimate=0;
      double dlestimate=0;
          
      double total_estimate;

      if(data->progress.lastshow == tvlong(now))
        return; /* never update this more than once a second if the end isn't 
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

      speeder[ nowindex ] = data->progress.downloaded>data->progress.uploaded?
        data->progress.downloaded:data->progress.uploaded;
      speeder_c++; /* increase */
      count = ((speeder_c>=CURR_TIME)?CURR_TIME:speeder_c) - 1;
      checkindex = (speeder_c>=CURR_TIME)?speeder_c%CURR_TIME:0;

      /* find out the average speed the last CURR_TIME seconds */
      data->progress.current_speed =
        (speeder[nowindex]-speeder[checkindex])/(count?count:1);

      if(data->progress.flags & PGRS_HIDE)
        return;

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
    }
    break;
#if 0
  case CURL_PROGRESS_BAR:
    /* original progress bar code by Lars Aas */
    if (progressmax == -1) {
      int prevblock = prev / 1024;
      int thisblock = point / 1024;
      while ( thisblock > prevblock ) {
        fprintf( data->err, "#" );
        prevblock++;
      }
        prev = point;
    }
    else {
      char line[256];
      char outline[256];
      char format[40];
      float frac = (float) point / (float) progressmax;
      float percent = frac * 100.0f;
      int barwidth = width - 7;
      int num = (int) (((float)barwidth) * frac);
        int i = 0;
        for ( i = 0; i < num; i++ ) {
          line[i] = '#';
        }
        line[i] = '\0';
        sprintf( format, "%%-%ds %%5.1f%%%%", barwidth );
        sprintf( outline, format, line, percent );
        fprintf( data->err, "\r%s", outline );
    }
    prev = point;
    break;
#endif
  }
}


#endif

#if 0
/* --- start of (the former) progress routines --- */
int progressmax=-1;

static int prev = 0;
static int width = 0;

void ProgressInit(struct UrlData *data, int max/*, int options, int moremax*/)
{
  if(data->conf&(CONF_NOPROGRESS|CONF_MUTE))
    return;

  prev = 0;

/* TODO: get terminal width through ansi escapes or something similar.
         try to update width when xterm is resized... - 19990617 larsa */
  if (curl_GetEnv("COLUMNS") != NULL)
    width = atoi(curl_GetEnv("COLUMNS"));
  else
    width = 79;

  progressmax = max;
  if(-1 == max)
    return;
  if(progressmax <= LEAST_SIZE_PROGRESS) {
    progressmax = -1; /* disable */
    return;
  }

  if ( data->progressmode == CURL_PROGRESS_STATS )
    fprintf(data->err,
            "  %%   Received    Total    Speed  Estimated   Time      Left   Curr.Speed\n");

}

void ProgressShow(struct UrlData *data,
                  int point, struct timeval start, struct timeval now, bool force)
{
  switch ( data->progressmode ) {
  case CURL_PROGRESS_STATS:
    {
      static long lastshow;
      double percen;

      double spent;
      double speed;

#define CURR_TIME 5

      static int speeder[ CURR_TIME ];
      static int speeder_c=0;

      int nowindex = speeder_c% CURR_TIME;
      int checkindex;
      int count;

      if(!force && (point != progressmax) && (lastshow == tvlong(now)))
        return; /* never update this more than once a second if the end isn't 
                   reached */

      spent = tvdiff (now, start);
      speed = point/(spent!=0.0?spent:1.0);
      if(!speed)
        speed=1;

      /* point is where we are right now */
      speeder[ nowindex ] = point;
      speeder_c++; /* increase */
      count = ((speeder_c>=CURR_TIME)?CURR_TIME:speeder_c) - 1;
      checkindex = (speeder_c>=CURR_TIME)?speeder_c%CURR_TIME:0;

      /* find out the average speed the last CURR_TIME seconds */
      data->current_speed = (speeder[nowindex]-speeder[checkindex])/(count?count:1);

#if 0
      printf("NOW %d(%d) THEN %d(%d) DIFF %lf COUNT %d\n",
	     speeder[nowindex], nowindex,
	     speeder[checkindex], checkindex,
	     data->current_speed, count);
#endif

      if(data->conf&(CONF_NOPROGRESS|CONF_MUTE))
        return;

      if(-1 != progressmax) {
        char left[20];
        char estim[20];
        char timespent[20];
        int estimate = progressmax/(int) speed;
    
        time2str(left,estimate-(int) spent); 
        time2str(estim,estimate);
        time2str(timespent,spent);

        percen=(double)point/progressmax;
        percen=percen*100;

        fprintf(stderr, "\r%3d %10d %10d %6.0lf %s %s %s %6.0lf   ",
                (int)percen, point, progressmax,
                speed, estim, timespent, left, data->current_speed);
      }
      else
        fprintf(data->err,
                "\r%d bytes received in %.3lf seconds (%.0lf bytes/sec)",
                point, spent, speed);

      lastshow = now.tv_sec;
      break;
    }
  case CURL_PROGRESS_BAR: /* 19990617 larsa */
    {
      if (point == prev) break;
      if (progressmax == -1) {
        int prevblock = prev / 1024;
        int thisblock = point / 1024;
        while ( thisblock > prevblock ) {
            fprintf( data->err, "#" );
            prevblock++;
        }
        prev = point;
      } else {
        char line[256];
        char outline[256];
        char format[40];
        float frac = (float) point / (float) progressmax;
        float percent = frac * 100.0f;
        int barwidth = width - 7;
        int num = (int) (((float)barwidth) * frac);
        int i = 0;
        for ( i = 0; i < num; i++ ) {
            line[i] = '#';
        }
        line[i] = '\0';
        sprintf( format, "%%-%ds %%5.1f%%%%", barwidth );
        sprintf( outline, format, line, percent );
        fprintf( data->err, "\r%s", outline );
      }
      prev = point;
      break;
    }
  default: /* 19990617 larsa */
    {
      int prevblock = prev / 1024;
      int thisblock = point / 1024;
      if (prev == point) break;
      while ( thisblock > prevblock ) {
        fprintf( data->err, "#" );
        prevblock++;
      }
      prev = point;
      break;
    }
  }
}

void ProgressEnd(struct UrlData *data)
{
  if(data->conf&(CONF_NOPROGRESS|CONF_MUTE))
    return;
  fputs("\n", data->err);
}

/* --- end of progress routines --- */
#endif
