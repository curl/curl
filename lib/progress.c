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

/* --- start of progress routines --- */
int progressmax=-1;

static int prev = 0;
static int width = 0;

void ProgressInit(struct UrlData *data, int max)
{
  if(data->conf&(CONF_NOPROGRESS|CONF_MUTE))
    return;

  prev = 0;

/* TODO: get terminal width through ansi escapes or something similar.
         try to update width when xterm is resized... - 19990617 larsa */
  if (curl_GetEnv("COLUMNS") != NULL)
    width = atoi(curl_GetEnv("COLUMNS"));
  else
    width = 80;

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

void time2str(char *r, int t)
{
  int h = (t/3600);
  int m = (t-(h*3600))/60;
  int s = (t-(h*3600)-(m*60));
  sprintf(r,"%3d:%02d:%02d",h,m,s);
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
