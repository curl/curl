/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
/*
  RFC 2616 3.3.1

  Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
  Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
  Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format

  we support dates without week day name:

  06 Nov 1994 08:49:37 GMT
  06-Nov-94 08:49:37 GMT
  Nov  6 08:49:37 1994

  and without the time zone (we always assume GMT):

  06 Nov 1994 08:49:37
  06-Nov-94 08:49:37

  or even in weird order:

  1994 Nov 6 08:49:37  (curl_getdate() and GNU date fails)
  08:49:37 06-Nov-94
  94 6 Nov 08:49:37    (curl_getdate() and GNU date fails)

*/
#include "setup.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h> /* for strtol() */
#endif

#include <curl/curl.h>


#include "parsedate.h"

static const char *wkday[] = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
static const char *weekday[] = { "Monday", "Tuesday", "Wednesday", "Thursday",
                                 "Friday", "Saturday", "Sunday" };
static const char *month[]= { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                              "Aug", "Sep", "Oct", "Nov", "Dec" };

static const char *tz[]= { "GMT", "UTC" };

/* returns:
   -1 no day
   0 monday - 6 sunday
*/

static int checkday(char *check, size_t len)
{
  int i;
  const char **what;
  bool found= FALSE;
  if(len > 3)
    what = &weekday[0];
  else
    what = &wkday[0];
  for(i=0; i<7; i++) {
    if(curl_strequal(check, what[0])) {
      found=TRUE;
      break;
    }
    what++;
  }
  return found?i:-1;
}

static int checkmonth(char *check)
{
  int i;
  const char **what;
  bool found= FALSE;

  what = &month[0];
  for(i=0; i<12; i++) {
    if(curl_strequal(check, what[0])) {
      found=TRUE;
      break;
    }
    what++;
  }
  return found?i:-1;
}

static int checktz(char *check)
{
  int i;
  const char **what;
  bool found= FALSE;

  what = &tz[0];
  for(i=0; i<2; i++) {
    if(curl_strequal(check, what[0])) {
      found=TRUE;
      break;
    }
    what++;
  }
  return found?i:-1;
}

static void skip(const char **date)
{
  /* skip everything that aren't letters or digits */
  while(**date && !isalnum((int)**date))
    (*date)++;
}

#define TM_YEAR_ORIGIN 1900

/* Yield A - B, measured in seconds. (from getdate.y)  */
static long
difftm (struct tm *a, struct tm *b)
{
  int ay = a->tm_year + (TM_YEAR_ORIGIN - 1);
  int by = b->tm_year + (TM_YEAR_ORIGIN - 1);
  long days = (
  /* difference in day of year */
		a->tm_yday - b->tm_yday
  /* + intervening leap days */
		+ ((ay >> 2) - (by >> 2))
		- (ay / 100 - by / 100)
		+ ((ay / 100 >> 2) - (by / 100 >> 2))
  /* + difference in years * 365 */
		+ (long) (ay - by) * 365
  );
  return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour))
		+ (a->tm_min - b->tm_min))
	  + (a->tm_sec - b->tm_sec));
}

enum assume {
  DATE_MDAY,
  DATE_YEAR,
  DATE_TIME
};

time_t Curl_parsedate(const char *date)
{
  time_t t = 0;
  int wdaynum=-1;  /* day of the week number, 0-6 (mon-sun) */
  int monnum=-1;   /* month of the year number, 0-11 */
  long mdaynum=-1; /* day of month, 1 - 31 */
  int hournum=-1;
  int minnum=-1;
  int secnum=-1;
  long yearnum=-1;
  int tznum=-1;
  struct tm tm;
  enum assume dignext = DATE_MDAY;

  int part = 0; /* max 6 parts */

  while(part < 6) {
    bool found=FALSE;

    skip(&date);

    if(isalpha((int)*date)) {
      /* a name coming up */
      char buf[32]="";
      size_t len;
      sscanf(date, "%31[^ ,\n\t-]", buf);
      len = strlen(buf);

      if(wdaynum == -1) {
        wdaynum = checkday(buf, len);
        if(wdaynum != -1)
          found = TRUE;
      }
      if(!found && (monnum == -1)) {
        monnum = checkmonth(buf);
        if(monnum != -1)
          found = TRUE;
      }

      if(!found && (tznum == -1)) {
        /* this just must be a time zone string */
        tznum = checktz(buf);
        if(tznum != -1)
          found = TRUE;
      }

      if(!found)
        return -1; /* bad string */

      date += len;
    }
    else if(isdigit((int)*date)) {
      /* a digit */
      long val;
      char *end;
      if((secnum == -1) &&
         (3 == sscanf(date, "%02d:%02d:%02d", &hournum, &minnum, &secnum))) {
        /* time stamp! */
        date += 8;
        found = TRUE;
      }
      else {
        val = strtol(date, &end, 10);

        if((dignext == DATE_MDAY) && (mdaynum == -1)) {
          if((val > 0) && (val<32)) {
            mdaynum = val;
            found = TRUE;
          }
          dignext = DATE_YEAR;
        }

        if(!found && (dignext == DATE_YEAR) && (yearnum == -1)) {
          yearnum = val;
          found = TRUE;
          if(yearnum < 1900) {
            if (yearnum > 70)
              yearnum += 1900;
            else
              yearnum += 2000;
          }
          if(mdaynum == -1)
            dignext = DATE_MDAY;
        }

        if(!found)
          return -1;

        date = end;
      }
    }

    part++;
  }

  tm.tm_sec = secnum;
  tm.tm_min = minnum;
  tm.tm_hour = hournum;
  tm.tm_mday = mdaynum;
  tm.tm_mon = monnum;
  tm.tm_year = yearnum - 1900;
  tm.tm_wday = 0;
  tm.tm_yday = 0;
  tm.tm_isdst = 0;

  t = mktime(&tm);

  /* We have the time-stamp now, but in our local time zone, we must now
     adjust it to GMT. */
  {
    struct tm *gmt;
    long delta;
#ifdef HAVE_GMTIME_R
    /* thread-safe version */
    struct tm keeptime2;
    gmt = (struct tm *)gmtime_r(&t, &keeptime2);
#else
    gmt = gmtime(&t); /* use gmtime_r() if available */
#endif
    delta = difftm(&tm, gmt);

    if(t + delta < t)
      return -1; /* time_t overflow */

    t += delta;
  }

  return t;
}

time_t curl_getdate(const char *p, const time_t *now)
{
  (void)now;
  return Curl_parsedate(p);
}

#ifdef TESTIT

int main(void)
{
  char buffer[1024];
  char cmd[1024];
  time_t t;

  while(fgets(buffer, sizeof(buffer), stdin)) {
    size_t len = strlen(buffer);

    buffer[len-1]=0; /* cut off newline */

    t = curl_getdate(buffer, NULL);

    printf("curl_getdate(): %d\n", t);

    sprintf(cmd, "date -d \"%s\" +%%s", buffer);

    printf("GNU date:\n");
    system(cmd);

    t = parse_a_date(buffer);
    printf("parse_a_date: %d\n===================\n\n", t);
  }

  return 0;
}

#endif
