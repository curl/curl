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
/*
  A brief summary of the date string formats this parser groks:

  RFC 2616 3.3.1

  Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
  Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
  Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format

  we support dates without week day name:

  06 Nov 1994 08:49:37 GMT
  06-Nov-94 08:49:37 GMT
  Nov  6 08:49:37 1994

  without the time zone:

  06 Nov 1994 08:49:37
  06-Nov-94 08:49:37

  weird order:

  1994 Nov 6 08:49:37  (GNU date fails)
  GMT 08:49:37 06-Nov-94 Sunday
  94 6 Nov 08:49:37    (GNU date fails)

  time left out:

  1994 Nov 6
  06-Nov-94
  Sun Nov 6 94

  unusual separators:

  1994.Nov.6
  Sun/Nov/6/94/GMT

  commonly used time zone names:

  Sun, 06 Nov 1994 08:49:37 CET
  06 Nov 1994 08:49:37 EST

  time zones specified using RFC822 style:

  Sun, 12 Sep 2004 15:05:58 -0700
  Sat, 11 Sep 2004 21:32:11 +0200

  compact numerical date strings:

  20040912 15:05:58 -0700
  20040911 +0200

*/
#include "setup.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h> /* for strtol() */
#endif

#include <curl/curl.h>

static time_t Curl_parsedate(const char *date);

const char * const Curl_wkday[] =
{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
static const char * const weekday[] =
{ "Monday", "Tuesday", "Wednesday", "Thursday",
  "Friday", "Saturday", "Sunday" };
const char * const Curl_month[]=
{ "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

struct tzinfo {
  const char *name;
  int offset; /* +/- in minutes */
};

/* Here's a bunch of frequently used time zone names. These were supported
   by the old getdate parser. */
#define tDAYZONE -60       /* offset for daylight savings time */
static const struct tzinfo tz[]= {
  {"GMT", 0},              /* Greenwich Mean */
  {"UTC", 0},              /* Universal (Coordinated) */
  {"WET", 0},              /* Western European */
  {"BST", 0 tDAYZONE},     /* British Summer */
  {"WAT", 60},             /* West Africa */
  {"AST", 240},            /* Atlantic Standard */
  {"ADT", 240 tDAYZONE},   /* Atlantic Daylight */
  {"EST", 300},            /* Eastern Standard */
  {"EDT", 300 tDAYZONE},   /* Eastern Daylight */
  {"CST", 360},            /* Central Standard */
  {"CDT", 360 tDAYZONE},   /* Central Daylight */
  {"MST", 420},            /* Mountain Standard */
  {"MDT", 420 tDAYZONE},   /* Mountain Daylight */
  {"PST", 480},            /* Pacific Standard */
  {"PDT", 480 tDAYZONE},   /* Pacific Daylight */
  {"YST", 540},            /* Yukon Standard */
  {"YDT", 540 tDAYZONE},   /* Yukon Daylight */
  {"HST", 600},            /* Hawaii Standard */
  {"HDT", 600 tDAYZONE},   /* Hawaii Daylight */
  {"CAT", 600},            /* Central Alaska */
  {"AHST", 600},           /* Alaska-Hawaii Standard */
  {"NT",  660},            /* Nome */
  {"IDLW", 720},           /* International Date Line West */
  {"CET", -60},            /* Central European */
  {"MET", -60},            /* Middle European */
  {"MEWT", -60},           /* Middle European Winter */
  {"MEST", -60 tDAYZONE},  /* Middle European Summer */
  {"CEST", -60 tDAYZONE},  /* Central European Summer */
  {"MESZ", -60 tDAYZONE},  /* Middle European Summer */
  {"FWT", -60},            /* French Winter */
  {"FST", -60 tDAYZONE},   /* French Summer */
  {"EET", -120},           /* Eastern Europe, USSR Zone 1 */
  {"WAST", -420},          /* West Australian Standard */
  {"WADT", -420 tDAYZONE}, /* West Australian Daylight */
  {"CCT", -480},           /* China Coast, USSR Zone 7 */
  {"JST", -540},           /* Japan Standard, USSR Zone 8 */
  {"EAST", -600},          /* Eastern Australian Standard */
  {"EADT", -600 tDAYZONE}, /* Eastern Australian Daylight */
  {"GST", -600},           /* Guam Standard, USSR Zone 9 */
  {"NZT", -720},           /* New Zealand */
  {"NZST", -720},          /* New Zealand Standard */
  {"NZDT", -720 tDAYZONE}, /* New Zealand Daylight */
  {"IDLE", -720},          /* International Date Line East */
};

/* returns:
   -1 no day
   0 monday - 6 sunday
*/

static int checkday(char *check, size_t len)
{
  int i;
  const char * const *what;
  bool found= FALSE;
  if(len > 3)
    what = &weekday[0];
  else
    what = &Curl_wkday[0];
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
  const char * const *what;
  bool found= FALSE;

  what = &Curl_month[0];
  for(i=0; i<12; i++) {
    if(curl_strequal(check, what[0])) {
      found=TRUE;
      break;
    }
    what++;
  }
  return found?i:-1; /* return the offset or -1, no real offset is -1 */
}

/* return the time zone offset between GMT and the input one, in number
   of seconds or -1 if the timezone wasn't found/legal */

static int checktz(char *check)
{
  unsigned int i;
  const struct tzinfo *what;
  bool found= FALSE;

  what = tz;
  for(i=0; i< sizeof(tz)/sizeof(tz[0]); i++) {
    if(curl_strequal(check, what->name)) {
      found=TRUE;
      break;
    }
    what++;
  }
  return found?what->offset*60:-1;
}

static void skip(const char **date)
{
  /* skip everything that aren't letters or digits */
  while(**date && !ISALNUM(**date))
    (*date)++;
}

enum assume {
  DATE_MDAY,
  DATE_YEAR,
  DATE_TIME
};

static time_t Curl_parsedate(const char *date)
{
  time_t t = 0;
  int wdaynum=-1;  /* day of the week number, 0-6 (mon-sun) */
  int monnum=-1;   /* month of the year number, 0-11 */
  int mdaynum=-1; /* day of month, 1 - 31 */
  int hournum=-1;
  int minnum=-1;
  int secnum=-1;
  int yearnum=-1;
  int tzoff=-1;
  struct tm tm;
  enum assume dignext = DATE_MDAY;
  const char *indate = date; /* save the original pointer */
  int part = 0; /* max 6 parts */

  while(*date && (part < 6)) {
    bool found=FALSE;

    skip(&date);

    if(ISALPHA(*date)) {
      /* a name coming up */
      char buf[32]="";
      size_t len;
      sscanf(date, "%31[A-Za-z]", buf);
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

      if(!found && (tzoff == -1)) {
        /* this just must be a time zone string */
        tzoff = checktz(buf);
        if(tzoff != -1)
          found = TRUE;
      }

      if(!found)
        return -1; /* bad string */

      date += len;
    }
    else if(ISDIGIT(*date)) {
      /* a digit */
      int val;
      char *end;
      if((secnum == -1) &&
         (3 == sscanf(date, "%02d:%02d:%02d", &hournum, &minnum, &secnum))) {
        /* time stamp! */
        date += 8;
        found = TRUE;
      }
      else {
        val = (int)strtol(date, &end, 10);

        if((tzoff == -1) &&
           ((end - date) == 4) &&
           (val < 1300) &&
           (indate< date) &&
           ((date[-1] == '+' || date[-1] == '-'))) {
          /* four digits and a value less than 1300 and it is preceeded with
             a plus or minus. This is a time zone indication. */
          found = TRUE;
          tzoff = (val/100 * 60 + val%100)*60;

          /* the + and - prefix indicates the local time compared to GMT,
             this we need ther reversed math to get what we want */
          tzoff = date[-1]=='+'?-tzoff:tzoff;
        }

        if(((end - date) == 8) &&
           (yearnum == -1) &&
           (monnum == -1) &&
           (mdaynum == -1)) {
          /* 8 digits, no year, month or day yet. This is YYYYMMDD */
          found = TRUE;
          yearnum = val/10000;
          monnum = (val%10000)/100-1; /* month is 0 - 11 */
          mdaynum = val%100;
        }

        if(!found && (dignext == DATE_MDAY) && (mdaynum == -1)) {
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

  if(-1 == secnum)
    secnum = minnum = hournum = 0; /* no time, make it zero */

  if((-1 == mdaynum) ||
     (-1 == monnum) ||
     (-1 == yearnum))
    /* lacks vital info, fail */
    return -1;

#if SIZEOF_TIME_T < 5
  /* 32 bit time_t can only hold dates to the beginning of 2038 */
  if(yearnum > 2037)
    return 0x7fffffff;
#endif

  tm.tm_sec = secnum;
  tm.tm_min = minnum;
  tm.tm_hour = hournum;
  tm.tm_mday = mdaynum;
  tm.tm_mon = monnum;
  tm.tm_year = yearnum - 1900;
  tm.tm_wday = 0;
  tm.tm_yday = 0;
  tm.tm_isdst = 0;

  /* mktime() returns a time_t. time_t is often 32 bits, even on many
     architectures that feature 64 bit 'long'.

     Some systems have 64 bit time_t and deal with years beyond 2038. However,
     even some of the systems with 64 bit time_t returns -1 for dates beyond
     03:14:07 UTC, January 19, 2038. (Such as AIX 5100-06)
  */
  t = mktime(&tm);

  /* time zone adjust (cast t to int to compare to negative one) */
  if(-1 != (int)t) {
    struct tm *gmt;
    long delta;
    time_t t2;

#ifdef HAVE_GMTIME_R
    /* thread-safe version */
    struct tm keeptime2;
    gmt = (struct tm *)gmtime_r(&t, &keeptime2);
    if(!gmt)
      return -1; /* illegal date/time */
    t2 = mktime(gmt);
#else
    /* It seems that at least the MSVC version of mktime() doesn't work
       properly if it gets the 'gmt' pointer passed in (which is a pointer
       returned from gmtime() pointing to static memory), so instead we copy
       the tm struct to a local struct and pass a pointer to that struct as
       input to mktime(). */
    struct tm gmt2;
    gmt = gmtime(&t); /* use gmtime_r() if available */
    if(!gmt)
      return -1; /* illegal date/time */
    gmt2 = *gmt;
    t2 = mktime(&gmt2);
#endif

    /* Add the time zone diff (between the given timezone and GMT) and the
       diff between the local time zone and GMT. */
    delta = (long)((tzoff!=-1?tzoff:0) + (t - t2));

    if((delta>0) && (t + delta < t))
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
