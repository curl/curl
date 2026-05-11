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

#include "parsedate.h"
#include "curlx/strparse.h"
#include "curlx/strcopy.h"

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

#if !defined(CURL_DISABLE_PARSEDATE) || !defined(CURL_DISABLE_FTP) || \
  !defined(CURL_DISABLE_FILE) || defined(USE_GNUTLS)
/* These names are also used by FTP and FILE code */
const char * const Curl_wkday[] = {
  "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"
};
const char * const Curl_month[] = {
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
#endif

#define PARSEDATE_OK     0
#define PARSEDATE_FAIL   (-1)

#ifndef CURL_DISABLE_PARSEDATE

#define PARSEDATE_LATER  1
#define PARSEDATE_SOONER 2

static const char * const weekday[] = {
  "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
};

struct tzinfo {
  char name[5];
  int16_t offset; /* +/- in minutes */
};

#define tDAYZONE (-60)         /* offset for daylight savings time */

/* alpha-sorted list of time zones */
static const struct tzinfo tz[] = {
  { "A", -1 * 60 },            /* Alpha */
  { "ADT",   240 + tDAYZONE }, /* Atlantic Daylight */
  { "AHST",  600 },            /* Alaska-Hawaii Standard */
  { "AST",   240 },            /* Atlantic Standard */
  { "B", -2 * 60 },            /* Bravo */
  { "BST",     0 + tDAYZONE }, /* British Summer */
  { "C", -3 * 60 },            /* Charlie */
  { "CAT",   600 },            /* Central Alaska */
  { "CCT",  -480 },            /* China Coast, USSR Zone 7 */
  { "CDT",   360 + tDAYZONE }, /* Central Daylight */
  { "CEST",  -60 + tDAYZONE }, /* Central European Summer */
  { "CET",   -60 },            /* Central European */
  { "CST",   360 },            /* Central Standard */
  { "D", -4 * 60 },            /* Delta */
  { "E", -5 * 60 },            /* Echo */
  { "EADT", -600 + tDAYZONE }, /* Eastern Australian Daylight */
  { "EAST", -600 },            /* Eastern Australian Standard */
  { "EDT",   300 + tDAYZONE }, /* Eastern Daylight */
  { "EET",  -120 },            /* Eastern Europe, USSR Zone 1 */
  { "EST",   300 },            /* Eastern Standard */
  { "F", -6 * 60 },            /* Foxtrot */
  { "FST",   -60 + tDAYZONE }, /* French Summer */
  { "FWT",   -60 },            /* French Winter */
  { "G", -7 * 60 },            /* Golf */
  { "GMT",     0 },            /* Greenwich Mean */
  { "GST",  -600 },            /* Guam Standard, USSR Zone 9 */
  { "H", -8 * 60 },            /* Hotel */
  { "HDT",   600 + tDAYZONE }, /* Hawaii Daylight */
  { "HST",   600 },            /* Hawaii Standard */
  { "I", -9 * 60 },            /* India */
  { "IDLE", -720 },            /* International Date Line East */
  { "IDLW",  720 },            /* International Date Line West */
  { "JST",  -540 },            /* Japan Standard, USSR Zone 8 */
  { "K", -10 * 60 },           /* Kilo */
  { "L", -11 * 60 },           /* Lima */
  { "M", -12 * 60 },           /* Mike */
  { "MDT",   420 + tDAYZONE }, /* Mountain Daylight */
  { "MEST",  -60 + tDAYZONE }, /* Middle European Summer */
  { "MESZ",  -60 + tDAYZONE }, /* Middle European Summer */
  { "MET",   -60 },            /* Middle European */
  { "MEWT",  -60 },            /* Middle European Winter */
  { "MST",   420 },            /* Mountain Standard */
  { "N",      60 },            /* November */
  { "NT",    660 },            /* Nome */ /* spellchecker:disable-line */
  { "NZDT", -720 + tDAYZONE }, /* New Zealand Daylight */
  { "NZST", -720 },            /* New Zealand Standard */
  { "NZT",  -720 },            /* New Zealand */
  { "O",  2 * 60 },            /* Oscar */
  { "P",  3 * 60 },            /* Papa */
  { "PDT",   480 + tDAYZONE }, /* Pacific Daylight */
  { "PST",   480 },            /* Pacific Standard */
  { "Q",  4 * 60 },            /* Quebec */
  { "R",  5 * 60 },            /* Romeo */
  { "S",  6 * 60 },            /* Sierra */
  { "T",  7 * 60 },            /* Tango */
  { "U",  8 * 60 },            /* Uniform */
  { "UT",      0 },            /* Universal Time */
  { "UTC",     0 },            /* Universal (Coordinated) */
  { "V",  9 * 60 },            /* Victor */
  { "W", 10 * 60 },            /* Whiskey */
  { "WADT", -420 + tDAYZONE }, /* West Australian Daylight */
  { "WAST", -420 }, /* spellchecker:disable-line */
                               /* West Australian Standard */
  { "WAT",    60 },            /* West Africa */
  { "WET",     0 },            /* Western European */
  { "X", 11 * 60 },            /* X-ray */
  { "Y", 12 * 60 },            /* Yankee */
  { "YDT",   540 + tDAYZONE }, /* Yukon Daylight */
  { "YST",   540 },            /* Yukon Standard */
  { "Z",       0 },            /* Zulu, zero meridian, a.k.a. UTC */
};

/* returns:
   -1 no day
   0 monday - 6 sunday
*/

static int checkday(const char *check, size_t len)
{
  int i;
  const char * const *what;
  if(len > 3)
    what = &weekday[0];
  else if(len == 3)
    what = &Curl_wkday[0];
  else
    return -1; /* too short */
  for(i = 0; i < 7; i++) {
    size_t ilen = strlen(what[0]);
    if((ilen == len) &&
       curl_strnequal(check, what[0], len))
      return i;
    what++;
  }
  return -1;
}

static int checkmonth(const char *check, size_t len)
{
  int i;
  const char * const *what = &Curl_month[0];
  if(len != 3)
    return -1; /* not a month */

  for(i = 0; i < 12; i++) {
    if(curl_strnequal(check, what[0], 3))
      return i;
    what++;
  }
  return -1; /* return the offset or -1, no real offset is -1 */
}

static int tzcompare(const void *m1, const void *m2)
{
  const struct tzinfo *tz1 = m1;
  const struct tzinfo *tz2 = m2;
  return strcmp(tz1->name, tz2->name);
}

/* return the time zone offset between GMT and the input one, in number of
   seconds or -1 if the timezone was not found/legal */
static int checktz(const char *check, size_t len)
{
  if(len <= 4) {
    const struct tzinfo *what;
    struct tzinfo find;
    curlx_strcopy(find.name, sizeof(find.name), check, len);
    what = bsearch(&find, tz, CURL_ARRAYSIZE(tz), sizeof(tz[0]), tzcompare);
    if(what)
      return what->offset * 60;
  }
  return -1;
}

static void skip(const char **date)
{
  /* skip everything that are not letters or digits */
  while(**date && !ISALNUM(**date))
    (*date)++;
}

/* each field is exactly -1 when unknown */
struct when {
  int wday;  /* day of the week, 0-6 (mon-sun) */
  int mon;   /* month of the year, 0-11 */
  int mday;  /* day of month, 1 - 31 */
  int hour;  /* hour of day, 0 - 23 */
  int min;   /* minute of hour, 0 - 59 */
  int sec;   /* second of minute, 0 - 60 (leap second) */
  int year;  /* year, >= 1583 */
  int tzoff; /* time zone offset in seconds */
};

enum assume {
  DATE_MDAY,
  DATE_YEAR,
  DATE_TIME
};

/* (1969 / 4) - (1969 / 100) + (1969 / 400) = 492 - 19 + 4 = 477 */
#define LEAP_DAYS_BEFORE_1969 477

/*
 * time2epoch: time stamp to seconds since epoch in GMT time zone. Similar to
 * mktime but for GMT only.
 */
static curl_off_t time2epoch(struct when *w)
{
  static const int cumulative_days[12] = {
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
  };
  int y = w->year - (w->mon <= 1);
  int leap_days = (y / 4) - (y / 100) + (y / 400) - LEAP_DAYS_BEFORE_1969;
  curl_off_t days = (curl_off_t)(w->year - 1970) * 365 + leap_days +
    cumulative_days[w->mon] + w->mday - 1;

  return (((days * 24 + w->hour) * 60 + w->min) * 60) + w->sec;
}

/* Returns the value of a single-digit or two-digit decimal number, return
   then pointer to after the number. The 'date' pointer is known to point to a
   digit. */
static int oneortwodigit(const char *date, const char **endp)
{
  int num = date[0] - '0';
  if(ISDIGIT(date[1])) {
    *endp = &date[2];
    return (num * 10) + (date[1] - '0');
  }
  *endp = &date[1];
  return num;
}

/* HH:MM:SS or HH:MM and accept single-digits too */
static bool match_time(const char *date, struct when *w, char **endp)
{
  const char *p;
  int hh, mm, ss = 0;
  hh = oneortwodigit(date, &p);
  if((hh < 24) && (*p == ':') && ISDIGIT(p[1])) {
    mm = oneortwodigit(&p[1], &p);
    if(mm < 60) {
      if((*p == ':') && ISDIGIT(p[1])) {
        ss = oneortwodigit(&p[1], &p);
        if(ss <= 60) {
          /* valid HH:MM:SS */
          goto match;
        }
      }
      else {
        /* valid HH:MM */
        goto match;
      }
    }
  }
  return FALSE; /* not a time string */
match:
  w->hour = hh;
  w->min = mm;
  w->sec = ss;
  *endp = (char *)CURL_UNCONST(p);
  return TRUE;
}

/*
 * parsedate()
 *
 * Returns:
 *
 * PARSEDATE_OK     - a fine conversion
 * PARSEDATE_FAIL   - failed to convert
 * PARSEDATE_LATER  - time overflow at the far end of time_t
 * PARSEDATE_SOONER - time underflow at the low end of time_t
 */

/* Wednesday is the longest name this parser knows about */
#define NAME_LEN 12

static void initwhen(struct when *w)
{
  w->wday = w->mon = w->mday = w->hour = w->min = w->sec = w->year = w->tzoff =
    -1;
}

static int datestring(const char **datep, struct when *w)
{
  /* a name coming up */
  size_t len = 0;
  const char *p = *datep;
  bool found = FALSE;
  while(ISALPHA(*p) && (len < NAME_LEN)) {
    p++;
    len++;
  }

  if(len != NAME_LEN) {
    if(w->wday == -1) {
      w->wday = checkday(*datep, len);
      if(w->wday != -1)
        found = TRUE;
    }
    if(!found && (w->mon == -1)) {
      w->mon = checkmonth(*datep, len);
      if(w->mon != -1)
        found = TRUE;
    }

    if(!found && (w->tzoff == -1)) {
      /* this must be a time zone string */
      w->tzoff = checktz(*datep, len);
      if(w->tzoff != -1)
        found = TRUE;
    }
  }
  if(!found)
    return PARSEDATE_FAIL; /* bad string */

  *datep += len;
  return PARSEDATE_OK;
}

static int datenum(const char *indate, const char **datep, struct when *w,
                   enum assume *dignextp)
{
  /* a digit */
  unsigned int val;
  char *end;
  const char *date = *datep;
  enum assume dignext = *dignextp;

  if((w->sec == -1) && match_time(date, w, &end)) {
    /* time stamp */
    date = end;
  }
  else {
    bool found = FALSE;
    curl_off_t lval;
    int num_digits = 0;
    const char *p = *datep;
    if(curlx_str_number(&p, &lval, 99999999))
      return PARSEDATE_FAIL;

    /* we know num_digits cannot be larger than 8 */
    num_digits = (int)(p - *datep);
    val = (unsigned int)lval;

    if((w->tzoff == -1) &&
       (num_digits == 4) &&
       (val <= 1400) &&
       (indate < date) &&
       (date[-1] == '+' || date[-1] == '-')) {
      /* four digits and a value less than or equal to 1400 (to take into
         account all sorts of funny time zone diffs) and it is preceded
         with a plus or minus. This is a time zone indication. 1400 is
         picked since +1300 is frequently used and +1400 is mentioned as
         an edge number in the document "ISO C 200X Proposal: Timezone
         Functions" at http://david.tribble.com/text/c0xtimezone.html If
         anyone has a more authoritative source for the exact maximum time
         zone offsets, please speak up! */
      found = TRUE;
      w->tzoff = ((val / 100 * 60) + (val % 100)) * 60;

      /* the + and - prefix indicates the local time compared to GMT,
         this we need their reversed math to get what we want */
      w->tzoff = date[-1] == '+' ? -w->tzoff : w->tzoff;
    }

    else if((num_digits == 8) && (w->year == -1) &&
            (w->mon == -1) && (w->mday == -1)) {
      /* 8 digits, no year, month or day yet. This is YYYYMMDD */
      found = TRUE;
      w->year = val / 10000;
      w->mon = ((val % 10000) / 100) - 1; /* month is 0 - 11 */
      w->mday = val % 100;
    }

    if(!found && (dignext == DATE_MDAY) && (w->mday == -1)) {
      if((val > 0) && (val < 32)) {
        w->mday = val;
        found = TRUE;
      }
      dignext = DATE_YEAR;
    }

    if(!found && (dignext == DATE_YEAR) && (w->year == -1)) {
      w->year = val;
      found = TRUE;
      if(w->year < 100) {
        if(w->year > 70)
          w->year += 1900;
        else
          w->year += 2000;
      }
      if(w->mday == -1)
        dignext = DATE_MDAY;
    }

    if(!found)
      return PARSEDATE_FAIL;

    date = p;
  }
  *datep = date;
  *dignextp = dignext;
  return PARSEDATE_OK;
}

static int datecheck(struct when *w)
{
  if(w->sec == -1)
    w->sec = w->min = w->hour = 0; /* no time, make it zero */

  if((w->mday == -1) || (w->mon == -1) || (w->year == -1))
    /* lacks vital info, fail */
    return PARSEDATE_FAIL;

  /* The Gregorian calendar was introduced 1582 */
  else if(w->year < 1583)
    return PARSEDATE_FAIL;

  else if((w->mday > 31) || (w->mon > 11) || (w->hour > 23) ||
          (w->min > 59) || (w->sec > 60))
    return PARSEDATE_FAIL; /* clearly an illegal date */

  return PARSEDATE_OK;
}

static void tzadjust(curl_off_t *tp, struct when *w)
{
  if(w->tzoff == -1) /* unknown tz means no offset */
    w->tzoff = 0;

  /* Add the time zone diff between local time zone and GMT. */
  if((w->tzoff > 0) && (*tp > (curl_off_t)(CURL_OFF_T_MAX - w->tzoff)))
    *tp = CURL_OFF_T_MAX;
  else
    *tp += w->tzoff;
  /* this needs no minimum check since we require a year > 1582 */
}

static int mktimet(curl_off_t seconds, time_t *output)
{
#if SIZEOF_TIME_T < 5
  if(seconds > TIME_T_MAX) {
    *output = TIME_T_MAX;
    return PARSEDATE_LATER;
  }
  else if(seconds < TIME_T_MIN) {
    *output = TIME_T_MIN;
    return PARSEDATE_SOONER;
  }
#elif defined(HAVE_TIME_T_UNSIGNED)
  if(seconds < 0) {
    *output = 0;
    return PARSEDATE_SOONER;
  }
#endif
  *output = (time_t)seconds;
  return PARSEDATE_OK;
}

static int parsedate(const char *date, time_t *output)
{
  curl_off_t seconds = 0;
  enum assume dignext = DATE_MDAY;
  const char *indate = date; /* save the original pointer */
  int part = 0; /* max 6 parts */
  int rc = 0;
  struct when w;
  initwhen(&w);

  while(*date && (part < 6)) {
    skip(&date);

    if(ISALPHA(*date))
      rc = datestring(&date, &w);
    else if(ISDIGIT(*date))
      rc = datenum(indate, &date, &w, &dignext);
    if(rc)
      return rc;

    part++;
  }

  rc = datecheck(&w);
  if(rc)
    return rc;

  seconds = time2epoch(&w); /* get number of seconds */
  tzadjust(&seconds, &w); /* handle the time zone offset */
  rc = mktimet(seconds, output); /* squeeze seconds into a time_t */

  return rc;
}
#else
/* disabled */
static int parsedate(const char *date, time_t *output)
{
  (void)date;
  *output = 0;
  return PARSEDATE_OK; /* a lie */
}
#endif

time_t curl_getdate(const char *p, const time_t *unused)
{
  time_t parsed = -1;
  int rc = parsedate(p, &parsed);
  (void)unused; /* legacy argument from the past that we ignore */

  if(rc == PARSEDATE_OK) {
    if(parsed == (time_t)-1)
      /* avoid returning -1 for a working scenario */
      parsed++;
    return parsed;
  }
  /* everything else is fail */
  return -1;
}

/* Curl_getdate_capped() differs from curl_getdate() in that this will return
   TIME_T_MAX in case the parsed time value was too big, instead of an
   error. Returns non-zero on error. */

int Curl_getdate_capped(const char *p, time_t *tp)
{
  int rc = parsedate(p, tp);
  return (rc == PARSEDATE_FAIL);
}
