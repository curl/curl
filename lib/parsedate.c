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

/* A brief summary of the date string formats this parser groks:

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

#if SIZEOF_TIME_T < 5
#define PARSEDATE_LATER  1
#endif
#if SIZEOF_TIME_T < 5 || defined(HAVE_TIME_T_UNSIGNED)
#define PARSEDATE_SOONER 2
#endif

#define DST (-60)     /* offset for daylight savings time */

/* two-letter time zones

  11 * 60,              NT - Nome    spellchecker:disable-line
  0,                    UT - Universal Time

*/

#define MKTZ(a,b,c,d) (((a)<<24) | ((b)<<16) | ((c)<<8) | (d))

#define LOWERCASE(x) ((x) | 0x20)

/* Pack three lowercase characters into a uint32_t for O(1) name lookups */
#define MKNAME3(a,b,c) \
  ((uint32_t)(LOWERCASE(a) << 16) | (uint32_t)(LOWERCASE(b) << 8) | \
   (uint32_t)LOWERCASE(c))

/* returns:
   -1 no day
   0 monday - 6 sunday

   @unittest 4781
*/
UNITTEST int checkday(const char *check, size_t len);
UNITTEST int checkday(const char *check, size_t len)
{
  int day;
  if(len < 3)
    return -1; /* too short */

  switch(MKNAME3(check[0], check[1], check[2])) {
  case MKNAME3('m','o','n'):
    day = 0;
    break;
  case MKNAME3('t','u','e'):
    day = 1;
    break;
  case MKNAME3('w','e','d'):
    day = 2;
    break;
  case MKNAME3('t','h','u'):
    day = 3;
    break;
  case MKNAME3('f','r','i'):
    day = 4;
    break;
  case MKNAME3('s','a','t'):
    day = 5;
    break;
  case MKNAME3('s','u','n'):
    day = 6;
    break;
  default:
    return -1;
  }

  if(len > 3) {
    /* when more than three letters are provided, verify the full name
       case-insensitively */
    static const struct {
      const char *suffix; /* chars minus the first three */
      size_t      slen;
    } daysuffix[] = {
      /* 0 Mon */ { "day",    3 },
      /* 1 Tue */ { "sday",   4 },
      /* 2 Wed */ { "nesday", 6 },
      /* 3 Thu */ { "rsday",  5 },
      /* 4 Fri */ { "day",    3 },
      /* 5 Sat */ { "urday",  5 },
      /* 6 Sun */ { "day",    3 },
    };
    size_t slen = daysuffix[day].slen;
    const char *suffix = daysuffix[day].suffix;
    size_t i;
    if((len - 3) != slen)
      return -1;
    for(i = 0; i < slen; i++) {
      if(LOWERCASE(check[3 + i]) != suffix[i])
        return -1;
    }
  }
  return day;
}

/* @unittest 4781 */

UNITTEST int checkmonth(const char *check, size_t len);
UNITTEST int checkmonth(const char *check, size_t len)
{
  if(len != 3)
    return -1; /* not a month */

  switch(MKNAME3(check[0], check[1], check[2])) {
  case MKNAME3('j','a','n'):
    return 0;
  case MKNAME3('f','e','b'):
    return 1;
  case MKNAME3('m','a','r'):
    return 2;
  case MKNAME3('a','p','r'):
    return 3;
  case MKNAME3('m','a','y'):
    return 4;
  case MKNAME3('j','u','n'):
    return 5;
  case MKNAME3('j','u','l'):
    return 6;
  case MKNAME3('a','u','g'):
    return 7;
  case MKNAME3('s','e','p'):
    return 8;
  case MKNAME3('o','c','t'):
    return 9;
  case MKNAME3('n','o','v'):
    return 10;
  case MKNAME3('d','e','c'):
    return 11;
  }
  return -1; /* return the offset or -1, no real offset is -1 */
}

/* return the time zone offset between GMT and the input one, in number of
   seconds or -1 if the timezone was not found/legal

   @unittest 4781
*/
UNITTEST int checktz(const char *check, size_t len);
UNITTEST int checktz(const char *check, size_t len)
{
  /* alpha-sorted list of single-letter time zones, A - Z */
  static const int16_t tzone[] = {
    -1 * 60,            /* Alpha */
    -2 * 60,            /* Bravo */
    -3 * 60,            /* Charlie */
    -4 * 60,            /* Delta */
    -5 * 60,            /* Echo */
    -6 * 60,            /* Foxtrot */
    -7 * 60,            /* Golf */
    -8 * 60,            /* Hotel */
    -9 * 60,            /* India */
    -1,                 /* J - not a timezone */
    -10 * 60,           /* Kilo */
    -11 * 60,           /* Lima */
    -12 * 60,           /* Mike */
    60,                 /* November */
    2 * 60,             /* Oscar */
    3 * 60,             /* Papa */
    4 * 60,             /* Quebec */
    5 * 60,             /* Romeo */
    6 * 60,             /* Sierra */
    7 * 60,             /* Tango */
    8 * 60,             /* Uniform */
    9 * 60,             /* Victor */
    10 * 60,            /* Whiskey */
    11 * 60,            /* X-ray */
    12 * 60,            /* Yankee */
    0                   /* Zulu, zero meridian, a.k.a. UTC */
  };
  char first;
  if(len > 4)
    return -1;
  first = check[0];
  if(len == 1) {
    /* short-cut single letter names */
    if((first > 'Z') || (first == 'J'))
      return -1; /* no such tz */
    return tzone[first - 'A'] * 60;
  }
  else if(len == 2) {
    /* two-letter names */
    if(check[1] == 'T') {
      if(first == 'N')
        return 11 * 60 * 60;
      else if(first == 'U')
        return 0;
    }
    return -1; /* nope */
  }
  else if(len == 3) {
    uint32_t key;
    if(first > 'Y')
      return -1;
    key = MKTZ(first, check[1], check[2], 0);
    switch(key) {
    case MKTZ('A','D','T','\0'):
      return (240 + DST) * 60; /* Atlantic Daylight */
    case MKTZ('A','S','T','\0'):
      return 240 * 60; /* Atlantic Standard */
    case MKTZ('B','S','T','\0'):
      return (0 + DST) * 60; /* British Summer */
    case MKTZ('C','A','T','\0'):
      return 600 * 60; /* Central Alaska */
    case MKTZ('C','C','T','\0'):
      return -480 * 60; /* China Coast, USSR Zone 7 */
    case MKTZ('C','D','T','\0'):
      return (360 + DST) * 60; /* Central Daylight */
    case MKTZ('C','E','T','\0'):
      return -60 * 60; /* Central European */
    case MKTZ('C','S','T','\0'):
      return 360 * 60; /* Central Standard */
    case MKTZ('E','D','T','\0'):
      return (300 + DST) * 60; /* Eastern Daylight */
    case MKTZ('E','E','T','\0'):
      return -120 * 60; /* Eastern Europe, USSR Zone 1 */
    case MKTZ('E','S','T','\0'):
      return 300 * 60; /* Eastern Standard */
    case MKTZ('F','S','T','\0'):
      return (-60 + DST) * 60; /* French Summer */
    case MKTZ('F','W','T','\0'):
      return -60 * 60; /* French Winter */
    case MKTZ('G','M','T','\0'):
      return 0; /* Greenwich Mean */
    case MKTZ('G','S','T','\0'):
      return -600 * 60; /* Guam Standard, USSR Zone 9 */
    case MKTZ('H','D','T','\0'):
      return (600 + DST) * 60; /* Hawaii Daylight */
    case MKTZ('H','S','T','\0'):
      return 600 * 60; /* Hawaii Standard */
    case MKTZ('J','S','T','\0'):
      return -540 * 60; /* Japan Standard, USSR Zone 8 */
    case MKTZ('M','D','T','\0'):
      return (420 + DST) * 60; /* Mountain Daylight */
    case MKTZ('M','E','T','\0'):
      return -60 * 60; /* Middle European */
    case MKTZ('M','S','T','\0'):
      return 420 * 60; /* Mountain Standard */
    case MKTZ('N','Z','T','\0'):
      return -720 * 60; /* New Zealand */
    case MKTZ('P','D','T','\0'):
      return (480 + DST) * 60; /* Pacific Daylight */
    case MKTZ('P','S','T','\0'):
      return 480 * 60; /* Pacific Standard */
    case MKTZ('U','T','C','\0'):
      return 0; /* Universal (Coordinated) */
    case MKTZ('W','A','T','\0'):
      return 60 * 60; /* West Africa */
    case MKTZ('W','E','T','\0'):
      return 0; /* Western European */
    case MKTZ('Y','D','T','\0'):
      return (540 + DST) * 60; /* Yukon Daylight */
    case MKTZ('Y','S','T','\0'):
      return 540 * 60; /* Yukon Standard */
    }
  }
  else {
    uint32_t key;
    if(first > 'W')
      return -1;
    key = MKTZ(first, check[1], check[2], check[3]);
    switch(key) {
    case MKTZ('A','H','S','T'):
      return 600 * 60; /* Alaska-Hawaii Standard */
    case MKTZ('C','E','S','T'):
      return (-60 + DST) * 60; /* Central European Summer */
    case MKTZ('E','A','D','T'):
      return (-600 + DST) * 60; /* Eastern Australian Daylight */
    case MKTZ('E','A','S','T'):
      return -600 * 60; /* Eastern Australian Standard */
    case MKTZ('I','D','L','E'):
      return -720 * 60; /* International Date Line East */
    case MKTZ('I','D','L','W'):
      return 720 * 60; /* International Date Line West */
    case MKTZ('M','E','S','T'):
      return (-60 + DST) * 60; /* Middle European Summer */
    case MKTZ('M','E','S','Z'):
      return (-60 + DST) * 60; /* Middle European Summer */
    case MKTZ('M','E','W','T'):
      return -60 * 60; /* Middle European Winter */
    case MKTZ('N','Z','D','T'):
      return (-720 + DST) * 60; /* New Zealand Daylight */
    case MKTZ('N','Z','S','T'):
      return -720 * 60; /* New Zealand Standard */
    case MKTZ('W','A','D','T'):
      return (-420 + DST) * 60; /* West Australian Daylight */
    case MKTZ('W','A','S','T'): /* spellchecker:disable-line */
      return -420 * 60; /* West Australian Standard */
    }
  }
  return -1;
}

/* each field is exactly -1 when unknown */
struct when {
  int wday;  /* day of the week, 0-6 (mon-sun) */
  int mon;   /* month of the year, 0-11 */
  int mday;  /* day of month, 1 - 31 */
  int dsecs; /* number of seconds into the day */
  int year;  /* year, >= 1583 */
  int tzoff; /* time zone offset in seconds */
};

/* (1969 / 4) - (1969 / 100) + (1969 / 400) = 492 - 19 + 4 = 477 */
#define LEAP_DAYS_BEFORE_1969 477
#define SECONDS_PER_DAY 86400

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

  return (days * SECONDS_PER_DAY) + w->dsecs;
}

/* HH:MM:SS or HH:MM and accept single-digits too */
static bool match_time(const char *date, struct when *w, char **endp)
{
  const unsigned char *p = (const unsigned char *)date;
  unsigned int hh, mm, ss = 0;

  if(!ISDIGIT(*p))
    return FALSE;

  hh = *p++ - '0';
  if(ISDIGIT(*p))
    hh = hh * 10 + (*p++ - '0');

  if((hh >= 24) || (*p++ != ':') || !ISDIGIT(*p))
    return FALSE;

  mm = *p++ - '0';
  if(ISDIGIT(*p))
    mm = mm * 10 + (*p++ - '0');

  if(mm >= 60)
    return FALSE;

  if(*p == ':') {
    p++;
    if(!ISDIGIT(*p))
      return FALSE;

    ss = *p++ - '0';
    if(ISDIGIT(*p))
      ss = ss * 10 + (*p++ - '0');

    if(ss > 60)
      return FALSE;
  }

  w->dsecs = (hh * 3600) + (mm * 60) + ss;
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
#define NAME_LEN 10

static void initwhen(struct when *w)
{
  w->wday = w->mon = w->mday = w->dsecs = w->year = w->tzoff = -1;
}

static int datestring(const char **datep, struct when *w)
{
  /* a name coming up */
  size_t len = 0;
  const char *p = *datep;
  while(ISALPHA(p[len]) && (len < NAME_LEN))
    len++;

  if(len != NAME_LEN) {
    if(w->wday == -1) {
      w->wday = checkday(p, len);
      if(w->wday != -1)
        goto found;
    }
    if(w->mon == -1) {
      w->mon = checkmonth(p, len);
      if(w->mon != -1)
        goto found;
    }
    if(w->tzoff == -1) {
      /* this must be a time zone string */
      w->tzoff = checktz(p, len);
      if(w->tzoff != -1)
        goto found;
    }
  }
  return PARSEDATE_FAIL; /* bad string */
found:
  *datep += len;
  return PARSEDATE_OK;
}

static int datenum(const char *indate, const char **datep, struct when *w)
{
  /* a digit */
  unsigned int val;
  char *end;
  const char *date = *datep;

  if((w->dsecs == -1) && match_time(date, w, &end)) {
    /* time stamp */
    date = end;
  }
  else {
    /* Parse up to 8 decimal digits inline - we know *date is a digit.
       Avoid the overhead of curlx_str_number(). */
    const char *p = date;
    unsigned int n = (unsigned int)(*p++ - '0');
    int num_digits;
    while(ISDIGIT(*p) && (p - date) < 8)
      n = n * 10 + (unsigned int)(*p++ - '0');
    /* reject a 9th digit */
    if(ISDIGIT(*p))
      return PARSEDATE_FAIL;
    num_digits = (int)(p - date);
    val = n;

    if((num_digits == 4) && (indate < date) &&
       (date[-1] == '+' || date[-1] == '-') &&
       (w->tzoff == -1) && (val <= 1400)) {
      /* four digits and a value less than or equal to 1400 (to take into
         account all sorts of funny time zone diffs) and it is preceded with a
         plus or minus. This is a time zone indication. 1400 is picked since
         +1300 is frequently used and +1400 is mentioned as an edge number in
         the document "ISO C 200X Proposal: Timezone Functions" */
      w->tzoff = ((val / 100 * 60) + (val % 100)) * 60;

      /* the + and - prefix indicates the local time compared to GMT,
         this we need their reversed math to get what we want */
      w->tzoff = date[-1] == '+' ? -w->tzoff : w->tzoff;
    }

    else if(num_digits == 8) {
      /* 8 digits, this is YYYYMMDD */
      if((w->year == -1) && (w->mon == -1) && (w->mday == -1)) {
        w->year = val / 10000;
        w->mon = ((val % 10000) / 100) - 1; /* month is 0 - 11 */
        if(w->mon > 11)
          return PARSEDATE_FAIL;
        w->mday = val % 100;
      }
      else
        return PARSEDATE_FAIL;
    }

    else if(w->mday == -1 && val > 0 && val < 32) {
      w->mday = val;
    }

    else if(w->year == -1) {
      w->year = val;
      if(w->year < 100) {
        if(w->year > 70)
          w->year += 1900;
        else
          w->year += 2000;
      }
    }

    else
      return PARSEDATE_FAIL;

    date = p;
  }
  *datep = date;
  return PARSEDATE_OK;
}

static bool datecheck(struct when *w)
{
  if(w->dsecs == -1)
    w->dsecs = 0; /* no time available, make it zero */

  if((w->mday == -1) || (w->mon == -1) || (w->year == -1) ||
    /* lacks vital info, fail */
     (w->year < 1583) ||
     /* The Gregorian calendar was introduced 1582 */
     (w->mday > 31) /* too long month */ )
    return TRUE;

  return FALSE;
}

static void tzadjust(curl_off_t *tp, struct when *w)
{
  if(w->tzoff != -1) { /* unknown tz means no offset */
    /* Add the time zone diff between local time zone and GMT. */
    if((w->tzoff > 0) && (*tp > (curl_off_t)(CURL_OFF_T_MAX - w->tzoff)))
      *tp = CURL_OFF_T_MAX;
    else
      *tp += w->tzoff;
  }
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
  const char *indate = date; /* save the original pointer */
  int part = 0; /* max 6 parts */
  int rc = 0;
  struct when w;
  initwhen(&w);

  while(*date && (part < 6)) {
    /* skip everything that are not letters or digits */
    while(*date && !ISALNUM(*date))
      date++;

    if(ISALPHA(*date))
      rc = datestring(&date, &w);
    else if(ISDIGIT(*date))
      rc = datenum(indate, &date, &w);
    if(rc)
      return rc;

    part++;
  }

  if(datecheck(&w))
    return PARSEDATE_FAIL;

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
  int rc;
  (void)unused; /* legacy argument from the past that we ignore */

  if(!p)
    return -1;

  rc = parsedate(p, &parsed);
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
