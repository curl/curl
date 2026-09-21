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

struct tzinfo {
  uint32_t tz;
  int16_t offset; /* +/- in minutes */
};

#define DST (-60)     /* offset for daylight savings time */

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
   2 * 60,            /* Oscar */
   3 * 60,            /* Papa */
   4 * 60,            /* Quebec */
   5 * 60,            /* Romeo */
   6 * 60,            /* Sierra */
   7 * 60,            /* Tango */
   8 * 60,            /* Uniform */
   9 * 60,            /* Victor */
  10 * 60,            /* Whiskey */
  11 * 60,            /* X-ray */
  12 * 60,            /* Yankee */
  0                   /* Zulu, zero meridian, a.k.a. UTC */
};

/* two-letter time zones

  11 * 60,              NT - Nome    spellchecker:disable-line
  0,                    UT - Universal Time

*/

#define MKTZ(a,b,c,d) (((a)<<24) | ((b)<<16) | ((c)<<8) | (d))

/* three-letter time zones */
static const struct tzinfo tzthree[] = {
  { MKTZ('A', 'D', 'T', '\0'),   240 + DST }, /* Atlantic Daylight */
  { MKTZ('A', 'S', 'T', '\0'),   240 },       /* Atlantic Standard */
  { MKTZ('B', 'S', 'T', '\0'),     0 + DST }, /* British Summer */
  { MKTZ('C', 'A', 'T', '\0'),   600 },       /* Central Alaska */
  { MKTZ('C', 'C', 'T', '\0'),  -480 },       /* China Coast, USSR Zone 7 */
  { MKTZ('C', 'D', 'T', '\0'),   360 + DST }, /* Central Daylight */
  { MKTZ('C', 'E', 'T', '\0'),   -60 },       /* Central European */
  { MKTZ('C', 'S', 'T', '\0'),   360 },       /* Central Standard */
  { MKTZ('E', 'D', 'T', '\0'),   300 + DST }, /* Eastern Daylight */
  { MKTZ('E', 'E', 'T', '\0'),  -120 },       /* Eastern Europe, USSR Zone 1 */
  { MKTZ('E', 'S', 'T', '\0'),   300 },       /* Eastern Standard */
  { MKTZ('F', 'S', 'T', '\0'),   -60 + DST }, /* French Summer */
  { MKTZ('F', 'W', 'T', '\0'),   -60 },       /* French Winter */
  { MKTZ('G', 'M', 'T', '\0'),     0 },       /* Greenwich Mean */
  { MKTZ('G', 'S', 'T', '\0'),  -600 },       /* Guam Standard, USSR Zone 9 */
  { MKTZ('H', 'D', 'T', '\0'),   600 + DST }, /* Hawaii Daylight */
  { MKTZ('H', 'S', 'T', '\0'),   600 },       /* Hawaii Standard */
  { MKTZ('J', 'S', 'T', '\0'),  -540 },       /* Japan Standard, USSR Zone 8 */
  { MKTZ('M', 'D', 'T', '\0'),   420 + DST }, /* Mountain Daylight */
  { MKTZ('M', 'E', 'T', '\0'),   -60 },       /* Middle European */
  { MKTZ('M', 'S', 'T', '\0'),   420 },       /* Mountain Standard */
  { MKTZ('N', 'Z', 'T', '\0'),  -720 },       /* New Zealand */
  { MKTZ('P', 'D', 'T', '\0'),   480 + DST }, /* Pacific Daylight */
  { MKTZ('P', 'S', 'T', '\0'),   480 },       /* Pacific Standard */
  { MKTZ('U', 'T', 'C', '\0'),     0 },       /* Universal (Coordinated) */
  { MKTZ('W', 'A', 'T', '\0'),    60 },       /* West Africa */
  { MKTZ('W', 'E', 'T', '\0'),     0 },       /* Western European */
  { MKTZ('Y', 'D', 'T', '\0'),   540 + DST }, /* Yukon Daylight */
  { MKTZ('Y', 'S', 'T', '\0'),   540 },       /* Yukon Standard */
};

/* four-letter time zones */
static const struct tzinfo tzfoura[] = {
  { MKTZ('A', 'H', 'S', 'T'),  600 },       /* Alaska-Hawaii Standard */
  { MKTZ('C', 'E', 'S', 'T'),  -60 + DST }, /* Central European Summer */
  { MKTZ('E', 'A', 'D', 'T'), -600 + DST }, /* Eastern Australian Daylight */
  { MKTZ('E', 'A', 'S', 'T'), -600 },       /* Eastern Australian Standard */
  { MKTZ('I', 'D', 'L', 'E'), -720 },       /* International Date Line East */
  { MKTZ('I', 'D', 'L', 'W'),  720 },       /* International Date Line West */
  { MKTZ('M', 'E', 'S', 'T'),  -60 + DST }, /* Middle European Summer */
  { MKTZ('M', 'E', 'S', 'Z'),  -60 + DST }, /* Middle European Summer */
  { MKTZ('M', 'E', 'W', 'T'),  -60 },       /* Middle European Winter */
  { MKTZ('N', 'Z', 'D', 'T'), -720 + DST }, /* New Zealand Daylight */
  { MKTZ('N', 'Z', 'S', 'T'), -720 },       /* New Zealand Standard */
  { MKTZ('W', 'A', 'D', 'T'), -420 + DST }, /* West Australian Daylight */
  { MKTZ('W', 'A', 'S', 'T'), -420 }, /* spellchecker:disable-line */
                               /* West Australian Standard */
};

#define LOWERCASE(x) ((x) | 0x20)

/* returns:
   -1 no day
   0 monday - 6 sunday

   @unittest 4781
*/
UNITTEST int checkday(const char *check, size_t len);
UNITTEST int checkday(const char *check, size_t len)
{
  int day = -1;
  if(len < 3)
    return -1; /* too short */

  switch(LOWERCASE(check[1])) {
  case 'o': /* monday */
    if((LOWERCASE(check[0]) == 'm') && LOWERCASE(check[2]) == 'n')
      day = 0;
    break;
  case 'u': /* tuesday or sunday */
    if((LOWERCASE(check[0]) == 't') && LOWERCASE(check[2]) == 'e')
      day = 1;
    else if((LOWERCASE(check[0]) == 's') && LOWERCASE(check[2]) == 'n')
      day = 6;
    break;
  case 'e': /* wednesday */
    if((LOWERCASE(check[0]) == 'w') && LOWERCASE(check[2]) == 'd')
      day = 2;
    break;
  case 'h': /* thursday */
    if((LOWERCASE(check[0]) == 't') && LOWERCASE(check[2]) == 'u')
      day = 3;
    break;
  case 'r': /* friday */
    if((LOWERCASE(check[0]) == 'f') && LOWERCASE(check[2]) == 'i')
      day = 4;
    break;
  case 'a': /* saturday */
    if((LOWERCASE(check[0]) == 's') && LOWERCASE(check[2]) == 't')
      day = 5;
    break;
  }
  if((len > 3) && (day != -1)) {
    /* when more than three letters are provided, verify the tail name case
       insensitively */
    static const char * const daysuffix[] = {
      /* without the leading three letters */
      "day", "sday", "nesday", "rsday", "day", "urday", "day"
    };

    size_t wlen = strlen(daysuffix[day]);
    if(((len - 3) != wlen) ||
       !curl_strnequal(&check[3], daysuffix[day], wlen))
      return -1;
  }
  return day;
}

/* @unittest 4781 */

UNITTEST int checkmonth(const char *check, size_t len);
UNITTEST int checkmonth(const char *check, size_t len)
{
  if(len != 3)
    return -1; /* not a month */

  switch(LOWERCASE(check[2])) {
  case 'n': /* jan, jun */
    if(LOWERCASE(check[0]) == 'j') {
      uint8_t c2 = LOWERCASE(check[1]);
      if(c2 == 'a')
        return 0;
      else if(c2 == 'u')
        return 5;
    }
    break;
  case 'b': /* feb */
    if((LOWERCASE(check[0]) == 'f') && LOWERCASE(check[1]) == 'e')
      return 1;
    break;
  case 'r': /* mar, apr */
    if(LOWERCASE(check[0]) == 'm') {
      if(LOWERCASE(check[1]) == 'a')
        return 2;
    }
    else if((LOWERCASE(check[0]) == 'a') && LOWERCASE(check[1]) == 'p')
      return 3;
    break;
  case 'y': /* may */
    if((LOWERCASE(check[0]) == 'm') && LOWERCASE(check[1]) == 'a')
      return 4;
    break;
  case 'l': /* jul */
    if((LOWERCASE(check[0]) == 'j') && LOWERCASE(check[1]) == 'u')
      return 6;
    break;
  case 'g': /* aug */
    if((LOWERCASE(check[0]) == 'a') && LOWERCASE(check[1]) == 'u')
      return 7;
    break;
  case 'p': /* sep */
    if((LOWERCASE(check[0]) == 's') && LOWERCASE(check[1]) == 'e')
      return 8;
    break;
  case 't': /* oct */
    if((LOWERCASE(check[0]) == 'o') && LOWERCASE(check[1]) == 'c')
      return 9;
    break;
  case 'v': /* nov */
    if((LOWERCASE(check[0]) == 'n') && LOWERCASE(check[1]) == 'o')
      return 10;
    break;
  case 'c': /* dec */
    if((LOWERCASE(check[0]) == 'd') && LOWERCASE(check[1]) == 'e')
      return 11;
    break;
  }
  return -1; /* return the offset or -1, no real offset is -1 */
}

static int tzcompare(const void *m1, const void *m2)
{
  const struct tzinfo *tz1 = m1;
  const struct tzinfo *tz2 = m2;
  return tz1->tz - tz2->tz;
}

/* return the time zone offset between GMT and the input one, in number of
   seconds or -1 if the timezone was not found/legal

   @unittest 4781
*/
UNITTEST int checktz(const char *check, size_t len);
UNITTEST int checktz(const char *check, size_t len)
{
  char first;
  if(len > 4)
    return -1;
  first = check[0];
  if(first < 'A')
    return -1;
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
    /* three-letter name */
    const struct tzinfo *what;
    struct tzinfo find;
    if(first > 'Y')
      return -1;
    find.tz = MKTZ(first, check[1], check[2], 0);
    what = bsearch(&find, tzthree, CURL_ARRAYSIZE(tzthree),
                   sizeof(tzthree[0]), tzcompare);
    if(what)
      return what->offset * 60;
  }
  else {
    /* four-letter name */
    const struct tzinfo *what;
    struct tzinfo find;
    if(first > 'W')
      return -1;
    find.tz = MKTZ(first, check[1], check[2], check[3]);
    what = bsearch(&find, tzfoura, CURL_ARRAYSIZE(tzfoura),
                   sizeof(tzfoura[0]), tzcompare);
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
