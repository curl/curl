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
#include "strtoofft.h"

/*
 * NOTE:
 *
 * In the ISO C standard (IEEE Std 1003.1), there is a strtoimax() function we
 * could use in case strtoll() doesn't exist...  See
 * http://www.opengroup.org/onlinepubs/009695399/functions/strtoimax.html
 */

#ifdef NEED_CURL_STRTOLL
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

static int get_char(char c, int base);

/**
 * Emulated version of the strtoll function.  This extracts a long long
 * value from the given input string and returns it.
 */
curl_off_t
curlx_strtoll(const char *nptr, char **endptr, int base)
{
  char *end;
  int is_negative = 0;
  int overflow;
  int i;
  curl_off_t value = 0;
  curl_off_t newval;

  /* Skip leading whitespace. */
  end = (char *)nptr;
  while (ISSPACE(end[0])) {
    end++;
  }

  /* Handle the sign, if any. */
  if (end[0] == '-') {
    is_negative = 1;
    end++;
  }
  else if (end[0] == '+') {
    end++;
  }
  else if (end[0] == '\0') {
    /* We had nothing but perhaps some whitespace -- there was no number. */
    if (endptr) {
      *endptr = end;
    }
    return 0;
  }

  /* Handle special beginnings, if present and allowed. */
  if (end[0] == '0' && end[1] == 'x') {
    if (base == 16 || base == 0) {
      end += 2;
      base = 16;
    }
  }
  else if (end[0] == '0') {
    if (base == 8 || base == 0) {
      end++;
      base = 8;
    }
  }

  /* Matching strtol, if the base is 0 and it doesn't look like
   * the number is octal or hex, we assume it's base 10.
   */
  if (base == 0) {
    base = 10;
  }

  /* Loop handling digits. */
  value = 0;
  overflow = 0;
  for (i = get_char(end[0], base);
       i != -1;
       end++, i = get_char(end[0], base)) {
    newval = base * value + i;
    if (newval < value) {
      /* We've overflowed. */
      overflow = 1;
      break;
    }
    else
      value = newval;
  }

  if (!overflow) {
    if (is_negative) {
      /* Fix the sign. */
      value *= -1;
    }
  }
  else {
    if (is_negative)
      value = CURL_LLONG_MIN;
    else
      value = CURL_LLONG_MAX;

    errno = ERANGE;
  }

  if (endptr)
    *endptr = end;

  return value;
}

/**
 * Returns the value of c in the given base, or -1 if c cannot
 * be interpreted properly in that base (i.e., is out of range,
 * is a null, etc.).
 *
 * @param c     the character to interpret according to base
 * @param base  the base in which to interpret c
 *
 * @return  the value of c in base, or -1 if c isn't in range
 */
static int get_char(char c, int base)
{
  int value = -1;
  if (c <= '9' && c >= '0') {
    value = c - '0';
  }
  else if (c <= 'Z' && c >= 'A') {
    value = c - 'A' + 10;
  }
  else if (c <= 'z' && c >= 'a') {
    value = c - 'a' + 10;
  }

  if (value >= base) {
    value = -1;
  }

  return value;
}
#endif  /* Only present if we need strtoll, but don't have it. */
