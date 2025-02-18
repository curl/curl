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

#include "strparse.h"
#include "strcase.h"

/* Get a word until the first DELIM or end of string. At least one byte long.
   return non-zero on error */
int Curl_str_until(const char **linep, struct Curl_str *out,
                   const size_t max, char delim)
{
  const char *s = *linep;
  size_t len = 0;
  DEBUGASSERT(linep && *linep && out && max && delim);

  out->str = NULL;
  out->len = 0;
  while(*s && (*s != delim)) {
    s++;
    if(++len > max) {
      return STRE_BIG;
    }
  }
  if(!len)
    return STRE_SHORT;
  out->str = *linep;
  out->len = len;
  *linep = s; /* point to the first byte after the word */
  return STRE_OK;
}

/* Get a word until the first space or end of string. At least one byte long.
   return non-zero on error */
int Curl_str_word(const char **linep, struct Curl_str *out,
                  const size_t max)
{
  return Curl_str_until(linep, out, max, ' ');
}


/* Get a "quoted" word. No escaping possible.
   return non-zero on error */
int Curl_str_quotedword(const char **linep, struct Curl_str *out,
                        const size_t max)
{
  const char *s = *linep;
  size_t len = 0;
  DEBUGASSERT(linep && *linep && out && max);

  out->str = NULL;
  out->len = 0;
  if(*s != '\"')
    return STRE_BEGQUOTE;
  s++;
  while(*s && (*s != '\"')) {
    s++;
    if(++len > max)
      return STRE_BIG;
  }
  if(*s != '\"')
    return STRE_ENDQUOTE;
  out->str = (*linep) + 1;
  out->len = len;
  *linep = s + 1;
  return STRE_OK;
}

/* Advance over a single character.
   return non-zero on error */
int Curl_str_single(const char **linep, char byte)
{
  DEBUGASSERT(linep && *linep);
  if(**linep != byte)
    return STRE_BYTE;
  (*linep)++; /* move over it */
  return STRE_OK;
}

/* Advance over a single space.
   return non-zero on error */
int Curl_str_singlespace(const char **linep)
{
  return Curl_str_single(linep, ' ');
}

/* given an ASCII hexadecimal character, return the value */
#define HEXDIGIT2NUM(x)                                         \
  (((x) > '9') ? Curl_raw_tolower(x) - 'a' + 10 : x - '0')

/* given an ASCII character and a given base, return TRUE if valid */
#define valid_digit(digit, base)                                        \
  (((base == 10) && ISDIGIT(digit)) ||                                  \
   ((base == 16) && ISXDIGIT(digit)) ||                                 \
   ((base == 8) && ISODIGIT(digit)))

/* given an ASCII character and a given base, return the value */
#define num_digit(digit, base)                          \
  ((base != 16) ? digit - '0' : HEXDIGIT2NUM(digit))

/* no support for 0x prefix nor leading spaces */
static int str_num_base(const char **linep, curl_off_t *nump, curl_off_t max,
                        int base) /* 8, 10 or 16, nothing else */
{
  curl_off_t num = 0;
  DEBUGASSERT(linep && *linep && nump);
  DEBUGASSERT((base == 8) || (base == 10) || (base == 16));
  *nump = 0;
  if(!valid_digit(**linep, base))
    return STRE_NO_NUM;
  do {
    int n = num_digit(**linep, base);
    if(num > ((CURL_OFF_T_MAX - n) / base))
      return STRE_OVERFLOW;
    num = num * base + n;
    if(num > max)
      return STRE_BIG; /** too big */
    (*linep)++;
  } while(valid_digit(**linep, base));
  *nump = num;
  return STRE_OK;
}

/* Get an unsigned decimal number with no leading space or minus. Leading
   zeroes are accepted. return non-zero on error */
int Curl_str_number(const char **linep, curl_off_t *nump, curl_off_t max)
{
  return str_num_base(linep, nump, max, 10);
}

/* Get an unsigned hexadecimal number with no leading space or minus and no
   "0x" support. Leading zeroes are accepted. return non-zero on error */
int Curl_str_hex(const char **linep, curl_off_t *nump, curl_off_t max)
{
  return str_num_base(linep, nump, max, 16);
}

/* Get an unsigned octal number with no leading space or minus and no "0"
   prefix support. Leading zeroes are accepted. return non-zero on error */
int Curl_str_octal(const char **linep, curl_off_t *nump, curl_off_t max)
{
  return str_num_base(linep, nump, max, 8);
}

/* CR or LF
   return non-zero on error */
int Curl_str_newline(const char **linep)
{
  DEBUGASSERT(linep && *linep);
  if(ISNEWLINE(**linep)) {
    (*linep)++;
    return STRE_OK; /* yessir */
  }
  return STRE_NEWLINE;
}

/* case insensitive compare that the parsed string matches the
   given string. Returns non-zero on match. */
int Curl_str_casecompare(struct Curl_str *str, const char *check)
{
  size_t clen = check ? strlen(check) : 0;
  return ((str->len == clen) && strncasecompare(str->str, check, clen));
}

/* Trim off 'num' number of bytes from the beginning (left side) of the
   string. If 'num' is larger than the string, return error. */
int Curl_str_nudge(struct Curl_str *str, size_t num)
{
  if(num <= str->len) {
    str->str += num;
    str->len -= num;
    return STRE_OK;
  }
  return STRE_OVERFLOW;
}
