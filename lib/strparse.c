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

/* Get a word until the first DELIM or end of string. At least one byte long.
   return non-zero on error */
int Curl_str_until(char **linep, struct Curl_str *out,
                   const size_t max, char delim)
{
  char *s = *linep;
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
int Curl_str_word(char **linep, struct Curl_str *out,
                  const size_t max)
{
  return Curl_str_until(linep, out, max, ' ');
}


/* Get a "quoted" word. No escaping possible.
   return non-zero on error */
int Curl_str_quotedword(char **linep, struct Curl_str *out,
                        const size_t max)
{
  char *s = *linep;
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
int Curl_str_single(char **linep, char byte)
{
  DEBUGASSERT(linep && *linep);
  if(**linep != byte)
    return STRE_BYTE;
  (*linep)++; /* move over it */
  return STRE_OK;
}

/* Advance over a single space.
   return non-zero on error */
int Curl_str_singlespace(char **linep)
{
  return Curl_str_single(linep, ' ');
}

/* Get an unsigned number. Leading zeroes are accepted.
   return non-zero on error */
int Curl_str_number(char **linep, size_t *nump, size_t max)
{
  size_t num = 0;
  DEBUGASSERT(linep && *linep && nump);
  *nump = 0;
  while(ISDIGIT(**linep)) {
    int n = **linep - '0';
    if(num > ((SIZE_T_MAX - n) / 10))
      return STRE_OVERFLOW;
    num = num * 10 + n;
    if(num > max)
      return STRE_BIG; /** too big */
    (*linep)++;
  }
  *nump = num;
  return STRE_OK;
}

/* CR or LF
   return non-zero on error */
int Curl_str_newline(char **linep)
{
  DEBUGASSERT(linep && *linep);
  if(ISNEWLINE(**linep)) {
    (*linep)++;
    return STRE_OK; /* yessir */
  }
  return STRE_NEWLINE;
}
