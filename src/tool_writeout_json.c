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
#include "tool_setup.h"

#include "tool_cfgable.h"
#include "tool_writeout_json.h"
#include "tool_writeout.h"

/* return the length of the valid UTF-8 sequence that starts at 'i', or 0 */
static size_t utf8len(const unsigned char *i, const unsigned char *end)
{
  unsigned char lo = 0x80, hi = 0xbf; /* allowed range of the second byte */
  size_t n, k;

  if(*i >= 0xc2 && *i <= 0xdf)
    n = 2;
  else if(*i >= 0xe0 && *i <= 0xef) {
    n = 3;
    if(*i == 0xe0)
      lo = 0xa0; /* no overlong forms */
    else if(*i == 0xed)
      hi = 0x9f; /* no surrogates */
  }
  else if(*i >= 0xf0 && *i <= 0xf4) {
    n = 4;
    if(*i == 0xf0)
      lo = 0x90; /* no overlong forms */
    else if(*i == 0xf4)
      hi = 0x8f; /* nothing above U+10FFFF */
  }
  else
    return 0;

  if((size_t)(end - i) < n || i[1] < lo || i[1] > hi)
    return 0;
  for(k = 2; k < n; k++)
    if((i[k] & 0xc0) != 0x80)
      return 0;
  return n;
}

/* The longest json form of one character is \u00XX. */
#define JSON_ESC_MAX 6

/* Write the json form of the character at *inp to buf, which must have room
   for JSON_ESC_MAX bytes, and move *inp past it. A valid UTF-8 sequence is
   one character. Return the number of bytes written. */
static size_t jsonescape(const unsigned char **inp, const unsigned char *end,
                         bool lowercase, char *buf)
{
  static const char hex[] = "0123456789abcdef";
  const unsigned char *i = *inp;
  const char *esc = NULL;

  *inp = i + 1;
  switch(*i) {
  case '\\':
    esc = "\\\\";
    break;
  case '\"':
    esc = "\\\"";
    break;
  case '\b':
    esc = "\\b";
    break;
  case '\f':
    esc = "\\f";
    break;
  case '\n':
    esc = "\\n";
    break;
  case '\r':
    esc = "\\r";
    break;
  case '\t':
    esc = "\\t";
    break;
  default:
    break;
  }
  if(esc) {
    memcpy(buf, esc, 2);
    return 2;
  }
  if(*i >= 0x80) {
    size_t n = utf8len(i, end);
    if(n) {
      memcpy(buf, i, n);
      *inp = i + n;
      return n;
    }
    /* not UTF-8, escape the byte as if it was ISO-8859-1 */
  }
  if(*i < 32 || *i >= 0x80) {
    buf[0] = '\\';
    buf[1] = 'u';
    buf[2] = buf[3] = '0';
    buf[4] = hex[*i >> 4];
    buf[5] = hex[*i & 0xf];
    return JSON_ESC_MAX;
  }
  buf[0] = (char)*i;
  if(lowercase && (*i >= 'A' && *i <= 'Z'))
    /* do not use tolower() since that is locale specific */
    buf[0] |= ('a' - 'A');
  return 1;
}

/* provide the given string in dynbuf as a quoted json string, but without the
   outer quotes. The buffer is not inited by this function.

   Return 0 on success, non-zero on error. */
int jsonquoted(const char *in, size_t len, struct dynbuf *out, bool lowercase)
{
  const unsigned char *i = (const unsigned char *)in;
  const unsigned char *in_end = &i[len];
  CURLcode result = CURLE_OK;

  while((i < in_end) && !result) {
    char esc[JSON_ESC_MAX];
    size_t elen = jsonescape(&i, in_end, lowercase, esc);
    result = curlx_dyn_addn(out, esc, elen);
  }
  if(result)
    return (int)result;
  return 0;
}

void jsonWriteString(FILE *stream, const char *in, bool lowercase)
{
  const unsigned char *i = (const unsigned char *)in;
  const unsigned char *in_end = &i[strlen(in)];
  char buf[128];
  size_t len = 0;

  /* escape into a small buffer and write it whenever it gets full: there is
     no size limit to pick and no allocation that can fail and lose the value,
     and an unbuffered stream gets no write call per byte */
  fputc('\"', stream);
  while(i < in_end) {
    len += jsonescape(&i, in_end, lowercase, &buf[len]);
    if(len > sizeof(buf) - JSON_ESC_MAX) {
      fwrite(buf, 1, len, stream);
      len = 0;
    }
  }
  if(len)
    fwrite(buf, 1, len, stream);
  fputc('\"', stream);
}

void ourWriteOutJSON(FILE *stream, const struct writeoutvar mappings[],
                     size_t nentries,
                     struct per_transfer *per, CURLcode per_result)
{
  size_t i;

  fputs("{", stream);

  for(i = 0; i < nentries; i++) {
    if(mappings[i].writefunc &&
       mappings[i].writefunc(stream, &mappings[i], per, per_result, TRUE))
      fputs(",", stream);
  }

  /* The variables are sorted in alphabetical order but as a special case
     curl_version (which is not actually a --write-out variable) is last. */
  curl_mfprintf(stream, "\"curl_version\":");
  jsonWriteString(stream, curl_version(), FALSE);
  curl_mfprintf(stream, "}");
}

void headerJSON(FILE *stream, struct per_transfer *per)
{
  struct curl_header *header;
  struct curl_header *prev = NULL;

  fputc('{', stream);
  while((header = curl_easy_nextheader(per->curl, CURLH_HEADER, -1,
                                       prev)) != NULL) {
    if(header->amount > 1) {
      if(!header->index) {
        /* act on the 0-index entry and pull the others in, then output in a
           JSON list */
        size_t a = header->amount;
        size_t i = 0;
        char *name = header->name;
        if(prev)
          fputs(",\n", stream);
        jsonWriteString(stream, header->name, TRUE);
        fputc(':', stream);
        prev = header;
        fputc('[', stream);
        do {
          jsonWriteString(stream, header->value, FALSE);
          if(++i >= a)
            break;
          fputc(',', stream);
          if(curl_easy_header(per->curl, name, i, CURLH_HEADER, -1, &header))
            break;
        } while(1);
        fputc(']', stream);
      }
    }
    else {
      if(prev)
        fputs(",\n", stream);
      jsonWriteString(stream, header->name, TRUE);
      fputc(':', stream);
      fputc('[', stream);
      jsonWriteString(stream, header->value, FALSE);
      fputc(']', stream);
      prev = header;
    }
  }
  fputs("\n}", stream);
}
