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

/* The longest escape sequence is \u00XX. */
#define JSON_ESC_MAX 6

/* Write the json form of the input byte to buf, which must have room for
   JSON_ESC_MAX bytes. Return the number of bytes written. */
static size_t jsonescape(unsigned char c, bool lowercase, char *buf)
{
  static const char hex[] = "0123456789abcdef";
  const char *esc = NULL;

  switch(c) {
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
  if(c < 32) {
    memcpy(buf, "\\u00", 4);
    buf[4] = hex[c >> 4];
    buf[5] = hex[c & 0xf];
    return JSON_ESC_MAX;
  }
  if(lowercase && (c >= 'A' && c <= 'Z'))
    /* do not use tolower() since that is locale specific */
    c |= ('a' - 'A');
  buf[0] = (char)c;
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

  for(; (i < in_end) && !result; i++) {
    char esc[JSON_ESC_MAX];
    size_t elen = jsonescape(*i, lowercase, esc);
    result = curlx_dyn_addn(out, esc, elen);
  }
  if(result)
    return (int)result;
  return 0;
}

void jsonWriteString(FILE *stream, const char *in, bool lowercase)
{
  const unsigned char *i = (const unsigned char *)in;

  /* escape straight to the stream: there is no buffer that could grow too
     large or fail to allocate and cost the caller the value */
  fputc('\"', stream);
  for(; *i; i++) {
    char esc[JSON_ESC_MAX];
    size_t elen = jsonescape(*i, lowercase, esc);
    fwrite(esc, 1, elen, stream);
  }
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
