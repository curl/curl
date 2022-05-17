/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#define ENABLE_CURLX_PRINTF

/* use our own printf() functions */
#include "curlx.h"
#include "tool_cfgable.h"
#include "tool_writeout_json.h"
#include "tool_writeout.h"

void jsonWriteString(FILE *stream, const char *in, bool lowercase)
{
  const char *i = in;
  const char *in_end = in + strlen(in);

  fputc('\"', stream);
  for(; i < in_end; i++) {
    switch(*i) {
    case '\\':
      fputs("\\\\", stream);
      break;
    case '\"':
      fputs("\\\"", stream);
      break;
    case '\b':
      fputs("\\b", stream);
      break;
    case '\f':
      fputs("\\f", stream);
      break;
    case '\n':
      fputs("\\n", stream);
      break;
    case '\r':
      fputs("\\r", stream);
      break;
    case '\t':
      fputs("\\t", stream);
      break;
    default:
      if (*i < 32) {
        fprintf(stream, "u%04x", *i);
      }
      else {
        char out = *i;
        if(lowercase && (out >= 'A' && out <= 'Z'))
          /* do not use tolower() since that's locale specific */
          out |= ('a' - 'A');
        fputc(out, stream);
      }
      break;
    }
  }
  fputc('\"', stream);
}

void ourWriteOutJSON(FILE *stream, const struct writeoutvar mappings[],
                     struct per_transfer *per, CURLcode per_result)
{
  int i;

  fputs("{", stream);

  for(i = 0; mappings[i].name != NULL; i++) {
    if(mappings[i].writefunc &&
       mappings[i].writefunc(stream, &mappings[i], per, per_result, true))
      fputs(",", stream);
  }

  /* The variables are sorted in alphabetical order but as a special case
     curl_version (which is not actually a --write-out variable) is last. */
  fprintf(stream, "\"curl_version\":");
  jsonWriteString(stream, curl_version(), FALSE);
  fprintf(stream, "}");
}

#ifdef _MSC_VER
/* warning C4706: assignment within conditional expression */
#pragma warning(disable:4706)
#endif

void headerJSON(FILE *stream, struct per_transfer *per)
{
  struct curl_header *header;
  struct curl_header *prev = NULL;

  fputc('{', stream);
  while((header = curl_easy_nextheader(per->curl, CURLH_HEADER, -1,
                                       prev))) {
    if(prev)
      fputs(",\n", stream);
    jsonWriteString(stream, header->name, TRUE);
    fputc(':', stream);
    prev = header;
    if(header->amount > 1) {
      if(!header->index) {
        /* act on the 0-index entry and pull the others in, then output in a
           JSON list */
        size_t a = header->amount;
        size_t i = 0;
        char *name = header->name;
        fputc('[', stream);
        do {
          jsonWriteString(stream, header->value, FALSE);
          if(++i >= a)
            break;
          fputc(',', stream);
          if(curl_easy_header(per->curl, name, i, CURLH_HEADER,
                              -1, &header))
            break;
        } while(1);
      }
      fputc(']', stream);
    }
    else {
      fputc('[', stream);
      jsonWriteString(stream, header->value, FALSE);
      fputc(']', stream);
    }
  }
  fputs("\n}", stream);
}
