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

#define ENABLE_CURLX_PRINTF

/* use our own printf() functions */
#include "curlx.h"
#include "tool_cfgable.h"
#include "tool_writeout_json.h"
#include "tool_writeout.h"

#define MAX_JSON_STRING 100000

/* provide the given string in dynbuf as a quoted json string, but without the
   outer quotes. The buffer is not inited by this function.

   Return 0 on success, non-zero on error.
*/
int jsonquoted(const char *in, size_t len,
               struct curlx_dynbuf *out, bool lowercase)
{
  const unsigned char *i = (unsigned char *)in;
  const unsigned char *in_end = &i[len];
  CURLcode result = CURLE_OK;

  for(; (i < in_end) && !result; i++) {
    switch(*i) {
    case '\\':
      result = curlx_dyn_addn(out, "\\\\", 2);
      break;
    case '\"':
      result = curlx_dyn_addn(out, "\\\"", 2);
      break;
    case '\b':
      result = curlx_dyn_addn(out, "\\b", 2);
      break;
    case '\f':
      result = curlx_dyn_addn(out, "\\f", 2);
      break;
    case '\n':
      result = curlx_dyn_addn(out, "\\n", 2);
      break;
    case '\r':
      result = curlx_dyn_addn(out, "\\r", 2);
      break;
    case '\t':
      result = curlx_dyn_addn(out, "\\t", 2);
      break;
    default:
      if(*i < 32)
        result = curlx_dyn_addf(out, "\\u%04x", *i);
      else {
        char o = (char)*i;
        if(lowercase && (o >= 'A' && o <= 'Z'))
          /* do not use tolower() since that is locale specific */
          o |= ('a' - 'A');
        result = curlx_dyn_addn(out, &o, 1);
      }
      break;
    }
  }
  if(result)
    return (int)result;
  return 0;
}

void jsonWriteString(FILE *stream, const char *in, bool lowercase)
{
  struct curlx_dynbuf out;
  curlx_dyn_init(&out, MAX_JSON_STRING);

  if(!jsonquoted(in, strlen(in), &out, lowercase)) {
    fputc('\"', stream);
    if(curlx_dyn_len(&out))
      fputs(curlx_dyn_ptr(&out), stream);
    fputc('\"', stream);
  }
  curlx_dyn_free(&out);
}

void ourWriteOutJSON(FILE *stream, const struct writeoutvar mappings[],
                     size_t nentries,
                     struct per_transfer *per, CURLcode per_result)
{
  size_t i;

  fputs("{", stream);

  for(i = 0; i < nentries; i++) {
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
          if(curl_easy_header(per->curl, name, i, CURLH_HEADER,
                              -1, &header))
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
