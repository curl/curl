/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "tool_setup.h"

#define ENABLE_CURLX_PRINTF

/* use our own printf() functions */
#include "curlx.h"
#include "tool_cfgable.h"
#include "tool_writeout_json.h"
#include "tool_writeout.h"


static const char *http_version[] = {
  "0",   /* CURL_HTTP_VERSION_NONE */
  "1",   /* CURL_HTTP_VERSION_1_0 */
  "1.1", /* CURL_HTTP_VERSION_1_1 */
  "2",   /* CURL_HTTP_VERSION_2 */
  "3"    /* CURL_HTTP_VERSION_3 */
};

static void jsonEscape(FILE *stream, const char *in)
{
  const char *i = in;
  const char *in_end = in + strlen(in);

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
        fputc(*i, stream);
      }
      break;
    };
  }
}

static int writeTime(FILE *str, CURL *curl, const char *key, CURLINFO ci)
{
  curl_off_t val = 0;
  if(CURLE_OK == curl_easy_getinfo(curl, ci, &val)) {
    curl_off_t s = val / 1000000l;
    curl_off_t ms = val % 1000000l;
    fprintf(str, "\"%s\":%" CURL_FORMAT_CURL_OFF_T
            ".%06" CURL_FORMAT_CURL_OFF_T, key, s, ms);
    return 1;
  }
  return 0;
}

static int writeString(FILE *str, CURL *curl, const char *key, CURLINFO ci)
{
  char *valp = NULL;
  if((CURLE_OK == curl_easy_getinfo(curl, ci, &valp)) && valp) {
    fprintf(str, "\"%s\":\"", key);
    jsonEscape(str, valp);
    fprintf(str, "\"");
    return 1;
  }
  return 0;
}

static int writeLong(FILE *str, CURL *curl, const char *key, CURLINFO ci,
                     struct per_transfer *per, const struct writeoutvar *wovar)
{
  if(wovar->id == VAR_NUM_HEADERS) {
    fprintf(str, "\"%s\":%ld", key, per->num_headers);
    return 1;
  }
  else {
    long val = 0;
    if(CURLE_OK == curl_easy_getinfo(curl, ci, &val)) {
      fprintf(str, "\"%s\":%ld", key, val);
      return 1;
    }
  }
  return 0;
}

static int writeOffset(FILE *str, CURL *curl, const char *key, CURLINFO ci)
{
  curl_off_t val = 0;
  if(CURLE_OK == curl_easy_getinfo(curl, ci, &val)) {
    fprintf(str, "\"%s\":%" CURL_FORMAT_CURL_OFF_T, key, val);
    return 1;
  }
  return 0;
}

static int writeFilename(FILE *str, const char *key, const char *filename)
{
  if(filename) {
    fprintf(str, "\"%s\":\"", key);
    jsonEscape(str, filename);
    fprintf(str, "\"");
  }
  else {
    fprintf(str, "\"%s\":null", key);
  }
  return 1;
}

static int writeVersion(FILE *str, CURL *curl, const char *key, CURLINFO ci)
{
  long version = 0;
  if(CURLE_OK == curl_easy_getinfo(curl, ci, &version) &&
     (version >= 0) &&
     (version < (long)(sizeof(http_version)/sizeof(char *)))) {
    fprintf(str, "\"%s\":\"%s\"", key, http_version[version]);
    return 1;
  }
  return 0;
}

void ourWriteOutJSON(const struct writeoutvar mappings[], CURL *curl,
                     struct per_transfer *per, FILE *stream)
{
  int i;

  fputs("{", stream);
  for(i = 0; mappings[i].name != NULL; i++) {
    const struct writeoutvar *wovar = &mappings[i];
    const char *name = mappings[i].name;
    CURLINFO cinfo = mappings[i].cinfo;
    int ok = 0;

    if(mappings[i].is_ctrl == 1) {
      continue;
    }

    switch(mappings[i].jsontype) {
    case JSON_STRING:
      ok = writeString(stream, curl, name, cinfo);
      break;
    case JSON_LONG:
      ok = writeLong(stream, curl, name, cinfo, per, wovar);
      break;
    case JSON_OFFSET:
      ok = writeOffset(stream, curl, name, cinfo);
      break;
    case JSON_TIME:
      ok = writeTime(stream, curl, name, cinfo);
      break;
    case JSON_FILENAME:
      ok = writeFilename(stream, name, per->outs.filename);
      break;
    case JSON_VERSION:
      ok = writeVersion(stream, curl, name, cinfo);
      break;
    default:
      break;
    }

    if(ok) {
      fputs(",", stream);
    }
  }

  fprintf(stream, "\"curl_version\":\"%s\"}", curl_version());
}
