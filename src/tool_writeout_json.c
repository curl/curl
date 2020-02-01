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
 * are also available at https://curl.haxx.se/docs/copyright.html.
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


typedef enum {
  JSON_NONE,
  JSON_STRING,
  JSON_LONG,
  JSON_TIME,
  JSON_VERSION,
  JSON_FILENAME
} jsontype;

struct mapping {
  const char *key;
  jsontype type;
  CURLINFO cinfo;
};

static const struct mapping mappings[]={
  {"url_effective", JSON_STRING, CURLINFO_EFFECTIVE_URL},
  {"http_code", JSON_LONG, CURLINFO_RESPONSE_CODE},
  {"response_code", JSON_LONG, CURLINFO_RESPONSE_CODE},
  {"http_connect", JSON_LONG, CURLINFO_HTTP_CONNECTCODE},
  {"time_total", JSON_TIME, CURLINFO_TOTAL_TIME_T},
  {"time_namelookup", JSON_TIME, CURLINFO_NAMELOOKUP_TIME_T},
  {"time_connect", JSON_TIME, CURLINFO_CONNECT_TIME_T},
  {"time_appconnect", JSON_TIME, CURLINFO_APPCONNECT_TIME_T},
  {"time_pretransfer", JSON_TIME, CURLINFO_PRETRANSFER_TIME_T},
  {"time_starttransfer", JSON_TIME, CURLINFO_STARTTRANSFER_TIME_T},
  {"size_header", JSON_LONG, CURLINFO_HEADER_SIZE},
  {"size_request", JSON_LONG, CURLINFO_REQUEST_SIZE},
  {"size_download", JSON_LONG, CURLINFO_SIZE_DOWNLOAD_T},
  {"size_upload", JSON_LONG, CURLINFO_SIZE_UPLOAD_T},
  {"speed_download", JSON_TIME, CURLINFO_SPEED_DOWNLOAD_T},
  {"speed_upload", JSON_TIME, CURLINFO_SPEED_UPLOAD_T},
  {"content_type", JSON_STRING, CURLINFO_CONTENT_TYPE},
  {"num_connects", JSON_LONG, CURLINFO_NUM_CONNECTS},
  {"time_redirect", JSON_TIME, CURLINFO_REDIRECT_TIME_T},
  {"num_redirects", JSON_LONG, CURLINFO_REDIRECT_COUNT},
  {"ftp_entry_path", JSON_STRING, CURLINFO_FTP_ENTRY_PATH},
  {"redirect_url", JSON_STRING, CURLINFO_REDIRECT_URL},
  {"ssl_verify_result", JSON_LONG, CURLINFO_SSL_VERIFYRESULT},
  {"proxy_ssl_verify_result", JSON_LONG, CURLINFO_PROXY_SSL_VERIFYRESULT},
  {"filename_effective", JSON_FILENAME, CURLINFO_NONE},
  {"remote_ip", JSON_STRING, CURLINFO_PRIMARY_IP},
  {"remote_port", JSON_LONG, CURLINFO_PRIMARY_PORT},
  {"local_ip", JSON_STRING, CURLINFO_LOCAL_IP},
  {"local_port", JSON_LONG, CURLINFO_LOCAL_PORT},
  {"http_version", JSON_VERSION, CURLINFO_HTTP_VERSION},
  {"scheme", JSON_STRING, CURLINFO_SCHEME},
  {NULL, JSON_NONE, CURLINFO_NONE}
};

static const char *http_version[] = {
  "0",   /* CURL_HTTP_VERSION_NONE */
  "1",   /* CURL_HTTP_VERSION_1_0 */
  "1.1", /* CURL_HTTP_VERSION_1_1 */
  "2"    /* CURL_HTTP_VERSION_2 */
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
    fprintf(str, "\"%s\":%ld.%06ld", key, s, ms);
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

static int writeLong(FILE *str, CURL *curl, const char *key, CURLINFO ci)
{
  curl_off_t val = 0;
  if(CURLE_OK == curl_easy_getinfo(curl, ci, &val)) {
    fprintf(str, "\"%s\":%ld", key, val);
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

void ourWriteOutJSON(CURL *curl, struct OutStruct *outs, FILE *stream)
{
  int i;

  fputs("{", stream);
  for(i = 0; mappings[i].key != NULL; i++) {
    const char *key = mappings[i].key;
    CURLINFO cinfo = mappings[i].cinfo;
    int ok = 0;
    switch(mappings[i].type) {
    case JSON_STRING:
      ok = writeString(stream, curl, key, cinfo);
      break;
    case JSON_LONG:
      ok = writeLong(stream, curl, key, cinfo);
      break;
    case JSON_TIME:
      ok = writeTime(stream, curl, key, cinfo);
      break;
    case JSON_FILENAME:
      ok = writeFilename(stream, key, outs->filename);
      break;
    case JSON_VERSION:
      ok = writeVersion(stream, curl, key, cinfo);
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
