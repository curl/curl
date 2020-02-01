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


#ifdef HAVE_LOCALE_H
#  include <locale.h>
#endif


#define ENABLE_CURLX_PRINTF


/* use our own printf() functions */
#include "curlx.h"
#include "tool_cfgable.h"
#include "tool_writeout_json.h"


typedef enum {
  JSON_NONE,
  JSON_STRING,
  JSON_LONG,
  JSON_DOUBLE,
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
  {"time_total", JSON_DOUBLE, CURLINFO_TOTAL_TIME},
  {"time_namelookup", JSON_DOUBLE, CURLINFO_NAMELOOKUP_TIME},
  {"time_connect", JSON_DOUBLE, CURLINFO_CONNECT_TIME},
  {"time_appconnect", JSON_DOUBLE, CURLINFO_APPCONNECT_TIME},
  {"time_pretransfer", JSON_DOUBLE, CURLINFO_PRETRANSFER_TIME},
  {"time_starttransfer", JSON_DOUBLE, CURLINFO_STARTTRANSFER_TIME},
  {"size_header", JSON_LONG, CURLINFO_HEADER_SIZE},
  {"size_request", JSON_LONG, CURLINFO_REQUEST_SIZE},
  {"size_download", JSON_DOUBLE, CURLINFO_SIZE_DOWNLOAD},
  {"size_upload", JSON_DOUBLE, CURLINFO_SIZE_UPLOAD},
  {"speed_download", JSON_DOUBLE, CURLINFO_SPEED_DOWNLOAD},
  {"speed_upload", JSON_DOUBLE, CURLINFO_SPEED_UPLOAD},
  {"content_type", JSON_STRING, CURLINFO_CONTENT_TYPE},
  {"num_connects", JSON_LONG, CURLINFO_NUM_CONNECTS},
  {"time_redirect", JSON_DOUBLE, CURLINFO_REDIRECT_TIME},
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

static void json_escape(FILE *stream, const char *in)
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


void ourWriteOutJSON(CURL *curl, struct OutStruct *outs, FILE *stream)
{
  char *stringp = NULL;
  long longinfo;
  double doubleinfo;
  int i;

#ifdef HAVE_SETLOCALE
  /* to produce valid JSON: disable any locale conversion of numbers */
  const char *current_locale = setlocale(LC_NUMERIC, NULL);
  setlocale(LC_NUMERIC, "POSIX");
#endif

  fputs("{", stream);
  for(i = 0; mappings[i].key != NULL; i++) {
    const char *k = mappings[i].key;
    CURLINFO cinfo = mappings[i].cinfo;
    switch(mappings[i].type) {
    case JSON_STRING:
      if((CURLE_OK == curl_easy_getinfo(curl, cinfo, &stringp)) && stringp) {
        fprintf(stream, "\"%s\":\"", k);
        json_escape(stream, stringp);
        fprintf(stream, "\",");
      }
      break;
    case JSON_LONG:
      longinfo = 0;
      if(CURLE_OK == curl_easy_getinfo(curl, cinfo, &longinfo)) {
        fprintf(stream, "\"%s\":%ld,", k, longinfo);
      }
      break;
    case JSON_DOUBLE:
      if(CURLE_OK == curl_easy_getinfo(curl, cinfo, &doubleinfo)) {
        fprintf(stream, "\"%s\":%.6f,", k, doubleinfo);
      }
      break;
    case JSON_FILENAME:
      if(outs->filename) {
        fprintf(stream, "\"%s\":\"", k);
        json_escape(stream, outs->filename);
        fprintf(stream, "\",");

      }
      else {
        fprintf(stream, "\"%s\":null,", k);
      }
      break;
    case JSON_VERSION:
      if(CURLE_OK == curl_easy_getinfo(curl, cinfo, &longinfo) &&
         (longinfo >= 0) &&
         (longinfo < (long)(sizeof(http_version)/sizeof(char *)))) {
        fprintf(stream, "\"%s\":\"%s\",", k, http_version[longinfo]);
      }
      break;
    default:
      break;
    }
  }
  fprintf(stream, "\"curl_version\":\"%s\"}", curl_version());

#ifdef HAVE_SETLOCALE
  setlocale(LC_NUMERIC, current_locale);
#endif
}
