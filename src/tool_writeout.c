/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_writeout.h"
#include "tool_writeout_json.h"

#include "memdebug.h" /* keep this as LAST include */

static const struct writeoutvar variables[] = {
  {"content_type", VAR_CONTENT_TYPE, 0, CURLINFO_CONTENT_TYPE, JSON_STRING},
  {"filename_effective", VAR_EFFECTIVE_FILENAME, 0, 0, JSON_FILENAME},
  {"exitcode", VAR_EXITCODE, 0, 0, JSON_LONG},
  {"errormsg", VAR_ERRORMSG, 0, 0, JSON_STRING},
  {"ftp_entry_path", VAR_FTP_ENTRY_PATH, 0, CURLINFO_FTP_ENTRY_PATH,
   JSON_STRING},
  {"http_code", VAR_HTTP_CODE, 0, CURLINFO_RESPONSE_CODE, JSON_LONG},
  {"http_connect", VAR_HTTP_CODE_PROXY, 0, CURLINFO_HTTP_CONNECTCODE,
   JSON_LONG},
  {"http_version", VAR_HTTP_VERSION, 0, CURLINFO_HTTP_VERSION, JSON_VERSION},
  {"json", VAR_JSON, 1, 0, JSON_NONE},
  {"local_ip", VAR_LOCAL_IP, 0, CURLINFO_LOCAL_IP, JSON_STRING},
  {"local_port", VAR_LOCAL_PORT, 0, CURLINFO_LOCAL_PORT, JSON_LONG},
  {"method", VAR_EFFECTIVE_METHOD, 0, CURLINFO_EFFECTIVE_METHOD, JSON_STRING},
  {"num_connects", VAR_NUM_CONNECTS, 0, CURLINFO_NUM_CONNECTS, JSON_LONG},
  {"num_headers", VAR_NUM_HEADERS, 0, 0, JSON_LONG},
  {"num_redirects", VAR_REDIRECT_COUNT, 0, CURLINFO_REDIRECT_COUNT, JSON_LONG},
  {"onerror", VAR_ONERROR, 1, 0, JSON_NONE},
  {"proxy_ssl_verify_result", VAR_PROXY_SSL_VERIFY_RESULT, 0,
   CURLINFO_PROXY_SSL_VERIFYRESULT, JSON_LONG},
  {"redirect_url", VAR_REDIRECT_URL, 0, CURLINFO_REDIRECT_URL, JSON_STRING},
  {"remote_ip", VAR_PRIMARY_IP, 0, CURLINFO_PRIMARY_IP, JSON_STRING},
  {"remote_port", VAR_PRIMARY_PORT, 0, CURLINFO_PRIMARY_PORT, JSON_LONG},
  {"response_code", VAR_HTTP_CODE, 0, CURLINFO_RESPONSE_CODE, JSON_LONG},
  {"scheme", VAR_SCHEME, 0, CURLINFO_SCHEME, JSON_STRING},
  {"size_download", VAR_SIZE_DOWNLOAD, 0, CURLINFO_SIZE_DOWNLOAD_T,
   JSON_OFFSET},
  {"size_header", VAR_HEADER_SIZE, 0, CURLINFO_HEADER_SIZE, JSON_LONG},
  {"size_request", VAR_REQUEST_SIZE, 0, CURLINFO_REQUEST_SIZE, JSON_LONG},
  {"size_upload", VAR_SIZE_UPLOAD, 0, CURLINFO_SIZE_UPLOAD_T, JSON_OFFSET},
  {"speed_download", VAR_SPEED_DOWNLOAD, 0, CURLINFO_SPEED_DOWNLOAD_T,
   JSON_OFFSET},
  {"speed_upload", VAR_SPEED_UPLOAD, 0, CURLINFO_SPEED_UPLOAD_T, JSON_OFFSET},
  {"ssl_verify_result", VAR_SSL_VERIFY_RESULT, 0, CURLINFO_SSL_VERIFYRESULT,
   JSON_LONG},
  {"stderr", VAR_STDERR, 1, 0, JSON_NONE},
  {"stdout", VAR_STDOUT, 1, 0, JSON_NONE},
  {"time_appconnect", VAR_APPCONNECT_TIME, 0, CURLINFO_APPCONNECT_TIME_T,
   JSON_TIME},
  {"time_connect", VAR_CONNECT_TIME, 0, CURLINFO_CONNECT_TIME_T, JSON_TIME},
  {"time_namelookup", VAR_NAMELOOKUP_TIME, 0, CURLINFO_NAMELOOKUP_TIME_T,
   JSON_TIME},
  {"time_pretransfer", VAR_PRETRANSFER_TIME, 0, CURLINFO_PRETRANSFER_TIME_T,
   JSON_TIME},
  {"time_redirect", VAR_REDIRECT_TIME, 0, CURLINFO_REDIRECT_TIME_T, JSON_TIME},
  {"time_starttransfer", VAR_STARTTRANSFER_TIME, 0,
   CURLINFO_STARTTRANSFER_TIME_T, JSON_TIME},
  {"time_total", VAR_TOTAL_TIME, 0, CURLINFO_TOTAL_TIME_T, JSON_TIME},
  {"url", VAR_INPUT_URL, 0, 0, JSON_STRING},
  {"url_effective", VAR_EFFECTIVE_URL, 0, CURLINFO_EFFECTIVE_URL, JSON_STRING},
  {"urlnum", VAR_URLNUM, 0, 0, JSON_LONG},
  {NULL, VAR_NONE, 1, 0, JSON_NONE}
};

static void us2sec(FILE *stream, curl_off_t us)
{
  curl_off_t secs = us / 1000000;
  us %= 1000000;
  fprintf(stream, "%" CURL_FORMAT_CURL_OFF_TU ".%06" CURL_FORMAT_CURL_OFF_TU,
          secs, us);
}

void ourWriteOut(CURL *curl, struct per_transfer *per, const char *writeinfo,
                 CURLcode result)
{
  FILE *stream = stdout;
  const char *ptr = writeinfo;
  char *stringp = NULL;
  long longinfo;
  curl_off_t offinfo;
  bool done = FALSE;

  while(ptr && *ptr && !done) {
    if('%' == *ptr && ptr[1]) {
      if('%' == ptr[1]) {
        /* an escaped %-letter */
        fputc('%', stream);
        ptr += 2;
      }
      else {
        /* this is meant as a variable to output */
        char *end;
        if('{' == ptr[1]) {
          char keepit;
          int i;
          bool match = FALSE;
          end = strchr(ptr, '}');
          ptr += 2; /* pass the % and the { */
          if(!end) {
            fputs("%{", stream);
            continue;
          }
          keepit = *end;
          *end = 0; /* null-terminate */
          for(i = 0; variables[i].name; i++) {
            if(curl_strequal(ptr, variables[i].name)) {
              match = TRUE;
              switch(variables[i].id) {
              case VAR_ONERROR:
                if(result == CURLE_OK)
                  /* this isn't error so skip the rest */
                  done = TRUE;
                break;
              case VAR_EXITCODE:
                fprintf(stream, "%d", (int)result);
                break;
              case VAR_ERRORMSG:
                if(result)
                  fputs(per->errorbuffer[0] ? per->errorbuffer :
                        curl_easy_strerror(result), stream);
                break;
              case VAR_INPUT_URL:
                if(per->this_url)
                  fputs(per->this_url, stream);
                break;
              case VAR_URLNUM:
                fprintf(stream, "%u", per->urlnum);
                break;
              case VAR_EFFECTIVE_URL:
                if((CURLE_OK ==
                    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &stringp))
                   && stringp)
                  fputs(stringp, stream);
                break;
              case VAR_EFFECTIVE_METHOD:
                if((CURLE_OK == curl_easy_getinfo(curl,
                                                  CURLINFO_EFFECTIVE_METHOD,
                                                  &stringp))
                   && stringp)
                  fputs(stringp, stream);
                break;
              case VAR_HTTP_CODE:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &longinfo))
                  fprintf(stream, "%03ld", longinfo);
                break;
              case VAR_NUM_HEADERS:
                fprintf(stream, "%ld", per->num_headers);
                break;
              case VAR_HTTP_CODE_PROXY:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_HTTP_CONNECTCODE,
                                     &longinfo))
                  fprintf(stream, "%03ld", longinfo);
                break;
              case VAR_HEADER_SIZE:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_HEADER_SIZE, &longinfo))
                  fprintf(stream, "%ld", longinfo);
                break;
              case VAR_REQUEST_SIZE:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_REQUEST_SIZE, &longinfo))
                  fprintf(stream, "%ld", longinfo);
                break;
              case VAR_NUM_CONNECTS:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_NUM_CONNECTS, &longinfo))
                  fprintf(stream, "%ld", longinfo);
                break;
              case VAR_REDIRECT_COUNT:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &longinfo))
                  fprintf(stream, "%ld", longinfo);
                break;
              case VAR_REDIRECT_TIME:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_REDIRECT_TIME_T, &offinfo))
                  us2sec(stream, offinfo);
                break;
              case VAR_TOTAL_TIME:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &offinfo))
                  us2sec(stream, offinfo);
                break;
              case VAR_NAMELOOKUP_TIME:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME_T,
                                     &offinfo))
                  us2sec(stream, offinfo);
                break;
              case VAR_CONNECT_TIME:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME_T, &offinfo))
                  us2sec(stream, offinfo);
                break;
              case VAR_APPCONNECT_TIME:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_APPCONNECT_TIME_T,
                                     &offinfo))
                  us2sec(stream, offinfo);
                break;
              case VAR_PRETRANSFER_TIME:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_PRETRANSFER_TIME_T,
                                     &offinfo))
                  us2sec(stream, offinfo);
                break;
              case VAR_STARTTRANSFER_TIME:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME_T,
                                     &offinfo))
                  us2sec(stream, offinfo);
                break;
              case VAR_SIZE_UPLOAD:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD_T, &offinfo))
                  fprintf(stream, "%" CURL_FORMAT_CURL_OFF_TU, offinfo);
                break;
              case VAR_SIZE_DOWNLOAD:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T,
                                     &offinfo))
                  fprintf(stream, "%" CURL_FORMAT_CURL_OFF_TU, offinfo);
                break;
              case VAR_SPEED_DOWNLOAD:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD_T,
                                     &offinfo))
                  fprintf(stream, "%" CURL_FORMAT_CURL_OFF_TU, offinfo);
                break;
              case VAR_SPEED_UPLOAD:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD_T, &offinfo))
                  fprintf(stream, "%" CURL_FORMAT_CURL_OFF_TU, offinfo);
                break;
              case VAR_CONTENT_TYPE:
                if((CURLE_OK ==
                    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &stringp))
                   && stringp)
                  fputs(stringp, stream);
                break;
              case VAR_FTP_ENTRY_PATH:
                if((CURLE_OK ==
                    curl_easy_getinfo(curl, CURLINFO_FTP_ENTRY_PATH, &stringp))
                   && stringp)
                  fputs(stringp, stream);
                break;
              case VAR_REDIRECT_URL:
                if((CURLE_OK ==
                    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &stringp))
                   && stringp)
                  fputs(stringp, stream);
                break;
              case VAR_SSL_VERIFY_RESULT:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT,
                                     &longinfo))
                  fprintf(stream, "%ld", longinfo);
                break;
              case VAR_PROXY_SSL_VERIFY_RESULT:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_PROXY_SSL_VERIFYRESULT,
                                     &longinfo))
                  fprintf(stream, "%ld", longinfo);
                break;
              case VAR_EFFECTIVE_FILENAME:
                if(per->outs.filename)
                  fputs(per->outs.filename, stream);
                break;
              case VAR_PRIMARY_IP:
                if((CURLE_OK == curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP,
                                                  &stringp)) && stringp)
                  fputs(stringp, stream);
                break;
              case VAR_PRIMARY_PORT:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_PRIMARY_PORT,
                                     &longinfo))
                  fprintf(stream, "%ld", longinfo);
                break;
              case VAR_LOCAL_IP:
                if((CURLE_OK == curl_easy_getinfo(curl, CURLINFO_LOCAL_IP,
                                                  &stringp)) && stringp)
                  fputs(stringp, stream);
                break;
              case VAR_LOCAL_PORT:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_LOCAL_PORT,
                                     &longinfo))
                  fprintf(stream, "%ld", longinfo);
                break;
              case VAR_HTTP_VERSION:
                if(CURLE_OK ==
                   curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION,
                                     &longinfo)) {
                  const char *version = "0";
                  switch(longinfo) {
                  case CURL_HTTP_VERSION_1_0:
                    version = "1.0";
                    break;
                  case CURL_HTTP_VERSION_1_1:
                    version = "1.1";
                    break;
                  case CURL_HTTP_VERSION_2_0:
                    version = "2";
                    break;
                  case CURL_HTTP_VERSION_3:
                    version = "3";
                    break;
                  }

                  fprintf(stream, version);
                }
                break;
              case VAR_SCHEME:
                if((CURLE_OK == curl_easy_getinfo(curl, CURLINFO_SCHEME,
                                                  &stringp)) && stringp)
                  fputs(stringp, stream);
                break;
              case VAR_STDOUT:
                stream = stdout;
                break;
              case VAR_STDERR:
                stream = stderr;
                break;
              case VAR_JSON:
                ourWriteOutJSON(variables, curl, per, stream);
              default:
                break;
              }
              break;
            }
          }
          if(!match) {
            fprintf(stderr, "curl: unknown --write-out variable: '%s'\n", ptr);
          }
          ptr = end + 1; /* pass the end */
          *end = keepit;
        }
        else {
          /* illegal syntax, then just output the characters that are used */
          fputc('%', stream);
          fputc(ptr[1], stream);
          ptr += 2;
        }
      }
    }
    else if('\\' == *ptr && ptr[1]) {
      switch(ptr[1]) {
      case 'r':
        fputc('\r', stream);
        break;
      case 'n':
        fputc('\n', stream);
        break;
      case 't':
        fputc('\t', stream);
        break;
      default:
        /* unknown, just output this */
        fputc(*ptr, stream);
        fputc(ptr[1], stream);
        break;
      }
      ptr += 2;
    }
    else {
      fputc(*ptr, stream);
      ptr++;
    }
  }
}
