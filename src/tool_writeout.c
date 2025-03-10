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

#include "curlx.h"
#include "tool_cfgable.h"
#include "tool_writeout.h"
#include "tool_writeout_json.h"
#include "dynbuf.h"

#include "memdebug.h" /* keep this as LAST include */

static int writeTime(FILE *stream, const struct writeoutvar *wovar,
                     struct per_transfer *per, CURLcode per_result,
                     bool use_json);

static int writeString(FILE *stream, const struct writeoutvar *wovar,
                       struct per_transfer *per, CURLcode per_result,
                       bool use_json);

static int writeLong(FILE *stream, const struct writeoutvar *wovar,
                     struct per_transfer *per, CURLcode per_result,
                     bool use_json);

static int writeOffset(FILE *stream, const struct writeoutvar *wovar,
                       struct per_transfer *per, CURLcode per_result,
                       bool use_json);

struct httpmap {
  const char *str;
  int num;
};

static const struct httpmap http_version[] = {
  { "0",   CURL_HTTP_VERSION_NONE},
  { "1",   CURL_HTTP_VERSION_1_0},
  { "1.1", CURL_HTTP_VERSION_1_1},
  { "2",   CURL_HTTP_VERSION_2},
  { "3",   CURL_HTTP_VERSION_3},
  { NULL, 0} /* end of list */
};

/* The designated write function should be the same as the CURLINFO return type
   with exceptions special cased in the respective function. For example,
   http_version uses CURLINFO_HTTP_VERSION which returns the version as a long,
   however it is output as a string and therefore is handled in writeString.

   Yes: "http_version": "1.1"
   No:  "http_version": 1.1

   Variable names MUST be in alphabetical order.
   */
static const struct writeoutvar variables[] = {
  {"certs", VAR_CERT, CURLINFO_NONE, writeString},
  {"conn_id", VAR_CONN_ID, CURLINFO_CONN_ID, writeOffset},
  {"content_type", VAR_CONTENT_TYPE, CURLINFO_CONTENT_TYPE, writeString},
  {"errormsg", VAR_ERRORMSG, CURLINFO_NONE, writeString},
  {"exitcode", VAR_EXITCODE, CURLINFO_NONE, writeLong},
  {"filename_effective", VAR_EFFECTIVE_FILENAME, CURLINFO_NONE, writeString},
  {"ftp_entry_path", VAR_FTP_ENTRY_PATH, CURLINFO_FTP_ENTRY_PATH, writeString},
  {"header_json", VAR_HEADER_JSON, CURLINFO_NONE, NULL},
  {"http_code", VAR_HTTP_CODE, CURLINFO_RESPONSE_CODE, writeLong},
  {"http_connect", VAR_HTTP_CODE_PROXY, CURLINFO_HTTP_CONNECTCODE, writeLong},
  {"http_version", VAR_HTTP_VERSION, CURLINFO_HTTP_VERSION, writeString},
  {"json", VAR_JSON, CURLINFO_NONE, NULL},
  {"local_ip", VAR_LOCAL_IP, CURLINFO_LOCAL_IP, writeString},
  {"local_port", VAR_LOCAL_PORT, CURLINFO_LOCAL_PORT, writeLong},
  {"method", VAR_EFFECTIVE_METHOD, CURLINFO_EFFECTIVE_METHOD, writeString},
  {"num_certs", VAR_NUM_CERTS, CURLINFO_NONE, writeLong},
  {"num_connects", VAR_NUM_CONNECTS, CURLINFO_NUM_CONNECTS, writeLong},
  {"num_headers", VAR_NUM_HEADERS, CURLINFO_NONE, writeLong},
  {"num_redirects", VAR_REDIRECT_COUNT, CURLINFO_REDIRECT_COUNT, writeLong},
  {"num_retries", VAR_NUM_RETRY, CURLINFO_NONE, writeLong},
  {"onerror", VAR_ONERROR, CURLINFO_NONE, NULL},
  {"proxy_ssl_verify_result", VAR_PROXY_SSL_VERIFY_RESULT,
   CURLINFO_PROXY_SSL_VERIFYRESULT, writeLong},
  {"proxy_used", VAR_PROXY_USED, CURLINFO_USED_PROXY, writeLong},
  {"redirect_url", VAR_REDIRECT_URL, CURLINFO_REDIRECT_URL, writeString},
  {"referer", VAR_REFERER, CURLINFO_REFERER, writeString},
  {"remote_ip", VAR_PRIMARY_IP, CURLINFO_PRIMARY_IP, writeString},
  {"remote_port", VAR_PRIMARY_PORT, CURLINFO_PRIMARY_PORT, writeLong},
  {"response_code", VAR_HTTP_CODE, CURLINFO_RESPONSE_CODE, writeLong},
  {"scheme", VAR_SCHEME, CURLINFO_SCHEME, writeString},
  {"size_download", VAR_SIZE_DOWNLOAD, CURLINFO_SIZE_DOWNLOAD_T, writeOffset},
  {"size_header", VAR_HEADER_SIZE, CURLINFO_HEADER_SIZE, writeLong},
  {"size_request", VAR_REQUEST_SIZE, CURLINFO_REQUEST_SIZE, writeLong},
  {"size_upload", VAR_SIZE_UPLOAD, CURLINFO_SIZE_UPLOAD_T, writeOffset},
  {"speed_download", VAR_SPEED_DOWNLOAD, CURLINFO_SPEED_DOWNLOAD_T,
   writeOffset},
  {"speed_upload", VAR_SPEED_UPLOAD, CURLINFO_SPEED_UPLOAD_T, writeOffset},
  {"ssl_verify_result", VAR_SSL_VERIFY_RESULT, CURLINFO_SSL_VERIFYRESULT,
   writeLong},
  {"stderr", VAR_STDERR, CURLINFO_NONE, NULL},
  {"stdout", VAR_STDOUT, CURLINFO_NONE, NULL},
  {"time_appconnect", VAR_APPCONNECT_TIME, CURLINFO_APPCONNECT_TIME_T,
   writeTime},
  {"time_connect", VAR_CONNECT_TIME, CURLINFO_CONNECT_TIME_T, writeTime},
  {"time_namelookup", VAR_NAMELOOKUP_TIME, CURLINFO_NAMELOOKUP_TIME_T,
   writeTime},
  {"time_posttransfer", VAR_POSTTRANSFER_TIME, CURLINFO_POSTTRANSFER_TIME_T,
   writeTime},
  {"time_pretransfer", VAR_PRETRANSFER_TIME, CURLINFO_PRETRANSFER_TIME_T,
   writeTime},
  {"time_queue", VAR_QUEUE_TIME, CURLINFO_QUEUE_TIME_T, writeTime},
  {"time_redirect", VAR_REDIRECT_TIME, CURLINFO_REDIRECT_TIME_T, writeTime},
  {"time_starttransfer", VAR_STARTTRANSFER_TIME, CURLINFO_STARTTRANSFER_TIME_T,
   writeTime},
  {"time_total", VAR_TOTAL_TIME, CURLINFO_TOTAL_TIME_T, writeTime},
  {"tls_earlydata", VAR_TLS_EARLYDATA_SENT, CURLINFO_EARLYDATA_SENT_T,
   writeOffset},
  {"url", VAR_INPUT_URL, CURLINFO_NONE, writeString},
  {"url.fragment", VAR_INPUT_URLFRAGMENT, CURLINFO_NONE, writeString},
  {"url.host", VAR_INPUT_URLHOST, CURLINFO_NONE, writeString},
  {"url.options", VAR_INPUT_URLOPTIONS, CURLINFO_NONE, writeString},
  {"url.password", VAR_INPUT_URLPASSWORD, CURLINFO_NONE, writeString},
  {"url.path", VAR_INPUT_URLPATH, CURLINFO_NONE, writeString},
  {"url.port", VAR_INPUT_URLPORT, CURLINFO_NONE, writeString},
  {"url.query", VAR_INPUT_URLQUERY, CURLINFO_NONE, writeString},
  {"url.scheme", VAR_INPUT_URLSCHEME, CURLINFO_NONE, writeString},
  {"url.user", VAR_INPUT_URLUSER, CURLINFO_NONE, writeString},
  {"url.zoneid", VAR_INPUT_URLZONEID, CURLINFO_NONE, writeString},
  {"url_effective", VAR_EFFECTIVE_URL, CURLINFO_EFFECTIVE_URL, writeString},
  {"urle.fragment", VAR_INPUT_URLEFRAGMENT, CURLINFO_NONE, writeString},
  {"urle.host", VAR_INPUT_URLEHOST, CURLINFO_NONE, writeString},
  {"urle.options", VAR_INPUT_URLEOPTIONS, CURLINFO_NONE, writeString},
  {"urle.password", VAR_INPUT_URLEPASSWORD, CURLINFO_NONE, writeString},
  {"urle.path", VAR_INPUT_URLEPATH, CURLINFO_NONE, writeString},
  {"urle.port", VAR_INPUT_URLEPORT, CURLINFO_NONE, writeString},
  {"urle.query", VAR_INPUT_URLEQUERY, CURLINFO_NONE, writeString},
  {"urle.scheme", VAR_INPUT_URLESCHEME, CURLINFO_NONE, writeString},
  {"urle.user", VAR_INPUT_URLEUSER, CURLINFO_NONE, writeString},
  {"urle.zoneid", VAR_INPUT_URLEZONEID, CURLINFO_NONE, writeString},
  {"urlnum", VAR_URLNUM, CURLINFO_NONE, writeLong},
  {"xfer_id", VAR_EASY_ID, CURLINFO_XFER_ID, writeOffset}
};

static int writeTime(FILE *stream, const struct writeoutvar *wovar,
                     struct per_transfer *per, CURLcode per_result,
                     bool use_json)
{
  bool valid = false;
  curl_off_t us = 0;

  (void)per;
  (void)per_result;
  DEBUGASSERT(wovar->writefunc == writeTime);

  if(wovar->ci) {
    if(!curl_easy_getinfo(per->curl, wovar->ci, &us))
      valid = true;
  }
  else {
    DEBUGASSERT(0);
  }

  if(valid) {
    curl_off_t secs = us / 1000000;
    us %= 1000000;

    if(use_json)
      fprintf(stream, "\"%s\":", wovar->name);

    fprintf(stream, "%" CURL_FORMAT_CURL_OFF_TU
            ".%06" CURL_FORMAT_CURL_OFF_TU, secs, us);
  }
  else {
    if(use_json)
      fprintf(stream, "\"%s\":null", wovar->name);
  }

  return 1; /* return 1 if anything was written */
}

static int urlpart(struct per_transfer *per, writeoutid vid,
                   const char **contentp)
{
  CURLU *uh = curl_url();
  int rc = 0;
  if(uh) {
    CURLUPart cpart = CURLUPART_HOST;
    char *part = NULL;
    const char *url = NULL;

    if(vid >= VAR_INPUT_URLESCHEME) {
      if(curl_easy_getinfo(per->curl, CURLINFO_EFFECTIVE_URL, &url))
        rc = 5;
    }
    else
      url = per->url;

    if(!rc) {
      switch(vid) {
      case VAR_INPUT_URLSCHEME:
      case VAR_INPUT_URLESCHEME:
        cpart = CURLUPART_SCHEME;
        break;
      case VAR_INPUT_URLUSER:
      case VAR_INPUT_URLEUSER:
        cpart = CURLUPART_USER;
        break;
      case VAR_INPUT_URLPASSWORD:
      case VAR_INPUT_URLEPASSWORD:
        cpart = CURLUPART_PASSWORD;
        break;
      case VAR_INPUT_URLOPTIONS:
      case VAR_INPUT_URLEOPTIONS:
        cpart = CURLUPART_OPTIONS;
        break;
      case VAR_INPUT_URLHOST:
      case VAR_INPUT_URLEHOST:
        cpart = CURLUPART_HOST;
        break;
      case VAR_INPUT_URLPORT:
      case VAR_INPUT_URLEPORT:
        cpart = CURLUPART_PORT;
        break;
      case VAR_INPUT_URLPATH:
      case VAR_INPUT_URLEPATH:
        cpart = CURLUPART_PATH;
        break;
      case VAR_INPUT_URLQUERY:
      case VAR_INPUT_URLEQUERY:
        cpart = CURLUPART_QUERY;
        break;
      case VAR_INPUT_URLFRAGMENT:
      case VAR_INPUT_URLEFRAGMENT:
        cpart = CURLUPART_FRAGMENT;
        break;
      case VAR_INPUT_URLZONEID:
      case VAR_INPUT_URLEZONEID:
        cpart = CURLUPART_ZONEID;
        break;
      default:
        /* not implemented */
        rc = 4;
        break;
      }
    }
    if(!rc && curl_url_set(uh, CURLUPART_URL, url,
                           CURLU_GUESS_SCHEME|CURLU_NON_SUPPORT_SCHEME))
      rc = 2;

    if(!rc && curl_url_get(uh, cpart, &part, CURLU_DEFAULT_PORT))
      rc = 3;

    if(!rc && part)
      *contentp = part;
    curl_url_cleanup(uh);
  }
  else
    return 1;
  return rc;
}

static void certinfo(struct per_transfer *per)
{
  if(!per->certinfo) {
    struct curl_certinfo *certinfo;
    CURLcode res = curl_easy_getinfo(per->curl, CURLINFO_CERTINFO, &certinfo);
    per->certinfo = (!res && certinfo) ? certinfo : NULL;
  }
}

static int writeString(FILE *stream, const struct writeoutvar *wovar,
                       struct per_transfer *per, CURLcode per_result,
                       bool use_json)
{
  bool valid = false;
  const char *strinfo = NULL;
  const char *freestr = NULL;
  struct dynbuf buf;
  curlx_dyn_init(&buf, 256*1024);

  DEBUGASSERT(wovar->writefunc == writeString);

  if(wovar->ci) {
    if(wovar->ci == CURLINFO_HTTP_VERSION) {
      long version = 0;
      if(!curl_easy_getinfo(per->curl, CURLINFO_HTTP_VERSION, &version)) {
        const struct httpmap *m = &http_version[0];
        while(m->str) {
          if(m->num == version) {
            strinfo = m->str;
            valid = true;
            break;
          }
          m++;
        }
      }
    }
    else {
      if(!curl_easy_getinfo(per->curl, wovar->ci, &strinfo) && strinfo)
        valid = true;
    }
  }
  else {
    switch(wovar->id) {
    case VAR_CERT:
      certinfo(per);
      if(per->certinfo) {
        int i;
        bool error = FALSE;
        for(i = 0; (i < per->certinfo->num_of_certs) && !error; i++) {
          struct curl_slist *slist;

          for(slist = per->certinfo->certinfo[i]; slist; slist = slist->next) {
            size_t len;
            if(curl_strnequal(slist->data, "cert:", 5)) {
              if(curlx_dyn_add(&buf, &slist->data[5])) {
                error = TRUE;
                break;
              }
            }
            else {
              if(curlx_dyn_add(&buf, slist->data)) {
                error = TRUE;
                break;
              }
            }
            len = curlx_dyn_len(&buf);
            if(len) {
              char *ptr = curlx_dyn_ptr(&buf);
              if(ptr[len -1] != '\n') {
                /* add a newline to make things look better */
                if(curlx_dyn_addn(&buf, "\n", 1)) {
                  error = TRUE;
                  break;
                }
              }
            }
          }
        }
        if(!error) {
          strinfo = curlx_dyn_ptr(&buf);
          if(!strinfo)
            /* maybe not a TLS protocol */
            strinfo = "";
          valid = true;
        }
      }
      else
        strinfo = ""; /* no cert info */
      break;
    case VAR_ERRORMSG:
      if(per_result) {
        strinfo = (per->errorbuffer && per->errorbuffer[0]) ?
          per->errorbuffer : curl_easy_strerror(per_result);
        valid = true;
      }
      break;
    case VAR_EFFECTIVE_FILENAME:
      if(per->outs.filename) {
        strinfo = per->outs.filename;
        valid = true;
      }
      break;
    case VAR_INPUT_URL:
      if(per->url) {
        strinfo = per->url;
        valid = true;
      }
      break;
    case VAR_INPUT_URLSCHEME:
    case VAR_INPUT_URLUSER:
    case VAR_INPUT_URLPASSWORD:
    case VAR_INPUT_URLOPTIONS:
    case VAR_INPUT_URLHOST:
    case VAR_INPUT_URLPORT:
    case VAR_INPUT_URLPATH:
    case VAR_INPUT_URLQUERY:
    case VAR_INPUT_URLFRAGMENT:
    case VAR_INPUT_URLZONEID:
    case VAR_INPUT_URLESCHEME:
    case VAR_INPUT_URLEUSER:
    case VAR_INPUT_URLEPASSWORD:
    case VAR_INPUT_URLEOPTIONS:
    case VAR_INPUT_URLEHOST:
    case VAR_INPUT_URLEPORT:
    case VAR_INPUT_URLEPATH:
    case VAR_INPUT_URLEQUERY:
    case VAR_INPUT_URLEFRAGMENT:
    case VAR_INPUT_URLEZONEID:
      if(per->url) {
        if(!urlpart(per, wovar->id, &strinfo)) {
          freestr = strinfo;
          valid = true;
        }
      }
      break;
    default:
      DEBUGASSERT(0);
      break;
    }
  }

  DEBUGASSERT(!valid || strinfo);
  if(valid && strinfo) {
    if(use_json) {
      fprintf(stream, "\"%s\":", wovar->name);
      jsonWriteString(stream, strinfo, FALSE);
    }
    else
      fputs(strinfo, stream);
  }
  else {
    if(use_json)
      fprintf(stream, "\"%s\":null", wovar->name);
  }
  curl_free((char *)CURL_UNCONST(freestr));

  curlx_dyn_free(&buf);
  return 1; /* return 1 if anything was written */
}

static int writeLong(FILE *stream, const struct writeoutvar *wovar,
                     struct per_transfer *per, CURLcode per_result,
                     bool use_json)
{
  bool valid = false;
  long longinfo = 0;

  DEBUGASSERT(wovar->writefunc == writeLong);

  if(wovar->ci) {
    if(!curl_easy_getinfo(per->curl, wovar->ci, &longinfo))
      valid = true;
  }
  else {
    switch(wovar->id) {
    case VAR_NUM_RETRY:
      longinfo = per->num_retries;
      valid = true;
      break;
    case VAR_NUM_CERTS:
      certinfo(per);
      longinfo = per->certinfo ? per->certinfo->num_of_certs : 0;
      valid = true;
      break;
    case VAR_NUM_HEADERS:
      longinfo = per->num_headers;
      valid = true;
      break;
    case VAR_EXITCODE:
      longinfo = (long)per_result;
      valid = true;
      break;
    case VAR_URLNUM:
      if(per->urlnum <= INT_MAX) {
        longinfo = (long)per->urlnum;
        valid = true;
      }
      break;
    default:
      DEBUGASSERT(0);
      break;
    }
  }

  if(valid) {
    if(use_json)
      fprintf(stream, "\"%s\":%ld", wovar->name, longinfo);
    else {
      if(wovar->id == VAR_HTTP_CODE || wovar->id == VAR_HTTP_CODE_PROXY)
        fprintf(stream, "%03ld", longinfo);
      else
        fprintf(stream, "%ld", longinfo);
    }
  }
  else {
    if(use_json)
      fprintf(stream, "\"%s\":null", wovar->name);
  }

  return 1; /* return 1 if anything was written */
}

static int writeOffset(FILE *stream, const struct writeoutvar *wovar,
                       struct per_transfer *per, CURLcode per_result,
                       bool use_json)
{
  bool valid = false;
  curl_off_t offinfo = 0;

  (void)per;
  (void)per_result;
  DEBUGASSERT(wovar->writefunc == writeOffset);

  if(wovar->ci) {
    if(!curl_easy_getinfo(per->curl, wovar->ci, &offinfo))
      valid = true;
  }
  else {
    DEBUGASSERT(0);
  }

  if(valid) {
    if(use_json)
      fprintf(stream, "\"%s\":", wovar->name);

    fprintf(stream, "%" CURL_FORMAT_CURL_OFF_T, offinfo);
  }
  else {
    if(use_json)
      fprintf(stream, "\"%s\":null", wovar->name);
  }

  return 1; /* return 1 if anything was written */
}

static int
matchvar(const void *m1, const void *m2)
{
  const struct writeoutvar *v1 = m1;
  const struct writeoutvar *v2 = m2;

  return strcmp(v1->name, v2->name);
}

#define MAX_WRITEOUT_NAME_LENGTH 24

void ourWriteOut(struct OperationConfig *config, struct per_transfer *per,
                 CURLcode per_result)
{
  FILE *stream = stdout;
  const char *writeinfo = config->writeout;
  const char *ptr = writeinfo;
  bool done = FALSE;
  bool fclose_stream = FALSE;
  struct dynbuf name;

  if(!writeinfo)
    return;

  curlx_dyn_init(&name, MAX_WRITEOUT_NAME_LENGTH);
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
        size_t vlen;
        if('{' == ptr[1]) {
          struct writeoutvar *wv = NULL;
          struct writeoutvar find = { 0 };
          end = strchr(ptr, '}');
          ptr += 2; /* pass the % and the { */
          if(!end) {
            fputs("%{", stream);
            continue;
          }
          vlen = end - ptr;

          curlx_dyn_reset(&name);
          if(!curlx_dyn_addn(&name, ptr, vlen)) {
            find.name = curlx_dyn_ptr(&name);
            wv = bsearch(&find,
                         variables, CURL_ARRAYSIZE(variables),
                         sizeof(variables[0]), matchvar);
          }
          if(wv) {
            switch(wv->id) {
            case VAR_ONERROR:
              if(per_result == CURLE_OK)
                /* this is not error so skip the rest */
                done = TRUE;
              break;
            case VAR_STDOUT:
              if(fclose_stream)
                fclose(stream);
              fclose_stream = FALSE;
              stream = stdout;
              break;
            case VAR_STDERR:
              if(fclose_stream)
                fclose(stream);
              fclose_stream = FALSE;
              stream = tool_stderr;
              break;
            case VAR_JSON:
              ourWriteOutJSON(stream, variables,
                              CURL_ARRAYSIZE(variables),
                              per, per_result);
              break;
            case VAR_HEADER_JSON:
              headerJSON(stream, per);
              break;
            default:
              (void)wv->writefunc(stream, wv, per, per_result, false);
              break;
            }
          }
          else {
            fprintf(tool_stderr,
                    "curl: unknown --write-out variable: '%.*s'\n",
                    (int)vlen, ptr);
          }
          ptr = end + 1; /* pass the end */
        }
        else if(!strncmp("header{", &ptr[1], 7)) {
          ptr += 8;
          end = strchr(ptr, '}');
          if(end) {
            char hname[256]; /* holds the longest header field name */
            struct curl_header *header;
            vlen = end - ptr;
            if(vlen < sizeof(hname)) {
              memcpy(hname, ptr, vlen);
              hname[vlen] = 0;
              if(CURLHE_OK == curl_easy_header(per->curl, hname, 0,
                                               CURLH_HEADER, -1, &header))
                fputs(header->value, stream);
            }
            ptr = end + 1;
          }
          else
            fputs("%header{", stream);
        }
        else if(!strncmp("output{", &ptr[1], 7)) {
          bool append = FALSE;
          ptr += 8;
          if((ptr[0] == '>') && (ptr[1] == '>')) {
            append = TRUE;
            ptr += 2;
          }
          end = strchr(ptr, '}');
          if(end) {
            char fname[512]; /* holds the longest filename */
            size_t flen = end - ptr;
            if(flen < sizeof(fname)) {
              FILE *stream2;
              memcpy(fname, ptr, flen);
              fname[flen] = 0;
              stream2 = fopen(fname, append ? FOPEN_APPENDTEXT :
                              FOPEN_WRITETEXT);
              if(stream2) {
                /* only change if the open worked */
                if(fclose_stream)
                  fclose(stream);
                stream = stream2;
                fclose_stream = TRUE;
              }
            }
            ptr = end + 1;
          }
          else
            fputs("%output{", stream);
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
  if(fclose_stream)
    fclose(stream);
  curlx_dyn_free(&name);
}
