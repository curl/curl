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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "tool_setup.h"

#include "fetchx.h"
#include "tool_cfgable.h"
#include "tool_writeout.h"
#include "tool_writeout_json.h"
#include "dynbuf.h"

#include "memdebug.h" /* keep this as LAST include */

static int writeTime(FILE *stream, const struct writeoutvar *wovar,
                     struct per_transfer *per, FETCHcode per_result,
                     bool use_json);

static int writeString(FILE *stream, const struct writeoutvar *wovar,
                       struct per_transfer *per, FETCHcode per_result,
                       bool use_json);

static int writeLong(FILE *stream, const struct writeoutvar *wovar,
                     struct per_transfer *per, FETCHcode per_result,
                     bool use_json);

static int writeOffset(FILE *stream, const struct writeoutvar *wovar,
                       struct per_transfer *per, FETCHcode per_result,
                       bool use_json);

struct httpmap
{
  const char *str;
  int num;
};

static const struct httpmap http_version[] = {
    {"0", FETCH_HTTP_VERSION_NONE},
    {"1", FETCH_HTTP_VERSION_1_0},
    {"1.1", FETCH_HTTP_VERSION_1_1},
    {"2", FETCH_HTTP_VERSION_2},
    {"3", FETCH_HTTP_VERSION_3},
    {NULL, 0} /* end of list */
};

/* The designated write function should be the same as the FETCHINFO return type
   with exceptions special cased in the respective function. For example,
   http_version uses FETCHINFO_HTTP_VERSION which returns the version as a long,
   however it is output as a string and therefore is handled in writeString.

   Yes: "http_version": "1.1"
   No:  "http_version": 1.1

   Variable names MUST be in alphabetical order.
   */
static const struct writeoutvar variables[] = {
    {"certs", VAR_CERT, FETCHINFO_NONE, writeString},
    {"conn_id", VAR_CONN_ID, FETCHINFO_CONN_ID, writeOffset},
    {"content_type", VAR_CONTENT_TYPE, FETCHINFO_CONTENT_TYPE, writeString},
    {"errormsg", VAR_ERRORMSG, FETCHINFO_NONE, writeString},
    {"exitcode", VAR_EXITCODE, FETCHINFO_NONE, writeLong},
    {"filename_effective", VAR_EFFECTIVE_FILENAME, FETCHINFO_NONE, writeString},
    {"ftp_entry_path", VAR_FTP_ENTRY_PATH, FETCHINFO_FTP_ENTRY_PATH, writeString},
    {"header_json", VAR_HEADER_JSON, FETCHINFO_NONE, NULL},
    {"http_code", VAR_HTTP_CODE, FETCHINFO_RESPONSE_CODE, writeLong},
    {"http_connect", VAR_HTTP_CODE_PROXY, FETCHINFO_HTTP_CONNECTCODE, writeLong},
    {"http_version", VAR_HTTP_VERSION, FETCHINFO_HTTP_VERSION, writeString},
    {"json", VAR_JSON, FETCHINFO_NONE, NULL},
    {"local_ip", VAR_LOCAL_IP, FETCHINFO_LOCAL_IP, writeString},
    {"local_port", VAR_LOCAL_PORT, FETCHINFO_LOCAL_PORT, writeLong},
    {"method", VAR_EFFECTIVE_METHOD, FETCHINFO_EFFECTIVE_METHOD, writeString},
    {"num_certs", VAR_NUM_CERTS, FETCHINFO_NONE, writeLong},
    {"num_connects", VAR_NUM_CONNECTS, FETCHINFO_NUM_CONNECTS, writeLong},
    {"num_headers", VAR_NUM_HEADERS, FETCHINFO_NONE, writeLong},
    {"num_redirects", VAR_REDIRECT_COUNT, FETCHINFO_REDIRECT_COUNT, writeLong},
    {"num_retries", VAR_NUM_RETRY, FETCHINFO_NONE, writeLong},
    {"onerror", VAR_ONERROR, FETCHINFO_NONE, NULL},
    {"proxy_ssl_verify_result", VAR_PROXY_SSL_VERIFY_RESULT,
     FETCHINFO_PROXY_SSL_VERIFYRESULT, writeLong},
    {"proxy_used", VAR_PROXY_USED, FETCHINFO_USED_PROXY, writeLong},
    {"redirect_url", VAR_REDIRECT_URL, FETCHINFO_REDIRECT_URL, writeString},
    {"referer", VAR_REFERER, FETCHINFO_REFERER, writeString},
    {"remote_ip", VAR_PRIMARY_IP, FETCHINFO_PRIMARY_IP, writeString},
    {"remote_port", VAR_PRIMARY_PORT, FETCHINFO_PRIMARY_PORT, writeLong},
    {"response_code", VAR_HTTP_CODE, FETCHINFO_RESPONSE_CODE, writeLong},
    {"scheme", VAR_SCHEME, FETCHINFO_SCHEME, writeString},
    {"size_download", VAR_SIZE_DOWNLOAD, FETCHINFO_SIZE_DOWNLOAD_T, writeOffset},
    {"size_header", VAR_HEADER_SIZE, FETCHINFO_HEADER_SIZE, writeLong},
    {"size_request", VAR_REQUEST_SIZE, FETCHINFO_REQUEST_SIZE, writeLong},
    {"size_upload", VAR_SIZE_UPLOAD, FETCHINFO_SIZE_UPLOAD_T, writeOffset},
    {"speed_download", VAR_SPEED_DOWNLOAD, FETCHINFO_SPEED_DOWNLOAD_T,
     writeOffset},
    {"speed_upload", VAR_SPEED_UPLOAD, FETCHINFO_SPEED_UPLOAD_T, writeOffset},
    {"ssl_verify_result", VAR_SSL_VERIFY_RESULT, FETCHINFO_SSL_VERIFYRESULT,
     writeLong},
    {"stderr", VAR_STDERR, FETCHINFO_NONE, NULL},
    {"stdout", VAR_STDOUT, FETCHINFO_NONE, NULL},
    {"time_appconnect", VAR_APPCONNECT_TIME, FETCHINFO_APPCONNECT_TIME_T,
     writeTime},
    {"time_connect", VAR_CONNECT_TIME, FETCHINFO_CONNECT_TIME_T, writeTime},
    {"time_namelookup", VAR_NAMELOOKUP_TIME, FETCHINFO_NAMELOOKUP_TIME_T,
     writeTime},
    {"time_posttransfer", VAR_POSTTRANSFER_TIME, FETCHINFO_POSTTRANSFER_TIME_T,
     writeTime},
    {"time_pretransfer", VAR_PRETRANSFER_TIME, FETCHINFO_PRETRANSFER_TIME_T,
     writeTime},
    {"time_queue", VAR_QUEUE_TIME, FETCHINFO_QUEUE_TIME_T, writeTime},
    {"time_redirect", VAR_REDIRECT_TIME, FETCHINFO_REDIRECT_TIME_T, writeTime},
    {"time_starttransfer", VAR_STARTTRANSFER_TIME, FETCHINFO_STARTTRANSFER_TIME_T,
     writeTime},
    {"time_total", VAR_TOTAL_TIME, FETCHINFO_TOTAL_TIME_T, writeTime},
    {"url", VAR_INPUT_URL, FETCHINFO_NONE, writeString},
    {"url.fragment", VAR_INPUT_URLFRAGMENT, FETCHINFO_NONE, writeString},
    {"url.host", VAR_INPUT_URLHOST, FETCHINFO_NONE, writeString},
    {"url.options", VAR_INPUT_URLOPTIONS, FETCHINFO_NONE, writeString},
    {"url.password", VAR_INPUT_URLPASSWORD, FETCHINFO_NONE, writeString},
    {"url.path", VAR_INPUT_URLPATH, FETCHINFO_NONE, writeString},
    {"url.port", VAR_INPUT_URLPORT, FETCHINFO_NONE, writeString},
    {"url.query", VAR_INPUT_URLQUERY, FETCHINFO_NONE, writeString},
    {"url.scheme", VAR_INPUT_URLSCHEME, FETCHINFO_NONE, writeString},
    {"url.user", VAR_INPUT_URLUSER, FETCHINFO_NONE, writeString},
    {"url.zoneid", VAR_INPUT_URLZONEID, FETCHINFO_NONE, writeString},
    {"url_effective", VAR_EFFECTIVE_URL, FETCHINFO_EFFECTIVE_URL, writeString},
    {"urle.fragment", VAR_INPUT_URLEFRAGMENT, FETCHINFO_NONE, writeString},
    {"urle.host", VAR_INPUT_URLEHOST, FETCHINFO_NONE, writeString},
    {"urle.options", VAR_INPUT_URLEOPTIONS, FETCHINFO_NONE, writeString},
    {"urle.password", VAR_INPUT_URLEPASSWORD, FETCHINFO_NONE, writeString},
    {"urle.path", VAR_INPUT_URLEPATH, FETCHINFO_NONE, writeString},
    {"urle.port", VAR_INPUT_URLEPORT, FETCHINFO_NONE, writeString},
    {"urle.query", VAR_INPUT_URLEQUERY, FETCHINFO_NONE, writeString},
    {"urle.scheme", VAR_INPUT_URLESCHEME, FETCHINFO_NONE, writeString},
    {"urle.user", VAR_INPUT_URLEUSER, FETCHINFO_NONE, writeString},
    {"urle.zoneid", VAR_INPUT_URLEZONEID, FETCHINFO_NONE, writeString},
    {"urlnum", VAR_URLNUM, FETCHINFO_NONE, writeLong},
    {"xfer_id", VAR_EASY_ID, FETCHINFO_XFER_ID, writeOffset}};

static int writeTime(FILE *stream, const struct writeoutvar *wovar,
                     struct per_transfer *per, FETCHcode per_result,
                     bool use_json)
{
  bool valid = false;
  fetch_off_t us = 0;

  (void)per;
  (void)per_result;
  DEBUGASSERT(wovar->writefunc == writeTime);

  if (wovar->ci)
  {
    if (!fetch_easy_getinfo(per->fetch, wovar->ci, &us))
      valid = true;
  }
  else
  {
    DEBUGASSERT(0);
  }

  if (valid)
  {
    fetch_off_t secs = us / 1000000;
    us %= 1000000;

    if (use_json)
      fprintf(stream, "\"%s\":", wovar->name);

    fprintf(stream, "%" FETCH_FORMAT_FETCH_OFF_TU ".%06" FETCH_FORMAT_FETCH_OFF_TU, secs, us);
  }
  else
  {
    if (use_json)
      fprintf(stream, "\"%s\":null", wovar->name);
  }

  return 1; /* return 1 if anything was written */
}

static int urlpart(struct per_transfer *per, writeoutid vid,
                   const char **contentp)
{
  FETCHU *uh = fetch_url();
  int rc = 0;
  if (uh)
  {
    FETCHUPart cpart = FETCHUPART_HOST;
    char *part = NULL;
    const char *url = NULL;

    if (vid >= VAR_INPUT_URLESCHEME)
    {
      if (fetch_easy_getinfo(per->fetch, FETCHINFO_EFFECTIVE_URL, &url))
        rc = 5;
    }
    else
      url = per->url;

    if (!rc)
    {
      switch (vid)
      {
      case VAR_INPUT_URLSCHEME:
      case VAR_INPUT_URLESCHEME:
        cpart = FETCHUPART_SCHEME;
        break;
      case VAR_INPUT_URLUSER:
      case VAR_INPUT_URLEUSER:
        cpart = FETCHUPART_USER;
        break;
      case VAR_INPUT_URLPASSWORD:
      case VAR_INPUT_URLEPASSWORD:
        cpart = FETCHUPART_PASSWORD;
        break;
      case VAR_INPUT_URLOPTIONS:
      case VAR_INPUT_URLEOPTIONS:
        cpart = FETCHUPART_OPTIONS;
        break;
      case VAR_INPUT_URLHOST:
      case VAR_INPUT_URLEHOST:
        cpart = FETCHUPART_HOST;
        break;
      case VAR_INPUT_URLPORT:
      case VAR_INPUT_URLEPORT:
        cpart = FETCHUPART_PORT;
        break;
      case VAR_INPUT_URLPATH:
      case VAR_INPUT_URLEPATH:
        cpart = FETCHUPART_PATH;
        break;
      case VAR_INPUT_URLQUERY:
      case VAR_INPUT_URLEQUERY:
        cpart = FETCHUPART_QUERY;
        break;
      case VAR_INPUT_URLFRAGMENT:
      case VAR_INPUT_URLEFRAGMENT:
        cpart = FETCHUPART_FRAGMENT;
        break;
      case VAR_INPUT_URLZONEID:
      case VAR_INPUT_URLEZONEID:
        cpart = FETCHUPART_ZONEID;
        break;
      default:
        /* not implemented */
        rc = 4;
        break;
      }
    }
    if (!rc && fetch_url_set(uh, FETCHUPART_URL, url,
                             FETCHU_GUESS_SCHEME | FETCHU_NON_SUPPORT_SCHEME))
      rc = 2;

    if (!rc && fetch_url_get(uh, cpart, &part, FETCHU_DEFAULT_PORT))
      rc = 3;

    if (!rc && part)
      *contentp = part;
    fetch_url_cleanup(uh);
  }
  else
    return 1;
  return rc;
}

static void certinfo(struct per_transfer *per)
{
  if (!per->certinfo)
  {
    struct fetch_certinfo *certinfo;
    FETCHcode res = fetch_easy_getinfo(per->fetch, FETCHINFO_CERTINFO, &certinfo);
    per->certinfo = (!res && certinfo) ? certinfo : NULL;
  }
}

static int writeString(FILE *stream, const struct writeoutvar *wovar,
                       struct per_transfer *per, FETCHcode per_result,
                       bool use_json)
{
  bool valid = false;
  const char *strinfo = NULL;
  const char *freestr = NULL;
  struct dynbuf buf;
  fetchx_dyn_init(&buf, 256 * 1024);

  DEBUGASSERT(wovar->writefunc == writeString);

  if (wovar->ci)
  {
    if (wovar->ci == FETCHINFO_HTTP_VERSION)
    {
      long version = 0;
      if (!fetch_easy_getinfo(per->fetch, FETCHINFO_HTTP_VERSION, &version))
      {
        const struct httpmap *m = &http_version[0];
        while (m->str)
        {
          if (m->num == version)
          {
            strinfo = m->str;
            valid = true;
            break;
          }
          m++;
        }
      }
    }
    else
    {
      if (!fetch_easy_getinfo(per->fetch, wovar->ci, &strinfo) && strinfo)
        valid = true;
    }
  }
  else
  {
    switch (wovar->id)
    {
    case VAR_CERT:
      certinfo(per);
      if (per->certinfo)
      {
        int i;
        bool error = FALSE;
        for (i = 0; (i < per->certinfo->num_of_certs) && !error; i++)
        {
          struct fetch_slist *slist;

          for (slist = per->certinfo->certinfo[i]; slist; slist = slist->next)
          {
            size_t len;
            if (fetch_strnequal(slist->data, "cert:", 5))
            {
              if (fetchx_dyn_add(&buf, &slist->data[5]))
              {
                error = TRUE;
                break;
              }
            }
            else
            {
              if (fetchx_dyn_add(&buf, slist->data))
              {
                error = TRUE;
                break;
              }
            }
            len = fetchx_dyn_len(&buf);
            if (len)
            {
              char *ptr = fetchx_dyn_ptr(&buf);
              if (ptr[len - 1] != '\n')
              {
                /* add a newline to make things look better */
                if (fetchx_dyn_addn(&buf, "\n", 1))
                {
                  error = TRUE;
                  break;
                }
              }
            }
          }
        }
        if (!error)
        {
          strinfo = fetchx_dyn_ptr(&buf);
          if (!strinfo)
            /* maybe not a TLS protocol */
            strinfo = "";
          valid = true;
        }
      }
      else
        strinfo = ""; /* no cert info */
      break;
    case VAR_ERRORMSG:
      if (per_result)
      {
        strinfo = (per->errorbuffer && per->errorbuffer[0]) ? per->errorbuffer : fetch_easy_strerror(per_result);
        valid = true;
      }
      break;
    case VAR_EFFECTIVE_FILENAME:
      if (per->outs.filename)
      {
        strinfo = per->outs.filename;
        valid = true;
      }
      break;
    case VAR_INPUT_URL:
      if (per->url)
      {
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
      if (per->url)
      {
        if (!urlpart(per, wovar->id, &strinfo))
        {
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
  if (valid && strinfo)
  {
    if (use_json)
    {
      fprintf(stream, "\"%s\":", wovar->name);
      jsonWriteString(stream, strinfo, FALSE);
    }
    else
      fputs(strinfo, stream);
  }
  else
  {
    if (use_json)
      fprintf(stream, "\"%s\":null", wovar->name);
  }
  fetch_free((char *)freestr);

  fetchx_dyn_free(&buf);
  return 1; /* return 1 if anything was written */
}

static int writeLong(FILE *stream, const struct writeoutvar *wovar,
                     struct per_transfer *per, FETCHcode per_result,
                     bool use_json)
{
  bool valid = false;
  long longinfo = 0;

  DEBUGASSERT(wovar->writefunc == writeLong);

  if (wovar->ci)
  {
    if (!fetch_easy_getinfo(per->fetch, wovar->ci, &longinfo))
      valid = true;
  }
  else
  {
    switch (wovar->id)
    {
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
      if (per->urlnum <= INT_MAX)
      {
        longinfo = (long)per->urlnum;
        valid = true;
      }
      break;
    default:
      DEBUGASSERT(0);
      break;
    }
  }

  if (valid)
  {
    if (use_json)
      fprintf(stream, "\"%s\":%ld", wovar->name, longinfo);
    else
    {
      if (wovar->id == VAR_HTTP_CODE || wovar->id == VAR_HTTP_CODE_PROXY)
        fprintf(stream, "%03ld", longinfo);
      else
        fprintf(stream, "%ld", longinfo);
    }
  }
  else
  {
    if (use_json)
      fprintf(stream, "\"%s\":null", wovar->name);
  }

  return 1; /* return 1 if anything was written */
}

static int writeOffset(FILE *stream, const struct writeoutvar *wovar,
                       struct per_transfer *per, FETCHcode per_result,
                       bool use_json)
{
  bool valid = false;
  fetch_off_t offinfo = 0;

  (void)per;
  (void)per_result;
  DEBUGASSERT(wovar->writefunc == writeOffset);

  if (wovar->ci)
  {
    if (!fetch_easy_getinfo(per->fetch, wovar->ci, &offinfo))
      valid = true;
  }
  else
  {
    DEBUGASSERT(0);
  }

  if (valid)
  {
    if (use_json)
      fprintf(stream, "\"%s\":", wovar->name);

    fprintf(stream, "%" FETCH_FORMAT_FETCH_OFF_T, offinfo);
  }
  else
  {
    if (use_json)
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
                 FETCHcode per_result)
{
  FILE *stream = stdout;
  const char *writeinfo = config->writeout;
  const char *ptr = writeinfo;
  bool done = FALSE;
  bool fclose_stream = FALSE;
  struct dynbuf name;

  if (!writeinfo)
    return;

  fetchx_dyn_init(&name, MAX_WRITEOUT_NAME_LENGTH);
  while (ptr && *ptr && !done)
  {
    if ('%' == *ptr && ptr[1])
    {
      if ('%' == ptr[1])
      {
        /* an escaped %-letter */
        fputc('%', stream);
        ptr += 2;
      }
      else
      {
        /* this is meant as a variable to output */
        char *end;
        size_t vlen;
        if ('{' == ptr[1])
        {
          struct writeoutvar *wv = NULL;
          struct writeoutvar find = {0};
          end = strchr(ptr, '}');
          ptr += 2; /* pass the % and the { */
          if (!end)
          {
            fputs("%{", stream);
            continue;
          }
          vlen = end - ptr;

          fetchx_dyn_reset(&name);
          if (!fetchx_dyn_addn(&name, ptr, vlen))
          {
            find.name = fetchx_dyn_ptr(&name);
            wv = bsearch(&find,
                         variables, sizeof(variables) / sizeof(variables[0]),
                         sizeof(variables[0]), matchvar);
          }
          if (wv)
          {
            switch (wv->id)
            {
            case VAR_ONERROR:
              if (per_result == FETCHE_OK)
                /* this is not error so skip the rest */
                done = TRUE;
              break;
            case VAR_STDOUT:
              if (fclose_stream)
                fclose(stream);
              fclose_stream = FALSE;
              stream = stdout;
              break;
            case VAR_STDERR:
              if (fclose_stream)
                fclose(stream);
              fclose_stream = FALSE;
              stream = tool_stderr;
              break;
            case VAR_JSON:
              ourWriteOutJSON(stream, variables,
                              sizeof(variables) / sizeof(variables[0]),
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
          else
          {
            fprintf(tool_stderr,
                    "fetch: unknown --write-out variable: '%.*s'\n",
                    (int)vlen, ptr);
          }
          ptr = end + 1; /* pass the end */
        }
        else if (!strncmp("header{", &ptr[1], 7))
        {
          ptr += 8;
          end = strchr(ptr, '}');
          if (end)
          {
            char hname[256]; /* holds the longest header field name */
            struct fetch_header *header;
            vlen = end - ptr;
            if (vlen < sizeof(hname))
            {
              memcpy(hname, ptr, vlen);
              hname[vlen] = 0;
              if (FETCHHE_OK == fetch_easy_header(per->fetch, hname, 0,
                                                  FETCHH_HEADER, -1, &header))
                fputs(header->value, stream);
            }
            ptr = end + 1;
          }
          else
            fputs("%header{", stream);
        }
        else if (!strncmp("output{", &ptr[1], 7))
        {
          bool append = FALSE;
          ptr += 8;
          if ((ptr[0] == '>') && (ptr[1] == '>'))
          {
            append = TRUE;
            ptr += 2;
          }
          end = strchr(ptr, '}');
          if (end)
          {
            char fname[512]; /* holds the longest filename */
            size_t flen = end - ptr;
            if (flen < sizeof(fname))
            {
              FILE *stream2;
              memcpy(fname, ptr, flen);
              fname[flen] = 0;
              stream2 = fopen(fname, append ? FOPEN_APPENDTEXT : FOPEN_WRITETEXT);
              if (stream2)
              {
                /* only change if the open worked */
                if (fclose_stream)
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
        else
        {
          /* illegal syntax, then just output the characters that are used */
          fputc('%', stream);
          fputc(ptr[1], stream);
          ptr += 2;
        }
      }
    }
    else if ('\\' == *ptr && ptr[1])
    {
      switch (ptr[1])
      {
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
    else
    {
      fputc(*ptr, stream);
      ptr++;
    }
  }
  if (fclose_stream)
    fclose(stream);
  fetchx_dyn_free(&name);
}
