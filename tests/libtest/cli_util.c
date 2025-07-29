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
#include "cli_util.h"

static void log_line_start(FILE *log, const char *idsbuf, curl_infotype type)
{
  /*
   * This is the trace look that is similar to what libcurl makes on its
   * own.
   */
  static const char * const s_infotype[] = {
    "* ", "< ", "> ", "{ ", "} ", "{ ", "} "
  };
  if(idsbuf && *idsbuf)
    curl_mfprintf(log, "%s%s", idsbuf, s_infotype[type]);
  else
    fputs(s_infotype[type], log);
}

/* callback for CURLOPT_DEBUGFUNCTION (used in client tests) */
int cli_debug_cb(CURL *handle, curl_infotype type,
                 char *data, size_t size, void *userp)
{
  FILE *output = stderr;
  static int newl = 0;
  static int traced_data = 0;
  char idsbuf[60];
  curl_off_t xfer_id, conn_id;

  (void)handle; /* not used */
  (void)userp;

  if(!curl_easy_getinfo(handle, CURLINFO_XFER_ID, &xfer_id) && xfer_id >= 0) {
    if(!curl_easy_getinfo(handle, CURLINFO_CONN_ID, &conn_id) &&
       conn_id >= 0) {
      curl_msnprintf(idsbuf, sizeof(idsbuf),
                     "[%" CURL_FORMAT_CURL_OFF_T "-"
                      "%" CURL_FORMAT_CURL_OFF_T "] ", xfer_id, conn_id);
    }
    else {
      curl_msnprintf(idsbuf, sizeof(idsbuf),
                     "[%" CURL_FORMAT_CURL_OFF_T "-x] ", xfer_id);
    }
  }
  else
    idsbuf[0] = 0;

  switch(type) {
  case CURLINFO_HEADER_OUT:
    if(size > 0) {
      size_t st = 0;
      size_t i;
      for(i = 0; i < size - 1; i++) {
        if(data[i] == '\n') { /* LF */
          if(!newl) {
            log_line_start(output, idsbuf, type);
          }
          (void)fwrite(data + st, i - st + 1, 1, output);
          st = i + 1;
          newl = 0;
        }
      }
      if(!newl)
        log_line_start(output, idsbuf, type);
      (void)fwrite(data + st, i - st + 1, 1, output);
    }
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case CURLINFO_TEXT:
  case CURLINFO_HEADER_IN:
    if(!newl)
      log_line_start(output, idsbuf, type);
    (void)fwrite(data, size, 1, output);
    newl = (size && (data[size - 1] != '\n')) ? 1 : 0;
    traced_data = 0;
    break;
  case CURLINFO_DATA_OUT:
  case CURLINFO_DATA_IN:
  case CURLINFO_SSL_DATA_IN:
  case CURLINFO_SSL_DATA_OUT:
    if(!traced_data) {
      if(!newl)
        log_line_start(output, idsbuf, type);
      curl_mfprintf(output, "[%ld bytes data]\n", (long)size);
      newl = 0;
      traced_data = 1;
    }
    break;
  default: /* nada */
    newl = 0;
    traced_data = 1;
    break;
  }

  return 0;
}

int coptind;
const char *coptarg;

int cgetopt(int argc, const char * const argv[], const char *optstring)
{
  static int optpos = 1;
  int coptopt;
  const char *arg;

  if(coptind == 0) {  /* Reset? */
    coptind = !!argc;
    optpos = 1;
  }

  arg = argv[coptind];
  if(arg && strcmp(arg, "--") == 0) {
    coptind++;
    return -1;
  }
  else if(!arg || arg[0] != '-') {
    return -1;
  }
  else {
    const char *opt = strchr(optstring, arg[optpos]);
    coptopt = arg[optpos];
    if(!opt) {
      if(!arg[++optpos]) {
        coptind++;
        optpos = 1;
      }
      return '?';
    }
    else if(opt[1] == ':') {
      if(arg[optpos + 1]) {
        coptarg = arg + optpos + 1;
        coptind++;
        optpos = 1;
        return coptopt;
      }
      else if(argv[coptind + 1]) {
        coptarg = argv[coptind + 1];
        coptind += 2;
        optpos = 1;
        return coptopt;
      }
      else {
        if(!arg[++optpos]) {
          coptind++;
          optpos = 1;
        }
        return *optstring == ':' ? ':' : '?';
      }
    }
    else {
      if(!arg[++optpos]) {
        coptind++;
        optpos = 1;
      }
      return coptopt;
    }
  }
}
