#ifndef HEADER_CLIENT_FIRST_H
#define HEADER_CLIENT_FIRST_H
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
#include "curl_setup.h"

typedef int (*entry_func_t)(int, char **);

struct entry_s {
  const char *name;
  entry_func_t ptr;
};

extern const struct entry_s s_entries[];

#include <curl/curl.h>

#include <curlx/curlx.h>

#define ERR()                                                                 \
  do {                                                                        \
    curl_mfprintf(stderr, "something unexpected went wrong - bailing out!\n");\
    return 2;                                                                 \
  } while(0)

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

#define TRC_IDS_FORMAT_IDS_1  "[%" CURL_FORMAT_CURL_OFF_T "-x] "
#define TRC_IDS_FORMAT_IDS_2  "[%" CURL_FORMAT_CURL_OFF_T "-%" \
                                   CURL_FORMAT_CURL_OFF_T "] "
/*
** callback for CURLOPT_DEBUGFUNCTION
*/
static int debug_cb(CURL *handle, curl_infotype type,
                    char *data, size_t size, void *userdata)
{
  FILE *output = stderr;
  static int newl = 0;
  static int traced_data = 0;
  char idsbuf[60];
  curl_off_t xfer_id, conn_id;

  (void)handle; /* not used */
  (void)userdata;

  if(!curl_easy_getinfo(handle, CURLINFO_XFER_ID, &xfer_id) && xfer_id >= 0) {
    if(!curl_easy_getinfo(handle, CURLINFO_CONN_ID, &conn_id) &&
       conn_id >= 0) {
      curl_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_2, xfer_id,
                     conn_id);
    }
    else {
      curl_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_1, xfer_id);
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

static void dump(const char *text, unsigned char *ptr, size_t size, char nohex)
{
  size_t i;
  size_t c;

  unsigned int width = 0x10;

  if(nohex)
    /* without the hex output, we can fit more on screen */
    width = 0x40;

  curl_mfprintf(stderr, "%s, %lu bytes (0x%lx)\n",
                text, (unsigned long)size, (unsigned long)size);

  for(i = 0; i < size; i += width) {

    curl_mfprintf(stderr, "%4.4lx: ", (unsigned long)i);

    if(!nohex) {
      /* hex not disabled, show it */
      for(c = 0; c < width; c++)
        if(i + c < size)
          curl_mfprintf(stderr, "%02x ", ptr[i + c]);
        else
          fputs("   ", stderr);
    }

    for(c = 0; (c < width) && (i + c < size); c++) {
      /* check for 0D0A; if found, skip past and start a new line of output */
      if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
         ptr[i + c + 1] == 0x0A) {
        i += (c + 2 - width);
        break;
      }
      curl_mfprintf(stderr, "%c",
               (ptr[i + c] >= 0x20) && (ptr[i + c] < 0x80) ? ptr[i + c] : '.');
      /* check again for 0D0A, to avoid an extra \n if it's at width */
      if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
         ptr[i + c + 2] == 0x0A) {
        i += (c + 3 - width);
        break;
      }
    }
    fputc('\n', stderr); /* newline */
  }
}

#ifndef CURL_DISABLE_WEBSOCKETS
/* just close the connection */
static void websocket_close(CURL *curl)
{
  size_t sent;
  CURLcode result =
    curl_ws_send(curl, "", 0, &sent, 0, CURLWS_CLOSE);
  curl_mfprintf(stderr, "ws: curl_ws_send returned %u, sent %u\n",
                (int)result, (int)sent);
}
#endif /* CURL_DISABLE_WEBSOCKETS */

static int coptind;
static char *coptarg;

static int cgetopt(int argc, char * const argv[], const char *optstring)
{
  static int optpos = 1;
  int coptopt;
  char *arg;

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

#endif /* HEADER_CLIENT_FIRST_H */
