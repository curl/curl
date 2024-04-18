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
/* <DESC>
 * upload pausing
 * </DESC>
 */
/* This is based on the poc client of issue #11769
 */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <curl/mprintf.h>

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
    fprintf(log, "%s%s", idsbuf, s_infotype[type]);
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
                    char *data, size_t size,
                    void *userdata)
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
      curl_msnprintf(idsbuf, sizeof(idsbuf), TRC_IDS_FORMAT_IDS_2,
                     xfer_id, conn_id);
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
      fprintf(output, "[%ld bytes data]\n", (long)size);
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

#define PAUSE_READ_AFTER  10
static size_t total_read = 0;

static size_t read_callback(char *ptr, size_t size, size_t nmemb,
                            void *userdata)
{
  (void)size;
  (void)nmemb;
  (void)userdata;
  if(total_read >= PAUSE_READ_AFTER) {
    return CURL_READFUNC_PAUSE;
  }
  else {
    ptr[0] = '\n';
    ++total_read;
    return 1;
  }
}

static int progress_callback(void *clientp,
                             double dltotal,
                             double dlnow,
                             double ultotal,
                             double ulnow)
{
  CURL *curl;
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  curl = (CURL *)clientp;
  curl_easy_pause(curl, CURLPAUSE_CONT);
  return 0;
}

static int err(void)
{
  fprintf(stderr, "something unexpected went wrong - bailing out!\n");
  exit(2);
}



int main(int argc, char *argv[])
{
  CURL *curl;
  CURLcode rc = CURLE_OK;
  CURLU *cu;
  struct curl_slist *resolve = NULL;
  char resolve_buf[1024];
  char *url, *host = NULL, *port = NULL;

  if(argc != 2) {
    fprintf(stderr, "ERROR: need URL as argument\n");
    return 2;
  }
  url = argv[1];

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_global_trace("ids,time");

  cu = curl_url();
  if(!cu) {
    fprintf(stderr, "out of memory\n");
    exit(1);
  }
  if(curl_url_set(cu, CURLUPART_URL, url, 0)) {
    fprintf(stderr, "not a URL: '%s'\n", url);
    exit(1);
  }
  if(curl_url_get(cu, CURLUPART_HOST, &host, 0)) {
    fprintf(stderr, "could not get host of '%s'\n", url);
    exit(1);
  }
  if(curl_url_get(cu, CURLUPART_PORT, &port, 0)) {
    fprintf(stderr, "could not get port of '%s'\n", url);
    exit(1);
  }
  memset(&resolve, 0, sizeof(resolve));
  curl_msnprintf(resolve_buf, sizeof(resolve_buf)-1,
                 "%s:%s:127.0.0.1", host, port);
  resolve = curl_slist_append(resolve, resolve_buf);

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "out of memory\n");
    exit(1);
  }
  /* We want to use our own read function. */
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

  /* It will help us to continue the read function. */
  curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
  curl_easy_setopt(curl, CURLOPT_XFERINFODATA, curl);
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

  /* It will help us to ensure that keepalive does not help. */
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 1L);
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 1L);

  /* Enable uploading. */
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

  if(curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L) != CURLE_OK ||
     curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debug_cb)
     != CURLE_OK ||
     curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve) != CURLE_OK)
    err();

  curl_easy_setopt(curl, CURLOPT_URL, url);
  rc = curl_easy_perform(curl);

  if(curl) {
    curl_easy_cleanup(curl);
  }

  curl_slist_free_all(resolve);
  curl_free(host);
  curl_free(port);
  curl_url_cleanup(cu);
  curl_global_cleanup();

  return (int)rc;
}
