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
 * TLS session reuse
 * </DESC>
 */
#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* #include <error.h> */
#include <errno.h>

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

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *opaque)
{
  (void)ptr;
  (void)opaque;
  return size * nmemb;
}

static void add_transfer(CURLM *multi, CURLSH *share,
                         struct curl_slist *resolve,
                         const char *url, int http_version)
{
  CURL *easy;
  CURLMcode mc;

  easy = curl_easy_init();
  if(!easy) {
    fprintf(stderr, "curl_easy_init failed\n");
    exit(1);
  }
  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, debug_cb);
  curl_easy_setopt(easy, CURLOPT_URL, url);
  curl_easy_setopt(easy, CURLOPT_SHARE, share);
  curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(easy, CURLOPT_AUTOREFERER, 1L);
  curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, http_version);
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, NULL);
  curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
  if(resolve)
    curl_easy_setopt(easy, CURLOPT_RESOLVE, resolve);


  mc = curl_multi_add_handle(multi, easy);
  if(mc != CURLM_OK) {
    fprintf(stderr, "curl_multi_add_handle: %s\n",
           curl_multi_strerror(mc));
    exit(1);
  }
}

int main(int argc, char *argv[])
{
  const char *url;
  CURLM *multi;
  CURLMcode mc;
  int running_handles = 0, numfds;
  CURLMsg *msg;
  CURLSH *share;
  CURLU *cu;
  struct curl_slist resolve;
  char resolve_buf[1024];
  int msgs_in_queue;
  int add_more, waits, ongoing = 0;
  char *host, *port;
  int http_version = CURL_HTTP_VERSION_1_1;

  if(argc != 3) {
    fprintf(stderr, "%s proto URL\n", argv[0]);
    exit(2);
  }

  if(!strcmp("h2", argv[1]))
    http_version = CURL_HTTP_VERSION_2;
  else if(!strcmp("h3", argv[1]))
    http_version = CURL_HTTP_VERSION_3ONLY;

  url = argv[2];
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
  curl_msnprintf(resolve_buf, sizeof(resolve_buf)-1, "%s:%s:127.0.0.1",
                 host, port);
  curl_slist_append(&resolve, resolve_buf);

  multi = curl_multi_init();
  if(!multi) {
    fprintf(stderr, "curl_multi_init failed\n");
    exit(1);
  }

  share = curl_share_init();
  if(!share) {
    fprintf(stderr, "curl_share_init failed\n");
    exit(1);
  }
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);


  add_transfer(multi, share, &resolve, url, http_version);
  ++ongoing;
  add_more = 6;
  waits = 3;
  do {
    mc = curl_multi_perform(multi, &running_handles);
    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_perform: %s\n",
             curl_multi_strerror(mc));
      exit(1);
    }

    if(running_handles) {
      mc = curl_multi_poll(multi, NULL, 0, 1000000, &numfds);
      if(mc != CURLM_OK) {
        fprintf(stderr, "curl_multi_poll: %s\n",
               curl_multi_strerror(mc));
        exit(1);
      }
    }

    if(waits) {
      --waits;
    }
    else {
      while(add_more) {
        add_transfer(multi, share, &resolve, url, http_version);
        ++ongoing;
        --add_more;
      }
    }

    /* Check for finished handles and remove. */
    /* !checksrc! disable EQUALSNULL 1 */
    while((msg = curl_multi_info_read(multi, &msgs_in_queue)) != NULL) {
      if(msg->msg == CURLMSG_DONE) {
        long status = 0;
        curl_off_t xfer_id;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_XFER_ID, &xfer_id);
        curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &status);
        if(msg->data.result == CURLE_SEND_ERROR ||
            msg->data.result == CURLE_RECV_ERROR) {
          /* We get these if the server had a GOAWAY in transit on
           * re-using a connection */
        }
        else if(msg->data.result) {
          fprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T
                  ": failed with %d\n", xfer_id, msg->data.result);
          exit(1);
        }
        else if(status != 200) {
          fprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T
                  ": wrong http status %ld (expected 200)\n", xfer_id, status);
          exit(1);
        }
        curl_multi_remove_handle(multi, msg->easy_handle);
        curl_easy_cleanup(msg->easy_handle);
        --ongoing;
        fprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T" retiring "
                "(%d now running)\n", xfer_id, running_handles);
      }
    }

    fprintf(stderr, "running_handles=%d, yet_to_start=%d\n",
            running_handles, add_more);

  } while(ongoing || add_more);

  fprintf(stderr, "exiting\n");
  exit(EXIT_SUCCESS);
}
