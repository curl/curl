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
 * HTTP/2 Upgrade test
 * </DESC>
 */
#include <curl/curl.h>

#include <stdio.h>
#include <stdlib.h>

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

int main(int argc, char *argv[])
{
  const char *url;
  CURLM *multi = NULL;
  CURL *easy;
  CURLMcode mc;
  int running_handles = 0, start_count, numfds;
  CURLMsg *msg;
  int msgs_in_queue;
  char range[128];
  int exitcode = 1;

  if(argc != 2) {
    fprintf(stderr, "%s URL\n", argv[0]);
    return 2;
  }

  url = argv[1];
  multi = curl_multi_init();
  if(!multi) {
    fprintf(stderr, "curl_multi_init failed\n");
    goto cleanup;
  }

  start_count = 200;
  do {
    if(start_count) {
      easy = curl_easy_init();
      if(!easy) {
        fprintf(stderr, "curl_easy_init failed\n");
        goto cleanup;
      }
      curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, debug_cb);
      curl_easy_setopt(easy, CURLOPT_URL, url);
      curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(easy, CURLOPT_AUTOREFERER, 1L);
      curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
      curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
      curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
      curl_easy_setopt(easy, CURLOPT_WRITEDATA, NULL);
      curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
      curl_msnprintf(range, sizeof(range),
                     "%" CURL_FORMAT_CURL_OFF_TU "-"
                     "%" CURL_FORMAT_CURL_OFF_TU,
                     (curl_off_t)0,
                     (curl_off_t)16384);
      curl_easy_setopt(easy, CURLOPT_RANGE, range);

      mc = curl_multi_add_handle(multi, easy);
      if(mc != CURLM_OK) {
        fprintf(stderr, "curl_multi_add_handle: %s\n",
                curl_multi_strerror(mc));
        curl_easy_cleanup(easy);
        goto cleanup;
      }
      --start_count;
    }

    mc = curl_multi_perform(multi, &running_handles);
    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_perform: %s\n",
              curl_multi_strerror(mc));
      goto cleanup;
    }

    if(running_handles) {
      mc = curl_multi_poll(multi, NULL, 0, 1000000, &numfds);
      if(mc != CURLM_OK) {
        fprintf(stderr, "curl_multi_poll: %s\n",
                curl_multi_strerror(mc));
        goto cleanup;
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
          goto cleanup;
        }
        else if(status != 206) {
          fprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T
                  ": wrong http status %ld (expected 206)\n", xfer_id, status);
          goto cleanup;
        }
        curl_multi_remove_handle(multi, msg->easy_handle);
        curl_easy_cleanup(msg->easy_handle);
        fprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T" retiring "
                "(%d now running)\n", xfer_id, running_handles);
      }
    }

    fprintf(stderr, "running_handles=%d, yet_to_start=%d\n",
            running_handles, start_count);

  } while(running_handles > 0 || start_count);

  fprintf(stderr, "exiting\n");
  exitcode = EXIT_SUCCESS;

cleanup:

  if(multi) {
    CURL **list = curl_multi_get_handles(multi);
    if(list) {
      int i;
      for(i = 0; list[i]; i++) {
        curl_multi_remove_handle(multi, list[i]);
        curl_easy_cleanup(list[i]);
      }
      curl_free(list);
    }
    curl_multi_cleanup(multi);
  }

  return exitcode;
}
