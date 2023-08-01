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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
/* #include <error.h> */
#include <errno.h>
#include <curl/curl.h>
#include <curl/mprintf.h>


static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *opaque)
{
  (void)ptr;
  (void)opaque;
  return size * nmemb;
}

int main(int argc, char *argv[])
{
  const char *url;
  CURLM *multi;
  CURL *easy;
  CURLMcode mc;
  int running_handles = 0, start_count, numfds;
  CURLMsg *msg;
  int msgs_in_queue;
  char range[128];

  if(argc != 2) {
    fprintf(stderr, "%s URL\n", argv[0]);
    exit(2);
  }

  url = argv[1];
  multi = curl_multi_init();
  if(!multi) {
    fprintf(stderr, "curl_multi_init failed\n");
    exit(1);
  }

  start_count = 500;
  do {
    if(start_count) {
      easy = curl_easy_init();
      if(!easy) {
        fprintf(stderr, "curl_easy_init failed\n");
        exit(1);
      }
      curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(easy, CURLOPT_URL, url);
      curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(easy, CURLOPT_AUTOREFERER, 1L);
      curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
      curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
      curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_cb);
      curl_easy_setopt(easy, CURLOPT_WRITEDATA, NULL);
      curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
      curl_msnprintf(range, sizeof(range), "%" PRIu64 "-%" PRIu64,
                     UINT64_C(0), UINT64_C(16384));
      curl_easy_setopt(easy, CURLOPT_RANGE, range);

      mc = curl_multi_add_handle(multi, easy);
      if(mc != CURLM_OK) {
        fprintf(stderr, "curl_multi_add_handle: %s\n",
               curl_multi_strerror(mc));
        exit(1);
      }
      --start_count;
    }

    mc = curl_multi_perform(multi, &running_handles);
    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_perform: %s\n",
             curl_multi_strerror(mc));
      exit(1);
    }

    /* Check for finished handles and remove. */
    while((msg = curl_multi_info_read(multi, &msgs_in_queue))) {
      if(msg->msg == CURLMSG_DONE) {
        long status = 0;
        curl_off_t xfer_id;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_XFER_ID, &xfer_id);
        curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &status);
        --running_handles;
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
        else if(status != 206) {
          fprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T
                  ": wrong http status %ld (expected 206)\n", xfer_id, status);
          exit(1);
        }
        curl_multi_remove_handle(multi, msg->easy_handle);
        curl_easy_cleanup(msg->easy_handle);
        fprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T" retiring\n",
                xfer_id);
      }
    }

    mc = curl_multi_poll(multi, NULL, 0, 1000000, &numfds);
    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_poll: %s\n",
             curl_multi_strerror(mc));
      exit(1);
    }

    fprintf(stderr, "running_handles = %d\n", running_handles);
  } while(running_handles > 0 || start_count);

  exit(EXIT_SUCCESS);
}
