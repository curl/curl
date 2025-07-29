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
#include "first.h"

#include "testtrace.h"
#include "memdebug.h"

static size_t write_h2_upg_extreme_cb(char *ptr, size_t size, size_t nmemb,
                                      void *opaque)
{
  (void)ptr;
  (void)opaque;
  return size * nmemb;
}

static CURLcode test_cli_h2_upgrade_extreme(const char *URL)
{
  CURLM *multi = NULL;
  CURL *easy;
  CURLMcode mc;
  int running_handles = 0, start_count, numfds;
  CURLMsg *msg;
  int msgs_in_queue;
  char range[128];
  CURLcode exitcode = (CURLcode)1;

  if(!URL) {
    curl_mfprintf(stderr, "need URL as argument\n");
    return (CURLcode)2;
  }

  multi = curl_multi_init();
  if(!multi) {
    curl_mfprintf(stderr, "curl_multi_init failed\n");
    goto cleanup;
  }

  start_count = 200;
  do {
    if(start_count) {
      easy = curl_easy_init();
      if(!easy) {
        curl_mfprintf(stderr, "curl_easy_init failed\n");
        goto cleanup;
      }
      curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
      curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, cli_debug_cb);
      curl_easy_setopt(easy, CURLOPT_URL, URL);
      curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
      curl_easy_setopt(easy, CURLOPT_AUTOREFERER, 1L);
      curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
      curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
      curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_h2_upg_extreme_cb);
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
        curl_mfprintf(stderr, "curl_multi_add_handle: %s\n",
                      curl_multi_strerror(mc));
        curl_easy_cleanup(easy);
        goto cleanup;
      }
      --start_count;
    }

    mc = curl_multi_perform(multi, &running_handles);
    if(mc != CURLM_OK) {
      curl_mfprintf(stderr, "curl_multi_perform: %s\n",
                    curl_multi_strerror(mc));
      goto cleanup;
    }

    if(running_handles) {
      mc = curl_multi_poll(multi, NULL, 0, 1000000, &numfds);
      if(mc != CURLM_OK) {
        curl_mfprintf(stderr, "curl_multi_poll: %s\n",
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
           * reusing a connection */
        }
        else if(msg->data.result) {
          curl_mfprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T
                        ": failed with %d\n", xfer_id, msg->data.result);
          goto cleanup;
        }
        else if(status != 206) {
          curl_mfprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T
                        ": wrong http status %ld (expected 206)\n", xfer_id,
                        status);
          goto cleanup;
        }
        curl_multi_remove_handle(multi, msg->easy_handle);
        curl_easy_cleanup(msg->easy_handle);
        curl_mfprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T" retiring "
                      "(%d now running)\n", xfer_id, running_handles);
      }
    }

    curl_mfprintf(stderr, "running_handles=%d, yet_to_start=%d\n",
                  running_handles, start_count);

  } while(running_handles > 0 || start_count);

  curl_mfprintf(stderr, "exiting\n");
  exitcode = CURLE_OK;

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
