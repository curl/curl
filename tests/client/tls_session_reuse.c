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

static size_t write_tse_cb(char *ptr, size_t size, size_t nmemb, void *opaque)
{
  (void)ptr;
  (void)opaque;
  return size * nmemb;
}

static int add_transfer(CURLM *multi, CURLSH *share,
                        struct curl_slist *resolve,
                        const char *url, long http_version)
{
  CURL *easy;
  CURLMcode mc;

  easy = curl_easy_init();
  if(!easy) {
    curl_mfprintf(stderr, "curl_easy_init failed\n");
    return 1;
  }
  curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(easy, CURLOPT_DEBUGFUNCTION, debug_cb);
  curl_easy_setopt(easy, CURLOPT_URL, url);
  curl_easy_setopt(easy, CURLOPT_SHARE, share);
  curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(easy, CURLOPT_AUTOREFERER, 1L);
  curl_easy_setopt(easy, CURLOPT_FAILONERROR, 1L);
  curl_easy_setopt(easy, CURLOPT_HTTP_VERSION, http_version);
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_tse_cb);
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, NULL);
  curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
  curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
  if(resolve)
    curl_easy_setopt(easy, CURLOPT_RESOLVE, resolve);


  mc = curl_multi_add_handle(multi, easy);
  if(mc != CURLM_OK) {
    curl_mfprintf(stderr, "curl_multi_add_handle: %s\n",
                  curl_multi_strerror(mc));
    curl_easy_cleanup(easy);
    return 1;
  }
  return 0;
}

static int test_tls_session_reuse(int argc, char *argv[])
{
  const char *url;
  CURLM *multi = NULL;
  CURLMcode mc;
  int running_handles = 0, numfds;
  CURLMsg *msg;
  CURLSH *share = NULL;
  CURLU *cu;
  struct curl_slist *resolve = NULL;
  char resolve_buf[1024];
  int msgs_in_queue;
  int add_more, waits, ongoing = 0;
  char *host = NULL, *port = NULL;
  int http_version = CURL_HTTP_VERSION_1_1;
  int exitcode = 1;

  if(argc != 3) {
    curl_mfprintf(stderr, "%s proto URL\n", argv[0]);
    return 2;
  }

  if(!strcmp("h2", argv[1]))
    http_version = CURL_HTTP_VERSION_2;
  else if(!strcmp("h3", argv[1]))
    http_version = CURL_HTTP_VERSION_3ONLY;

  url = argv[2];
  cu = curl_url();
  if(!cu) {
    curl_mfprintf(stderr, "out of memory\n");
    return 1;
  }
  if(curl_url_set(cu, CURLUPART_URL, url, 0)) {
    curl_mfprintf(stderr, "not a URL: '%s'\n", url);
    goto cleanup;
  }
  if(curl_url_get(cu, CURLUPART_HOST, &host, 0)) {
    curl_mfprintf(stderr, "could not get host of '%s'\n", url);
    goto cleanup;
  }
  if(curl_url_get(cu, CURLUPART_PORT, &port, 0)) {
    curl_mfprintf(stderr, "could not get port of '%s'\n", url);
    goto cleanup;
  }

  curl_msnprintf(resolve_buf, sizeof(resolve_buf)-1, "%s:%s:127.0.0.1",
                 host, port);
  resolve = curl_slist_append(resolve, resolve_buf);

  multi = curl_multi_init();
  if(!multi) {
    curl_mfprintf(stderr, "curl_multi_init failed\n");
    goto cleanup;
  }

  share = curl_share_init();
  if(!share) {
    curl_mfprintf(stderr, "curl_share_init failed\n");
    goto cleanup;
  }
  curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);


  if(add_transfer(multi, share, resolve, url, http_version))
    goto cleanup;
  ++ongoing;
  add_more = 6;
  waits = 3;
  do {
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

    if(waits) {
      --waits;
    }
    else {
      while(add_more) {
        if(add_transfer(multi, share, resolve, url, http_version))
          goto cleanup;
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
          curl_mfprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T
                        ": failed with %d\n", xfer_id, msg->data.result);
          goto cleanup;
        }
        else if(status != 200) {
          curl_mfprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T
                        ": wrong http status %ld (expected 200)\n", xfer_id,
                        status);
          goto cleanup;
        }
        curl_multi_remove_handle(multi, msg->easy_handle);
        curl_easy_cleanup(msg->easy_handle);
        --ongoing;
        curl_mfprintf(stderr, "transfer #%" CURL_FORMAT_CURL_OFF_T" retiring "
                      "(%d now running)\n", xfer_id, running_handles);
      }
    }

    curl_mfprintf(stderr, "running_handles=%d, yet_to_start=%d\n",
                  running_handles, add_more);

  } while(ongoing || add_more);

  curl_mfprintf(stderr, "exiting\n");
  exitcode = 0;

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
  curl_share_cleanup(share);
  curl_slist_free_all(resolve);
  curl_free(host);
  curl_free(port);
  curl_url_cleanup(cu);

  return exitcode;
}
