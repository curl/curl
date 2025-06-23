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
/* This is based on the PoC client of issue #11982
 */
#include "first.h"

static void usage_h2_pausing(const char *msg)
{
  if(msg)
    curl_mfprintf(stderr, "%s\n", msg);
  curl_mfprintf(stderr,
    "usage: [options] url\n"
    "  pause downloads with following options:\n"
    "  -V http_version (http/1.1, h2, h3) http version to use\n"
  );
}

struct handle
{
  size_t idx;
  int paused;
  int resumed;
  int errored;
  int fail_write;
  CURL *h;
};

static size_t cb(char *data, size_t size, size_t nmemb, void *clientp)
{
  size_t realsize = size * nmemb;
  struct handle *handle = (struct handle *) clientp;
  curl_off_t totalsize;

  (void)data;
  if(curl_easy_getinfo(handle->h, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                       &totalsize) == CURLE_OK)
    curl_mfprintf(stderr, "INFO: [%d] write, "
                  "Content-Length %" CURL_FORMAT_CURL_OFF_T "\n",
                  (int)handle->idx, totalsize);

  if(!handle->resumed) {
    ++handle->paused;
    curl_mfprintf(stderr, "INFO: [%d] write, PAUSING %d time on %lu bytes\n",
                  (int)handle->idx, handle->paused, (long)realsize);
    assert(handle->paused == 1);
    return CURL_WRITEFUNC_PAUSE;
  }
  if(handle->fail_write) {
    ++handle->errored;
    curl_mfprintf(stderr, "INFO: [%d] FAIL write of %lu bytes, %d time\n",
                  (int)handle->idx, (long)realsize, handle->errored);
    return CURL_WRITEFUNC_ERROR;
  }
  curl_mfprintf(stderr, "INFO: [%d] write, accepting %lu bytes\n",
                (int)handle->idx, (long)realsize);
  return realsize;
}

static int test_h2_pausing(int argc, char *argv[])
{
  struct handle handles[2];
  CURLM *multi_handle;
  int still_running = 1, msgs_left, numfds;
  size_t i;
  CURLMsg *msg;
  int rounds = 0;
  int rc = 0;
  CURLU *cu;
  struct curl_slist *resolve = NULL;
  char resolve_buf[1024];
  char *url, *host = NULL, *port = NULL;
  int all_paused = 0;
  int resume_round = -1;
  int http_version = CURL_HTTP_VERSION_2_0;
  int ch;

  while((ch = cgetopt(argc, argv, "hV:")) != -1) {
    switch(ch) {
    case 'h':
      usage_h2_pausing(NULL);
      return 2;
    case 'V': {
      if(!strcmp("http/1.1", coptarg))
        http_version = CURL_HTTP_VERSION_1_1;
      else if(!strcmp("h2", coptarg))
        http_version = CURL_HTTP_VERSION_2_0;
      else if(!strcmp("h3", coptarg))
        http_version = CURL_HTTP_VERSION_3ONLY;
      else {
        usage_h2_pausing("invalid http version");
        return 1;
      }
      break;
    }
    default:
      usage_h2_pausing("invalid option");
      return 1;
    }
  }
  argc -= coptind;
  argv += coptind;

  if(argc != 1) {
    curl_mfprintf(stderr, "ERROR: need URL as argument\n");
    return 2;
  }
  url = argv[0];

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_global_trace("ids,time,http/2,http/3");

  cu = curl_url();
  if(!cu) {
    curl_mfprintf(stderr, "out of memory\n");
    return 1;
  }
  if(curl_url_set(cu, CURLUPART_URL, url, 0)) {
    curl_mfprintf(stderr, "not a URL: '%s'\n", url);
    return 1;
  }
  if(curl_url_get(cu, CURLUPART_HOST, &host, 0)) {
    curl_mfprintf(stderr, "could not get host of '%s'\n", url);
    return 1;
  }
  if(curl_url_get(cu, CURLUPART_PORT, &port, 0)) {
    curl_mfprintf(stderr, "could not get port of '%s'\n", url);
    return 1;
  }
  memset(&resolve, 0, sizeof(resolve));
  curl_msnprintf(resolve_buf, sizeof(resolve_buf)-1, "%s:%s:127.0.0.1",
                 host, port);
  resolve = curl_slist_append(resolve, resolve_buf);

  for(i = 0; i < CURL_ARRAYSIZE(handles); i++) {
    handles[i].idx = i;
    handles[i].paused = 0;
    handles[i].resumed = 0;
    handles[i].errored = 0;
    handles[i].fail_write = 1;
    handles[i].h = curl_easy_init();
    if(!handles[i].h ||
      curl_easy_setopt(handles[i].h, CURLOPT_WRITEFUNCTION, cb) != CURLE_OK ||
      curl_easy_setopt(handles[i].h, CURLOPT_WRITEDATA, &handles[i])
        != CURLE_OK ||
      curl_easy_setopt(handles[i].h, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ||
      curl_easy_setopt(handles[i].h, CURLOPT_VERBOSE, 1L) != CURLE_OK ||
      curl_easy_setopt(handles[i].h, CURLOPT_DEBUGFUNCTION, debug_cb)
        != CURLE_OK ||
      curl_easy_setopt(handles[i].h, CURLOPT_SSL_VERIFYPEER, 0L) != CURLE_OK ||
      curl_easy_setopt(handles[i].h, CURLOPT_RESOLVE, resolve) != CURLE_OK ||
      curl_easy_setopt(handles[i].h, CURLOPT_PIPEWAIT, 1L) ||
      curl_easy_setopt(handles[i].h, CURLOPT_URL, url) != CURLE_OK) {
      ERR();
    }
    curl_easy_setopt(handles[i].h, CURLOPT_HTTP_VERSION, (long)http_version);
  }

  multi_handle = curl_multi_init();
  if(!multi_handle)
    ERR();

  for(i = 0; i < CURL_ARRAYSIZE(handles); i++) {
    if(curl_multi_add_handle(multi_handle, handles[i].h) != CURLM_OK)
      ERR();
  }

  for(rounds = 0;; rounds++) {
    curl_mfprintf(stderr, "INFO: multi_perform round %d\n", rounds);
    if(curl_multi_perform(multi_handle, &still_running) != CURLM_OK)
      ERR();

    if(!still_running) {
      int as_expected = 1;
      curl_mfprintf(stderr, "INFO: no more handles running\n");
      for(i = 0; i < CURL_ARRAYSIZE(handles); i++) {
        if(!handles[i].paused) {
          curl_mfprintf(stderr, "ERROR: [%d] NOT PAUSED\n", (int)i);
          as_expected = 0;
        }
        else if(handles[i].paused != 1) {
          curl_mfprintf(stderr, "ERROR: [%d] PAUSED %d times!\n",
                        (int)i, handles[i].paused);
          as_expected = 0;
        }
        else if(!handles[i].resumed) {
          curl_mfprintf(stderr, "ERROR: [%d] NOT resumed!\n", (int)i);
          as_expected = 0;
        }
        else if(handles[i].errored != 1) {
          curl_mfprintf(stderr, "ERROR: [%d] NOT errored once, %d instead!\n",
                        (int)i, handles[i].errored);
          as_expected = 0;
        }
      }
      if(!as_expected) {
        curl_mfprintf(stderr, "ERROR: handles not in expected state "
                      "after %d rounds\n", rounds);
        rc = 1;
      }
      break;
    }

    if(curl_multi_poll(multi_handle, NULL, 0, 100, &numfds) != CURLM_OK)
      ERR();

    /* !checksrc! disable EQUALSNULL 1 */
    while((msg = curl_multi_info_read(multi_handle, &msgs_left)) != NULL) {
      if(msg->msg == CURLMSG_DONE) {
        for(i = 0; i < CURL_ARRAYSIZE(handles); i++) {
          if(msg->easy_handle == handles[i].h) {
            if(handles[i].paused != 1 || !handles[i].resumed) {
              curl_mfprintf(stderr, "ERROR: [%d] done, pauses=%d, resumed=%d, "
                            "result %d - wtf?\n", (int)i, handles[i].paused,
                            handles[i].resumed, msg->data.result);
              rc = 1;
              goto out;
            }
          }
        }
      }
    }

    /* Successfully paused? */
    if(!all_paused) {
      for(i = 0; i < CURL_ARRAYSIZE(handles); i++) {
        if(!handles[i].paused) {
          break;
        }
      }
      all_paused = (i == CURL_ARRAYSIZE(handles));
      if(all_paused) {
        curl_mfprintf(stderr, "INFO: all transfers paused\n");
        /* give transfer some rounds to mess things up */
        resume_round = rounds + 2;
      }
    }
    if(resume_round > 0 && rounds == resume_round) {
      /* time to resume */
      for(i = 0; i < CURL_ARRAYSIZE(handles); i++) {
        curl_mfprintf(stderr, "INFO: [%d] resumed\n", (int)i);
        handles[i].resumed = 1;
        curl_easy_pause(handles[i].h, CURLPAUSE_CONT);
      }
    }
  }

out:
  for(i = 0; i < CURL_ARRAYSIZE(handles); i++) {
    curl_multi_remove_handle(multi_handle, handles[i].h);
    curl_easy_cleanup(handles[i].h);
  }

  curl_slist_free_all(resolve);
  curl_free(host);
  curl_free(port);
  curl_url_cleanup(cu);
  curl_multi_cleanup(multi_handle);
  curl_global_cleanup();

  return rc;
}
