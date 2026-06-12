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

static FILE *out_download = NULL;

static int setup_h2_serverpush(CURL *curl, const char *url)
{
  out_download = curlx_fopen("download_0.data", "wb");
  if(!out_download)
    return 1;  /* failed */

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  curl_easy_setopt(curl, CURLOPT_WRITEDATA, out_download);

  /* please be verbose */
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &debug_config);

  /* wait for pipe connection to confirm */
  curl_easy_setopt(curl, CURLOPT_PIPEWAIT, 1L);

  return 0; /* all is good */
}

static FILE *out_push = NULL;

/* called when there is an incoming push */
static int server_push_callback(CURL *parent,
                                CURL *curl,
                                size_t num_headers,
                                struct curl_pushheaders *headers,
                                void *userp)
{
  const char *headp;
  size_t i;
  int *transfers = (int *)userp;
  char filename[128];
  static unsigned int count = 0;

  (void)parent;

  curl_msnprintf(filename, sizeof(filename) - 1, "push%u", count++);

  /* here's a new stream, save it in a new file for each new push */
  out_push = curlx_fopen(filename, "wb");
  if(!out_push) {
    /* if we cannot save it, deny it */
    curl_mfprintf(stderr, "Failed to create output file for push\n");
    return CURL_PUSH_DENY;
  }

  /* write to this file */
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, out_push);

  curl_mfprintf(stderr, "**** push callback approves stream %u, "
                "got %zu headers!\n", count, num_headers);

  for(i = 0; i < num_headers; i++) {
    headp = curl_pushheader_bynum(headers, i);
    curl_mfprintf(stderr, "**** header %zu: %s\n", i, headp);
  }

  headp = curl_pushheader_byname(headers, ":path");
  if(headp) {
    curl_mfprintf(stderr, "**** The PATH is %s\n",
                  headp /* skip :path + colon */);
  }

  (*transfers)++; /* one more */

  return CURL_PUSH_OK;
}

/*
 * Download a file over HTTP/2, take care of server push.
 */
static CURLcode test_cli_h2_serverpush(const char *URL)
{
  CURL *curl = NULL;
  CURLM *multi;
  int transfers = 1; /* we start with one */
  CURLcode result = CURLE_OK;

  debug_config.nohex = TRUE;
  debug_config.tracetime = FALSE;

  if(!URL) {
    curl_mfprintf(stderr, "need URL as argument\n");
    return (CURLcode)2;
  }

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return (CURLcode)3;
  }

  multi = curl_multi_init();
  if(!multi) {
    result = (CURLcode)1;
    goto cleanup;
  }

  curl = curl_easy_init();
  if(!curl) {
    result = (CURLcode)1;
    goto cleanup;
  }

  if(setup_h2_serverpush(curl, URL)) {
    curl_mfprintf(stderr, "failed\n");
    result = (CURLcode)1;
    goto cleanup;
  }

  curl_multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi, CURLMOPT_PUSHFUNCTION, server_push_callback);
  curl_multi_setopt(multi, CURLMOPT_PUSHDATA, &transfers);

  curl_multi_add_handle(multi, curl);

  do {
    struct CURLMsg *m;
    int still_running; /* keep number of running handles */
    CURLMcode mresult = curl_multi_perform(multi, &still_running);

    if(still_running)
      /* wait for activity, timeout or "nothing" */
      mresult = curl_multi_poll(multi, NULL, 0, 1000, NULL);

    if(mresult)
      break;

    /*
     * A little caution when doing server push is that libcurl itself has
     * created and added one or more easy handles but we need to clean them up
     * when we are done.
     */
    do {
      int msgq = 0;
      m = curl_multi_info_read(multi, &msgq);
      if(m && (m->msg == CURLMSG_DONE)) {
        CURL *easy = m->easy_handle;
        transfers--;
        curl_multi_remove_handle(multi, easy);
        curl_easy_cleanup(easy);
      }
    } while(m);

  } while(transfers); /* as long as we have transfers going */

cleanup:

  curl_multi_cleanup(multi);

  if(out_download)
    curlx_fclose(out_download);
  if(out_push)
    curlx_fclose(out_push);

  curl_global_cleanup();

  return result;
}
