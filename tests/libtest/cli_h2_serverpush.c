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

static FILE *out_download;

static int setup_h2_serverpush(CURL *hnd, const char *url)
{
  out_download = fopen("download_0.data", "wb");
  if(!out_download)
    return 1;  /* failed */

  curl_easy_setopt(hnd, CURLOPT_URL, url);
  curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);

  curl_easy_setopt(hnd, CURLOPT_WRITEDATA, out_download);

  /* please be verbose */
  curl_easy_setopt(hnd, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(hnd, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  curl_easy_setopt(hnd, CURLOPT_DEBUGDATA, &debug_config);

  /* wait for pipe connection to confirm */
  curl_easy_setopt(hnd, CURLOPT_PIPEWAIT, 1L);

  return 0; /* all is good */
}

static FILE *out_push;

/* called when there's an incoming push */
static int server_push_callback(CURL *parent,
                                CURL *easy,
                                size_t num_headers,
                                struct curl_pushheaders *headers,
                                void *userp)
{
  char *headp;
  size_t i;
  int *transfers = (int *)userp;
  char filename[128];
  static unsigned int count = 0;
  int rv;

  (void)parent;
  curl_msnprintf(filename, sizeof(filename) - 1, "push%u", count++);

  /* here's a new stream, save it in a new file for each new push */
  out_push = fopen(filename, "wb");
  if(!out_push) {
    /* if we cannot save it, deny it */
    curl_mfprintf(stderr, "Failed to create output file for push\n");
    rv = CURL_PUSH_DENY;
    goto out;
  }

  /* write to this file */
  curl_easy_setopt(easy, CURLOPT_WRITEDATA, out_push);

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
  rv = CURL_PUSH_OK;

out:
  return rv;
}

/*
 * Download a file over HTTP/2, take care of server push.
 */
static CURLcode test_cli_h2_serverpush(const char *URL)
{
  CURL *easy;
  CURLM *multi_handle;
  int transfers = 1; /* we start with one */
  struct CURLMsg *m;

  debug_config.nohex = TRUE;
  debug_config.tracetime = FALSE;

  if(!URL) {
    curl_mfprintf(stderr, "need URL as argument\n");
    return (CURLcode)2;
  }

  multi_handle = curl_multi_init();
  curl_multi_setopt(multi_handle, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
  curl_multi_setopt(multi_handle, CURLMOPT_PUSHFUNCTION, server_push_callback);
  curl_multi_setopt(multi_handle, CURLMOPT_PUSHDATA, &transfers);

  easy = curl_easy_init();
  if(setup_h2_serverpush(easy, URL)) {
    fclose(out_download);
    curl_mfprintf(stderr, "failed\n");
    return (CURLcode)1;
  }

  curl_multi_add_handle(multi_handle, easy);
  do {
    int still_running; /* keep number of running handles */
    CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

    if(still_running)
      /* wait for activity, timeout or "nothing" */
      mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);

    if(mc)
      break;

    /*
     * A little caution when doing server push is that libcurl itself has
     * created and added one or more easy handles but we need to clean them up
     * when we are done.
     */
    do {
      int msgq = 0;
      m = curl_multi_info_read(multi_handle, &msgq);
      if(m && (m->msg == CURLMSG_DONE)) {
        CURL *e = m->easy_handle;
        transfers--;
        curl_multi_remove_handle(multi_handle, e);
        curl_easy_cleanup(e);
      }
    } while(m);

  } while(transfers); /* as long as we have transfers going */

  curl_multi_cleanup(multi_handle);

  fclose(out_download);
  if(out_push)
    fclose(out_push);

  return CURLE_OK;
}
