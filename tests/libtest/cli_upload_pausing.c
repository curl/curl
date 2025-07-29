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
/* This is based on the PoC client of issue #11769
 */
#include "first.h"

#include "testtrace.h"
#include "memdebug.h"

static size_t total_read = 0;

static size_t read_callback(char *ptr, size_t size, size_t nmemb,
                            void *userdata)
{
  static const size_t PAUSE_READ_AFTER = 1;

  (void)size;
  (void)nmemb;
  (void)userdata;
  if(total_read >= PAUSE_READ_AFTER) {
    curl_mfprintf(stderr, "read_callback, return PAUSE\n");
    return CURL_READFUNC_PAUSE;
  }
  else {
    ptr[0] = '\n';
    ++total_read;
    curl_mfprintf(stderr, "read_callback, return 1 byte\n");
    return 1;
  }
}

static int progress_callback(void *clientp,
                             curl_off_t dltotal,
                             curl_off_t dlnow,
                             curl_off_t ultotal,
                             curl_off_t ulnow)
{
  (void)dltotal;
  (void)dlnow;
  (void)ultotal;
  (void)ulnow;
  (void)clientp;
#if 0
  /* Used to unpause on progress, but keeping for now. */
  {
    CURL *curl = (CURL *)clientp;
    curl_easy_pause(curl, CURLPAUSE_CONT);
    /* curl_easy_pause(curl, CURLPAUSE_RECV_CONT); */
  }
#endif
  return 0;
}

static void usage_upload_pausing(const char *msg)
{
  if(msg)
    curl_mfprintf(stderr, "%s\n", msg);
  curl_mfprintf(stderr,
    "usage: [options] url\n"
    "  upload and pause, options:\n"
    "  -V http_version (http/1.1, h2, h3) http version to use\n"
  );
}

static CURLcode test_cli_upload_pausing(const char *URL)
{
  CURL *curl;
  CURLcode rc = CURLE_OK;
  CURLU *cu;
  struct curl_slist *resolve = NULL;
  char resolve_buf[1024];
  const char *url;
  char *host = NULL, *port = NULL;
  long http_version = CURL_HTTP_VERSION_1_1;
  int ch;

  (void)URL;

  while((ch = cgetopt(test_argc, test_argv, "V:")) != -1) {
    switch(ch) {
    case 'V': {
      if(!strcmp("http/1.1", coptarg))
        http_version = CURL_HTTP_VERSION_1_1;
      else if(!strcmp("h2", coptarg))
        http_version = CURL_HTTP_VERSION_2_0;
      else if(!strcmp("h3", coptarg))
        http_version = CURL_HTTP_VERSION_3ONLY;
      else {
        usage_upload_pausing("invalid http version");
        return (CURLcode)1;
      }
      break;
    }
    default:
      usage_upload_pausing("invalid option");
      return (CURLcode)1;
    }
  }
  test_argc -= coptind;
  test_argv += coptind;

  if(test_argc != 1) {
    usage_upload_pausing("not enough arguments");
    return (CURLcode)2;
  }
  url = test_argv[0];

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl_global_trace("ids,time");

  cu = curl_url();
  if(!cu) {
    curl_mfprintf(stderr, "out of memory\n");
    return (CURLcode)1;
  }
  if(curl_url_set(cu, CURLUPART_URL, url, 0)) {
    curl_mfprintf(stderr, "not a URL: '%s'\n", url);
    return (CURLcode)1;
  }
  if(curl_url_get(cu, CURLUPART_HOST, &host, 0)) {
    curl_mfprintf(stderr, "could not get host of '%s'\n", url);
    return (CURLcode)1;
  }
  if(curl_url_get(cu, CURLUPART_PORT, &port, 0)) {
    curl_mfprintf(stderr, "could not get port of '%s'\n", url);
    return (CURLcode)1;
  }
  memset(&resolve, 0, sizeof(resolve));
  curl_msnprintf(resolve_buf, sizeof(resolve_buf)-1, "%s:%s:127.0.0.1",
                 host, port);
  resolve = curl_slist_append(resolve, resolve_buf);

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "out of memory\n");
    return (CURLcode)1;
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
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPCNT, 1L);

  /* Enable uploading. */
  curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  if(curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L) != CURLE_OK ||
     curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, cli_debug_cb) != CURLE_OK ||
     curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve) != CURLE_OK) {
    curl_mfprintf(stderr, "something unexpected went wrong - bailing out!\n");
    return (CURLcode)2;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, http_version);

  rc = curl_easy_perform(curl);

  if(curl) {
    curl_easy_cleanup(curl);
  }

  curl_slist_free_all(resolve);
  curl_free(host);
  curl_free(port);
  curl_url_cleanup(cu);
  curl_global_cleanup();

  return rc;
}
