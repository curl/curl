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

#ifndef CURL_DISABLE_FTP

struct test_cli_ftp_upload_data {
  const char *data;
  size_t data_len;
  size_t offset;
  int done;
};

static size_t test_cli_ftp_upload_read(char *buf,
                                       size_t nitems, size_t blen,
                                       void *userdata)
{
  struct test_cli_ftp_upload_data *d = userdata;
  size_t nread = d->data_len - d->offset;

  if(nread) {
    if(nread > (nitems * blen))
      nread = (nitems * blen);
    memcpy(buf, d->data + d->offset, nread);
    d->offset += nread;
  }
  else
    d->done = 1;
  return nread;
}

static void usage_ftp_upload(const char *msg)
{
  if(msg)
    curl_mfprintf(stderr, "%s\n", msg);
  curl_mfprintf(stderr,
    "usage: [options] url\n"
    "  -r <host>:<port>:<addr>  resolve information\n"
  );
}

#endif

static CURLcode test_cli_ftp_upload(const char *URL)
{
#ifndef CURL_DISABLE_FTP
  CURLM *multi_handle;
  CURL *curl_handle;
  int running_handles = 0;
  int max_fd = -1;
  struct timeval timeout = { 1, 0 };
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;
  struct test_cli_ftp_upload_data data;
  struct curl_slist *host = NULL;
  const char *resolve = NULL, *url;
  int ch;
  CURLcode result = CURLE_FAILED_INIT;
  curl_off_t uploadsize = -1;

  (void)URL;
  while((ch = cgetopt(test_argc, test_argv, "r:")) != -1) {
    switch(ch) {
    case 'r':
      resolve = coptarg;
      break;
    default:
      usage_ftp_upload("unknown option");
      return (CURLcode)1;
    }
  }
  test_argc -= coptind;
  test_argv += coptind;
  if(test_argc != 1) {
    usage_ftp_upload("not enough arguments");
    return (CURLcode)2;
  }
  url = test_argv[0];

  if(resolve)
    host = curl_slist_append(NULL, resolve);

  memset(&data, 0, sizeof(data));
  data.data = "abcdefghijklmnopqrstuvwxyz"
              "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  data.data_len = strlen(data.data);

  curl_global_init(CURL_GLOBAL_ALL);
  multi_handle = curl_multi_init();
  curl_handle = curl_easy_init();

  curl_easy_setopt(curl_handle, CURLOPT_FTPPORT, "-");
  curl_easy_setopt(curl_handle, CURLOPT_FTP_USE_EPRT, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(curl_handle, CURLOPT_USE_SSL, CURLUSESSL_TRY);
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_USERPWD, NULL);
  curl_easy_setopt(curl_handle, CURLOPT_FTP_CREATE_MISSING_DIRS,
                   CURLFTP_CREATE_DIR);
  curl_easy_setopt(curl_handle, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION,
                   test_cli_ftp_upload_read);
  curl_easy_setopt(curl_handle, CURLOPT_READDATA, &data);
  curl_easy_setopt(curl_handle, CURLOPT_INFILESIZE_LARGE, uploadsize);

  curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, cli_debug_cb);
  if(host)
    curl_easy_setopt(curl_handle, CURLOPT_RESOLVE, host);

  curl_multi_add_handle(multi_handle, curl_handle);
  curl_multi_perform(multi_handle, &running_handles);
  while(running_handles && !data.done) {
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &max_fd);
    select(max_fd + 1, &fdread, &fdwrite, &fdexcep, &timeout);
    curl_multi_perform(multi_handle, &running_handles);
  }
  while(running_handles) {
    curl_mfprintf(stderr, "reports to hang herel\n");
    curl_multi_perform(multi_handle, &running_handles);
  }

  while(1) {
    int msgq = 0;
    struct CURLMsg *msg = curl_multi_info_read(multi_handle, &msgq);
    if(msg && (msg->msg == CURLMSG_DONE)) {
      if(msg->easy_handle == curl_handle) {
        result = msg->data.result;
      }
    }
    else
      break;
  }

  curl_multi_remove_handle(multi_handle, curl_handle);

  curl_easy_reset(curl_handle);
  curl_easy_cleanup(curl_handle);
  curl_multi_cleanup(multi_handle);
  curl_global_cleanup();
  curl_slist_free_all(host);

  curl_mfprintf(stderr, "transfer result: %d\n", result);
  return result;
#else /* !CURL_DISABLE_FTP */
  (void)URL;
  curl_mfprintf(stderr, "FTP not enabled in libcurl\n");
  return (CURLcode)1;
#endif /* CURL_DISABLE_FTP */
}
