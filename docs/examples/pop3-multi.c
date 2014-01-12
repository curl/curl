/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include <stdio.h>
#include <curl/curl.h>

/* This is a simple example showing how to retrieve mail using libcurl's POP3
 * capabilities. It builds on the pop3-retr.c example to demonstrate how to use
 * libcurl's multi interface.
 *
 * Note that this example requires libcurl 7.20.0 or above.
 */

#define MULTI_PERFORM_HANG_TIMEOUT 60 * 1000

static struct timeval tvnow(void)
{
  struct timeval now;

  /* time() returns the value of time in seconds since the epoch */
  now.tv_sec = (long)time(NULL);
  now.tv_usec = 0;

  return now;
}

static long tvdiff(struct timeval newer, struct timeval older)
{
  return (newer.tv_sec - older.tv_sec) * 1000 +
    (newer.tv_usec - older.tv_usec) / 1000;
}

int main(void)
{
  CURL *curl;
  CURLM *mcurl;
  int still_running = 1;
  struct timeval mp_start;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  curl = curl_easy_init();
  if(!curl)
    return 1;

  mcurl = curl_multi_init();
  if(!mcurl)
    return 2;

  /* Set username and password */
  curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
  curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");

  /* This will retreive message 1 from the user's mailbox */
  curl_easy_setopt(curl, CURLOPT_URL, "pop3://pop.example.com/1");

  /* Tell the multi stack about our easy handle */
  curl_multi_add_handle(mcurl, curl);

  /* Record the start time which we can use later */
  mp_start = tvnow();

  /* We start some action by calling perform right away */
  curl_multi_perform(mcurl, &still_running);

  while(still_running) {
    struct timeval timeout;
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;
    int rc;

    long curl_timeo = -1;

    /* Initialise the file descriptors */
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    /* Set a suitable timeout to play around with */
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    curl_multi_timeout(mcurl, &curl_timeo);
    if(curl_timeo >= 0) {
      timeout.tv_sec = curl_timeo / 1000;
      if(timeout.tv_sec > 1)
        timeout.tv_sec = 1;
      else
        timeout.tv_usec = (curl_timeo % 1000) * 1000;
    }

    /* Get file descriptors from the transfers */
    curl_multi_fdset(mcurl, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* In a real-world program you OF COURSE check the return code of the
       function calls. On success, the value of maxfd is guaranteed to be
       greater or equal than -1. We call select(maxfd + 1, ...), specially in
       case of (maxfd == -1), we call select(0, ...), which is basically equal
       to sleep. */
    rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

    if(tvdiff(tvnow(), mp_start) > MULTI_PERFORM_HANG_TIMEOUT) {
      fprintf(stderr,
              "ABORTING: Since it seems that we would have run forever.\n");
      break;
    }

    switch(rc) {
    case -1:  /* select error */
      break;
    case 0:   /* timeout */
    default:  /* action */
      curl_multi_perform(mcurl, &still_running);
      break;
    }
  }

  /* Always cleanup */
  curl_multi_remove_handle(mcurl, curl);
  curl_multi_cleanup(mcurl);
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return 0;
}
