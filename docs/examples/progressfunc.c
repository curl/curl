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
 * Use the progress callbacks, old and/or new one depending on available
 * libcurl version.
 * </DESC>
 */
#include <stdio.h>
#include <curl/curl.h>

#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL     3000000
#define STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES         6000

struct myprogress {
  curl_off_t lastruntime; /* type depends on version, see above */
  CURL *curl;
};

/* this is how the CURLOPT_XFERINFOFUNCTION callback works */
static int xferinfo(void *p,
                    curl_off_t dltotal, curl_off_t dlnow,
                    curl_off_t ultotal, curl_off_t ulnow)
{
  struct myprogress *myp = (struct myprogress *)p;
  CURL *curl = myp->curl;
  curl_off_t curtime = 0;

  curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &curtime);

  /* under certain circumstances it may be desirable for certain functionality
     to only run every N seconds, in order to do this the transaction time can
     be used */
  if((curtime - myp->lastruntime) >= MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL) {
    myp->lastruntime = curtime;
    fprintf(stderr, "TOTAL TIME: %" CURL_FORMAT_CURL_OFF_T
            ".%06" CURL_FORMAT_CURL_OFF_T "\r\n",
            curtime / 1000000,
            curtime % 1000000);
  }

  fprintf(stderr,
          "UP: "
          "%" CURL_FORMAT_CURL_OFF_T " of %" CURL_FORMAT_CURL_OFF_T "  "
          "DOWN: "
          "%" CURL_FORMAT_CURL_OFF_T " of %" CURL_FORMAT_CURL_OFF_T "\r\n",
          ulnow, ultotal,
          dlnow, dltotal);

  if(dlnow > STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES)
    return 1;
  return 0;
}

int main(void)
{
  CURL *curl;

  CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
  if(res)
    return (int)res;

  curl = curl_easy_init();
  if(curl) {
    struct myprogress prog;

    prog.lastruntime = 0;
    prog.curl = curl;

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");

    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo);
    /* pass the struct pointer into the xferinfo function */
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &prog);

    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
    res = curl_easy_perform(curl);

    if(res != CURLE_OK)
      fprintf(stderr, "%s\n", curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return (int)res;
}
