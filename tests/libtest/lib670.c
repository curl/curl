/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <time.h>

#include "test.h"

#include "memdebug.h"

#define PAUSE_TIME      2


static const char name[] = "field";

struct ReadThis {
  CURL *easy;
  time_t origin;
  int count;
};


static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct ReadThis *pooh = (struct ReadThis *) userp;
  time_t delta;

  if(size * nmemb < 1)
    return 0;

  switch(pooh->count++) {
  case 0:
    *ptr = '\x41'; /* ASCII A. */
    return 1;
  case 1:
    pooh->origin = time(NULL);
    return CURL_READFUNC_PAUSE;
  case 2:
    delta = time(NULL) - pooh->origin;
    *ptr = delta >= PAUSE_TIME? '\x42': '\x41'; /* ASCII A or B. */
    return 1;
  case 3:
    return 0;
  }
  fprintf(stderr, "Read callback called after EOF\n");
  exit(1);
}

#if !defined(LIB670) && !defined(LIB672)
static int xferinfo(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                    curl_off_t ultotal, curl_off_t ulnow)
{
  struct ReadThis *pooh = (struct ReadThis *) clientp;

  (void) dltotal;
  (void) dlnow;
  (void) ultotal;
  (void) ulnow;

  if(pooh->origin) {
    time_t delta = time(NULL) - pooh->origin;

    if(delta >= 4 * PAUSE_TIME) {
      fprintf(stderr, "unpausing failed: drain problem?\n");
      return CURLE_ABORTED_BY_CALLBACK;
    }

    if(delta >= PAUSE_TIME)
      curl_easy_pause(pooh->easy, CURLPAUSE_CONT);
  }

  return 0;
}
#endif

int test(char *URL)
{
#if defined(LIB670) || defined(LIB671)
  curl_mime *mime = NULL;
  curl_mimepart *part;
#else
  CURLFORMcode formrc;
  struct curl_httppost *formpost = NULL;
  struct curl_httppost *lastptr = NULL;
#endif
#if defined(LIB670) || defined(LIB672)
  CURLM *multi = NULL;
  CURLMcode mres;
  CURLMsg *msg;
  int msgs_left;
  int still_running = 0;
#endif

  struct ReadThis pooh;
  CURLcode result;
  int res = TEST_ERR_FAILURE;

  /*
   * Check proper pausing/unpausing from a mime or form read callback.
   */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  pooh.origin = (time_t) 0;
  pooh.count = 0;
  pooh.easy = curl_easy_init();

  /* First set the URL that is about to receive our POST. */
  test_setopt(pooh.easy, CURLOPT_URL, URL);

  /* get verbose debug output please */
  test_setopt(pooh.easy, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(pooh.easy, CURLOPT_HEADER, 1L);

#if defined(LIB670) || defined(LIB671)
  /* Build the mime tree. */
  mime = curl_mime_init(pooh.easy);
  part = curl_mime_addpart(mime);
  result = curl_mime_name(part, name);
  if(!result)
    res = curl_mime_data_cb(part, (curl_off_t) 2, read_callback,
                            NULL, NULL, &pooh);

  if(result) {
    fprintf(stderr,
            "Something went wrong when building the mime structure: %d\n",
            (int) result);
    goto test_cleanup;
  }

  /* Bind mime data to its easy handle. */
  if(!res)
    test_setopt(pooh.easy, CURLOPT_MIMEPOST, mime);
#else
  /* Build the form. */
  formrc = curl_formadd(&formpost, &lastptr,
                        CURLFORM_COPYNAME, name,
                        CURLFORM_STREAM, &pooh,
                        CURLFORM_CONTENTLEN, (curl_off_t) 2,
                        CURLFORM_END);
  if(formrc) {
    fprintf(stderr, "curl_formadd() = %d\n", (int) formrc);
    goto test_cleanup;
  }

  /* We want to use our own read function. */
  test_setopt(pooh.easy, CURLOPT_READFUNCTION, read_callback);

  /* Send a multi-part formpost. */
  test_setopt(pooh.easy, CURLOPT_HTTPPOST, formpost);
#endif

#if defined(LIB670) || defined(LIB672)
  /* Use the multi interface. */
  multi = curl_multi_init();
  mres = curl_multi_add_handle(multi, pooh.easy);
  while(!mres) {
    struct timeval timeout;
    int rc = 0;
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcept;
    int maxfd = -1;

    mres = curl_multi_perform(multi, &still_running);
    if(!still_running || mres != CURLM_OK)
      break;

    if(pooh.origin) {
      time_t delta = time(NULL) - pooh.origin;

      if(delta >= 4 * PAUSE_TIME) {
        fprintf(stderr, "unpausing failed: drain problem?\n");
        res = CURLE_OPERATION_TIMEDOUT;
        break;
      }

      if(delta >= PAUSE_TIME)
        curl_easy_pause(pooh.easy, CURLPAUSE_CONT);
    }

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcept);
    timeout.tv_sec = 0;
    timeout.tv_usec = 1000000 * PAUSE_TIME / 10;
    mres = curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcept, &maxfd);
    if(mres)
      break;
#if defined(WIN32) || defined(_WIN32)
    if(maxfd == -1)
      Sleep(100);
    else
#endif
    rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcept, &timeout);
    if(rc == -1) {
      fprintf(stderr, "Select error\n");
      break;
    }
  }

  if(mres != CURLM_OK)
    for(;;) {
      msg = curl_multi_info_read(multi, &msgs_left);
      if(!msg)
        break;
      if(msg->msg == CURLMSG_DONE) {
        result = msg->data.result;
        res = (int) result;
      }
    }

  curl_multi_remove_handle(multi, pooh.easy);
  curl_multi_cleanup(multi);

#else
  /* Use the easy interface. */
  test_setopt(pooh.easy, CURLOPT_XFERINFODATA, &pooh);
  test_setopt(pooh.easy, CURLOPT_XFERINFOFUNCTION, xferinfo);
  test_setopt(pooh.easy, CURLOPT_NOPROGRESS, 0L);
  result = curl_easy_perform(pooh.easy);
  res = (int) result;
#endif


test_cleanup:
  curl_easy_cleanup(pooh.easy);
#if defined(LIB670) || defined(LIB671)
  curl_mime_free(mime);
#else
  curl_formfree(formpost);
#endif

  curl_global_cleanup();
  return res;
}
