/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

int test(char *URL)
{
  CURLM *cm = NULL;
  CURLSH *sh = NULL;
  CURL *ch = NULL;
  int unfinished;

  cm = curl_multi_init();
  if(!cm)
    return 1;
  sh = curl_share_init();
  if(!sh)
    goto cleanup;

  curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
  curl_share_setopt(sh, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);

  ch = curl_easy_init();
  if(!ch)
    goto cleanup;

  curl_easy_setopt(ch, CURLOPT_SHARE, sh);
  curl_easy_setopt(ch, CURLOPT_URL, URL);
  curl_easy_setopt(ch, CURLOPT_COOKIEFILE, "log/cookies1905");
  curl_easy_setopt(ch, CURLOPT_COOKIEJAR, "log/cookies1905");

  curl_multi_add_handle(cm, ch);

  unfinished = 1;
  while(unfinished) {
    int MAX = 0;
    long max_tout;
    fd_set R, W, E;
    struct timeval timeout;

    FD_ZERO(&R);
    FD_ZERO(&W);
    FD_ZERO(&E);
    curl_multi_perform(cm, &unfinished);

    curl_multi_fdset(cm, &R, &W, &E, &MAX);
    curl_multi_timeout(cm, &max_tout);

    if(max_tout > 0) {
      timeout.tv_sec = max_tout / 1000;
      timeout.tv_usec = (max_tout % 1000) * 1000;
    }
    else {
      timeout.tv_sec = 0;
      timeout.tv_usec = 1000;
    }

    select(MAX + 1, &R, &W, &E, &timeout);
  }

  curl_easy_setopt(ch, CURLOPT_COOKIELIST, "FLUSH");
  curl_easy_setopt(ch, CURLOPT_SHARE, NULL);

  curl_multi_remove_handle(cm, ch);
  cleanup:
  curl_easy_cleanup(ch);
  curl_share_cleanup(sh);
  curl_multi_cleanup(cm);
  curl_global_cleanup();

  return 0;
}
