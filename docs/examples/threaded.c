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
 * A multi-threaded program using pthreads to fetch several files at once
 * </DESC>
 */
/* A multi-threaded example that uses pthreads and fetches 4 remote files at
 * once over HTTPS.
 *
 * Recent versions of OpenSSL and GnuTLS are thread-safe by design, assuming
 * support for the underlying OS threading API is built-in. Older revisions
 * of this example demonstrated locking callbacks for the SSL library, which
 * are no longer necessary. An older revision with callbacks can be found at
 * https://github.com/curl/curl/blob/curl-7_88_1/docs/examples/threaded-ssl.c
 */

/* Requires: HAVE_PTHREAD_H */
/* Also requires TLS support to run */

#include <stdio.h>

#include <pthread.h>

#include <curl/curl.h>

#define NUMT 4

/* List of URLs to fetch. */
static const char * const urls[NUMT] = {
  "https://curl.se/",
  "ftp://example.com/",
  "https://example.net/",
  "www.example"
};

struct targ {
  const char *url;
};

static void *pull_one_url(void *p)
{
  CURL *curl;

  curl = curl_easy_init();
  if(curl) {
    struct targ *targ = p;
    curl_easy_setopt(curl, CURLOPT_URL, targ->url);
    (void)curl_easy_perform(curl); /* ignores error */
    curl_easy_cleanup(curl);
  }

  return NULL;
}

/*
   int pthread_create(pthread_t *new_thread_ID,
                      const pthread_attr_t *attr,
                      void * (*start_func)(void *), void *arg);
*/

int main(void)
{
  CURLcode result;
  pthread_t tid[NUMT];
  struct targ targs[NUMT];
  int i;

  /* Must initialize libcurl before any threads are started */
  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  for(i = 0; i < NUMT; i++) {
    int error;
    targs[i].url = urls[i];
    error = pthread_create(&tid[i],
                           NULL, /* default attributes please */
                           pull_one_url,
                           (void *)&targs[i]);
    if(error)
      fprintf(stderr, "Could not run thread number %d, errno %d\n", i, error);
    else
      fprintf(stderr, "Thread %d, gets %s\n", i, urls[i]);
  }

  /* now wait for all threads to terminate */
  for(i = 0; i < NUMT; i++) {
    pthread_join(tid[i], NULL);
    fprintf(stderr, "Thread %d terminated\n", i);
  }

  curl_global_cleanup();

  return 0;
}
