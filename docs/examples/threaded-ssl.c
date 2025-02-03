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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * Show the required mutex callback setups for GnuTLS and OpenSSL when using
 * libfetch multi-threaded.
 * </DESC>
 */
/* A multi-threaded example that uses pthreads and fetches 4 remote files at
 * once over HTTPS.
 *
 * Recent versions of OpenSSL and GnuTLS are thread safe by design, assuming
 * support for the underlying OS threading API is built-in. Older revisions
 * of this example demonstrated locking callbacks for the SSL library, which
 * are no longer necessary. An older revision with callbacks can be found at
 * https://github.com/fetch/fetch/blob/fetch-7_88_1/docs/examples/threaded-ssl.c
 */

#define USE_OPENSSL /* or USE_GNUTLS accordingly */

#include <stdio.h>
#include <pthread.h>
#include <fetch/fetch.h>

#define NUMT 4

/* List of URLs to fetch.*/
static const char * const urls[]= {
  "https://www.example.com/",
  "https://www2.example.com/",
  "https://www3.example.com/",
  "https://www4.example.com/",
};

static void *pull_one_url(void *url)
{
  FETCH *fetch;

  fetch = fetch_easy_init();
  fetch_easy_setopt(fetch, FETCHOPT_URL, url);
  /* this example does not verify the server's certificate, which means we
     might be downloading stuff from an impostor */
  fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYPEER, 0L);
  fetch_easy_setopt(fetch, FETCHOPT_SSL_VERIFYHOST, 0L);
  fetch_easy_perform(fetch); /* ignores error */
  fetch_easy_cleanup(fetch);

  return NULL;
}

int main(int argc, char **argv)
{
  pthread_t tid[NUMT];
  int i;
  (void)argc; /* we do not use any arguments in this example */
  (void)argv;

  /* Must initialize libfetch before any threads are started */
  fetch_global_init(FETCH_GLOBAL_ALL);

  for(i = 0; i < NUMT; i++) {
    int error = pthread_create(&tid[i],
                               NULL, /* default attributes please */
                               pull_one_url,
                               (void *)urls[i]);
    if(0 != error)
      fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, error);
    else
      fprintf(stderr, "Thread %d, gets %s\n", i, urls[i]);
  }

  /* now wait for all threads to terminate */
  for(i = 0; i < NUMT; i++) {
    pthread_join(tid[i], NULL);
    fprintf(stderr, "Thread %d terminated\n", i);
  }

  return 0;
}
