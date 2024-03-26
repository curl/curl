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
 * Preload domains to HSTS
 * </DESC>
 */
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

struct entry {
  const char *name;
  const char *exp;
};

static const struct entry preload_hosts[] = {
  { "example.com", "20370320 01:02:03" },
  { "curl.se",     "20370320 03:02:01" },
  { NULL, NULL } /* end of list marker */
};

struct state {
  int index;
};

/* "read" is from the point of the library, it wants data from us. One domain
   entry per invoke. */
static CURLSTScode hstsread(CURL *easy, struct curl_hstsentry *e,
                            void *userp)
{
  const char *host;
  const char *expire;
  struct state *s = (struct state *)userp;
  (void)easy;
  host = preload_hosts[s->index].name;
  expire = preload_hosts[s->index++].exp;

  if(host && (strlen(host) < e->namelen)) {
    strcpy(e->name, host);
    e->includeSubDomains = 0;
    strcpy(e->expire, expire);
    fprintf(stderr, "HSTS preload '%s' until '%s'\n", host, expire);
  }
  else
    return CURLSTS_DONE;
  return CURLSTS_OK;
}

static CURLSTScode hstswrite(CURL *easy, struct curl_hstsentry *e,
                             struct curl_index *i, void *userp)
{
  (void)easy;
  (void)userp; /* we have no custom input */
  printf("[%u/%u] %s %s\n", (unsigned int)i->index, (unsigned int)i->total,
         e->name, e->expire);
  return CURLSTS_OK;
}

int main(void)
{
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if(curl) {
    struct state st = {0};

    /* enable HSTS for this handle */
    curl_easy_setopt(curl, CURLOPT_HSTS_CTRL, (long)CURLHSTS_ENABLE);

    /* function to call at first to populate the cache before the transfer */
    curl_easy_setopt(curl, CURLOPT_HSTSREADFUNCTION, hstsread);
    curl_easy_setopt(curl, CURLOPT_HSTSREADDATA, &st);

    /* function to call after transfer to store the new state of the HSTS
       cache */
    curl_easy_setopt(curl, CURLOPT_HSTSWRITEFUNCTION, hstswrite);
    curl_easy_setopt(curl, CURLOPT_HSTSWRITEDATA, NULL);

    /* use the domain with HTTP but due to the preload, it should do the
       transfer using HTTPS */
    curl_easy_setopt(curl, CURLOPT_URL, "http://curl.se");

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* Perform the request, res gets the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return 0;
}
