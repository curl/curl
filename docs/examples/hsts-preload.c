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
 * Preload domains to HSTS
 * </DESC>
 */
#include <stdio.h>
#include <string.h>
#include <fetch/fetch.h>

struct entry
{
  const char *name;
  const char *exp;
};

static const struct entry preload_hosts[] = {
    {"example.com", "20370320 01:02:03"},
    {"fetch.se", "20370320 03:02:01"},
    {NULL, NULL} /* end of list marker */
};

struct state
{
  int index;
};

/* "read" is from the point of the library, it wants data from us. One domain
   entry per invoke. */
static FETCHSTScode hstsread(FETCH *easy, struct fetch_hstsentry *e,
                             void *userp)
{
  const char *host;
  const char *expire;
  struct state *s = (struct state *)userp;
  (void)easy;
  host = preload_hosts[s->index].name;
  expire = preload_hosts[s->index++].exp;

  if (host && (strlen(host) < e->namelen))
  {
    strcpy(e->name, host);
    e->includeSubDomains = 0;
    strcpy(e->expire, expire);
    fprintf(stderr, "HSTS preload '%s' until '%s'\n", host, expire);
  }
  else
    return FETCHSTS_DONE;
  return FETCHSTS_OK;
}

static FETCHSTScode hstswrite(FETCH *easy, struct fetch_hstsentry *e,
                              struct fetch_index *i, void *userp)
{
  (void)easy;
  (void)userp; /* we have no custom input */
  printf("[%u/%u] %s %s\n", (unsigned int)i->index, (unsigned int)i->total,
         e->name, e->expire);
  return FETCHSTS_OK;
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch = fetch_easy_init();
  if (fetch)
  {
    struct state st = {0};

    /* enable HSTS for this handle */
    fetch_easy_setopt(fetch, FETCHOPT_HSTS_CTRL, (long)FETCHHSTS_ENABLE);

    /* function to call at first to populate the cache before the transfer */
    fetch_easy_setopt(fetch, FETCHOPT_HSTSREADFUNCTION, hstsread);
    fetch_easy_setopt(fetch, FETCHOPT_HSTSREADDATA, &st);

    /* function to call after transfer to store the new state of the HSTS
       cache */
    fetch_easy_setopt(fetch, FETCHOPT_HSTSWRITEFUNCTION, hstswrite);
    fetch_easy_setopt(fetch, FETCHOPT_HSTSWRITEDATA, NULL);

    /* use the domain with HTTP but due to the preload, it should do the
       transfer using HTTPS */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "http://fetch.se");

    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    /* Perform the request, res gets the return code */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
