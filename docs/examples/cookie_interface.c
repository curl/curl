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
 * Import and export cookies with COOKIELIST.
 * </DESC>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <fetch/fetch.h>
#include <fetch/mprintf.h>

static void
print_cookies(FETCH *fetch)
{
  FETCHcode res;
  struct fetch_slist *cookies;
  struct fetch_slist *nc;
  int i;

  printf("Cookies, fetch knows:\n");
  res = fetch_easy_getinfo(fetch, FETCHINFO_COOKIELIST, &cookies);
  if(res != FETCHE_OK) {
    fprintf(stderr, "Curl fetch_easy_getinfo failed: %s\n",
            fetch_easy_strerror(res));
    exit(1);
  }
  nc = cookies;
  i = 1;
  while(nc) {
    printf("[%d]: %s\n", i, nc->data);
    nc = nc->next;
    i++;
  }
  if(i == 1) {
    printf("(none)\n");
  }
  fetch_slist_free_all(cookies);
}

int
main(void)
{
  FETCH *fetch;
  FETCHcode res;

  fetch_global_init(FETCH_GLOBAL_ALL);
  fetch = fetch_easy_init();
  if(fetch) {
    char nline[512];

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://www.example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_COOKIEFILE, ""); /* start cookie engine */
    res = fetch_easy_perform(fetch);
    if(res != FETCHE_OK) {
      fprintf(stderr, "Curl perform failed: %s\n", fetch_easy_strerror(res));
      return 1;
    }

    print_cookies(fetch);

    printf("Erasing fetch's knowledge of cookies!\n");
    fetch_easy_setopt(fetch, FETCHOPT_COOKIELIST, "ALL");

    print_cookies(fetch);

    printf("-----------------------------------------------\n"
           "Setting a cookie \"PREF\" via cookie interface:\n");
    /* Netscape format cookie */
    fetch_msnprintf(nline, sizeof(nline), "%s\t%s\t%s\t%s\t%.0f\t%s\t%s",
                   ".example.com", "TRUE", "/", "FALSE",
                   difftime(time(NULL) + 31337, (time_t)0),
                   "PREF", "hello example, i like you!");
    res = fetch_easy_setopt(fetch, FETCHOPT_COOKIELIST, nline);
    if(res != FETCHE_OK) {
      fprintf(stderr, "Curl fetch_easy_setopt failed: %s\n",
              fetch_easy_strerror(res));
      return 1;
    }

    /* HTTP-header style cookie. If you use the Set-Cookie format and do not
       specify a domain then the cookie is sent for any domain and is not
       modified, likely not what you intended. For more information refer to
       the FETCHOPT_COOKIELIST documentation.
    */
    fetch_msnprintf(nline, sizeof(nline),
      "Set-Cookie: OLD_PREF=3d141414bf4209321; "
      "expires=Sun, 17-Jan-2038 19:14:07 GMT; path=/; domain=.example.com");
    res = fetch_easy_setopt(fetch, FETCHOPT_COOKIELIST, nline);
    if(res != FETCHE_OK) {
      fprintf(stderr, "Curl fetch_easy_setopt failed: %s\n",
              fetch_easy_strerror(res));
      return 1;
    }

    print_cookies(fetch);

    res = fetch_easy_perform(fetch);
    if(res != FETCHE_OK) {
      fprintf(stderr, "Curl perform failed: %s\n", fetch_easy_strerror(res));
      return 1;
    }

    fetch_easy_cleanup(fetch);
  }
  else {
    fprintf(stderr, "Curl init failed!\n");
    return 1;
  }

  fetch_global_cleanup();
  return 0;
}
