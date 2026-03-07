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
 * Import and export cookies with COOKIELIST.
 * </DESC>
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for _snprintf() */
#endif
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <curl/curl.h>

#if defined(_MSC_VER) && (_MSC_VER < 1900)
#define snprintf _snprintf
#endif

static int print_cookies(CURL *curl)
{
  CURLcode result;
  struct curl_slist *cookies;
  struct curl_slist *nc;
  int i;

  printf("Cookies, curl knows:\n");
  result = curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);
  if(result != CURLE_OK) {
    fprintf(stderr, "curl curl_easy_getinfo failed: %s\n",
            curl_easy_strerror(result));
    return 1;
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
  curl_slist_free_all(cookies);

  return 0;
}

int main(void)
{
  CURL *curl;
  CURLcode result;

  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result != CURLE_OK)
    return (int)result;

  curl = curl_easy_init();
  if(curl) {
    char nline[512];

    curl_easy_setopt(curl, CURLOPT_URL, "https://www.example.com/");
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, ""); /* start cookie engine */
    result = curl_easy_perform(curl);
    if(result != CURLE_OK) {
      fprintf(stderr, "curl perform failed: %s\n", curl_easy_strerror(result));
      return 1;
    }

    print_cookies(curl);

    printf("Erasing curl's knowledge of cookies!\n");
    curl_easy_setopt(curl, CURLOPT_COOKIELIST, "ALL");

    print_cookies(curl);

    printf("-----------------------------------------------\n"
           "Setting a cookie \"PREF\" via cookie interface:\n");
    /* Netscape format cookie */
    snprintf(nline, sizeof(nline), "%s\t%s\t%s\t%s\t%.0f\t%s\t%s",
             ".example.com", "TRUE", "/", "FALSE",
             difftime(time(NULL) + 31337, (time_t)0),
             "PREF", "hello example, I like you!");
    result = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nline);
    if(result != CURLE_OK) {
      fprintf(stderr, "curl curl_easy_setopt failed: %s\n",
              curl_easy_strerror(result));
      return 1;
    }

    /* HTTP-header style cookie. If you use the Set-Cookie format and do not
       specify a domain then the cookie is sent for any domain and is not
       modified, likely not what you intended. For more information refer to
       the CURLOPT_COOKIELIST documentation.
    */
    snprintf(nline, sizeof(nline),
      "Set-Cookie: OLD_PREF=3d141414bf4209321; "
      "expires=Sun, 17-Jan-2038 19:14:07 GMT; path=/; domain=.example.com");
    result = curl_easy_setopt(curl, CURLOPT_COOKIELIST, nline);
    if(result != CURLE_OK) {
      fprintf(stderr, "curl curl_easy_setopt failed: %s\n",
              curl_easy_strerror(result));
      return 1;
    }

    print_cookies(curl);

    result = curl_easy_perform(curl);
    if(result != CURLE_OK) {
      fprintf(stderr, "curl perform failed: %s\n", curl_easy_strerror(result));
      return 1;
    }

    curl_easy_cleanup(curl);
  }
  else {
    fprintf(stderr, "curl init failed!\n");
    return 1;
  }

  curl_global_cleanup();
  return 0;
}
