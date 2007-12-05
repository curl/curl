/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * argv1 = URL
 * argv2 = proxy
 * argv3 = proxyuser:password
 */

#include "test.h"

#define UPLOADTHIS "this is the blurb we want to upload\n"

static size_t readcallback(void  *ptr,
                           size_t size,
                           size_t nmemb,
                           void *stream)
{
  (void)stream; /* unused */
  if(size * nmemb > strlen(UPLOADTHIS)) {
    strcpy(ptr, UPLOADTHIS);
    return strlen(UPLOADTHIS);
  }
  return 0;
}

int test(char *URL)
{
  CURLcode res;
  CURL *curl;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  curl_easy_setopt(curl, CURLOPT_URL, URL);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
  curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);
#ifdef LIB548
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, UPLOADTHIS);
#else
  /* 547 style */
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, readcallback);
#endif
  curl_easy_setopt(curl, CURLOPT_POST, 1);
  curl_easy_setopt(curl, CURLOPT_PROXY, libtest_arg2);
  curl_easy_setopt(curl, CURLOPT_PROXYUSERPWD, libtest_arg3);
  curl_easy_setopt(curl, CURLOPT_PROXYAUTH,
                   CURLAUTH_NTLM | CURLAUTH_DIGEST | CURLAUTH_BASIC );

  res = curl_easy_perform(curl);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}

