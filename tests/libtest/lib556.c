/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 */

#include "test.h"

#include "memdebug.h"

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
  curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

  res = curl_easy_perform(curl);

  if(!res) {
    /* we are connected, now get a HTTP document the raw way */
    const char *request = "GET /556 HTTP/1.2\r\n"
      "Host: ninja\r\n\r\n";
    size_t iolen;
    char buf[1024];

    res = curl_easy_send(curl, request, strlen(request), &iolen);

    if(!res) {
      /* we assume that sending always work */
      int total=0;

      do {
        /* busy-read like crazy */
        res = curl_easy_recv(curl, buf, 1024, &iolen);

        if(iolen)
          /* send received stuff to stdout */
          write(STDOUT_FILENO, buf, iolen);

        total += iolen;

      } while(((res == CURLE_OK) || (res == CURLE_AGAIN)) && (total < 129));
    }
  }


  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}

