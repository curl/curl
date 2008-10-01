/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * $Id$
 *
 * This test case and code is based on the bug recipe Joe Malicki provided for
 * bug report #1871269, fixed on Jan 14 2008 before the 7.18.0 release.
 */

#include "test.h"

#include "memdebug.h"

#define POSTLEN 40960

static size_t myreadfunc(void *ptr, size_t size, size_t nmemb, void *stream)
{
  static size_t total=POSTLEN;
  static char buf[1024];
  (void)stream;

  memset(buf, 'A', sizeof(buf));

  size *= nmemb;
  if (size > total)
    size = total;

  if(size > sizeof(buf))
    size = sizeof(buf);

  memcpy(ptr, buf, size);
  total -= size;
  return size;
}

#define NUM_HEADERS 8
#define SIZE_HEADERS 5000

static char buf[SIZE_HEADERS + 100];

int test(char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_FAILED_INIT;
  int i;
  struct curl_slist *headerlist=NULL, *hl;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();

  if(curl) {
    for (i = 0; i < NUM_HEADERS; i++) {
      int len = sprintf(buf, "Header%d: ", i);
      memset(&buf[len], 'A', SIZE_HEADERS);
      buf[len + SIZE_HEADERS]=0; /* zero terminate */
      hl = curl_slist_append(headerlist,  buf);
      if (!hl)
        goto errout;
      headerlist = hl;
    }
    hl = curl_slist_append(headerlist, "Expect: ");
    if (!hl)
      goto errout;
    headerlist = hl;

    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)POSTLEN);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, myreadfunc);
    res = curl_easy_perform(curl);

errout:
    curl_easy_cleanup(curl);

    curl_slist_free_all(headerlist);
  }
  curl_global_cleanup();

  return (int)res;
}
