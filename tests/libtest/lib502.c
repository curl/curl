#include "test.h"

/*
 * Get a single URL without select().
 */

int test(char *URL)
{
  CURL *c;
  CURLM *m;
  CURLMcode res;
  int running=1;

  curl_global_init(CURL_GLOBAL_ALL);
  c = curl_easy_init();
  curl_easy_setopt(c, CURLOPT_URL, URL);
  m = curl_multi_init();

  res = curl_multi_add_handle(m, c);
  while (running) {
    res = curl_multi_perform(m, &running);
    if (running <= 0) {
      fprintf(stderr, "nothing left running.\n");
      break;
    }
  }
  curl_multi_remove_handle(m, c);
  curl_easy_cleanup(c);
  curl_multi_cleanup(m);

  return res;
}

