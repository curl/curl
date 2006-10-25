#include "test.h"

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  (void)ptr;
  (void)size;
  (void)nmemb;
  (void)userp;
  return CURL_READFUNC_ABORT;
}

int test(char *URL)
{
  CURL *curl;
  CURLcode res=CURLE_OK;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  curl_easy_setopt(curl, CURLOPT_URL, URL);

  /* Now specify we want to POST data */
  curl_easy_setopt(curl, CURLOPT_POST, TRUE);

  /* Set the expected POST size */
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 1);

  /* we want to use our own read function */
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

  /* pointer to pass to our read function */
  curl_easy_setopt(curl, CURLOPT_INFILE, NULL);

  /* get verbose debug output please */
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

  /* include headers in the output */
  curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)res;
}
