#include "test.h"

static const char *post[]={
  "one",
  "two",
  "three",
  "and a final longer crap: four",
  NULL
};


struct WriteThis {
  int counter;
};

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
  const char *data;

  if(size*nmemb < 1)
    return 0;

  data = post[pooh->counter];

  if(data) {
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    pooh->counter++; /* advance pointer */
    return len;
  }
  return 0;                         /* no more data left to deliver */
}

int test(char *URL)
{
  CURL *curl;
  CURLcode res=CURLE_OK;
  struct curl_slist *slist = NULL;

  struct WriteThis pooh;
  pooh.counter = 0;

  slist = curl_slist_append(slist, "Transfer-Encoding: chunked");

  curl = curl_easy_init();
  if(curl) {
    /* First set the URL that is about to receive our POST. */
    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* Now specify we want to POST data */
    curl_easy_setopt(curl, CURLOPT_POST, TRUE);

    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

    /* pointer to pass to our read function */
    curl_easy_setopt(curl, CURLOPT_INFILE, &pooh);

    /* get verbose debug output please */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    /* include headers in the output */
    curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);

    /* enforce chunked transfer by setting the header */
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* clean up the headers list */
    curl_slist_free_all(slist);

  }
  return res;
}
