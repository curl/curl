#include "test.h"

static char data[]="this is what we post to the silly web server\n";

struct WriteThis {
  char *readptr;
  size_t sizeleft;
};

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;

  if(size*nmemb < 1)
    return 0;

  if(pooh->sizeleft) {
    *(char *)ptr = pooh->readptr[0]; /* copy one single byte */
    pooh->readptr++;                 /* advance pointer */
    pooh->sizeleft--;                /* less data left */
    return 1;                        /* we return 1 byte at a time! */
  }

  return -1;                         /* no more data left to deliver */
}

int test(char *URL)
{
  CURL *curl;
  CURLcode res=CURLE_OK;

  struct WriteThis pooh;

  pooh.readptr = data;
  pooh.sizeleft = strlen(data);

  curl = curl_easy_init();
  if(curl) {
    /* First set the URL that is about to receive our POST. */
    curl_easy_setopt(curl, CURLOPT_URL, URL);

    /* Now specify we want to POST data */
    curl_easy_setopt(curl, CURLOPT_POST, TRUE);

    /* Set the expected POST size */
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)pooh.sizeleft);

    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

    /* pointer to pass to our read function */
    curl_easy_setopt(curl, CURLOPT_INFILE, &pooh);

    /* get verbose debug output please */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    /* include headers in the output */
    curl_easy_setopt(curl, CURLOPT_HEADER, TRUE);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  return res;
}
