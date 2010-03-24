/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 */

#include "test.h"

#include "memdebug.h"

static char data[]=
#ifdef CURL_DOES_CONVERSIONS
  /* ASCII representation with escape sequences for non-ASCII platforms */
  "\x74\x68\x69\x73\x20\x69\x73\x20\x77\x68\x61\x74\x20\x77\x65\x20\x70"
  "\x6f\x73\x74\x20\x74\x6f\x20\x74\x68\x65\x20\x73\x69\x6c\x6c\x79\x20"
  "\x77\x65\x62\x20\x73\x65\x72\x76\x65\x72\x0a";
#else
  "this is what we post to the silly web server\n";
#endif

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

  return 0;                         /* no more data left to deliver */
}

int test(char *URL)
{
  CURL *curl;
  CURLcode res=CURLE_OK;
  CURLFORMcode formrc;

  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct WriteThis pooh;

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  pooh.readptr = data;
  pooh.sizeleft = strlen(data);

  /* Fill in the file upload field */
  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_COPYNAME, "sendfile",
                        CURLFORM_STREAM, &pooh,
                        CURLFORM_CONTENTSLENGTH, pooh.sizeleft,
                        CURLFORM_FILENAME, "postit2.c",
                        CURLFORM_END);

  if(formrc)
    printf("curl_formadd(1) = %d\n", (int)formrc);

  /* Fill in the filename field */
  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_COPYNAME, "filename",
#ifdef CURL_DOES_CONVERSIONS
                        /* ASCII representation with escape
                           sequences for non-ASCII platforms */
                        CURLFORM_COPYCONTENTS,
                           "\x70\x6f\x73\x74\x69\x74\x32\x2e\x63",
#else
                        CURLFORM_COPYCONTENTS, "postit2.c",
#endif
                        CURLFORM_END);

  if(formrc)
    printf("curl_formadd(2) = %d\n", (int)formrc);

  /* Fill in a submit field too */
  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_COPYNAME, "submit",
#ifdef CURL_DOES_CONVERSIONS
                        /* ASCII representation with escape
                           sequences for non-ASCII platforms */
                        CURLFORM_COPYCONTENTS, "\x73\x65\x6e\x64",
#else
                        CURLFORM_COPYCONTENTS, "send",
#endif
                        CURLFORM_END);

  if(formrc)
    printf("curl_formadd(3) = %d\n", (int)formrc);

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_formfree(formpost);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* Now specify we want to POST data */
  test_setopt(curl, CURLOPT_POST, 1L);

  /* Set the expected POST size */
  test_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)pooh.sizeleft);

  /* we want to use our own read function */
  test_setopt(curl, CURLOPT_READFUNCTION, read_callback);

  /* send a multi-part formpost */
  test_setopt(curl, CURLOPT_HTTPPOST, formpost);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  /* now cleanup the formpost chain */
  curl_formfree(formpost);

  return res;
}
