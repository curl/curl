/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
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
#ifdef LIB587
  (void)ptr;
  (void)size;
  (void)nmemb;
  (void)userp;
  return CURL_READFUNC_ABORT;
#else

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
#endif
}

static int once(char *URL, bool oldstyle)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  CURLFORMcode formrc;

  struct curl_httppost *formpost = NULL;
  struct curl_httppost *lastptr = NULL;
  struct WriteThis pooh;
  struct WriteThis pooh2;

  pooh.readptr = data;
  pooh.sizeleft = strlen(data);

  /* Fill in the file upload field */
  if(oldstyle) {
    formrc = curl_formadd(&formpost,
                          &lastptr,
                          CURLFORM_COPYNAME, "sendfile",
                          CURLFORM_STREAM, &pooh,
                          CURLFORM_CONTENTSLENGTH, (long)pooh.sizeleft,
                          CURLFORM_FILENAME, "postit2.c",
                          CURLFORM_END);
  }
  else {
    /* new style */
    formrc = curl_formadd(&formpost,
                          &lastptr,
                          CURLFORM_COPYNAME, "sendfile alternative",
                          CURLFORM_STREAM, &pooh,
                          CURLFORM_CONTENTLEN, (curl_off_t)pooh.sizeleft,
                          CURLFORM_FILENAME, "file name 2",
                          CURLFORM_END);
  }

  if(formrc)
    printf("curl_formadd(1) = %d\n", (int)formrc);

  /* Now add the same data with another name and make it not look like
     a file upload but still using the callback */

  pooh2.readptr = data;
  pooh2.sizeleft = strlen(data);

  /* Fill in the file upload field */
  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_COPYNAME, "callbackdata",
                        CURLFORM_STREAM, &pooh2,
                        CURLFORM_CONTENTSLENGTH, (long)pooh2.sizeleft,
                        CURLFORM_END);

  if(formrc)
    printf("curl_formadd(2) = %d\n", (int)formrc);

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
    printf("curl_formadd(3) = %d\n", (int)formrc);

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
                        CURLFORM_CONTENTTYPE, "text/plain",
                        CURLFORM_END);

  if(formrc)
    printf("curl_formadd(4) = %d\n", (int)formrc);

  formrc = curl_formadd(&formpost, &lastptr,
                        CURLFORM_COPYNAME, "somename",
                        CURLFORM_BUFFER, "somefile.txt",
                        CURLFORM_BUFFERPTR, "blah blah",
                        CURLFORM_BUFFERLENGTH, (long)9,
                        CURLFORM_END);

  if(formrc)
    printf("curl_formadd(5) = %d\n", (int)formrc);

  curl = curl_easy_init();
  if(!curl) {
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

  /* now cleanup the formpost chain */
  curl_formfree(formpost);

  return res;
}

int test(char *URL)
{
  int res;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  res = once(URL, TRUE); /* old */
  if(!res)
    res = once(URL, FALSE); /* new */

  curl_global_cleanup();

  return res;
}
