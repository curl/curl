/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "test.h"

#include "memdebug.h"

static char data[]=
  "dummy\n";

struct WriteThis {
  char *readptr;
  curl_off_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
#ifdef LIB644
  static int count = 0;
  (void)ptr;
  (void)size;
  (void)nmemb;
  (void)userp;
  switch(count++) {
  case 0: /* Return a single byte. */
    *ptr = '\n';
    return 1;
  case 1: /* Request abort. */
    return CURL_READFUNC_ABORT;
  }
  printf("Wrongly called >2 times\n");
  exit(1); /* trigger major failure */
#else

  struct WriteThis *pooh = (struct WriteThis *)userp;
  int eof = !*pooh->readptr;

  if(size*nmemb < 1)
    return 0;

#ifndef LIB645
  eof = pooh->sizeleft <= 0;
  if(!eof)
    pooh->sizeleft--;
#endif

  if(!eof) {
    *ptr = *pooh->readptr;           /* copy one single byte */
    pooh->readptr++;                 /* advance pointer */
    return 1;                        /* we return 1 byte at a time! */
  }

  return 0;                         /* no more data left to deliver */
#endif
}

static int once(char *URL, bool oldstyle)
{
  CURL *curl;
  CURLcode res = CURLE_OK;

  curl_mime *mime = NULL;
  curl_mimepart *part = NULL;
  struct WriteThis pooh;
  struct WriteThis pooh2;
  curl_off_t datasize = -1;

  pooh.readptr = data;
#ifndef LIB645
  datasize = (curl_off_t)strlen(data);
#endif
  pooh.sizeleft = datasize;

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  mime = curl_mime_init(curl);
  if(!mime) {
    fprintf(stderr, "curl_mime_init() failed\n");
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  part = curl_mime_addpart(mime);
  if(!part) {
    fprintf(stderr, "curl_mime_addpart(1) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* Fill in the file upload part */
  if(oldstyle) {
    res = curl_mime_name(part, "sendfile");
    if(!res)
      res = curl_mime_data_cb(part, datasize, read_callback,
                              NULL, NULL, &pooh);
    if(!res)
      res = curl_mime_filename(part, "postit2.c");
  }
  else {
    /* new style */
    res = curl_mime_name(part, "sendfile alternative");
    if(!res)
      res = curl_mime_data_cb(part, datasize, read_callback,
                              NULL, NULL, &pooh);
    if(!res)
      res = curl_mime_filename(part, "file name 2");
  }

  if(res)
    printf("curl_mime_xxx(1) = %s\n", curl_easy_strerror(res));

  /* Now add the same data with another name and make it not look like
     a file upload but still using the callback */

  pooh2.readptr = data;
#ifndef LIB645
  datasize = (curl_off_t)strlen(data);
#endif
  pooh2.sizeleft = datasize;

  part = curl_mime_addpart(mime);
  if(!part) {
    fprintf(stderr, "curl_mime_addpart(2) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  /* Fill in the file upload part */
  res = curl_mime_name(part, "callbackdata");
  if(!res)
    res = curl_mime_data_cb(part, datasize, read_callback,
                            NULL, NULL, &pooh2);

  if(res)
    printf("curl_mime_xxx(2) = %s\n", curl_easy_strerror(res));

  part = curl_mime_addpart(mime);
  if(!part) {
    fprintf(stderr, "curl_mime_addpart(3) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* Fill in the filename field */
  res = curl_mime_name(part, "filename");
  if(!res)
    res = curl_mime_data(part, "postit2.c",
                         CURL_ZERO_TERMINATED);

  if(res)
    printf("curl_mime_xxx(3) = %s\n", curl_easy_strerror(res));

  /* Fill in a submit field too */
  part = curl_mime_addpart(mime);
  if(!part) {
    fprintf(stderr, "curl_mime_addpart(4) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  res = curl_mime_name(part, "submit");
  if(!res)
    res = curl_mime_data(part, "send",
                         CURL_ZERO_TERMINATED);

  if(res)
    printf("curl_mime_xxx(4) = %s\n", curl_easy_strerror(res));

  part = curl_mime_addpart(mime);
  if(!part) {
    fprintf(stderr, "curl_mime_addpart(5) failed\n");
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }
  res = curl_mime_name(part, "somename");
  if(!res)
    res = curl_mime_filename(part, "somefile.txt");
  if(!res)
    res = curl_mime_data(part, "blah blah", 9);

  if(res)
    printf("curl_mime_xxx(5) = %s\n", curl_easy_strerror(res));

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* send a multi-part mimepost */
  test_setopt(curl, CURLOPT_MIMEPOST, mime);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* include headers in the output */
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);

  /* now cleanup the mimepost structure */
  curl_mime_free(mime);

  return res;
}

static int cyclic_add(void)
{
  CURL *easy = curl_easy_init();
  curl_mime *mime = curl_mime_init(easy);
  curl_mimepart *part = curl_mime_addpart(mime);
  CURLcode a1 = curl_mime_subparts(part, mime);

  if(a1 == CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mime *submime = curl_mime_init(easy);
    curl_mimepart *subpart = curl_mime_addpart(submime);

    curl_mime_subparts(part, submime);
    a1 = curl_mime_subparts(subpart, mime);
  }

  curl_mime_free(mime);
  curl_easy_cleanup(easy);
  if(a1 != CURLE_BAD_FUNCTION_ARGUMENT)
    /* that should have failed */
    return 1;

  return 0;
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

  if(!res)
    res = cyclic_add();

  curl_global_cleanup();

  return res;
}
