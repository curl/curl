/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
/* <DESC>
 * HTTP PUT upload with authentication using "any" method. libcurl picks the
 * one the server supports/wants.
 * </DESC>
 */
#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS  /* for fopen() */
#endif
#endif

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <curl/curl.h>

#ifdef _WIN32
#undef stat
#define stat _stati64
#undef fstat
#define fstat _fstati64
#define fileno _fileno
#endif

#if LIBCURL_VERSION_NUM < 0x070c03
#error "upgrade your libcurl to no less than 7.12.3"
#endif

/*
 * This example shows an HTTP PUT operation with authentication using "any"
 * type. It PUTs a file given as a command line argument to the URL also given
 * on the command line.
 *
 * Since libcurl 7.12.3, using "any" auth and POST/PUT requires a set seek
 * function.
 *
 * This example also uses its own read callback.
 */

/* seek callback function */
static int my_seek(void *userp, curl_off_t offset, int origin)
{
  FILE *fp = (FILE *)userp;

  if(fseek(fp, (long)offset, origin) == -1)
    /* could not seek */
    return CURL_SEEKFUNC_CANTSEEK;

  return CURL_SEEKFUNC_OK; /* success! */
}

/* read callback function, fread() look alike */
static size_t read_cb(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t nread;

  nread = fread(ptr, size, nmemb, stream);

  if(nread > 0) {
    fprintf(stderr, "*** We read %lu bytes from file\n", (unsigned long)nread);
  }

  return nread;
}

int main(int argc, const char **argv)
{
  CURL *curl;
  CURLcode result;
  FILE *fp;
  struct stat file_info;

  const char *file;
  const char *url;

  if(argc < 3)
    return 1;

  file = argv[1];
  url = argv[2];

  /* get the file size of the local file */
  fp = fopen(file, "rb");
  if(!fp)
    return 2;

  if(fstat(fileno(fp), &file_info) != 0) {
    fclose(fp);
    return 1; /* cannot continue */
  }

  /* In Windows, this inits the Winsock stuff */
  result = curl_global_init(CURL_GLOBAL_ALL);
  if(result) {
    fclose(fp);
    return (int)result;
  }

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_cb);

    /* which file to upload */
    curl_easy_setopt(curl, CURLOPT_READDATA, (void *)fp);

    /* set the seek function */
    curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, my_seek);

    /* pass the file descriptor to the seek callback as well */
    curl_easy_setopt(curl, CURLOPT_SEEKDATA, (void *)fp);

    /* enable "uploading" (which means PUT when doing HTTP) */
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    /* specify target URL, and note that this URL should also include a file
       name, not only a directory (as you can do with GTP uploads) */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* and give the size of the upload, this supports large file sizes
       on systems that have general support for it */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                     (curl_off_t)file_info.st_size);

    /* tell libcurl we can use "any" auth, which lets the lib pick one, but it
       also costs one extra round-trip and possibly sending of all the PUT
       data twice */
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

    /* set username and password for the authentication */
    curl_easy_setopt(curl, CURLOPT_USERPWD, "user:password");

    /* Now run off and do what you have been told! */
    result = curl_easy_perform(curl);
    /* Check for errors */
    if(result != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(result));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  fclose(fp); /* close the local file */

  curl_global_cleanup();
  return (int)result;
}
