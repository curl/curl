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
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <curl/curl.h>

#ifdef _WIN32
#  define FILENO(fp) _fileno(fp)
#else
#  define FILENO(fp) fileno(fp)
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
  FILE *fp = (FILE *) userp;

  if(-1 == fseek(fp, (long) offset, origin))
    /* could not seek */
    return CURL_SEEKFUNC_CANTSEEK;

  return CURL_SEEKFUNC_OK; /* success! */
}

/* read callback function, fread() look alike */
static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t nread;

  nread = fread(ptr, size, nmemb, stream);

  if(nread > 0) {
    fprintf(stderr, "*** We read %lu bytes from file\n", (unsigned long)nread);
  }

  return nread;
}

int main(int argc, char **argv)
{
  CURL *curl;
  CURLcode res;
  FILE *fp;
  struct stat file_info;

  char *file;
  char *url;

  if(argc < 3)
    return 1;

  file = argv[1];
  url = argv[2];

  /* get the file size of the local file */
  fp = fopen(file, "rb");
  fstat(FILENO(fp), &file_info);

  /* In windows, this inits the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);

    /* which file to upload */
    curl_easy_setopt(curl, CURLOPT_READDATA, (void *) fp);

    /* set the seek function */
    curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, my_seek);

    /* pass the file descriptor to the seek callback as well */
    curl_easy_setopt(curl, CURLOPT_SEEKDATA, (void *) fp);

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
       data twice!!! */
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_ANY);

    /* set user name and password for the authentication */
    curl_easy_setopt(curl, CURLOPT_USERPWD, "user:password");

    /* Now run off and do what you have been told! */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  fclose(fp); /* close the local file */

  curl_global_cleanup();
  return 0;
}
