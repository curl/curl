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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * HTTP PUT with easy interface and read callback
 * </DESC>
 */
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <fetch/fetch.h>

#ifdef _WIN32
#undef stat
#define stat _stat
#endif

/*
 * This example shows an HTTP PUT operation. PUTs a file given as a command
 * line argument to the URL also given on the command line.
 *
 * This example also uses its own read callback.
 *
 * Here's an article on how to setup a PUT handler for Apache:
 * http://www.apacheweek.com/features/put
 */

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t retcode;
  unsigned long nread;

  /* in real-world cases, this would probably get this data differently
     as this fread() stuff is exactly what the library already would do
     by default internally */
  retcode = fread(ptr, size, nmemb, stream);

  if(retcode > 0) {
    nread = (unsigned long)retcode;
    fprintf(stderr, "*** We read %lu bytes from file\n", nread);
  }

  return retcode;
}

int main(int argc, char **argv)
{
  FETCH *fetch;
  FETCHcode res;
  FILE * hd_src;
  struct stat file_info;

  char *file;
  char *url;

  if(argc < 3)
    return 1;

  file = argv[1];
  url = argv[2];

  /* get the file size of the local file */
  stat(file, &file_info);

  /* get a FILE * of the same file, could also be made with
     fdopen() from the previous descriptor, but hey this is just
     an example! */
  hd_src = fopen(file, "rb");
  if(!hd_src)
    return 2;

  /* In Windows, this inits the Winsock stuff */
  fetch_global_init(FETCH_GLOBAL_ALL);

  /* get a fetch handle */
  fetch = fetch_easy_init();
  if(fetch) {
    /* we want to use our own read function */
    fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

    /* enable uploading (implies PUT over HTTP) */
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    /* specify target URL, and note that this URL should include a file
       name, not only a directory */
    fetch_easy_setopt(fetch, FETCHOPT_URL, url);

    /* now specify which file to upload */
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, hd_src);

    /* provide the size of the upload, we typecast the value to fetch_off_t
       since we must be sure to use the correct data size */
    fetch_easy_setopt(fetch, FETCHOPT_INFILESIZE_LARGE,
                     (fetch_off_t)file_info.st_size);

    /* Now run off and do what you have been told! */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fclose(hd_src); /* close the local file */

  fetch_global_cleanup();
  return 0;
}
