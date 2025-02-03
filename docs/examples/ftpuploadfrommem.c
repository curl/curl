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
 * FTP upload a file from memory
 * </DESC>
 */
#include <stdio.h>
#include <string.h>
#include <fetch/fetch.h>

static const char data[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    "Nam rhoncus odio id venenatis volutpat. Vestibulum dapibus "
    "bibendum ullamcorper. Maecenas finibus elit augue, vel "
    "condimentum odio maximus nec. In hac habitasse platea dictumst. "
    "Vestibulum vel dolor et turpis rutrum finibus ac at nulla. "
    "Vivamus nec neque ac elit blandit pretium vitae maximus ipsum. "
    "Quisque sodales magna vel erat auctor, sed pellentesque nisi "
    "rhoncus. Donec vehicula maximus pretium. Aliquam eu tincidunt "
    "lorem.";

struct WriteThis
{
  const char *readptr;
  size_t sizeleft;
};

static size_t read_callback(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *upload = (struct WriteThis *)userp;
  size_t max = size * nmemb;

  if (max < 1)
    return 0;

  if (upload->sizeleft)
  {
    size_t copylen = max;
    if (copylen > upload->sizeleft)
      copylen = upload->sizeleft;
    memcpy(ptr, upload->readptr, copylen);
    upload->readptr += copylen;
    upload->sizeleft -= copylen;
    return copylen;
  }

  return 0; /* no more data left to deliver */
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  struct WriteThis upload;

  upload.readptr = data;
  upload.sizeleft = strlen(data);

  /* In Windows, this inits the Winsock stuff */
  res = fetch_global_init(FETCH_GLOBAL_DEFAULT);
  /* Check for errors */
  if (res != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed: %s\n",
            fetch_easy_strerror(res));
    return 1;
  }

  /* get a fetch handle */
  fetch = fetch_easy_init();
  if (fetch)
  {
    /* First set the URL, the target file */
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                      "ftp://example.com/path/to/upload/file");

    /* User and password for the FTP login */
    fetch_easy_setopt(fetch, FETCHOPT_USERPWD, "login:secret");

    /* Now specify we want to UPLOAD data */
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

    /* we want to use our own read function */
    fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

    /* pointer to pass to our read function */
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, &upload);

    /* get verbose debug output please */
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    /* Set the expected upload size. */
    fetch_easy_setopt(fetch, FETCHOPT_INFILESIZE_LARGE,
                      (fetch_off_t)upload.sizeleft);

    /* Perform the request, res gets the return code */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if (res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  fetch_global_cleanup();
  return 0;
}
