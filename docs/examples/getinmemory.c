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
 * Shows how the write callback function can be used to download data into a
 * chunk of memory instead of storing it in a file.
 * </DESC>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fetch/fetch.h>

struct MemoryStruct
{
  char *memory;
  size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if (!ptr)
  {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

int main(void)
{
  FETCH *fetch_handle;
  FETCHcode res;

  struct MemoryStruct chunk;

  chunk.memory = malloc(1); /* grown as needed by the realloc above */
  chunk.size = 0;           /* no data at this point */

  fetch_global_init(FETCH_GLOBAL_ALL);

  /* init the fetch session */
  fetch_handle = fetch_easy_init();

  /* specify URL to get */
  fetch_easy_setopt(fetch_handle, FETCHOPT_URL, "https://www.example.com/");

  /* send all data to this function  */
  fetch_easy_setopt(fetch_handle, FETCHOPT_WRITEFUNCTION, WriteMemoryCallback);

  /* we pass our 'chunk' struct to the callback function */
  fetch_easy_setopt(fetch_handle, FETCHOPT_WRITEDATA, (void *)&chunk);

  /* some servers do not like requests that are made without a user-agent
     field, so we provide one */
  fetch_easy_setopt(fetch_handle, FETCHOPT_USERAGENT, "libfetch-agent/1.0");

  /* get it! */
  res = fetch_easy_perform(fetch_handle);

  /* check for errors */
  if (res != FETCHE_OK)
  {
    fprintf(stderr, "fetch_easy_perform() failed: %s\n",
            fetch_easy_strerror(res));
  }
  else
  {
    /*
     * Now, our chunk.memory points to a memory block that is chunk.size
     * bytes big and contains the remote file.
     *
     * Do something nice with it!
     */

    printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
  }

  /* cleanup fetch stuff */
  fetch_easy_cleanup(fetch_handle);

  free(chunk.memory);

  /* we are done with libfetch, so clean it up */
  fetch_global_cleanup();

  return 0;
}
