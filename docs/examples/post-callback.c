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
 * Issue an HTTP POST and provide the data through the read callback.
 * </DESC>
 */
#include <stdio.h>
#include <string.h>
#include <fetch/fetch.h>

/* silly test data to POST */
static const char data[] = "Lorem ipsum dolor sit amet, consectetur adipiscing "
                           "elit. Sed vel urna neque. Ut quis leo metus. Quisque eleifend, ex at "
                           "laoreet rhoncus, odio ipsum semper metus, at tempus ante urna in mauris. "
                           "Suspendisse ornare tempor venenatis. Ut dui neque, pellentesque a varius "
                           "eget, mattis vitae ligula. Fusce ut pharetra est. Ut ullamcorper mi ac "
                           "sollicitudin semper. Praesent sit amet tellus varius, posuere nulla non, "
                           "rhoncus ipsum.";

struct WriteThis
{
  const char *readptr;
  size_t sizeleft;
};

static size_t read_callback(char *dest, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *wt = (struct WriteThis *)userp;
  size_t buffer_size = size * nmemb;

  if (wt->sizeleft)
  {
    /* copy as much as possible from the source to the destination */
    size_t copy_this_much = wt->sizeleft;
    if (copy_this_much > buffer_size)
      copy_this_much = buffer_size;
    memcpy(dest, wt->readptr, copy_this_much);

    wt->readptr += copy_this_much;
    wt->sizeleft -= copy_this_much;
    return copy_this_much; /* we copied this many bytes */
  }

  return 0; /* no more data left to deliver */
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;

  struct WriteThis wt;

  wt.readptr = data;
  wt.sizeleft = strlen(data);

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
    /* First set the URL that is about to receive our POST. */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/index.cgi");

    /* Now specify we want to POST data */
    fetch_easy_setopt(fetch, FETCHOPT_POST, 1L);

    /* we want to use our own read function */
    fetch_easy_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);

    /* pointer to pass to our read function */
    fetch_easy_setopt(fetch, FETCHOPT_READDATA, &wt);

    /* get verbose debug output please */
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    /*
      If you use POST to an HTTP 1.1 server, you can send data without knowing
      the size before starting the POST if you use chunked encoding. You
      enable this by adding a header like "Transfer-Encoding: chunked" with
      FETCHOPT_HTTPHEADER. With HTTP 1.0 or without chunked transfer, you must
      specify the size in the request.
    */
#ifdef USE_CHUNKED
    {
      struct fetch_slist *chunk = NULL;

      chunk = fetch_slist_append(chunk, "Transfer-Encoding: chunked");
      res = fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, chunk);
      /* use fetch_slist_free_all() after the *perform() call to free this
         list again */
    }
#else
    /* Set the expected POST size. If you want to POST large amounts of data,
       consider FETCHOPT_POSTFIELDSIZE_LARGE */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)wt.sizeleft);
#endif

#ifdef DISABLE_EXPECT
    /*
      Using POST with HTTP 1.1 implies the use of a "Expect: 100-continue"
      header.  You can disable this header with FETCHOPT_HTTPHEADER as usual.
      NOTE: if you want chunked transfer too, you need to combine these two
      since you can only set one list of headers with FETCHOPT_HTTPHEADER. */

    /* A less good option would be to enforce HTTP 1.0, but that might also
       have other implications. */
    {
      struct fetch_slist *chunk = NULL;

      chunk = fetch_slist_append(chunk, "Expect:");
      res = fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, chunk);
      /* use fetch_slist_free_all() after the *perform() call to free this
         list again */
    }
#endif

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
