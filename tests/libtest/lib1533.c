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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/*
 * This test sends data with FETCHOPT_KEEP_SENDING_ON_ERROR.
 * The server responds with an early error response.
 * The test is successful if the connection can be reused for the next request,
 * because this implies that the data has been sent completely to the server.
 */

#include "test.h"

#include "memdebug.h"

struct cb_data
{
  FETCH *easy_handle;
  int response_received;
  int paused;
  size_t remaining_bytes;
};

static void reset_data(struct cb_data *data, FETCH *fetch)
{
  data->easy_handle = fetch;
  data->response_received = 0;
  data->paused = 0;
  data->remaining_bytes = 3;
}

static size_t read_callback(char *ptr, size_t size, size_t nitems,
                            void *userdata)
{
  struct cb_data *data = (struct cb_data *)userdata;

  /* wait until the server has sent all response headers */
  if (data->response_received)
  {
    size_t totalsize = nitems * size;

    size_t bytes_to_send = data->remaining_bytes;
    if (bytes_to_send > totalsize)
    {
      bytes_to_send = totalsize;
    }

    memset(ptr, 'a', bytes_to_send);
    data->remaining_bytes -= bytes_to_send;

    return bytes_to_send;
  }
  else
  {
    data->paused = 1;
    return FETCH_READFUNC_PAUSE;
  }
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb,
                             void *userdata)
{
  struct cb_data *data = (struct cb_data *)userdata;
  size_t totalsize = nmemb * size;

  /* unused parameter */
  (void)ptr;

  /* all response headers have been received */
  data->response_received = 1;

  if (data->paused)
  {
    /* continue to send request body data */
    data->paused = 0;
    fetch_easy_pause(data->easy_handle, FETCHPAUSE_CONT);
  }

  return totalsize;
}

static int perform_and_check_connections(FETCH *fetch, const char *description,
                                         long expected_connections)
{
  FETCHcode res;
  long connections = 0;

  res = fetch_easy_perform(fetch);
  if (res != FETCHE_OK)
  {
    fprintf(stderr, "fetch_easy_perform() failed with %d\n", res);
    return TEST_ERR_MAJOR_BAD;
  }

  res = fetch_easy_getinfo(fetch, FETCHINFO_NUM_CONNECTS, &connections);
  if (res != FETCHE_OK)
  {
    fprintf(stderr, "fetch_easy_getinfo() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fprintf(stderr, "%s: expected: %ld connections; actual: %ld connections\n",
          description, expected_connections, connections);

  if (connections != expected_connections)
  {
    return TEST_ERR_FAILURE;
  }

  return TEST_ERR_SUCCESS;
}

FETCHcode test(char *URL)
{
  struct cb_data data;
  FETCH *fetch = NULL;
  FETCHcode res = TEST_ERR_FAILURE;
  int result;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  reset_data(&data, fetch);

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_POST, 1L);
  test_setopt(fetch, FETCHOPT_POSTFIELDSIZE_LARGE,
              (fetch_off_t)data.remaining_bytes);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_READFUNCTION, read_callback);
  test_setopt(fetch, FETCHOPT_READDATA, &data);
  test_setopt(fetch, FETCHOPT_WRITEFUNCTION, write_callback);
  test_setopt(fetch, FETCHOPT_WRITEDATA, &data);

  result = perform_and_check_connections(fetch,
                                         "First request without FETCHOPT_KEEP_SENDING_ON_ERROR", 1);
  if (result != TEST_ERR_SUCCESS)
  {
    res = (FETCHcode)result;
    goto test_cleanup;
  }

  reset_data(&data, fetch);

  result = perform_and_check_connections(fetch,
                                         "Second request without FETCHOPT_KEEP_SENDING_ON_ERROR", 1);
  if (result != TEST_ERR_SUCCESS)
  {
    res = (FETCHcode)result;
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_KEEP_SENDING_ON_ERROR, 1L);

  reset_data(&data, fetch);

  result = perform_and_check_connections(fetch,
                                         "First request with FETCHOPT_KEEP_SENDING_ON_ERROR", 1);
  if (result != TEST_ERR_SUCCESS)
  {
    res = (FETCHcode)result;
    goto test_cleanup;
  }

  reset_data(&data, fetch);

  result = perform_and_check_connections(fetch,
                                         "Second request with FETCHOPT_KEEP_SENDING_ON_ERROR", 0);
  if (result != TEST_ERR_SUCCESS)
  {
    res = (FETCHcode)result;
    goto test_cleanup;
  }

  res = TEST_ERR_SUCCESS;

test_cleanup:

  fetch_easy_cleanup(fetch);

  fetch_global_cleanup();

  return res;
}
