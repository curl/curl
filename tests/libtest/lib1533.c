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

/*
 * This test sends data with CURLOPT_KEEP_SENDING_ON_ERROR.
 * The server responds with an early error response.
 * The test is successful if the connection can be reused for the next request,
 * because this implies that the data has been sent completely to the server.
 */

#include "first.h"

#include "memdebug.h"

struct cb_data {
  CURL *easy_handle;
  int response_received;
  int paused;
  size_t remaining_bytes;
};

static void reset_data(struct cb_data *data, CURL *curl)
{
  data->easy_handle = curl;
  data->response_received = 0;
  data->paused = 0;
  data->remaining_bytes = 3;
}

static size_t t1533_read_cb(char *ptr, size_t size, size_t nitems, void *userp)
{
  struct cb_data *data = (struct cb_data *)userp;

  /* wait until the server has sent all response headers */
  if(data->response_received) {
    size_t totalsize = nitems * size;

    size_t bytes_to_send = data->remaining_bytes;
    if(bytes_to_send > totalsize) {
      bytes_to_send = totalsize;
    }

    memset(ptr, 'a', bytes_to_send);
    data->remaining_bytes -= bytes_to_send;

    return bytes_to_send;
  }
  else {
    data->paused = 1;
    return CURL_READFUNC_PAUSE;
  }
}

static size_t t1533_write_cb(char *ptr, size_t size, size_t nmemb, void *userp)
{
  struct cb_data *data = (struct cb_data *)userp;
  size_t totalsize = nmemb * size;

  (void)ptr;

  /* all response headers have been received */
  data->response_received = 1;

  if(data->paused) {
    /* continue to send request body data */
    data->paused = 0;
    curl_easy_pause(data->easy_handle, CURLPAUSE_CONT);
  }

  return totalsize;
}

static CURLcode perform_and_check_connections(CURL *curl,
                                              const char *description,
                                              long expected_connections)
{
  CURLcode res;
  long connections = 0;

  res = curl_easy_perform(curl);
  if(res != CURLE_OK) {
    curl_mfprintf(stderr, "curl_easy_perform() failed with %d\n", res);
    return TEST_ERR_MAJOR_BAD;
  }

  res = curl_easy_getinfo(curl, CURLINFO_NUM_CONNECTS, &connections);
  if(res != CURLE_OK) {
    curl_mfprintf(stderr, "curl_easy_getinfo() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl_mfprintf(stderr,
                "%s: expected: %ld connections; actual: %ld connections\n",
                description, expected_connections, connections);

  if(connections != expected_connections) {
    return TEST_ERR_FAILURE;
  }

  return TEST_ERR_SUCCESS;
}


static CURLcode test_lib1533(const char *URL)
{
  struct cb_data data;
  CURL *curl = NULL;
  CURLcode res = TEST_ERR_FAILURE;
  CURLcode result;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  reset_data(&data, curl);

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_POST, 1L);
  test_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
              (curl_off_t)data.remaining_bytes);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_READFUNCTION, t1533_read_cb);
  test_setopt(curl, CURLOPT_READDATA, &data);
  test_setopt(curl, CURLOPT_WRITEFUNCTION, t1533_write_cb);
  test_setopt(curl, CURLOPT_WRITEDATA, &data);

  result = perform_and_check_connections(curl,
    "First request without CURLOPT_KEEP_SENDING_ON_ERROR", 1);
  if(result != TEST_ERR_SUCCESS) {
    res = result;
    goto test_cleanup;
  }

  reset_data(&data, curl);

  result = perform_and_check_connections(curl,
    "Second request without CURLOPT_KEEP_SENDING_ON_ERROR", 1);
  if(result != TEST_ERR_SUCCESS) {
    res = result;
    goto test_cleanup;
  }

  test_setopt(curl, CURLOPT_KEEP_SENDING_ON_ERROR, 1L);

  reset_data(&data, curl);

  result = perform_and_check_connections(curl,
    "First request with CURLOPT_KEEP_SENDING_ON_ERROR", 1);
  if(result != TEST_ERR_SUCCESS) {
    res = result;
    goto test_cleanup;
  }

  reset_data(&data, curl);

  result = perform_and_check_connections(curl,
    "Second request with CURLOPT_KEEP_SENDING_ON_ERROR", 0);
  if(result != TEST_ERR_SUCCESS) {
    res = result;
    goto test_cleanup;
  }

  res = TEST_ERR_SUCCESS;

test_cleanup:

  curl_easy_cleanup(curl);

  curl_global_cleanup();

  return res;
}
