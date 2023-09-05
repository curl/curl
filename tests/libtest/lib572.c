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
#include "test.h"

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "memdebug.h"

/* build request url */
static char *suburl(const char *base, int i)
{
  return curl_maprintf("%s%.4d", base, i);
}

/*
 * Test GET_PARAMETER: PUT, HEARTBEAT, and POST
 */
int test(char *URL)
{
  int res;
  CURL *curl;
  int params;
  FILE *paramsf = NULL;
  struct_stat file_info;
  char *stream_uri = NULL;
  int request = 1;
  struct curl_slist *custom_headers = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    fprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }


  test_setopt(curl, CURLOPT_HEADERDATA, stdout);
  test_setopt(curl, CURLOPT_WRITEDATA, stdout);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  test_setopt(curl, CURLOPT_URL, URL);

  /* SETUP */
  stream_uri = suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  test_setopt(curl, CURLOPT_RTSP_TRANSPORT, "Planes/Trains/Automobiles");
  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_SETUP);
  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  stream_uri = suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  /* PUT style GET_PARAMETERS */
  params = open(libtest_arg2, O_RDONLY);
  fstat(params, &file_info);
  close(params);

  paramsf = fopen(libtest_arg2, "rb");
  if(!paramsf) {
    fprintf(stderr, "can't open %s\n", libtest_arg2);
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_GET_PARAMETER);

  test_setopt(curl, CURLOPT_READDATA, paramsf);
  test_setopt(curl, CURLOPT_UPLOAD, 1L);
  test_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) file_info.st_size);

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  test_setopt(curl, CURLOPT_UPLOAD, 0L);
  fclose(paramsf);
  paramsf = NULL;

  /* Heartbeat GET_PARAMETERS */
  stream_uri = suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  /* POST GET_PARAMETERS */

  stream_uri = suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_GET_PARAMETER);
  test_setopt(curl, CURLOPT_POSTFIELDS, "packets_received\njitter\n");

  res = curl_easy_perform(curl);
  if(res)
    goto test_cleanup;

  test_setopt(curl, CURLOPT_POSTFIELDS, NULL);

  /* Make sure we can do a normal request now */
  stream_uri = suburl(URL, request++);
  if(!stream_uri) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  test_setopt(curl, CURLOPT_RTSP_STREAM_URI, stream_uri);
  curl_free(stream_uri);
  stream_uri = NULL;

  test_setopt(curl, CURLOPT_RTSP_REQUEST, CURL_RTSPREQ_OPTIONS);
  res = curl_easy_perform(curl);

test_cleanup:

  if(paramsf)
    fclose(paramsf);

  curl_free(stream_uri);

  if(custom_headers)
    curl_slist_free_all(custom_headers);

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
