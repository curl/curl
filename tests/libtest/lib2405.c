/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Dmitry Karpov <dkarpov1970@gmail.com>
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
 * The purpose of this test is to test behavior of curl_multi_waitfds
 * function in different scenarios:
 *  empty multi handle (expected zero descriptors),
 *  HTTP1 amd HTTP2 (no multiplexing) two transfers (expected two descriptors),
 *  HTTP2 with multiplexing (expected one descriptors)
 *  Improper inputs to the API result in CURLM_BAD_FUNCTION_ARGUMENT.
 *  Sending a empty ufds, and size = 0 will return the number of fds needed.
 *  Sending a non-empty ufds, but smaller than the fds needed will result in a
 *    CURLM_OUT_OF_MEMORY, and a number of fds that is >= to the number needed.
 *
 *  It is also expected that all transfers run by multi-handle should complete
 *  successfully.
 */

#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"


 /* ---------------------------------------------------------------- */

#define test_check(expected_fds) \
  if(res != CURLE_OK) { \
    fprintf(stderr, "test failed with code: %d\n", res); \
    goto test_cleanup; \
  } \
  else if(fd_count != expected_fds) { \
    fprintf(stderr, "Max number of waitfds: %d not as expected: %d\n", \
      fd_count, expected_fds); \
    res = TEST_ERR_FAILURE; \
    goto test_cleanup; \
  }

#define test_run_check(option, expected_fds) do { \
  res = test_run(URL, option, &fd_count); \
  test_check(expected_fds); \
} while(0)

 /* ---------------------------------------------------------------- */

enum {
  TEST_USE_HTTP1 = 0,
  TEST_USE_HTTP2,
  TEST_USE_HTTP2_MPLEX
};

static size_t emptyWriteFunc(void *ptr, size_t size, size_t nmemb,
    void *data) {
  (void)ptr; (void)data;
  return size * nmemb;
}

static CURLcode set_easy(char *URL, CURL *easy, long option)
{
  CURLcode res = CURLE_OK;

  /* First set the URL that is about to receive our POST. */
  easy_setopt(easy, CURLOPT_URL, URL);

  /* get verbose debug output please */
  easy_setopt(easy, CURLOPT_VERBOSE, 1L);

  switch(option) {
  case TEST_USE_HTTP1:
    /* go http1 */
    easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    break;

  case TEST_USE_HTTP2:
    /* go http2 */
    easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    break;

  case TEST_USE_HTTP2_MPLEX:
    /* go http2 with multiplexing */
    easy_setopt(easy, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    easy_setopt(easy, CURLOPT_PIPEWAIT, 1L);
    break;
  }

  /* no peer verify */
  easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 0L);
  easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 0L);

  /* include headers */
  easy_setopt(easy, CURLOPT_HEADER, 1L);

  /* empty write function */
  easy_setopt(easy, CURLOPT_WRITEFUNCTION, emptyWriteFunc);

test_cleanup:
  return res;
}

static CURLcode test_run(char *URL, long option, unsigned int *max_fd_count)
{
  CURLMcode mc = CURLM_OK;
  CURLM *multi = NULL;
  CURLM *multi1 = NULL;

  CURL *easy1 = NULL;
  CURL *easy2 = NULL;

  unsigned int max_count = 0;

  int still_running; /* keep number of running handles */
  CURLMsg *msg; /* for picking up messages with the transfer status */
  int msgs_left; /* how many messages are left */

  CURLcode result;
  CURLcode res = CURLE_OK;

  struct curl_waitfd ufds[10];
  struct curl_waitfd ufds1[10];
  int numfds;

  easy_init(easy1);
  easy_init(easy2);

  if(set_easy(URL, easy1, option) != CURLE_OK)
    goto test_cleanup;

  if(set_easy(URL, easy2, option) != CURLE_OK)
    goto test_cleanup;

  multi_init(multi);
  multi_init(multi1);

  if(option == TEST_USE_HTTP2_MPLEX)
    multi_setopt(multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  multi_add_handle(multi, easy1);
  multi_add_handle(multi, easy2);

  while(!mc) {
    /* get the count of file descriptors from the transfers */
    unsigned int fd_count = 0;
    unsigned int fd_count_chk = 0;

    mc = curl_multi_perform(multi, &still_running);
    if(!still_running || mc != CURLM_OK)
      break;

    /* verify improper inputs are treated correctly. */
    mc = curl_multi_waitfds(multi, NULL, 0, NULL);

    if(mc != CURLM_BAD_FUNCTION_ARGUMENT) {
      fprintf(stderr, "curl_multi_waitfds() return code %d instead of "
        "CURLM_BAD_FUNCTION_ARGUMENT.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    mc = curl_multi_waitfds(multi, NULL, 1, NULL);

    if(mc != CURLM_BAD_FUNCTION_ARGUMENT) {
      fprintf(stderr, "curl_multi_waitfds() return code %d instead of "
        "CURLM_BAD_FUNCTION_ARGUMENT.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    mc = curl_multi_waitfds(multi, NULL, 1, &fd_count);

    if(mc != CURLM_BAD_FUNCTION_ARGUMENT) {
      fprintf(stderr, "curl_multi_waitfds() return code %d instead of "
        "CURLM_BAD_FUNCTION_ARGUMENT.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    mc = curl_multi_waitfds(multi, ufds, 10, &fd_count);

    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_waitfds() failed, code %d.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    if(!fd_count)
      continue; /* no descriptors yet */

    /* verify that sending nothing but the fd_count results in at least the
     * same number of fds */
    mc = curl_multi_waitfds(multi, NULL, 0, &fd_count_chk);

    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_waitfds() failed, code %d.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    if(fd_count_chk < fd_count) {
      fprintf(stderr, "curl_multi_waitfds() should return at least the number "
        "of fds needed\n");
      res = TEST_ERR_FAILURE;
      break;
    }

    /* checking case when we don't have enough space for waitfds */
    mc = curl_multi_waitfds(multi, ufds1, fd_count - 1, &fd_count_chk);

    if(mc != CURLM_OUT_OF_MEMORY) {
      fprintf(stderr, "curl_multi_waitfds() return code %d instead of "
        "CURLM_OUT_OF_MEMORY.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    if(fd_count_chk < fd_count) {
      fprintf(stderr, "curl_multi_waitfds() sould return the amount of fds "
        "needed if enough isn't passed in.\n");
      res = TEST_ERR_FAILURE;
      break;
    }

    /* sending ufds with zero size, is valid */
    mc = curl_multi_waitfds(multi, ufds, 0, NULL);

    if(mc != CURLM_OUT_OF_MEMORY) {
      fprintf(stderr, "curl_multi_waitfds() return code %d instead of "
        "CURLM_OUT_OF_MEMORY.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    mc = curl_multi_waitfds(multi, ufds, 0, &fd_count_chk);

    if(mc != CURLM_OUT_OF_MEMORY) {
      fprintf(stderr, "curl_multi_waitfds() return code %d instead of "
        "CURLM_OUT_OF_MEMORY.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    if(fd_count_chk < fd_count) {
      fprintf(stderr, "curl_multi_waitfds() sould return the amount of fds "
        "needed if enough isn't passed in.\n");
      res = TEST_ERR_FAILURE;
      break;
    }

    if(fd_count > max_count)
      max_count = fd_count;

    /* Do polling on descriptors in ufds in Multi 1 */
    mc = curl_multi_poll(multi1, ufds, fd_count, 500, &numfds);

    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_poll() failed, code %d.\\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }
  }

  for(;;) {
    msg = curl_multi_info_read(multi, &msgs_left);
    if(!msg)
      break;
    if(msg->msg == CURLMSG_DONE) {
      result = msg->data.result;

      if(!res)
        res = result;
    }
  }

  curl_multi_remove_handle(multi, easy1);
  curl_multi_remove_handle(multi, easy2);

test_cleanup:
  curl_easy_cleanup(easy1);
  curl_easy_cleanup(easy2);

  curl_multi_cleanup(multi);
  curl_multi_cleanup(multi1);

  if(max_fd_count)
    *max_fd_count = max_count;

  return res;
}

static CURLcode empty_multi_test(void)
{
  CURLMcode mc = CURLM_OK;
  CURLM *multi = NULL;
  CURL *easy = NULL;

  struct curl_waitfd ufds[10];

  CURLcode res = CURLE_OK;
  unsigned int fd_count = 0;

  multi_init(multi);

  /* calling curl_multi_waitfds() on an empty multi handle.  */
  mc = curl_multi_waitfds(multi, ufds, 10, &fd_count);

  if(mc != CURLM_OK) {
    fprintf(stderr, "curl_multi_waitfds() failed, code %d.\n", mc);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  else if(fd_count > 0) {
    fprintf(stderr, "curl_multi_waitfds() returned non-zero count of "
        "waitfds: %d.\n", fd_count);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* calling curl_multi_waitfds() on multi handle with added easy handle. */
  easy_init(easy);

  if(set_easy((char *)"http://example.com", easy, TEST_USE_HTTP1) != CURLE_OK)
    goto test_cleanup;

  multi_add_handle(multi, easy);

  mc = curl_multi_waitfds(multi, ufds, 10, &fd_count);

  if(mc != CURLM_OK) {
    fprintf(stderr, "curl_multi_waitfds() failed, code %d.\n", mc);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  else if(fd_count > 0) {
    fprintf(stderr, "curl_multi_waitfds() returned non-zero count of "
        "waitfds: %d.\n", fd_count);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  curl_multi_remove_handle(multi, easy);

test_cleanup:
  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);
  return res;
}

CURLcode test(char *URL)
{
  CURLcode res = CURLE_OK;
  unsigned int fd_count = 0;

  global_init(CURL_GLOBAL_ALL);

  /* Testing curl_multi_waitfds on empty and not started handles */
  res = empty_multi_test();
  if(res != CURLE_OK)
    goto test_cleanup;

  /* HTTP1, expected 2 waitfds - one for each transfer */
  test_run_check(TEST_USE_HTTP1, 2);

  /* HTTP2, expected 2 waitfds - one for each transfer */
  test_run_check(TEST_USE_HTTP2, 2);

  /* HTTP2 with multiplexing, expected 1 waitfds - one for all transfers */
  test_run_check(TEST_USE_HTTP2_MPLEX, 1);

test_cleanup:
  curl_global_cleanup();
  return res;
}
