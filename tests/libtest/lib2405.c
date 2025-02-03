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

/*
 * The purpose of this test is to test behavior of fetch_multi_waitfds
 * function in different scenarios:
 *  empty multi handle (expected zero descriptors),
 *  HTTP1 amd HTTP2 (no multiplexing) two transfers (expected two descriptors),
 *  HTTP2 with multiplexing (expected one descriptors)
 *  Improper inputs to the API result in FETCHM_BAD_FUNCTION_ARGUMENT.
 *  Sending a empty ufds, and size = 0 will return the number of fds needed.
 *  Sending a non-empty ufds, but smaller than the fds needed will result in a
 *    FETCHM_OUT_OF_MEMORY, and a number of fds that is >= to the number needed.
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
  if(res != FETCHE_OK) { \
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

static FETCHcode set_easy(char *URL, FETCH *easy, long option)
{
  FETCHcode res = FETCHE_OK;

  /* First set the URL that is about to receive our POST. */
  easy_setopt(easy, FETCHOPT_URL, URL);

  /* get verbose debug output please */
  easy_setopt(easy, FETCHOPT_VERBOSE, 1L);

  switch(option) {
  case TEST_USE_HTTP1:
    /* go http1 */
    easy_setopt(easy, FETCHOPT_HTTP_VERSION, FETCH_HTTP_VERSION_1_1);
    break;

  case TEST_USE_HTTP2:
    /* go http2 */
    easy_setopt(easy, FETCHOPT_HTTP_VERSION, FETCH_HTTP_VERSION_2_0);
    break;

  case TEST_USE_HTTP2_MPLEX:
    /* go http2 with multiplexing */
    easy_setopt(easy, FETCHOPT_HTTP_VERSION, FETCH_HTTP_VERSION_2_0);
    easy_setopt(easy, FETCHOPT_PIPEWAIT, 1L);
    break;
  }

  /* no peer verify */
  easy_setopt(easy, FETCHOPT_SSL_VERIFYPEER, 0L);
  easy_setopt(easy, FETCHOPT_SSL_VERIFYHOST, 0L);

  /* include headers */
  easy_setopt(easy, FETCHOPT_HEADER, 1L);

  /* empty write function */
  easy_setopt(easy, FETCHOPT_WRITEFUNCTION, emptyWriteFunc);

test_cleanup:
  return res;
}

static FETCHcode test_run(char *URL, long option, unsigned int *max_fd_count)
{
  FETCHMcode mc = FETCHM_OK;
  FETCHM *multi = NULL;
  FETCHM *multi1 = NULL;

  FETCH *easy1 = NULL;
  FETCH *easy2 = NULL;

  unsigned int max_count = 0;

  int still_running; /* keep number of running handles */
  FETCHMsg *msg; /* for picking up messages with the transfer status */
  int msgs_left; /* how many messages are left */

  FETCHcode result;
  FETCHcode res = FETCHE_OK;

  struct fetch_waitfd ufds[10];
  struct fetch_waitfd ufds1[10];
  int numfds;

  easy_init(easy1);
  easy_init(easy2);

  if(set_easy(URL, easy1, option) != FETCHE_OK)
    goto test_cleanup;

  if(set_easy(URL, easy2, option) != FETCHE_OK)
    goto test_cleanup;

  multi_init(multi);
  multi_init(multi1);

  if(option == TEST_USE_HTTP2_MPLEX)
    multi_setopt(multi, FETCHMOPT_PIPELINING, FETCHPIPE_MULTIPLEX);

  multi_add_handle(multi, easy1);
  multi_add_handle(multi, easy2);

  while(!mc) {
    /* get the count of file descriptors from the transfers */
    unsigned int fd_count = 0;
    unsigned int fd_count_chk = 0;

    mc = fetch_multi_perform(multi, &still_running);
    if(!still_running || mc != FETCHM_OK)
      break;

    /* verify improper inputs are treated correctly. */
    mc = fetch_multi_waitfds(multi, NULL, 0, NULL);

    if(mc != FETCHM_BAD_FUNCTION_ARGUMENT) {
      fprintf(stderr, "fetch_multi_waitfds() return code %d instead of "
        "FETCHM_BAD_FUNCTION_ARGUMENT.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    mc = fetch_multi_waitfds(multi, NULL, 1, NULL);

    if(mc != FETCHM_BAD_FUNCTION_ARGUMENT) {
      fprintf(stderr, "fetch_multi_waitfds() return code %d instead of "
        "FETCHM_BAD_FUNCTION_ARGUMENT.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    mc = fetch_multi_waitfds(multi, NULL, 1, &fd_count);

    if(mc != FETCHM_BAD_FUNCTION_ARGUMENT) {
      fprintf(stderr, "fetch_multi_waitfds() return code %d instead of "
        "FETCHM_BAD_FUNCTION_ARGUMENT.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    mc = fetch_multi_waitfds(multi, ufds, 10, &fd_count);

    if(mc != FETCHM_OK) {
      fprintf(stderr, "fetch_multi_waitfds() failed, code %d.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    if(!fd_count)
      continue; /* no descriptors yet */

    /* verify that sending nothing but the fd_count results in at least the
     * same number of fds */
    mc = fetch_multi_waitfds(multi, NULL, 0, &fd_count_chk);

    if(mc != FETCHM_OK) {
      fprintf(stderr, "fetch_multi_waitfds() failed, code %d.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    if(fd_count_chk < fd_count) {
      fprintf(stderr, "fetch_multi_waitfds() should return at least the number "
        "of fds needed\n");
      res = TEST_ERR_FAILURE;
      break;
    }

    /* checking case when we don't have enough space for waitfds */
    mc = fetch_multi_waitfds(multi, ufds1, fd_count - 1, &fd_count_chk);

    if(mc != FETCHM_OUT_OF_MEMORY) {
      fprintf(stderr, "fetch_multi_waitfds() return code %d instead of "
        "FETCHM_OUT_OF_MEMORY.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    if(fd_count_chk < fd_count) {
      fprintf(stderr, "fetch_multi_waitfds() sould return the amount of fds "
        "needed if enough isn't passed in.\n");
      res = TEST_ERR_FAILURE;
      break;
    }

    /* sending ufds with zero size, is valid */
    mc = fetch_multi_waitfds(multi, ufds, 0, NULL);

    if(mc != FETCHM_OUT_OF_MEMORY) {
      fprintf(stderr, "fetch_multi_waitfds() return code %d instead of "
        "FETCHM_OUT_OF_MEMORY.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    mc = fetch_multi_waitfds(multi, ufds, 0, &fd_count_chk);

    if(mc != FETCHM_OUT_OF_MEMORY) {
      fprintf(stderr, "fetch_multi_waitfds() return code %d instead of "
        "FETCHM_OUT_OF_MEMORY.\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }

    if(fd_count_chk < fd_count) {
      fprintf(stderr, "fetch_multi_waitfds() sould return the amount of fds "
        "needed if enough isn't passed in.\n");
      res = TEST_ERR_FAILURE;
      break;
    }

    if(fd_count > max_count)
      max_count = fd_count;

    /* Do polling on descriptors in ufds in Multi 1 */
    mc = fetch_multi_poll(multi1, ufds, fd_count, 500, &numfds);

    if(mc != FETCHM_OK) {
      fprintf(stderr, "fetch_multi_poll() failed, code %d.\\n", mc);
      res = TEST_ERR_FAILURE;
      break;
    }
  }

  for(;;) {
    msg = fetch_multi_info_read(multi, &msgs_left);
    if(!msg)
      break;
    if(msg->msg == FETCHMSG_DONE) {
      result = msg->data.result;

      if(!res)
        res = result;
    }
  }

  fetch_multi_remove_handle(multi, easy1);
  fetch_multi_remove_handle(multi, easy2);

test_cleanup:
  fetch_easy_cleanup(easy1);
  fetch_easy_cleanup(easy2);

  fetch_multi_cleanup(multi);
  fetch_multi_cleanup(multi1);

  if(max_fd_count)
    *max_fd_count = max_count;

  return res;
}

static FETCHcode empty_multi_test(void)
{
  FETCHMcode mc = FETCHM_OK;
  FETCHM *multi = NULL;
  FETCH *easy = NULL;

  struct fetch_waitfd ufds[10];

  FETCHcode res = FETCHE_OK;
  unsigned int fd_count = 0;

  multi_init(multi);

  /* calling fetch_multi_waitfds() on an empty multi handle.  */
  mc = fetch_multi_waitfds(multi, ufds, 10, &fd_count);

  if(mc != FETCHM_OK) {
    fprintf(stderr, "fetch_multi_waitfds() failed, code %d.\n", mc);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  else if(fd_count > 0) {
    fprintf(stderr, "fetch_multi_waitfds() returned non-zero count of "
        "waitfds: %d.\n", fd_count);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* calling fetch_multi_waitfds() on multi handle with added easy handle. */
  easy_init(easy);

  if(set_easy((char *)"http://example.com", easy, TEST_USE_HTTP1) != FETCHE_OK)
    goto test_cleanup;

  multi_add_handle(multi, easy);

  mc = fetch_multi_waitfds(multi, ufds, 10, &fd_count);

  if(mc != FETCHM_OK) {
    fprintf(stderr, "fetch_multi_waitfds() failed, code %d.\n", mc);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  else if(fd_count > 0) {
    fprintf(stderr, "fetch_multi_waitfds() returned non-zero count of "
        "waitfds: %d.\n", fd_count);
    res = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  fetch_multi_remove_handle(multi, easy);

test_cleanup:
  fetch_easy_cleanup(easy);
  fetch_multi_cleanup(multi);
  return res;
}

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  unsigned int fd_count = 0;

  global_init(FETCH_GLOBAL_ALL);

  /* Testing fetch_multi_waitfds on empty and not started handles */
  res = empty_multi_test();
  if(res != FETCHE_OK)
    goto test_cleanup;

  /* HTTP1, expected 2 waitfds - one for each transfer */
  test_run_check(TEST_USE_HTTP1, 2);

  /* HTTP2, expected 2 waitfds - one for each transfer */
  test_run_check(TEST_USE_HTTP2, 2);

  /* HTTP2 with multiplexing, expected 1 waitfds - one for all transfers */
  test_run_check(TEST_USE_HTTP2_MPLEX, 1);

test_cleanup:
  fetch_global_cleanup();
  return res;
}
