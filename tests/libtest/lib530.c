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
 * The purpose of this test is to make sure that if CURLMOPT_SOCKETFUNCTION or
 * CURLMOPT_TIMERFUNCTION returns error, the associated transfer should be
 * aborted correctly.
 */

#include "test.h"

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

struct Sockets {
  curl_socket_t *sockets;
  int count;      /* number of sockets actually stored in array */
  int max_count;  /* max number of sockets that fit in allocated array */
};

struct ReadWriteSockets {
  struct Sockets read, write;
};

/**
 * Remove a file descriptor from a sockets array.
 */
static void removeFd(struct Sockets *sockets, curl_socket_t fd, int mention)
{
  int i;

  if(mention)
    fprintf(stderr, "Remove socket fd %d\n", (int) fd);

  for(i = 0; i < sockets->count; ++i) {
    if(sockets->sockets[i] == fd) {
      if(i < sockets->count - 1)
        memmove(&sockets->sockets[i], &sockets->sockets[i + 1],
              sizeof(curl_socket_t) * (sockets->count - (i + 1)));
      --sockets->count;
    }
  }
}

/**
 * Add a file descriptor to a sockets array.
 * Return 0 on success, 1 on error.
 */
static int addFd(struct Sockets *sockets, curl_socket_t fd, const char *what)
{
  /**
   * To ensure we only have each file descriptor once, we remove it then add
   * it again.
   */
  fprintf(stderr, "Add socket fd %d for %s\n", (int) fd, what);
  removeFd(sockets, fd, 0);
  /*
   * Allocate array storage when required.
   */
  if(!sockets->sockets) {
    sockets->sockets = malloc(sizeof(curl_socket_t) * 20U);
    if(!sockets->sockets)
      return 1;
    sockets->max_count = 20;
  }
  else if(sockets->count + 1 > sockets->max_count) {
    curl_socket_t *ptr = realloc(sockets->sockets, sizeof(curl_socket_t) *
                                 (sockets->max_count + 20));
    if(!ptr)
      /* cleanup in test_cleanup */
      return 1;
    sockets->sockets = ptr;
    sockets->max_count += 20;
  }
  /*
   * Add file descriptor to array.
   */
  sockets->sockets[sockets->count] = fd;
  ++sockets->count;
  return 0;
}

static int max_socket_calls;
static int socket_calls = 0;

/**
 * Callback invoked by curl to poll reading / writing of a socket.
 */
static int curlSocketCallback(CURL *easy, curl_socket_t s, int action,
                              void *userp, void *socketp)
{
  struct ReadWriteSockets *sockets = userp;

  (void)easy; /* unused */
  (void)socketp; /* unused */

  fprintf(stderr, "CURLMOPT_SOCKETFUNCTION called: %u\n", socket_calls++);
  if(socket_calls == max_socket_calls) {
    fprintf(stderr, "curlSocketCallback returns error\n");
    return -1;
  }

  if(action == CURL_POLL_IN || action == CURL_POLL_INOUT)
    if(addFd(&sockets->read, s, "read"))
      return -1; /* bail out */

  if(action == CURL_POLL_OUT || action == CURL_POLL_INOUT)
    if(addFd(&sockets->write, s, "write"))
      return -1;

  if(action == CURL_POLL_REMOVE) {
    removeFd(&sockets->read, s, 1);
    removeFd(&sockets->write, s, 0);
  }

  return 0;
}

static int max_timer_calls;
static int timer_calls = 0;

/**
 * Callback invoked by curl to set a timeout.
 */
static int curlTimerCallback(CURLM *multi, long timeout_ms, void *userp)
{
  struct timeval *timeout = userp;

  (void)multi; /* unused */
  fprintf(stderr, "CURLMOPT_TIMERFUNCTION called: %u\n", timer_calls++);
  if(timer_calls == max_timer_calls) {
    fprintf(stderr, "curlTimerCallback returns error\n");
    return -1;
  }
  if(timeout_ms != -1) {
    *timeout = tutil_tvnow();
    timeout->tv_usec += (int)timeout_ms * 1000;
  }
  else {
    timeout->tv_sec = -1;
  }
  return 0;
}

/**
 * Check for curl completion.
 */
static int checkForCompletion(CURLM *curl, int *success)
{
  int result = 0;
  *success = 0;
  while(1) {
    int numMessages;
    CURLMsg *message = curl_multi_info_read(curl, &numMessages);
    if(!message)
      break;
    if(message->msg == CURLMSG_DONE) {
      result = 1;
      if(message->data.result == CURLE_OK)
        *success = 1;
      else
        *success = 0;
    }
    else {
      fprintf(stderr, "Got an unexpected message from curl: %i\n",
              message->msg);
      result = 1;
      *success = 0;
    }
  }
  return result;
}

static int getMicroSecondTimeout(struct timeval *timeout)
{
  struct timeval now;
  ssize_t result;
  now = tutil_tvnow();
  result = (ssize_t)((timeout->tv_sec - now.tv_sec) * 1000000 +
    timeout->tv_usec - now.tv_usec);
  if(result < 0)
    result = 0;

  return curlx_sztosi(result);
}

/**
 * Update a fd_set with all of the sockets in use.
 */
static void updateFdSet(struct Sockets *sockets, fd_set* fdset,
                        curl_socket_t *maxFd)
{
  int i;
  for(i = 0; i < sockets->count; ++i) {
#if defined(__DJGPP__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
    FD_SET(sockets->sockets[i], fdset);
#if defined(__DJGPP__)
#pragma GCC diagnostic pop
#endif
    if(*maxFd < sockets->sockets[i] + 1) {
      *maxFd = sockets->sockets[i] + 1;
    }
  }
}

static int socket_action(CURLM *curl, curl_socket_t s, int evBitmask,
                         const char *info)
{
  int numhandles = 0;
  CURLMcode result = curl_multi_socket_action(curl, s, evBitmask, &numhandles);
  if(result != CURLM_OK) {
    fprintf(stderr, "Curl error on %s: %i (%s)\n",
            info, result, curl_multi_strerror(result));
  }
  return (int)result;
}

/**
 * Invoke curl when a file descriptor is set.
 */
static int checkFdSet(CURLM *curl,
                      struct Sockets *sockets, fd_set *fdset,
                      int evBitmask, const char *name)
{
  int i;
  int result = 0;
  for(i = 0; i < sockets->count; ++i) {
    if(FD_ISSET(sockets->sockets[i], fdset)) {
      result = socket_action(curl, sockets->sockets[i], evBitmask, name);
      if(result)
        break;
    }
  }
  return result;
}

static CURLcode testone(char *URL, int timercb, int socketcb)
{
  CURLcode res = CURLE_OK;
  CURL *curl = NULL;  CURLM *m = NULL;
  struct ReadWriteSockets sockets = {{NULL, 0, 0}, {NULL, 0, 0}};
  int success = 0;
  struct timeval timeout = {0};
  timeout.tv_sec = (time_t)-1;

  /* set the limits */
  max_timer_calls = timercb;
  max_socket_calls = socketcb;
  timer_calls = 0; /* reset the globals */
  socket_calls = 0;

  fprintf(stderr, "start test: %d %d\n", timercb, socketcb);
  start_test_timing();

  res_global_init(CURL_GLOBAL_ALL);
  if(res != CURLE_OK)
    return res;

  easy_init(curl);

  /* specify target */
  easy_setopt(curl, CURLOPT_URL, URL);

  /* go verbose */
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  multi_init(m);

  multi_setopt(m, CURLMOPT_SOCKETFUNCTION, curlSocketCallback);
  multi_setopt(m, CURLMOPT_SOCKETDATA, &sockets);

  multi_setopt(m, CURLMOPT_TIMERFUNCTION, curlTimerCallback);
  multi_setopt(m, CURLMOPT_TIMERDATA, &timeout);

  multi_add_handle(m, curl);

  if(socket_action(m, CURL_SOCKET_TIMEOUT, 0, "timeout")) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  while(!checkForCompletion(m, &success)) {
    fd_set readSet, writeSet;
    curl_socket_t maxFd = 0;
    struct timeval tv = {0};
    tv.tv_sec = 10;

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    updateFdSet(&sockets.read, &readSet, &maxFd);
    updateFdSet(&sockets.write, &writeSet, &maxFd);

    if(timeout.tv_sec != (time_t)-1) {
      int usTimeout = getMicroSecondTimeout(&timeout);
      tv.tv_sec = usTimeout / 1000000;
      tv.tv_usec = usTimeout % 1000000;
    }
    else if(maxFd <= 0) {
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
    }

    assert(maxFd);
    select_test((int)maxFd, &readSet, &writeSet, NULL, &tv);

    /* Check the sockets for reading / writing */
    if(checkFdSet(m, &sockets.read, &readSet, CURL_CSELECT_IN, "read")) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    if(checkFdSet(m, &sockets.write, &writeSet, CURL_CSELECT_OUT, "write")) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    if(timeout.tv_sec != (time_t)-1 && getMicroSecondTimeout(&timeout) == 0) {
      /* Curl's timer has elapsed. */
      if(socket_action(m, CURL_SOCKET_TIMEOUT, 0, "timeout")) {
        res = TEST_ERR_BAD_TIMEOUT;
        goto test_cleanup;
      }
    }

    abort_on_test_timeout();
  }

  if(!success) {
    fprintf(stderr, "Error getting file.\n");
    res = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:

  /* proper cleanup sequence */
  fprintf(stderr, "cleanup: %d %d\n", timercb, socketcb);
  curl_multi_remove_handle(m, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);
  curl_global_cleanup();

  /* free local memory */
  free(sockets.read.sockets);
  free(sockets.write.sockets);
  return res;
}

CURLcode test(char *URL)
{
  CURLcode rc;
  /* rerun the same transfer multiple times and make it fail in different
     callback calls */
  rc = testone(URL, 0, 0);
  if(rc)
    fprintf(stderr, "test 0/0 failed: %d\n", rc);

  rc = testone(URL, 1, 0);
  if(!rc)
    fprintf(stderr, "test 1/0 failed: %d\n", rc);

  rc = testone(URL, 2, 0);
  if(!rc)
    fprintf(stderr, "test 2/0 failed: %d\n", rc);

  rc = testone(URL, 0, 1);
  if(!rc)
    fprintf(stderr, "test 0/1 failed: %d\n", rc);

  rc = testone(URL, 0, 2);
  if(!rc)
    fprintf(stderr, "test 0/2 failed: %d\n", rc);

  return CURLE_OK;
}
