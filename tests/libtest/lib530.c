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
 * The purpose of this test is to make sure that if FETCHMOPT_SOCKETFUNCTION or
 * FETCHMOPT_TIMERFUNCTION returns error, the associated transfer should be
 * aborted correctly.
 */

#include "test.h"

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

struct Sockets
{
  fetch_socket_t *sockets;
  int count;     /* number of sockets actually stored in array */
  int max_count; /* max number of sockets that fit in allocated array */
};

struct ReadWriteSockets
{
  struct Sockets read, write;
};

/**
 * Remove a file descriptor from a sockets array.
 */
static void removeFd(struct Sockets *sockets, fetch_socket_t fd, int mention)
{
  int i;

  if (mention)
    fprintf(stderr, "Remove socket fd %d\n", (int)fd);

  for (i = 0; i < sockets->count; ++i)
  {
    if (sockets->sockets[i] == fd)
    {
      if (i < sockets->count - 1)
        memmove(&sockets->sockets[i], &sockets->sockets[i + 1],
                sizeof(fetch_socket_t) * (sockets->count - (i + 1)));
      --sockets->count;
    }
  }
}

/**
 * Add a file descriptor to a sockets array.
 * Return 0 on success, 1 on error.
 */
static int addFd(struct Sockets *sockets, fetch_socket_t fd, const char *what)
{
  /**
   * To ensure we only have each file descriptor once, we remove it then add
   * it again.
   */
  fprintf(stderr, "Add socket fd %d for %s\n", (int)fd, what);
  removeFd(sockets, fd, 0);
  /*
   * Allocate array storage when required.
   */
  if (!sockets->sockets)
  {
    sockets->sockets = malloc(sizeof(fetch_socket_t) * 20U);
    if (!sockets->sockets)
      return 1;
    sockets->max_count = 20;
  }
  else if (sockets->count + 1 > sockets->max_count)
  {
    fetch_socket_t *ptr = realloc(sockets->sockets, sizeof(fetch_socket_t) *
                                                        (sockets->max_count + 20));
    if (!ptr)
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
 * Callback invoked by fetch to poll reading / writing of a socket.
 */
static int fetchSocketCallback(FETCH *easy, fetch_socket_t s, int action,
                               void *userp, void *socketp)
{
  struct ReadWriteSockets *sockets = userp;

  (void)easy;    /* unused */
  (void)socketp; /* unused */

  fprintf(stderr, "FETCHMOPT_SOCKETFUNCTION called: %u\n", socket_calls++);
  if (socket_calls == max_socket_calls)
  {
    fprintf(stderr, "fetchSocketCallback returns error\n");
    return -1;
  }

  if (action == FETCH_POLL_IN || action == FETCH_POLL_INOUT)
    if (addFd(&sockets->read, s, "read"))
      return -1; /* bail out */

  if (action == FETCH_POLL_OUT || action == FETCH_POLL_INOUT)
    if (addFd(&sockets->write, s, "write"))
      return -1;

  if (action == FETCH_POLL_REMOVE)
  {
    removeFd(&sockets->read, s, 1);
    removeFd(&sockets->write, s, 0);
  }

  return 0;
}

static int max_timer_calls;
static int timer_calls = 0;

/**
 * Callback invoked by fetch to set a timeout.
 */
static int fetchTimerCallback(FETCHM *multi, long timeout_ms, void *userp)
{
  struct timeval *timeout = userp;

  (void)multi; /* unused */
  fprintf(stderr, "FETCHMOPT_TIMERFUNCTION called: %u\n", timer_calls++);
  if (timer_calls == max_timer_calls)
  {
    fprintf(stderr, "fetchTimerCallback returns error\n");
    return -1;
  }
  if (timeout_ms != -1)
  {
    *timeout = tutil_tvnow();
    timeout->tv_usec += (int)timeout_ms * 1000;
  }
  else
  {
    timeout->tv_sec = -1;
  }
  return 0;
}

/**
 * Check for fetch completion.
 */
static int checkForCompletion(FETCHM *fetch, int *success)
{
  int result = 0;
  *success = 0;
  while (1)
  {
    int numMessages;
    FETCHMsg *message = fetch_multi_info_read(fetch, &numMessages);
    if (!message)
      break;
    if (message->msg == FETCHMSG_DONE)
    {
      result = 1;
      if (message->data.result == FETCHE_OK)
        *success = 1;
      else
        *success = 0;
    }
    else
    {
      fprintf(stderr, "Got an unexpected message from fetch: %i\n",
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
  if (result < 0)
    result = 0;

  return fetchx_sztosi(result);
}

/**
 * Update a fd_set with all of the sockets in use.
 */
static void updateFdSet(struct Sockets *sockets, fd_set *fdset,
                        fetch_socket_t *maxFd)
{
  int i;
  for (i = 0; i < sockets->count; ++i)
  {
#if defined(__DJGPP__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
    FD_SET(sockets->sockets[i], fdset);
#if defined(__DJGPP__)
#pragma GCC diagnostic pop
#endif
    if (*maxFd < sockets->sockets[i] + 1)
    {
      *maxFd = sockets->sockets[i] + 1;
    }
  }
}

static int socket_action(FETCHM *fetch, fetch_socket_t s, int evBitmask,
                         const char *info)
{
  int numhandles = 0;
  FETCHMcode result = fetch_multi_socket_action(fetch, s, evBitmask, &numhandles);
  if (result != FETCHM_OK)
  {
    fprintf(stderr, "Curl error on %s: %i (%s)\n",
            info, result, fetch_multi_strerror(result));
  }
  return (int)result;
}

/**
 * Invoke fetch when a file descriptor is set.
 */
static int checkFdSet(FETCHM *fetch,
                      struct Sockets *sockets, fd_set *fdset,
                      int evBitmask, const char *name)
{
  int i;
  int result = 0;
  for (i = 0; i < sockets->count; ++i)
  {
    if (FD_ISSET(sockets->sockets[i], fdset))
    {
      result = socket_action(fetch, sockets->sockets[i], evBitmask, name);
      if (result)
        break;
    }
  }
  return result;
}

static FETCHcode testone(char *URL, int timercb, int socketcb)
{
  FETCHcode res = FETCHE_OK;
  FETCH *fetch = NULL;
  FETCHM *m = NULL;
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

  res_global_init(FETCH_GLOBAL_ALL);
  if (res != FETCHE_OK)
    return res;

  easy_init(fetch);

  /* specify target */
  easy_setopt(fetch, FETCHOPT_URL, URL);

  /* go verbose */
  easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  multi_init(m);

  multi_setopt(m, FETCHMOPT_SOCKETFUNCTION, fetchSocketCallback);
  multi_setopt(m, FETCHMOPT_SOCKETDATA, &sockets);

  multi_setopt(m, FETCHMOPT_TIMERFUNCTION, fetchTimerCallback);
  multi_setopt(m, FETCHMOPT_TIMERDATA, &timeout);

  multi_add_handle(m, fetch);

  if (socket_action(m, FETCH_SOCKET_TIMEOUT, 0, "timeout"))
  {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  while (!checkForCompletion(m, &success))
  {
    fd_set readSet, writeSet;
    fetch_socket_t maxFd = 0;
    struct timeval tv = {0};
    tv.tv_sec = 10;

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    updateFdSet(&sockets.read, &readSet, &maxFd);
    updateFdSet(&sockets.write, &writeSet, &maxFd);

    if (timeout.tv_sec != (time_t)-1)
    {
      int usTimeout = getMicroSecondTimeout(&timeout);
      tv.tv_sec = usTimeout / 1000000;
      tv.tv_usec = usTimeout % 1000000;
    }
    else if (maxFd <= 0)
    {
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
    }

    assert(maxFd);
    select_test((int)maxFd, &readSet, &writeSet, NULL, &tv);

    /* Check the sockets for reading / writing */
    if (checkFdSet(m, &sockets.read, &readSet, FETCH_CSELECT_IN, "read"))
    {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    if (checkFdSet(m, &sockets.write, &writeSet, FETCH_CSELECT_OUT, "write"))
    {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    if (timeout.tv_sec != (time_t)-1 && getMicroSecondTimeout(&timeout) == 0)
    {
      /* Curl's timer has elapsed. */
      if (socket_action(m, FETCH_SOCKET_TIMEOUT, 0, "timeout"))
      {
        res = TEST_ERR_BAD_TIMEOUT;
        goto test_cleanup;
      }
    }

    abort_on_test_timeout();
  }

  if (!success)
  {
    fprintf(stderr, "Error getting file.\n");
    res = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:

  /* proper cleanup sequence */
  fprintf(stderr, "cleanup: %d %d\n", timercb, socketcb);
  fetch_multi_remove_handle(m, fetch);
  fetch_easy_cleanup(fetch);
  fetch_multi_cleanup(m);
  fetch_global_cleanup();

  /* free local memory */
  free(sockets.read.sockets);
  free(sockets.write.sockets);
  return res;
}

FETCHcode test(char *URL)
{
  FETCHcode rc;
  /* rerun the same transfer multiple times and make it fail in different
     callback calls */
  rc = testone(URL, 0, 0);
  if (rc)
    fprintf(stderr, "test 0/0 failed: %d\n", rc);

  rc = testone(URL, 1, 0);
  if (!rc)
    fprintf(stderr, "test 1/0 failed: %d\n", rc);

  rc = testone(URL, 2, 0);
  if (!rc)
    fprintf(stderr, "test 2/0 failed: %d\n", rc);

  rc = testone(URL, 0, 1);
  if (!rc)
    fprintf(stderr, "test 0/1 failed: %d\n", rc);

  rc = testone(URL, 0, 2);
  if (!rc)
    fprintf(stderr, "test 0/2 failed: %d\n", rc);

  return FETCHE_OK;
}
