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
 */
static void addFd(struct Sockets *sockets, fetch_socket_t fd, const char *what)
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
      return;
    sockets->max_count = 20;
  }
  else if (sockets->count >= sockets->max_count)
  {
    /* this can't happen in normal cases */
    fprintf(stderr, "too many file handles error\n");
    exit(2);
  }
  /*
   * Add file descriptor to array.
   */
  sockets->sockets[sockets->count] = fd;
  ++sockets->count;
}

/**
 * Callback invoked by fetch to poll reading / writing of a socket.
 */
static int fetchSocketCallback(FETCH *easy, fetch_socket_t s, int action,
                               void *userp, void *socketp)
{
  struct ReadWriteSockets *sockets = userp;

  (void)easy;    /* unused */
  (void)socketp; /* unused */

  if (action == FETCH_POLL_IN || action == FETCH_POLL_INOUT)
    addFd(&sockets->read, s, "read");

  if (action == FETCH_POLL_OUT || action == FETCH_POLL_INOUT)
    addFd(&sockets->write, s, "write");

  if (action == FETCH_POLL_REMOVE)
  {
    removeFd(&sockets->read, s, 1);
    removeFd(&sockets->write, s, 0);
  }

  return 0;
}

/**
 * Callback invoked by fetch to set a timeout.
 */
static int fetchTimerCallback(FETCHM *multi, long timeout_ms, void *userp)
{
  struct timeval *timeout = userp;

  (void)multi; /* unused */
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
              (int)message->msg);
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

static void notifyFetch(FETCHM *fetch, fetch_socket_t s, int evBitmask,
                       const char *info)
{
  int numhandles = 0;
  FETCHMcode result = fetch_multi_socket_action(fetch, s, evBitmask, &numhandles);
  if (result != FETCHM_OK)
  {
    fprintf(stderr, "Fetch error on %s: %i (%s)\n",
            info, result, fetch_multi_strerror(result));
  }
}

/**
 * Invoke fetch when a file descriptor is set.
 */
static void checkFdSet(FETCHM *fetch, struct Sockets *sockets, fd_set *fdset,
                       int evBitmask, const char *name)
{
  int i;
  for (i = 0; i < sockets->count; ++i)
  {
    if (FD_ISSET(sockets->sockets[i], fdset))
    {
      notifyFetch(fetch, sockets->sockets[i], evBitmask, name);
    }
  }
}

FETCHcode test(char *URL)
{
  FETCHcode res = FETCHE_OK;
  FETCH *fetch = NULL;
  FILE *hd_src = NULL;
  int hd;
  struct_stat file_info;
  FETCHM *m = NULL;
  struct ReadWriteSockets sockets = {{NULL, 0, 0}, {NULL, 0, 0}};
  int success = 0;
  struct timeval timeout = {0};
  timeout.tv_sec = (time_t)-1;

  assert(test_argc >= 5);

  start_test_timing();

  if (!libtest_arg3)
  {
    fprintf(stderr, "Usage: lib582 [url] [filename] [username]\n");
    return TEST_ERR_USAGE;
  }

  hd_src = fopen(libtest_arg2, "rb");
  if (!hd_src)
  {
    fprintf(stderr, "fopen() failed with error: %d (%s)\n",
            errno, strerror(errno));
    fprintf(stderr, "Error opening file: (%s)\n", libtest_arg2);
    return TEST_ERR_FOPEN;
  }

  /* get the file size of the local file */
  hd = fstat(fileno(hd_src), &file_info);
  if (hd == -1)
  {
    /* can't open file, bail out */
    fprintf(stderr, "fstat() failed with error: %d (%s)\n",
            errno, strerror(errno));
    fprintf(stderr, "ERROR: cannot open file (%s)\n", libtest_arg2);
    fclose(hd_src);
    return TEST_ERR_FSTAT;
  }
  fprintf(stderr, "Set to upload %d bytes\n", (int)file_info.st_size);

  res_global_init(FETCH_GLOBAL_ALL);
  if (res)
  {
    fclose(hd_src);
    return res;
  }

  easy_init(fetch);

  /* enable uploading */
  easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);

  /* specify target */
  easy_setopt(fetch, FETCHOPT_URL, URL);

  /* go verbose */
  easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* now specify which file to upload */
  easy_setopt(fetch, FETCHOPT_READDATA, hd_src);

  easy_setopt(fetch, FETCHOPT_USERPWD, libtest_arg3);
  easy_setopt(fetch, FETCHOPT_SSH_PUBLIC_KEYFILE, test_argv[4]);
  easy_setopt(fetch, FETCHOPT_SSH_PRIVATE_KEYFILE, test_argv[5]);
  easy_setopt(fetch, FETCHOPT_SSL_VERIFYHOST, 0L);

  easy_setopt(fetch, FETCHOPT_INFILESIZE_LARGE, (fetch_off_t)file_info.st_size);

  multi_init(m);

  multi_setopt(m, FETCHMOPT_SOCKETFUNCTION, fetchSocketCallback);
  multi_setopt(m, FETCHMOPT_SOCKETDATA, &sockets);

  multi_setopt(m, FETCHMOPT_TIMERFUNCTION, fetchTimerCallback);
  multi_setopt(m, FETCHMOPT_TIMERDATA, &timeout);

  multi_add_handle(m, fetch);

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

    select_test((int)maxFd, &readSet, &writeSet, NULL, &tv);

    /* Check the sockets for reading / writing */
    checkFdSet(m, &sockets.read, &readSet, FETCH_CSELECT_IN, "read");
    checkFdSet(m, &sockets.write, &writeSet, FETCH_CSELECT_OUT, "write");

    if (timeout.tv_sec != (time_t)-1 && getMicroSecondTimeout(&timeout) == 0)
    {
      /* Fetch's timer has elapsed. */
      notifyFetch(m, FETCH_SOCKET_TIMEOUT, 0, "timeout");
    }

    abort_on_test_timeout();
  }

  if (!success)
  {
    fprintf(stderr, "Error uploading file.\n");
    res = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:

  /* proper cleanup sequence - type PB */

  fetch_multi_remove_handle(m, fetch);
  fetch_easy_cleanup(fetch);
  fetch_multi_cleanup(m);
  fetch_global_cleanup();

  /* close the local file */
  fclose(hd_src);

  /* free local memory */
  free(sockets.read.sockets);
  free(sockets.write.sockets);

  return res;
}
