/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "test.h"

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 60 * 1000

struct Sockets
{
  curl_socket_t *sockets;
  int count;      /* number of sockets actually stored in array */
  int max_count;  /* max number of sockets that fit in allocated array */
};

struct ReadWriteSockets
{
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
 */
static void addFd(struct Sockets *sockets, curl_socket_t fd, const char *what)
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
      return;
    sockets->max_count = 20;
  }
  else if(sockets->count + 1 > sockets->max_count) {
    curl_socket_t *oldptr = sockets->sockets;
    sockets->sockets = realloc(oldptr, sizeof(curl_socket_t) *
                               (sockets->max_count + 20));
    if(!sockets->sockets) {
      /* cleanup in test_cleanup */
      sockets->sockets = oldptr;
      return;
    }
    sockets->max_count += 20;
  }
  /*
   * Add file descriptor to array.
   */
  sockets->sockets[sockets->count] = fd;
  ++sockets->count;
}

/**
 * Callback invoked by curl to poll reading / writing of a socket.
 */
static int curlSocketCallback(CURL *easy, curl_socket_t s, int action,
                              void *userp, void *socketp)
{
  struct ReadWriteSockets *sockets = userp;

  (void)easy; /* unused */
  (void)socketp; /* unused */

  if(action == CURL_POLL_IN || action == CURL_POLL_INOUT)
    addFd(&sockets->read, s, "read");

  if(action == CURL_POLL_OUT || action == CURL_POLL_INOUT)
    addFd(&sockets->write, s, "write");

  if(action == CURL_POLL_REMOVE) {
    removeFd(&sockets->read, s, 1);
    removeFd(&sockets->write, s, 0);
  }

  return 0;
}

/**
 * Callback invoked by curl to set a timeout.
 */
static int curlTimerCallback(CURLM *multi, long timeout_ms, void *userp)
{
  struct timeval *timeout = userp;

  (void)multi; /* unused */
  if(timeout_ms != -1) {
    *timeout = tutil_tvnow();
    timeout->tv_usec += timeout_ms * 1000;
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
  int numMessages;
  CURLMsg *message;
  int result = 0;
  *success = 0;
  while((message = curl_multi_info_read(curl, &numMessages)) != NULL) {
    if(message->msg == CURLMSG_DONE) {
      result = 1;
      if(message->data.result == CURLE_OK)
        *success = 1;
      else
        *success = 0;
    }
    else {
      fprintf(stderr, "Got an unexpected message from curl: %i\n",
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
    FD_SET(sockets->sockets[i], fdset);
    if(*maxFd < sockets->sockets[i] + 1) {
      *maxFd = sockets->sockets[i] + 1;
    }
  }
}

static void notifyCurl(CURLM *curl, curl_socket_t s, int evBitmask,
                       const char *info)
{
  int numhandles = 0;
  CURLMcode result = curl_multi_socket_action(curl, s, evBitmask, &numhandles);
  if(result != CURLM_OK) {
    fprintf(stderr, "Curl error on %s: %i (%s)\n",
            info, result, curl_multi_strerror(result));
  }
}

/**
 * Invoke curl when a file descriptor is set.
 */
static void checkFdSet(CURLM *curl, struct Sockets *sockets, fd_set *fdset,
                       int evBitmask, const char *name)
{
  int i;
  for(i = 0; i < sockets->count; ++i) {
    if(FD_ISSET(sockets->sockets[i], fdset)) {
      notifyCurl(curl, sockets->sockets[i], evBitmask, name);
    }
  }
}

int test(char *URL)
{
  int res = 0;
  CURL *curl = NULL;
  FILE *hd_src = NULL;
  int hd;
  struct_stat file_info;
  CURLM *m = NULL;
  struct ReadWriteSockets sockets = {{NULL, 0, 0}, {NULL, 0, 0}};
  struct timeval timeout = {-1, 0};
  int success = 0;

  start_test_timing();

  if(!libtest_arg3) {
    fprintf(stderr, "Usage: lib582 [url] [filename] [username]\n");
    return TEST_ERR_USAGE;
  }

  hd_src = fopen(libtest_arg2, "rb");
  if(NULL == hd_src) {
    fprintf(stderr, "fopen() failed with error: %d (%s)\n",
            errno, strerror(errno));
    fprintf(stderr, "Error opening file: (%s)\n", libtest_arg2);
    return TEST_ERR_FOPEN;
  }

  /* get the file size of the local file */
  hd = fstat(fileno(hd_src), &file_info);
  if(hd == -1) {
    /* can't open file, bail out */
    fprintf(stderr, "fstat() failed with error: %d (%s)\n",
            errno, strerror(errno));
    fprintf(stderr, "ERROR: cannot open file (%s)\n", libtest_arg2);
    fclose(hd_src);
    return TEST_ERR_FSTAT;
  }
  fprintf(stderr, "Set to upload %d bytes\n", (int)file_info.st_size);

  res_global_init(CURL_GLOBAL_ALL);
  if(res) {
    fclose(hd_src);
    return res;
  }

  easy_init(curl);

  /* enable uploading */
  easy_setopt(curl, CURLOPT_UPLOAD, 1L);

  /* specify target */
  easy_setopt(curl, CURLOPT_URL, URL);

  /* go verbose */
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* now specify which file to upload */
  easy_setopt(curl, CURLOPT_READDATA, hd_src);

  easy_setopt(curl, CURLOPT_USERPWD, libtest_arg3);
  easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, "curl_client_key.pub");
  easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, "curl_client_key");
  easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);

  multi_init(m);

  multi_setopt(m, CURLMOPT_SOCKETFUNCTION, curlSocketCallback);
  multi_setopt(m, CURLMOPT_SOCKETDATA, &sockets);

  multi_setopt(m, CURLMOPT_TIMERFUNCTION, curlTimerCallback);
  multi_setopt(m, CURLMOPT_TIMERDATA, &timeout);

  multi_add_handle(m, curl);

  while(!checkForCompletion(m, &success)) {
    fd_set readSet, writeSet;
    curl_socket_t maxFd = 0;
    struct timeval tv = {10, 0};

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    updateFdSet(&sockets.read, &readSet, &maxFd);
    updateFdSet(&sockets.write, &writeSet, &maxFd);

    if(timeout.tv_sec != -1) {
      int usTimeout = getMicroSecondTimeout(&timeout);
      tv.tv_sec = usTimeout / 1000000;
      tv.tv_usec = usTimeout % 1000000;
    }
    else if(maxFd <= 0) {
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
    }

    select_test((int)maxFd, &readSet, &writeSet, NULL, &tv);

    /* Check the sockets for reading / writing */
    checkFdSet(m, &sockets.read, &readSet, CURL_CSELECT_IN, "read");
    checkFdSet(m, &sockets.write, &writeSet, CURL_CSELECT_OUT, "write");

    if(timeout.tv_sec != -1 && getMicroSecondTimeout(&timeout) == 0) {
      /* Curl's timer has elapsed. */
      notifyCurl(m, CURL_SOCKET_TIMEOUT, 0, "timeout");
    }

    abort_on_test_timeout();
  }

  if(!success) {
    fprintf(stderr, "Error uploading file.\n");
    res = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:

  /* proper cleanup sequence - type PB */

  curl_multi_remove_handle(m, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);
  curl_global_cleanup();

  /* close the local file */
  fclose(hd_src);

  /* free local memory */
  free(sockets.read.sockets);
  free(sockets.write.sockets);

  return res;
}
