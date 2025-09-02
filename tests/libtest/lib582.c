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
#include "first.h"

#include "memdebug.h"

struct t582_Sockets {
  curl_socket_t *sockets;
  int count;      /* number of sockets actually stored in array */
  int max_count;  /* max number of sockets that fit in allocated array */
};

struct t582_ReadWriteSockets {
  struct t582_Sockets read, write;
};

/**
 * Remove a file descriptor from a sockets array.
 */
static void t582_removeFd(struct t582_Sockets *sockets, curl_socket_t fd,
                          int mention)
{
  int i;

  if(mention)
    curl_mfprintf(stderr, "Remove socket fd %" FMT_SOCKET_T "\n", fd);

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
static void t582_addFd(struct t582_Sockets *sockets, curl_socket_t fd,
                       const char *what)
{
  /**
   * To ensure we only have each file descriptor once, we remove it then add
   * it again.
   */
  curl_mfprintf(stderr, "Add socket fd %" FMT_SOCKET_T " for %s\n", fd, what);
  t582_removeFd(sockets, fd, 0);
  /*
   * Allocate array storage when required.
   */
  if(!sockets->sockets) {
    sockets->sockets = malloc(sizeof(curl_socket_t) * 20U);
    if(!sockets->sockets)
      return;
    sockets->max_count = 20;
  }
  else if(sockets->count >= sockets->max_count) {
    /* this can't happen in normal cases */
    curl_mfprintf(stderr, "too many file handles error\n");
    exit(2);
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
static int t582_curlSocketCallback(CURL *easy, curl_socket_t s, int action,
                                   void *userp, void *socketp)
{
  struct t582_ReadWriteSockets *sockets = userp;

  (void)easy;
  (void)socketp;

  if(action == CURL_POLL_IN || action == CURL_POLL_INOUT)
    t582_addFd(&sockets->read, s, "read");

  if(action == CURL_POLL_OUT || action == CURL_POLL_INOUT)
    t582_addFd(&sockets->write, s, "write");

  if(action == CURL_POLL_REMOVE) {
    t582_removeFd(&sockets->read, s, 1);
    t582_removeFd(&sockets->write, s, 0);
  }

  return 0;
}

/**
 * Callback invoked by curl to set a timeout.
 */
static int t582_curlTimerCallback(CURLM *multi, long timeout_ms, void *userp)
{
  struct curltime *timeout = userp;

  (void)multi;
  if(timeout_ms != -1) {
    *timeout = curlx_now();
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
static int t582_checkForCompletion(CURLM *curl, int *success)
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
      curl_mfprintf(stderr, "Got an unexpected message from curl: %i\n",
                    message->msg);
      result = 1;
      *success = 0;
    }
  }
  return result;
}

static ssize_t t582_getMicroSecondTimeout(struct curltime *timeout)
{
  struct curltime now;
  ssize_t result;
  now = curlx_now();
  result = (ssize_t)((timeout->tv_sec - now.tv_sec) * 1000000 +
    timeout->tv_usec - now.tv_usec);
  if(result < 0)
    result = 0;

  return result;
}

/**
 * Update a fd_set with all of the sockets in use.
 */
static void t582_updateFdSet(struct t582_Sockets *sockets, fd_set* fdset,
                             curl_socket_t *maxFd)
{
  int i;
  for(i = 0; i < sockets->count; ++i) {
#ifdef __DJGPP__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
    FD_SET(sockets->sockets[i], fdset);
#ifdef __DJGPP__
#pragma GCC diagnostic pop
#endif
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
    curl_mfprintf(stderr, "Curl error on %s (%i) %s\n",
                  info, result, curl_multi_strerror(result));
  }
}

/**
 * Invoke curl when a file descriptor is set.
 */
static void t582_checkFdSet(CURLM *curl, struct t582_Sockets *sockets,
                            fd_set *fdset, int evBitmask, const char *name)
{
  int i;
  for(i = 0; i < sockets->count; ++i) {
    if(FD_ISSET(sockets->sockets[i], fdset)) {
      notifyCurl(curl, sockets->sockets[i], evBitmask, name);
    }
  }
}

static CURLcode test_lib582(const char *URL)
{
  CURLcode res = CURLE_OK;
  CURL *curl = NULL;
  FILE *hd_src = NULL;
  int hd;
  struct_stat file_info;
  CURLM *m = NULL;
  struct t582_ReadWriteSockets sockets = {{NULL, 0, 0}, {NULL, 0, 0}};
  int success = 0;
  struct curltime timeout = {0};
  timeout.tv_sec = (time_t)-1;

  assert(test_argc >= 5);

  start_test_timing();

  if(!libtest_arg3) {
    curl_mfprintf(stderr, "Usage: lib582 [url] [filename] [username]\n");
    return TEST_ERR_USAGE;
  }

  hd_src = fopen(libtest_arg2, "rb");
  if(!hd_src) {
    curl_mfprintf(stderr, "fopen() failed with error (%d) %s\n",
                  errno, strerror(errno));
    curl_mfprintf(stderr, "Error opening file '%s'\n", libtest_arg2);
    return TEST_ERR_FOPEN;
  }

  /* get the file size of the local file */
#ifdef UNDER_CE
  hd = stat(libtest_arg2, &file_info);
#else
  hd = fstat(fileno(hd_src), &file_info);
#endif
  if(hd == -1) {
    /* can't open file, bail out */
    curl_mfprintf(stderr, "fstat() failed with error (%d) %s\n",
                  errno, strerror(errno));
    curl_mfprintf(stderr, "Error opening file '%s'\n", libtest_arg2);
    fclose(hd_src);
    return TEST_ERR_FSTAT;
  }
  curl_mfprintf(stderr, "Set to upload %" CURL_FORMAT_CURL_OFF_T " bytes\n",
                (curl_off_t)file_info.st_size);

  res_global_init(CURL_GLOBAL_ALL);
  if(res != CURLE_OK) {
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
  easy_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, test_argv[4]);
  easy_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, test_argv[5]);
  easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)file_info.st_size);

  multi_init(m);

  multi_setopt(m, CURLMOPT_SOCKETFUNCTION, t582_curlSocketCallback);
  multi_setopt(m, CURLMOPT_SOCKETDATA, &sockets);

  multi_setopt(m, CURLMOPT_TIMERFUNCTION, t582_curlTimerCallback);
  multi_setopt(m, CURLMOPT_TIMERDATA, &timeout);

  multi_add_handle(m, curl);

  while(!t582_checkForCompletion(m, &success)) {
    fd_set readSet, writeSet;
    curl_socket_t maxFd = 0;
    struct timeval tv = {0};
    tv.tv_sec = 10;

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    t582_updateFdSet(&sockets.read, &readSet, &maxFd);
    t582_updateFdSet(&sockets.write, &writeSet, &maxFd);

    if(timeout.tv_sec != (time_t)-1) {
      int usTimeout = curlx_sztosi(t582_getMicroSecondTimeout(&timeout));
      tv.tv_sec = usTimeout / 1000000;
      tv.tv_usec = usTimeout % 1000000;
    }
    else if(maxFd <= 0) {
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
    }

    select_test((int)maxFd, &readSet, &writeSet, NULL, &tv);

    /* Check the sockets for reading / writing */
    t582_checkFdSet(m, &sockets.read, &readSet, CURL_CSELECT_IN, "read");
    t582_checkFdSet(m, &sockets.write, &writeSet, CURL_CSELECT_OUT, "write");

    if(timeout.tv_sec != (time_t)-1 &&
       t582_getMicroSecondTimeout(&timeout) == 0) {
      /* Curl's timer has elapsed. */
      notifyCurl(m, CURL_SOCKET_TIMEOUT, 0, "timeout");
    }

    abort_on_test_timeout();
  }

  if(!success) {
    curl_mfprintf(stderr, "Error uploading file.\n");
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
