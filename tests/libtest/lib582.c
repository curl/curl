/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define MAIN_LOOP_HANG_TIMEOUT     4 * 1000

struct Sockets
{
  curl_socket_t* sockets;
  int count;
};

struct ReadWriteSockets
{
  struct Sockets read, write;
};

/**
 * Remove a file descriptor from a sockets array.
 */
static void removeFd(struct Sockets* sockets, curl_socket_t fd, int mention)
{
  int i;

  if(mention)
    fprintf(stderr, "Remove socket fd %d\n", (int) fd);

  for (i = 0; i < sockets->count; ++i) {
    if (sockets->sockets[i] == fd) {
      memmove(&sockets->sockets[i], &sockets->sockets[i + 1],
              sizeof(curl_socket_t) * (sockets->count - i - 1));
      --sockets->count;
    }
  }
}

/**
 * Add a file descriptor to a sockets array.
 */
static void addFd(struct Sockets* sockets, curl_socket_t fd, const char *what)
{
  /**
   * To ensure we only have each file descriptor once, we remove it then add
   * it again.
   */
  fprintf(stderr, "Add socket fd %d for %s\n", (int) fd, what);
  removeFd(sockets, fd, 0);
  sockets->sockets = realloc(sockets->sockets,
        sizeof(curl_socket_t) * (sockets->count + 1));
  sockets->sockets[sockets->count] = fd;
  ++sockets->count;
}

/**
 * Callback invoked by curl to poll reading / writing of a socket.
 */
static int curlSocketCallback(CURL *easy, curl_socket_t s, int action,
                              void *userp, void *socketp)
{
  struct ReadWriteSockets* sockets = userp;

  (void)easy; /* unused */
  (void)socketp; /* unused */

  if (action == CURL_POLL_IN || action == CURL_POLL_INOUT)
    addFd(&sockets->read, s, "read");

  if (action == CURL_POLL_OUT || action == CURL_POLL_INOUT)
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
  struct timeval* timeout = userp;

  (void)multi; /* unused */
  if (timeout_ms != -1) {
    gettimeofday(timeout, 0);
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
static int checkForCompletion(CURLM* curl, int* success)
{
  int numMessages;
  CURLMsg* message;
  int result = 0;
  *success = 0;
  while ((message = curl_multi_info_read(curl, &numMessages)) != NULL) {
    if (message->msg == CURLMSG_DONE) {
      result = 1;
      if (message->data.result == CURLE_OK)
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

static int getMicroSecondTimeout(struct timeval* timeout)
{
  struct timeval now;
  int result;

  gettimeofday(&now, 0);
  result = (timeout->tv_sec - now.tv_sec) * 1000000 +
    timeout->tv_usec - now.tv_usec;
  if (result < 0)
    result = 0;

  return result;
}

/**
 * Update a fd_set with all of the sockets in use.
 */
static void updateFdSet(struct Sockets* sockets, fd_set* fdset,
                        curl_socket_t *maxFd)
{
  int i;
  for (i = 0; i < sockets->count; ++i) {
    FD_SET(sockets->sockets[i], fdset);
    if (*maxFd < sockets->sockets[i] + 1) {
      *maxFd = sockets->sockets[i] + 1;
    }
  }
}

static void notifyCurl(CURL* curl, curl_socket_t s, int evBitmask,
                       const char* info)
{
  int numhandles = 0;
  CURLMcode result = curl_multi_socket_action(curl, s, evBitmask, &numhandles);
  if (result != CURLM_OK && result != CURLM_CALL_MULTI_PERFORM)
  {
    fprintf(stderr, "Curl error on %s: %i (%s)\n",
            info, result, curl_multi_strerror(result));
  }
}

/**
 * Invoke curl when a file descriptor is set.
 */
static void checkFdSet(CURL* curl, struct Sockets* sockets, fd_set* fdset,
                       int evBitmask, const char* name)
{
  int i;
  for (i = 0; i < sockets->count; ++i)
  {
    if (FD_ISSET(sockets->sockets[i], fdset))
    {
      notifyCurl(curl, sockets->sockets[i], evBitmask, name);
    }
  }
}

int test(char *URL)
{
  int res = 0;
  CURL *curl;
  FILE *hd_src ;
  int hd ;
  int error;
  struct_stat file_info;
  CURLM *m = NULL;
  struct timeval ml_start;
  char ml_timedout = FALSE;
  struct ReadWriteSockets sockets = {{0, 0}, {0, 0}};
  struct timeval timeout = {-1, 0};
  int success = 0;

  if (!libtest_arg3) {
    fprintf(stderr, "Usage: lib582 [url] [filename] [username]\n");
    return -1;
  }

  hd_src = fopen(libtest_arg2, "rb");
  if(NULL == hd_src) {
    error = ERRNO;
    fprintf(stderr, "fopen() failed with error: %d %s\n",
            error, strerror(error));
    fprintf(stderr, "Error opening file: %s\n", libtest_arg2);
    return TEST_ERR_MAJOR_BAD;
  }

  /* get the file size of the local file */
  hd = fstat(fileno(hd_src), &file_info);
  if(hd == -1) {
    /* can't open file, bail out */
    error = ERRNO;
    fprintf(stderr, "fstat() failed with error: %d %s\n",
            error, strerror(error));
    fprintf(stderr, "ERROR: cannot open file %s\n", libtest_arg2);
    fclose(hd_src);
    return -1;
  }
  fprintf(stderr, "Set to upload %d bytes\n", (int)file_info.st_size);

  if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }

  if ((curl = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    fclose(hd_src);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  /* enable uploading */
  test_setopt(curl, CURLOPT_UPLOAD, 1L);

  /* specify target */
  test_setopt(curl,CURLOPT_URL, URL);

  /* go verbose */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* now specify which file to upload */
  test_setopt(curl, CURLOPT_READDATA, hd_src);

  test_setopt(curl, CURLOPT_USERPWD, libtest_arg3);
  test_setopt(curl, CURLOPT_SSH_PUBLIC_KEYFILE, "curl_client_key.pub");
  test_setopt(curl, CURLOPT_SSH_PRIVATE_KEYFILE, "curl_client_key");

  test_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                   (curl_off_t)file_info.st_size);

  if ((m = curl_multi_init()) == NULL) {
    fprintf(stderr, "curl_multi_init() failed\n");
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }
  test_multi_setopt(m, CURLMOPT_SOCKETFUNCTION, curlSocketCallback);
  test_multi_setopt(m, CURLMOPT_SOCKETDATA, &sockets);

  test_multi_setopt(m, CURLMOPT_TIMERFUNCTION, curlTimerCallback);
  test_multi_setopt(m, CURLMOPT_TIMERDATA, &timeout);

  if ((res = (int)curl_multi_add_handle(m, curl)) != CURLM_OK) {
    fprintf(stderr, "curl_multi_add_handle() failed, "
            "with code %d\n", res);
    curl_multi_cleanup(m);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    fclose(hd_src);
    return TEST_ERR_MAJOR_BAD;
  }

  ml_timedout = FALSE;
  ml_start = tutil_tvnow();

  while (!checkForCompletion(m, &success))
  {
    fd_set readSet, writeSet;
    curl_socket_t maxFd = 0;
    struct timeval tv = {10, 0};

    if (tutil_tvdiff(tutil_tvnow(), ml_start) >
        MAIN_LOOP_HANG_TIMEOUT) {
      ml_timedout = TRUE;
      break;
    }

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    updateFdSet(&sockets.read, &readSet, &maxFd);
    updateFdSet(&sockets.write, &writeSet, &maxFd);

    if (timeout.tv_sec != -1)
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

    select_test(maxFd, &readSet, &writeSet, NULL, &tv);

    /* Check the sockets for reading / writing */
    checkFdSet(m, &sockets.read, &readSet, CURL_CSELECT_IN, "read");
    checkFdSet(m, &sockets.write, &writeSet, CURL_CSELECT_OUT, "write");

    if (timeout.tv_sec != -1 && getMicroSecondTimeout(&timeout) == 0)
    {
      /* Curl's timer has elapsed. */
      notifyCurl(m, CURL_SOCKET_TIMEOUT, 0, "timeout");
    }
  }

  if (!success)
  {
    fprintf(stderr, "Error uploading file.\n");
    res = TEST_ERR_MAJOR_BAD;
  }
  else if (ml_timedout) {
    fprintf(stderr, "ABORTING TEST, since it seems "
            "that it would have run forever.\n");
    res = TEST_ERR_RUNS_FOREVER;
  }

test_cleanup:

  if(m)
    curl_multi_remove_handle(m, curl);
  curl_easy_cleanup(curl);
  if(m) {
    fprintf(stderr, "Now multi-cleanup!\n");
    curl_multi_cleanup(m);
  }

  fclose(hd_src); /* close the local file */
  if (sockets.read.sockets != 0)
    free(sockets.read.sockets);
  if (sockets.write.sockets != 0)
    free(sockets.write.sockets);

  curl_global_cleanup();
  return res;
}
