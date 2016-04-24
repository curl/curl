/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
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

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <assert.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

#define TEST_HANG_TIMEOUT 5 * 1000
#define MAX_EASY_HANDLES 3

static CURL *easy[MAX_EASY_HANDLES];
static curl_socket_t sockets[MAX_EASY_HANDLES];
static int res = 0;

static size_t callback(char* ptr, size_t size, size_t nmemb, void* data)
{
  ssize_t idx = ((CURL **) data) - easy;
  curl_socket_t sock;
  long longdata;
  CURLcode code;

  const size_t failure = (size * nmemb) ? 0 : 1;

  char *output = malloc(size * nmemb + 1);
  if (!output) {
    fprintf(stderr, "output, malloc() failed\n");
    res = TEST_ERR_MAJOR_BAD;
    return failure;
  }

  memcpy(output, ptr, size * nmemb);
  output[size * nmemb] = '\0';
  fprintf(stdout, "%s", output);
  free(output);

  /* Get socket being used for this easy handle, otherwise CURL_SOCKET_BAD */
  code = curl_easy_getinfo(easy[idx], CURLINFO_LASTSOCKET, &longdata);
  if (CURLE_OK != code) {
    fprintf(stderr, "%s:%d curl_easy_getinfo() failed, "
            "with code %d (%s)\n",
            __FILE__, __LINE__, (int)code, curl_easy_strerror(code));
    res = TEST_ERR_MAJOR_BAD;
    return failure;
  }
  if (longdata == -1L)
    sock = CURL_SOCKET_BAD;
  else
    sock = (curl_socket_t)longdata;

  if (sock != CURL_SOCKET_BAD) {
    /* Track relationship between this easy handle and the socket. */
    if (sockets[idx] == CURL_SOCKET_BAD) {
      /* An easy handle without previous socket, record the socket. */
      sockets[idx] = sock;
    }
    else if (sock != sockets[idx]) {
      /* An easy handle with a socket different to previously
         tracked one, log and fail right away. Known bug #37. */
      fprintf(stderr, "Handle %d started on socket %d and moved to %d\n",
              curlx_sztosi(idx), (int)sockets[idx], (int)sock);
      res = TEST_ERR_MAJOR_BAD;
      return failure;
    }
  }
  return size * nmemb;
}

enum HandleState {
  ReadyForNewHandle,
  NeedSocketForNewHandle,
  NoMoreHandles
};

int test(char *url)
{
  CURLM *multi = NULL;
  int running;
  int i, j;
  int num_handles = 0;
  enum HandleState state = ReadyForNewHandle;
  char* full_url = malloc(strlen(url) + 4 + 1);

  start_test_timing();

  if (!full_url) {
    fprintf(stderr, "Not enough memory for full url\n");
    return TEST_ERR_MAJOR_BAD;
  }

  for (i = 0; i < MAX_EASY_HANDLES; ++i) {
    easy[i] = NULL;
    sockets[i] = CURL_SOCKET_BAD;
  }

  res_global_init(CURL_GLOBAL_ALL);
  if(res) {
    free(full_url);
    return res;
  }

  multi_init(multi);

#ifdef USE_PIPELINING
  multi_setopt(multi, CURLMOPT_PIPELINING, 1L);
  multi_setopt(multi, CURLMOPT_MAX_HOST_CONNECTIONS, 5L);
  multi_setopt(multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, 10L);
#endif

  for(;;) {
    struct timeval interval;
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    long timeout = -99;
    int maxfd = -99;
    bool found_new_socket = FALSE;

    /* Start a new handle if we aren't at the max */
    if (state == ReadyForNewHandle) {
      easy_init(easy[num_handles]);

      if (num_handles % 3 == 2) {
        sprintf(full_url, "%s0200", url);
        easy_setopt(easy[num_handles], CURLOPT_HTTPAUTH, CURLAUTH_NTLM);
      } else {
        sprintf(full_url, "%s0100", url);
        easy_setopt(easy[num_handles], CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
      }
      easy_setopt(easy[num_handles], CURLOPT_FRESH_CONNECT, 1L);
      easy_setopt(easy[num_handles], CURLOPT_URL, full_url);
      easy_setopt(easy[num_handles], CURLOPT_VERBOSE, 1L);
      easy_setopt(easy[num_handles], CURLOPT_HTTPGET, 1L);
      easy_setopt(easy[num_handles], CURLOPT_USERPWD, "testuser:testpass");
      easy_setopt(easy[num_handles], CURLOPT_WRITEFUNCTION, callback);
      easy_setopt(easy[num_handles], CURLOPT_WRITEDATA, easy + num_handles);
      easy_setopt(easy[num_handles], CURLOPT_HEADER, 1L);

      multi_add_handle(multi, easy[num_handles]);
      num_handles += 1;
      state = NeedSocketForNewHandle;
    }

    multi_perform(multi, &running);

    abort_on_test_timeout();

    if(!running && state == NoMoreHandles)
      break; /* done */

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);

    /* At this point, maxfd is guaranteed to be greater or equal than -1. */

    /* Any socket which is new in fdread is associated with the new handle */
    for (i = 0; i <= maxfd; ++i) {
      bool socket_exists = FALSE;
      curl_socket_t curfd = (curl_socket_t)i;

      if (!FD_ISSET(curfd, &fdread)) {
        continue;
      }

      /* Check if this socket was already detected for an earlier handle (or
         for this handle, num_handles-1, in the callback */
      for (j = 0; j < num_handles; ++j) {
        if (sockets[j] == curfd) {
          socket_exists = TRUE;
          break;
        }
      }
      if (socket_exists) {
        continue;
      }

      if (found_new_socket || state != NeedSocketForNewHandle) {
        fprintf(stderr, "Unexpected new socket\n");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }

      /* Now we know the socket is for the most recent handle, num_handles-1 */
      if (sockets[num_handles-1] != CURL_SOCKET_BAD) {
        /* A socket for this handle was already detected in the callback; if it
           matched socket_exists should be true and we would never get here */
        assert(curfd != sockets[num_handles-1]);
        fprintf(stderr, "Handle %d wrote to socket %d then detected on %d\n",
                num_handles-1, (int)sockets[num_handles-1], (int)curfd);
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      else {
        sockets[num_handles-1] = curfd;
        found_new_socket = TRUE;
        /* continue to make sure there's only one new handle */
      }
    }

    if (state == NeedSocketForNewHandle) {
      if(maxfd != -1 && !found_new_socket) {
        fprintf(stderr, "Warning: socket did not open immediately for new "
                "handle (trying again)\n");
        continue;
      }
      state = num_handles < MAX_EASY_HANDLES ? ReadyForNewHandle
                                             : NoMoreHandles;
    }

    multi_timeout(multi, &timeout);

    /* At this point, timeout is guaranteed to be greater or equal than -1. */

    fprintf(stderr, "%s:%d num_handles %d timeout %ld\n",
            __FILE__, __LINE__, num_handles, timeout);

    if(timeout != -1L) {
      int itimeout = (timeout > (long)INT_MAX) ? INT_MAX : (int)timeout;
      interval.tv_sec = itimeout/1000;
      interval.tv_usec = (itimeout%1000)*1000;
    }
    else {
      interval.tv_sec = TEST_HANG_TIMEOUT/1000+1;
      interval.tv_usec = 0;

      /* if there's no timeout and we get here on the last handle, we may
         already have read the last part of the stream so waiting makes no
         sense */
      if(!running && num_handles == MAX_EASY_HANDLES) {
        break;
      }
    }

    select_test(maxfd+1, &fdread, &fdwrite, &fdexcep, &interval);

    abort_on_test_timeout();
  }

test_cleanup:

  /* proper cleanup sequence - type PB */

  for(i = 0; i < MAX_EASY_HANDLES; i++) {
    curl_multi_remove_handle(multi, easy[i]);
    curl_easy_cleanup(easy[i]);
  }

  curl_multi_cleanup(multi);
  curl_global_cleanup();

  free(full_url);

  return res;
}
