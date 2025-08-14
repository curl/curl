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

#include "first.h"

#include "memdebug.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>

static struct t530_ctx {
  int socket_calls;
  int max_socket_calls;
  int timer_calls;
  int max_timer_calls;
  int fake_async_cert_verification_pending;
  int fake_async_cert_verification_finished;
  int number_of_cert_verify_callbacks;
  char buf[1024];
} t530_ctx;

static const char *t530_tag(void)
{
  curl_msnprintf(t530_ctx.buf, sizeof(t530_ctx.buf),
                "[T530-%d-%d] [%d/%d]",
                t530_ctx.max_socket_calls, t530_ctx.max_timer_calls,
                t530_ctx.socket_calls, t530_ctx.timer_calls);
  return t530_ctx.buf;
}

static void t530_msg(const char *msg)
{
  curl_mfprintf(stderr, "%s %s\n", t530_tag(), msg);
}



static const char *curl_infotype_to_string(curl_infotype type)
{
  switch(type) {
    case CURLINFO_TEXT:
      return "text";
    case CURLINFO_HEADER_IN:
      return "header_in";
    case CURLINFO_HEADER_OUT:
      return "header_out";
    case CURLINFO_DATA_IN:
      return "data_in";
    case CURLINFO_DATA_OUT:
      return "data_out";
    case CURLINFO_SSL_DATA_IN:
      return "ssl_data_in";
    case CURLINFO_SSL_DATA_OUT:
      return "ssl_data_out";
    default:
      return "unknown";
  }
}

static int debug_cb(CURL *handle,
                    curl_infotype type,
                    char *data,
                    size_t size,
                    void *userdata)
{
  char buf[65536];
  (void)handle; /* unused */
  (void)userdata; /* unused */
  if(size >= sizeof(buf))
    size = sizeof(buf) - 1; /* leave room for NUL */
  memcpy(buf, data, size);
  buf[size] = '\0'; /* ensure NUL termination */
  curl_mfprintf(stderr, "%s %s %s\n", t530_tag(),
                curl_infotype_to_string(type), buf);
  return 0;
}

struct t530_Sockets {
  curl_socket_t *sockets;
  int count;      /* number of sockets actually stored in array */
  int max_count;  /* max number of sockets that fit in allocated array */
};

struct t530_ReadWriteSockets {
  struct t530_Sockets read, write;
};

/**
 * Remove a file descriptor from a sockets array.
 */
static void t530_removeFd(struct t530_Sockets *sockets, curl_socket_t fd,
                          int mention)
{
  int i;

  if(mention)
    curl_mfprintf(stderr, "%s remove socket fd %d\n", t530_tag(), (int)fd);

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
static int t530_addFd(struct t530_Sockets *sockets, curl_socket_t fd,
                      const char *what)
{
  /**
   * To ensure we only have each file descriptor once, we remove it then add
   * it again.
   */
  curl_mfprintf(stderr, "%s add socket fd %d for %s\n",
                t530_tag(), (int)fd, what);
  t530_removeFd(sockets, fd, 0);
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

/**
 * Callback invoked by curl to poll reading / writing of a socket.
 */
static int t530_curlSocketCallback(CURL *easy, curl_socket_t s, int action,
                                   void *userp, void *socketp)
{
  struct t530_ReadWriteSockets *sockets = userp;

  (void)easy; /* unused */
  (void)socketp; /* unused */

  t530_ctx.socket_calls++;
  t530_msg("-> CURLMOPT_SOCKETFUNCTION");
  if(t530_ctx.socket_calls == t530_ctx.max_socket_calls) {
    t530_msg("<- CURLMOPT_SOCKETFUNCTION returns error");
    return -1;
  }

  if(action == CURL_POLL_IN || action == CURL_POLL_INOUT)
    if(t530_addFd(&sockets->read, s, "read"))
      return -1; /* bail out */

  if(action == CURL_POLL_OUT || action == CURL_POLL_INOUT)
    if(t530_addFd(&sockets->write, s, "write"))
      return -1;

  if(action == CURL_POLL_REMOVE) {
    t530_removeFd(&sockets->read, s, 1);
    t530_removeFd(&sockets->write, s, 0);
  }

  return 0;
}

/**
 * Callback invoked by curl to set a timeout.
 */
static int t530_curlTimerCallback(CURLM *multi, long timeout_ms, void *userp)
{
  struct curltime *timeout = userp;

  (void)multi; /* unused */
  t530_ctx.timer_calls++;
  t530_msg("-> CURLMOPT_TIMERFUNCTION");
  if(t530_ctx.timer_calls == t530_ctx.max_timer_calls) {
    t530_msg("<- CURLMOPT_TIMERFUNCTION returns error");
    return -1;
  }
  if(timeout_ms != -1) {
    *timeout = curlx_now();
    timeout->tv_usec += (int)timeout_ms * 1000;
  }
  else {
    timeout->tv_sec = -1;
  }
  return 0;
}

static int t530_cert_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
  SSL * ssl;
  (void)arg; /* unused */
  ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
  t530_ctx.number_of_cert_verify_callbacks++;
  if(!t530_ctx.fake_async_cert_verification_pending) {
    t530_ctx.fake_async_cert_verification_pending = 1;
    t530_msg("   initial t530_cert_verify_callback");
    return SSL_set_retry_verify(ssl);
  }
  else if(t530_ctx.fake_async_cert_verification_finished) {
    t530_msg("   final t530_cert_verify_callback");
    return 1; /* success */
  }
  else {
    t530_msg("   pending t530_cert_verify_callback");
    return SSL_set_retry_verify(ssl);
  }
}

static CURLcode
t530_set_ssl_ctx_callback(CURL *curl, void *ssl_ctx, void *clientp)
{
  SSL_CTX *ctx = (SSL_CTX *) ssl_ctx;
  (void)curl; /* unused */
  SSL_CTX_set_cert_verify_callback(ctx, t530_cert_verify_callback, clientp);
  return CURLE_OK;
}

/**
 * Check for curl completion.
 */
static int t530_checkForCompletion(CURLM *curl, int *success)
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
      curl_mfprintf(stderr, "%s got an unexpected message from curl: %i\n",
                    t530_tag(), (int)message->msg);
      result = 1;
      *success = 0;
    }
  }
  return result;
}

static int t530_getMicroSecondTimeout(struct curltime *timeout)
{
  struct curltime now;
  ssize_t result;
  now = curlx_now();
  result = (ssize_t)((timeout->tv_sec - now.tv_sec) * 1000000 +
    timeout->tv_usec - now.tv_usec);
  if(result < 0)
    result = 0;

  return curlx_sztosi(result);
}

/**
 * Update a fd_set with all of the sockets in use.
 */
static void t530_updateFdSet(struct t530_Sockets *sockets, fd_set* fdset,
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
    curl_mfprintf(stderr, "%s Curl error on %s (%i) %s\n",
                  t530_tag(), info, result, curl_multi_strerror(result));
  }
  return (int)result;
}

/**
 * Invoke curl when a file descriptor is set.
 */
static int t530_checkFdSet(CURLM *curl, struct t530_Sockets *sockets,
                           fd_set *fdset, int evBitmask, const char *name)
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

static CURLcode testone(char *URL, int timer_fail_at, int socket_fail_at)
{
  CURLcode res = CURLE_OK;
  CURL *curl = NULL;  CURLM *m = NULL;
  struct t530_ReadWriteSockets sockets = {{NULL, 0, 0}, {NULL, 0, 0}};
  int success = 0;
  struct curltime timeout = {0};
  timeout.tv_sec = (time_t)-1;

  /* set the limits */
  memset(&t530_ctx, 0, sizeof(t530_ctx));
  t530_ctx.max_timer_calls = timer_fail_at;
  t530_ctx.max_socket_calls = socket_fail_at;

  t530_msg("start");
  start_test_timing();

  curl_global_trace("all");

  res_global_init(CURL_GLOBAL_ALL);
  if(res != CURLE_OK)
    return res;

  easy_init(curl);
  easy_setopt(curl, CURLOPT_DEBUGFUNCTION, debug_cb);

  /* specify target */
  easy_setopt(curl, CURLOPT_URL, URL);

  /* go verbose */
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, t530_set_ssl_ctx_callback);

  multi_init(m);

  multi_setopt(m, CURLMOPT_SOCKETFUNCTION, t530_curlSocketCallback);
  multi_setopt(m, CURLMOPT_SOCKETDATA, &sockets);

  multi_setopt(m, CURLMOPT_TIMERFUNCTION, t530_curlTimerCallback);
  multi_setopt(m, CURLMOPT_TIMERDATA, &timeout);

  multi_add_handle(m, curl);

  if(socket_action(m, CURL_SOCKET_TIMEOUT, 0, "timeout")) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  while(!t530_checkForCompletion(m, &success)) {
    fd_set readSet, writeSet;
    curl_socket_t maxFd = 0;
    struct timeval tv = {0};
    tv.tv_sec = 10;

    if(t530_ctx.fake_async_cert_verification_pending &&
        !t530_ctx.fake_async_cert_verification_finished) {
      if(sockets.read.count || sockets.write.count) {
        t530_msg("during verification there should be no sockets scheduled");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      if(t530_ctx.number_of_cert_verify_callbacks != 1) {
        t530_msg("expecting exactly one cert verify callback here");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      t530_ctx.fake_async_cert_verification_finished = 1;
      if(socket_action(m, CURL_SOCKET_RETRY_CERT, 0, "timeout")) {
        t530_msg("spurious retry cert action");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      easy_setopt(curl, CURLOPT_ASYNC_CERT_VERIFY_FINISHED, 1L);
      if(socket_action(m, CURL_SOCKET_RETRY_CERT, 0, "timeout")) {
        t530_msg("unblocking transfer after cert verification finished");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      if(t530_ctx.number_of_cert_verify_callbacks != 2) {
        t530_msg("this should have triggered the callback again, right?");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      t530_msg("TEST: all fine?");
    }
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    t530_updateFdSet(&sockets.read, &readSet, &maxFd);
    t530_updateFdSet(&sockets.write, &writeSet, &maxFd);

    if(timeout.tv_sec != (time_t)-1) {
      int usTimeout = t530_getMicroSecondTimeout(&timeout);
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
    if(t530_checkFdSet(m, &sockets.read, &readSet, CURL_CSELECT_IN,
                       "read")) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    if(t530_checkFdSet(m, &sockets.write, &writeSet, CURL_CSELECT_OUT,
                       "write")) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    if(timeout.tv_sec != (time_t)-1 &&
       t530_getMicroSecondTimeout(&timeout) == 0) {
      /* Curl's timer has elapsed. */
      if(socket_action(m, CURL_SOCKET_TIMEOUT, 0, "timeout")) {
        res = TEST_ERR_BAD_TIMEOUT;
        goto test_cleanup;
      }
    }

    abort_on_test_timeout();
  }
  if(success && t530_ctx.number_of_cert_verify_callbacks != 2) {
    t530_msg("unexpected invocations of cert verify callback");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  if(!success) {
    t530_msg("Error getting file.");
    res = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:

  /* proper cleanup sequence */
  t530_msg("cleanup");
  curl_multi_remove_handle(m, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);
  curl_global_cleanup();

  /* free local memory */
  free(sockets.read.sockets);
  free(sockets.write.sockets);
  t530_msg("done");

  return res;
}

static CURLcode test_lib530(char *URL)
{
  CURLcode rc;
  /* rerun the same transfer multiple times and make it fail in different
     callback calls */
  rc = testone(URL, 0, 0); /* no callback fails */
  if(rc)
    curl_mfprintf(stderr, "%s FAILED: %d\n", t530_tag(), rc);

  return CURLE_OK;
}
