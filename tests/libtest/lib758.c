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

#include "testtrace.h"
#include "memdebug.h"

#ifdef USE_OPENSSL

#include <openssl/x509.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define T578_ENABLED
#endif
#endif

#ifdef T578_ENABLED

static struct t758_ctx {
  int socket_calls;
  int max_socket_calls;
  int timer_calls;
  int max_timer_calls;
  int fake_async_cert_verification_pending;
  int fake_async_cert_verification_finished;
  int number_of_cert_verify_callbacks;
  char buf[1024];
} t758_ctx;

static const char *t758_tag(void)
{
  curl_msnprintf(t758_ctx.buf, sizeof(t758_ctx.buf),
                 "[T758-%d-%d] [%d/%d]",
                 t758_ctx.max_socket_calls, t758_ctx.max_timer_calls,
                 t758_ctx.socket_calls, t758_ctx.timer_calls);
  return t758_ctx.buf;
}

static void t758_msg(const char *msg)
{
  curl_mfprintf(stderr, "%s %s\n", t758_tag(), msg);
}


struct t758_Sockets {
  curl_socket_t *sockets;
  int count;      /* number of sockets actually stored in array */
  int max_count;  /* max number of sockets that fit in allocated array */
};

struct t758_ReadWriteSockets {
  struct t758_Sockets read, write;
};

/**
 * Remove a file descriptor from a sockets array.
 */
static void t758_removeFd(struct t758_Sockets *sockets, curl_socket_t fd,
                          int mention)
{
  int i;

  if(mention)
    curl_mfprintf(stderr, "%s remove socket fd %" FMT_SOCKET_T "\n",
                  t758_tag(), fd);

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
static int t758_addFd(struct t758_Sockets *sockets, curl_socket_t fd,
                      const char *what)
{
  /**
   * To ensure we only have each file descriptor once, we remove it then add
   * it again.
   */
  curl_mfprintf(stderr, "%s add socket fd %" FMT_SOCKET_T " for %s\n",
                t758_tag(), fd, what);
  t758_removeFd(sockets, fd, 0);
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
static int t758_curlSocketCallback(CURL *easy, curl_socket_t s, int action,
                                   void *userp, void *socketp)
{
  struct t758_ReadWriteSockets *sockets = userp;

  (void)easy;
  (void)socketp;

  t758_ctx.socket_calls++;
  t758_msg("-> CURLMOPT_SOCKETFUNCTION");
  if(t758_ctx.socket_calls == t758_ctx.max_socket_calls) {
    t758_msg("<- CURLMOPT_SOCKETFUNCTION returns error");
    return -1;
  }

  if(action == CURL_POLL_IN || action == CURL_POLL_INOUT)
    if(t758_addFd(&sockets->read, s, "read"))
      return -1; /* bail out */

  if(action == CURL_POLL_OUT || action == CURL_POLL_INOUT)
    if(t758_addFd(&sockets->write, s, "write"))
      return -1;

  if(action == CURL_POLL_REMOVE) {
    t758_removeFd(&sockets->read, s, 1);
    t758_removeFd(&sockets->write, s, 0);
  }

  return 0;
}

/**
 * Callback invoked by curl to set a timeout.
 */
static int t758_curlTimerCallback(CURLM *multi, long timeout_ms, void *userp)
{
  struct curltime *timeout = userp;

  (void)multi;
  t758_ctx.timer_calls++;
  t758_msg("-> CURLMOPT_TIMERFUNCTION");
  if(t758_ctx.timer_calls == t758_ctx.max_timer_calls) {
    t758_msg("<- CURLMOPT_TIMERFUNCTION returns error");
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

static int t758_cert_verify_callback(X509_STORE_CTX *ctx, void *arg)
{
  SSL * ssl;
  (void)arg;
  ssl = (SSL *)X509_STORE_CTX_get_ex_data(ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx());
  t758_ctx.number_of_cert_verify_callbacks++;
  if(!t758_ctx.fake_async_cert_verification_pending) {
    t758_ctx.fake_async_cert_verification_pending = 1;
    t758_msg("   initial t758_cert_verify_callback");
    return SSL_set_retry_verify(ssl);
  }
  else if(t758_ctx.fake_async_cert_verification_finished) {
    t758_msg("   final t758_cert_verify_callback");
    return 1; /* success */
  }
  else {
    t758_msg("   pending t758_cert_verify_callback");
    return SSL_set_retry_verify(ssl);
  }
}

static CURLcode
t758_set_ssl_ctx_callback(CURL *curl, void *ssl_ctx, void *clientp)
{
  SSL_CTX *ctx = (SSL_CTX *) ssl_ctx;
  (void)curl;
  SSL_CTX_set_cert_verify_callback(ctx, t758_cert_verify_callback, clientp);
  return CURLE_OK;
}

/**
 * Check for curl completion.
 */
static int t758_checkForCompletion(CURLM *curl, int *success)
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
                    t758_tag(), message->msg);
      result = 1;
      *success = 0;
    }
  }
  return result;
}

static ssize_t t758_getMicroSecondTimeout(struct curltime *timeout)
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
static void t758_updateFdSet(struct t758_Sockets *sockets, fd_set* fdset,
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

static CURLMcode t758_saction(CURLM *curl, curl_socket_t s,
                              int evBitmask, const char *info)
{
  int numhandles = 0;
  CURLMcode result = curl_multi_socket_action(curl, s, evBitmask, &numhandles);
  if(result != CURLM_OK) {
    curl_mfprintf(stderr, "%s Curl error on %s (%i) %s\n",
                  t758_tag(), info, result, curl_multi_strerror(result));
  }
  return result;
}

/**
 * Invoke curl when a file descriptor is set.
 */
static CURLMcode t758_checkFdSet(CURLM *curl, struct t758_Sockets *sockets,
                                 fd_set *fdset, int evBitmask,
                                 const char *name)
{
  int i;
  CURLMcode result = CURLM_OK;
  for(i = 0; i < sockets->count; ++i) {
    if(FD_ISSET(sockets->sockets[i], fdset)) {
      result = t758_saction(curl, sockets->sockets[i], evBitmask, name);
      if(result)
        break;
    }
  }
  return result;
}

static CURLcode t758_one(const char *URL, int timer_fail_at,
                         int socket_fail_at)
{
  CURLcode res = CURLE_OK;
  CURL *curl = NULL;  CURLM *m = NULL;
  struct t758_ReadWriteSockets sockets = {{NULL, 0, 0}, {NULL, 0, 0}};
  int success = 0;
  struct curltime timeout = {0};
  timeout.tv_sec = (time_t)-1;

  /* set the limits */
  memset(&t758_ctx, 0, sizeof(t758_ctx));
  t758_ctx.max_timer_calls = timer_fail_at;
  t758_ctx.max_socket_calls = socket_fail_at;

  t758_msg("start");
  start_test_timing();

  if(curl_global_sslset(CURLSSLBACKEND_OPENSSL, NULL, NULL) != CURLSSLSET_OK) {
    t758_msg("could not set OpenSSL as backend");
    res = CURLE_FAILED_INIT;
    return res;
  }

  res_global_init(CURL_GLOBAL_ALL);
  if(res != CURLE_OK)
    return res;

  curl_global_trace("all");


  easy_init(curl);
  debug_config.nohex = TRUE;
  debug_config.tracetime = TRUE;
  test_setopt(curl, CURLOPT_DEBUGDATA, &debug_config);
  easy_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* specify target */
  easy_setopt(curl, CURLOPT_URL, URL);

  /* go verbose */
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);

  easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, t758_set_ssl_ctx_callback);

  multi_init(m);

  multi_setopt(m, CURLMOPT_SOCKETFUNCTION, t758_curlSocketCallback);
  multi_setopt(m, CURLMOPT_SOCKETDATA, &sockets);

  multi_setopt(m, CURLMOPT_TIMERFUNCTION, t758_curlTimerCallback);
  multi_setopt(m, CURLMOPT_TIMERDATA, &timeout);

  multi_add_handle(m, curl);

  if(t758_saction(m, CURL_SOCKET_TIMEOUT, 0, "timeout")) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  while(!t758_checkForCompletion(m, &success)) {
    fd_set readSet, writeSet;
    curl_socket_t maxFd = 0;
    struct timeval tv = {0};
    tv.tv_sec = 10;

    if(t758_ctx.fake_async_cert_verification_pending &&
        !t758_ctx.fake_async_cert_verification_finished) {
      if(sockets.read.count || sockets.write.count) {
        t758_msg("during verification there should be no sockets scheduled");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      if(t758_ctx.number_of_cert_verify_callbacks != 1) {
        t758_msg("expecting exactly one cert verify callback here");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      t758_ctx.fake_async_cert_verification_finished = 1;
      if(t758_saction(m, CURL_SOCKET_TIMEOUT, 0, "timeout")) {
        t758_msg("spurious retry cert action");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      curl_easy_pause(curl, CURLPAUSE_CONT);
      if(t758_saction(m, CURL_SOCKET_TIMEOUT, 0, "timeout")) {
        t758_msg("unblocking transfer after cert verification finished");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      if(t758_ctx.number_of_cert_verify_callbacks != 2) {
        t758_msg("this should have triggered the callback again, right?");
        res = TEST_ERR_MAJOR_BAD;
        goto test_cleanup;
      }
      t758_msg("TEST: all fine?");
    }
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    t758_updateFdSet(&sockets.read, &readSet, &maxFd);
    t758_updateFdSet(&sockets.write, &writeSet, &maxFd);

    if(timeout.tv_sec != (time_t)-1) {
      int usTimeout = curlx_sztosi(t758_getMicroSecondTimeout(&timeout));
      tv.tv_sec = usTimeout / 1000000;
      tv.tv_usec = usTimeout % 1000000;
    }
    else if(maxFd <= 0) {
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
    }

    select_test((int)maxFd, &readSet, &writeSet, NULL, &tv);

    /* Check the sockets for reading / writing */
    if(t758_checkFdSet(m, &sockets.read, &readSet, CURL_CSELECT_IN,
                       "read")) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }
    if(t758_checkFdSet(m, &sockets.write, &writeSet, CURL_CSELECT_OUT,
                       "write")) {
      res = TEST_ERR_MAJOR_BAD;
      goto test_cleanup;
    }

    if(timeout.tv_sec != (time_t)-1 &&
       t758_getMicroSecondTimeout(&timeout) == 0) {
      /* Curl's timer has elapsed. */
      if(t758_saction(m, CURL_SOCKET_TIMEOUT, 0, "timeout")) {
        res = TEST_ERR_BAD_TIMEOUT;
        goto test_cleanup;
      }
    }

    abort_on_test_timeout();
  }
  if(success && t758_ctx.number_of_cert_verify_callbacks != 2) {
    t758_msg("unexpected invocations of cert verify callback");
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  if(!success) {
    t758_msg("Error getting file.");
    res = TEST_ERR_MAJOR_BAD;
  }

test_cleanup:

  /* proper cleanup sequence */
  t758_msg("cleanup");
  curl_multi_remove_handle(m, curl);
  curl_easy_cleanup(curl);
  curl_multi_cleanup(m);
  curl_global_cleanup();

  /* free local memory */
  free(sockets.read.sockets);
  free(sockets.write.sockets);
  t758_msg("done");

  return res;
}

static CURLcode test_lib758(const char *URL)
{
  CURLcode rc;
  /* rerun the same transfer multiple times and make it fail in different
     callback calls */
  rc = t758_one(URL, 0, 0); /* no callback fails */
  if(rc)
    curl_mfprintf(stderr, "%s FAILED: %d\n", t758_tag(), rc);

  return rc;
}

#else /* T578_ENABLED */
static CURLcode test_lib758(const char *URL)
{
  (void)URL;
  return CURLE_OK;
}
#endif
