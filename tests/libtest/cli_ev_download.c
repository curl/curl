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

/* An event-based download client, driving transfers purely via
 * curl_multi_socket_action() with its own socket/timer callbacks, the
 * way an event-based application does. It runs its transfers serially
 * with CURLOPT_FORBID_REUSE, so every transfer's connection enters
 * shutdown when done, and reports whether the connection sockets
 * remain under event supervision until their shutdown finished. */

#define EV_DL_MAX_SOCKS 8

struct ev_dl_ctx {
  CURLM *multi;
  struct curltime timer_started;
  curl_socket_t fds[EV_DL_MAX_SOCKS];
  int actions[EV_DL_MAX_SOCKS];
  size_t nsocks;
  long timer_ms; /* last timeout set, -1 for none */
};

static int ev_dl_socket_cb(CURL *easy, curl_socket_t fd, int what,
                           void *clientp, void *socketp)
{
  struct ev_dl_ctx *ctx = clientp;
  size_t i;

  (void)easy;
  (void)socketp;
  for(i = 0; i < ctx->nsocks; ++i) {
    if(ctx->fds[i] == fd)
      break;
  }
  if(what == CURL_POLL_REMOVE) {
    if(i < ctx->nsocks) {
      ctx->nsocks--;
      ctx->fds[i] = ctx->fds[ctx->nsocks];
      ctx->actions[i] = ctx->actions[ctx->nsocks];
    }
  }
  else {
    if(i == ctx->nsocks) {
      if(ctx->nsocks >= EV_DL_MAX_SOCKS) {
        curl_mfprintf(stderr, "[ev] too many sockets to track\n");
        return -1;
      }
      ctx->nsocks++;
    }
    ctx->fds[i] = fd;
    ctx->actions[i] = what;
  }
  curl_mfprintf(stderr, "[ev] socket fd=%ld what=%d, tracking %zu\n",
                (long)fd, what, ctx->nsocks);
  return 0;
}

static int ev_dl_timer_cb(CURLM *multi, long timeout_ms, void *clientp)
{
  struct ev_dl_ctx *ctx = clientp;

  (void)multi;
  ctx->timer_ms = timeout_ms;
  if(timeout_ms >= 0)
    ctx->timer_started = curlx_now();
  return 0;
}

static size_t ev_dl_discard_cb(char *ptr, size_t size, size_t nmemb,
                               void *userdata)
{
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

/* wait for socket events or the timer, then feed libcurl. */
static CURLMcode ev_dl_roundtrip(struct ev_dl_ctx *ctx)
{
  curl_socket_t fds[EV_DL_MAX_SOCKS];
  int actions[EV_DL_MAX_SOCKS];
  struct timeval tv;
  fd_set rd, wr;
  size_t i, nsocks;
  long wait_ms = 100;
  int maxfd = -1;
  int running = 0;
  CURLMcode mres = CURLM_OK;

  FD_ZERO(&rd);
  FD_ZERO(&wr);
  for(i = 0; i < ctx->nsocks; ++i) {
    if(ctx->actions[i] & CURL_POLL_IN)
      FD_SET(ctx->fds[i], &rd);
    if(ctx->actions[i] & CURL_POLL_OUT)
      FD_SET(ctx->fds[i], &wr);
    if((int)ctx->fds[i] > maxfd)
      maxfd = (int)ctx->fds[i];
  }
  if(ctx->timer_ms >= 0) {
    long left = ctx->timer_ms -
      (long)curlx_timediff_ms(curlx_now(), ctx->timer_started);
    if(left < 0)
      left = 0;
    if(left < wait_ms)
      wait_ms = left;
  }
  tv.tv_sec = wait_ms / 1000;
  tv.tv_usec = (int)(wait_ms % 1000) * 1000;
  select_wrapper(maxfd + 1, &rd, &wr, NULL, &tv);

  /* the callbacks change our socket table while we dispatch */
  nsocks = ctx->nsocks;
  memcpy(fds, ctx->fds, sizeof(fds));
  memcpy(actions, ctx->actions, sizeof(actions));
  for(i = 0; i < nsocks; ++i) {
    int ev_bitmask = 0;
    if((actions[i] & CURL_POLL_IN) && FD_ISSET(fds[i], &rd))
      ev_bitmask |= CURL_CSELECT_IN;
    if((actions[i] & CURL_POLL_OUT) && FD_ISSET(fds[i], &wr))
      ev_bitmask |= CURL_CSELECT_OUT;
    if(ev_bitmask) {
      mres = curl_multi_socket_action(ctx->multi, fds[i], ev_bitmask,
                                      &running);
      if(mres)
        return mres;
    }
  }

  if((ctx->timer_ms >= 0) &&
     (curlx_timediff_ms(curlx_now(), ctx->timer_started) >= ctx->timer_ms)) {
    ctx->timer_ms = -1;
    mres = curl_multi_socket_action(ctx->multi, CURL_SOCKET_TIMEOUT, 0,
                                    &running);
  }
  return mres;
}

static void usage_ev_download(const char *msg)
{
  if(msg)
    curl_mfprintf(stderr, "%s\n", msg);
  curl_mfprintf(stderr,
    "usage: [options] url\n"
    "  event-based downloads with connection reuse forbidden\n"
    "  -n number      of transfers to do serially (default: 5)\n"
    "  -C certfile    for CA verification\n"
  );
}

static CURLcode test_cli_ev_download(const char *URL)
{
  struct ev_dl_ctx ctx;
  CURLM *multi = NULL;
  char *cafile = NULL;
  const char *url;
  size_t transfer_count = 5;
  size_t i;
  int watched = 0;
  struct curltime started;
  CURLcode result = CURLE_OK;
  int ch;

  (void)URL;
  memset(&ctx, 0, sizeof(ctx));
  ctx.timer_ms = -1;

  while((ch = cgetopt(test_argc, test_argv, "hn:C:")) != -1) {
    switch(ch) {
    case 'h':
      usage_ev_download(NULL);
      result = (CURLcode)2;
      goto optcleanup;
    case 'n': {
      const char *opt = coptarg;
      curl_off_t num;
      if(!curlx_str_number(&opt, &num, LONG_MAX))
        transfer_count = (size_t)num;
      break;
    }
    case 'C':
      curlx_free(cafile);
      cafile = curlx_strdup(coptarg);
      break;
    default:
      usage_ev_download("invalid option");
      result = (CURLcode)1;
      goto optcleanup;
    }
  }
  test_argc -= coptind;
  test_argv += coptind;

  if(test_argc != 1) {
    usage_ev_download("not enough arguments");
    result = (CURLcode)2;
    goto optcleanup;
  }
  url = test_argv[0];

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    result = (CURLcode)3;
    goto optcleanup;
  }
  curl_global_trace("ids,time");

  multi = curl_multi_init();
  if(!multi) {
    curl_mfprintf(stderr, "curl_multi_init() failed\n");
    result = (CURLcode)3;
    goto cleanup;
  }
  ctx.multi = multi;
  curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, ev_dl_socket_cb);
  curl_multi_setopt(multi, CURLMOPT_SOCKETDATA, &ctx);
  curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, ev_dl_timer_cb);
  curl_multi_setopt(multi, CURLMOPT_TIMERDATA, &ctx);

  for(i = 0; i < transfer_count && !result; ++i) {
    CURL *easy = curl_easy_init();
    int done = 0;
    int running = 0;

    if(!easy) {
      curl_mfprintf(stderr, "[t-%zu] FAILED setup\n", i);
      result = (CURLcode)1;
      goto cleanup;
    }
    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, ev_dl_discard_cb);
    curl_easy_setopt(easy, CURLOPT_FORBID_REUSE, 1L);
    curl_easy_setopt(easy, CURLOPT_VERBOSE, 1L);
    if(cafile)
      curl_easy_setopt(easy, CURLOPT_CAINFO, cafile);

    curl_multi_add_handle(multi, easy);
    curl_mfprintf(stderr, "[t-%zu] STARTED\n", i);
    curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &running);

    started = curlx_now();
    while(!done) {
      struct CURLMsg *m;
      int msgq = 0;

      if(ev_dl_roundtrip(&ctx)) {
        curl_mfprintf(stderr, "[t-%zu] multi failure\n", i);
        result = (CURLcode)1;
        goto cleanup;
      }
      m = curl_multi_info_read(multi, &msgq);
      if(m && (m->msg == CURLMSG_DONE)) {
        done = 1;
        result = m->data.result;
        curl_mfprintf(stderr, "[t-%zu] FINISHED with result %d\n",
                      i, (int)result);
      }
      else if(curlx_timediff_ms(curlx_now(), started) > (timediff_t)30000) {
        curl_mfprintf(stderr, "[t-%zu] transfer timed out\n", i);
        result = (CURLcode)1;
        goto cleanup;
      }
    }
    curl_multi_remove_handle(multi, easy);
    curl_easy_cleanup(easy);

    /* The transfer is over and its connection may not be reused. A
     * graceful shutdown that could not finish right away needs its
     * socket watched by us, or it can never make progress. */
    curl_mfprintf(stderr, "[t-%zu] sockets tracked after done: %zu\n",
                  i, ctx.nsocks);
    if(ctx.nsocks)
      watched++;
  }

  /* drive the remaining shutdowns via socket events */
  started = curlx_now();
  while(ctx.nsocks &&
        (curlx_timediff_ms(curlx_now(), started) < (timediff_t)5000)) {
    if(ev_dl_roundtrip(&ctx))
      break;
  }
  curl_mfprintf(stderr, "[ev] final: watched=%d socks_left=%zu\n",
                watched, ctx.nsocks);

cleanup:
  curl_multi_cleanup(multi);
  curl_global_cleanup();
optcleanup:
  curlx_free(cafile);
  return result;
}
