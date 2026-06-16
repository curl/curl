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

#include <curl/multi.h>

#define MAX_SOCKS 32

struct ctx {
  curl_socket_t reads[MAX_SOCKS];
  int read_count;
  curl_socket_t writes[MAX_SOCKS];
  int write_count;
  struct curltime timer_expiry;
  int transfers_done;
};

static void socks_add(curl_socket_t *arr, int *count, curl_socket_t fd)
{
  int i;
  for(i = 0; i < *count; i++)
    if(arr[i] == fd)
      return;
  arr[(*count)++] = fd;
}

static void socks_remove(curl_socket_t *arr, int *count, curl_socket_t fd)
{
  int i;
  for(i = 0; i < *count; i++) {
    if(arr[i] == fd) {
      if(i < *count - 1)
        memmove(&arr[i], &arr[i + 1],
                sizeof(curl_socket_t) * (size_t)(*count - i - 1));
      (*count)--;
      return;
    }
  }
}

static int sock_cb(CURL *e, curl_socket_t fd, int what, void *userp, void *sp)
{
  struct ctx *c = userp;
  (void)e;
  (void)sp;

  if(what == CURL_POLL_REMOVE) {
    socks_remove(c->reads, &c->read_count, fd);
    socks_remove(c->writes, &c->write_count, fd);
    return 0;
  }
  if(what & CURL_POLL_IN)
    socks_add(c->reads, &c->read_count, fd);
  if(what & CURL_POLL_OUT)
    socks_add(c->writes, &c->write_count, fd);
  return 0;
}

static int timer_cb(CURLM *multi, long timeout_ms, void *userp)
{
  struct ctx *c = userp;
  (void)multi;
  if(timeout_ms < 0) {
    c->timer_expiry.tv_sec = -1;
    return 0;
  }
  c->timer_expiry = curlx_now();
  c->timer_expiry.tv_usec += (int)timeout_ms * 1000;
  return 0;
}

static long timer_remain_ms(struct ctx *c)
{
  struct curltime now;
  long diff;
  if(c->timer_expiry.tv_sec < 0)
    return -1;
  now = curlx_now();
  diff = (long)((c->timer_expiry.tv_sec - now.tv_sec) * 1000 +
                (c->timer_expiry.tv_usec - now.tv_usec) / 1000);
  return diff < 0 ? 0 : diff;
}

static CURLcode test_lib3402(const char *URL)
{
  CURLM *multi = NULL;
  CURL *e1 = NULL, *e2 = NULL;
  CURLcode result = CURLE_OK;
  struct ctx c;
  int still_running;
  int i;

  memset(&c, 0, sizeof(c));
  c.timer_expiry.tv_sec = -1;

  res_global_init(CURL_GLOBAL_ALL);
  multi_init(multi);

  multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
  multi_setopt(multi, CURLMOPT_SOCKETDATA, &c);
  multi_setopt(multi, CURLMOPT_TIMERFUNCTION, timer_cb);
  multi_setopt(multi, CURLMOPT_TIMERDATA, &c);
  multi_setopt(multi, CURLMOPT_MONITOR_IDLE_CONNECTIONS, 1L);

  easy_init(e1);
  easy_setopt(e1, CURLOPT_URL, URL);
  easy_setopt(e1, CURLOPT_TIMEOUT, 10L);
  multi_add_handle(multi, e1);

  /* drive transfer to completion */
  still_running = 1;
  while(still_running) {
    fd_set rset, wset;
    struct timeval tv;
    curl_socket_t maxfd = CURL_SOCKET_BAD;
    long timeout_ms;

    FD_ZERO(&rset);
    FD_ZERO(&wset);
    for(i = 0; i < c.read_count; i++) {
      FD_SET(c.reads[i], &rset);
      if(maxfd == CURL_SOCKET_BAD || c.reads[i] > maxfd)
        maxfd = c.reads[i];
    }
    for(i = 0; i < c.write_count; i++) {
      FD_SET(c.writes[i], &wset);
      if(maxfd == CURL_SOCKET_BAD || c.writes[i] > maxfd)
        maxfd = c.writes[i];
    }

    timeout_ms = timer_remain_ms(&c);
    if(timeout_ms < 0)
      timeout_ms = 1000;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    select_test((int)maxfd + 1, &rset, &wset, NULL, &tv);

    if(maxfd == CURL_SOCKET_BAD) {
      curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &still_running);
      continue;
    }

    for(i = 0; i < c.read_count; i++) {
      if(FD_ISSET(c.reads[i], &rset))
        curl_multi_socket_action(multi, c.reads[i], CURL_CSELECT_IN,
                                 &still_running);
    }
    for(i = 0; i < c.write_count; i++) {
      if(FD_ISSET(c.writes[i], &wset))
        curl_multi_socket_action(multi, c.writes[i], CURL_CSELECT_OUT,
                                 &still_running);
    }

    if(timer_remain_ms(&c) == 0)
      curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &still_running);
  }

  /* transfer complete. verify result via multi_info_read */
  {
    CURLMsg *msg;
    int msgs_left;
    while((msg = curl_multi_info_read(multi, &msgs_left))) {
      if(msg->msg == CURLMSG_DONE) {
        c.transfers_done++;
        if(msg->data.result != CURLE_OK)
          result = msg->data.result;
      }
    }
  }

  /* After transfer, the connection should be idle in the pool.
   * With CURLMOPT_MONITOR_IDLE_CONNECTIONS enabled, the socket callback
   * should have registered POLLIN on it. */
  if(c.read_count < 1) {
    curl_mfprintf(stderr, "FAIL: idle connection not monitored (reads=%d)\n",
            c.read_count);
    result = TEST_ERR_FAILURE;
  }
  if(c.write_count) {
    curl_mfprintf(stderr,
                  "UNEXPECTED: write sockets on idle conn (writes=%d)\n",
                  c.write_count);
  }

  /* now run a second transfer reusing the idle connection */
  easy_init(e2);
  easy_setopt(e2, CURLOPT_URL, URL);
  easy_setopt(e2, CURLOPT_TIMEOUT, 10L);
  multi_add_handle(multi, e2);

  still_running = 1;
  while(still_running) {
    fd_set rset, wset;
    struct timeval tv;
    curl_socket_t maxfd = CURL_SOCKET_BAD;
    long timeout_ms;

    FD_ZERO(&rset);
    FD_ZERO(&wset);
    for(i = 0; i < c.read_count; i++) {
      FD_SET(c.reads[i], &rset);
      if(maxfd == CURL_SOCKET_BAD || c.reads[i] > maxfd)
        maxfd = c.reads[i];
    }
    for(i = 0; i < c.write_count; i++) {
      FD_SET(c.writes[i], &wset);
      if(maxfd == CURL_SOCKET_BAD || c.writes[i] > maxfd)
        maxfd = c.writes[i];
    }

    timeout_ms = timer_remain_ms(&c);
    if(timeout_ms < 0)
      timeout_ms = 1000;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    select_test((int)maxfd + 1, &rset, &wset, NULL, &tv);

    if(maxfd == CURL_SOCKET_BAD) {
      curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &still_running);
      continue;
    }

    for(i = 0; i < c.read_count; i++) {
      if(FD_ISSET(c.reads[i], &rset))
        curl_multi_socket_action(multi, c.reads[i], CURL_CSELECT_IN,
                                 &still_running);
    }
    for(i = 0; i < c.write_count; i++) {
      if(FD_ISSET(c.writes[i], &wset))
        curl_multi_socket_action(multi, c.writes[i], CURL_CSELECT_OUT,
                                 &still_running);
    }

    if(timer_remain_ms(&c) == 0)
      curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0, &still_running);
  }

  {
    CURLMsg *msg;
    int msgs_left;
    while((msg = curl_multi_info_read(multi, &msgs_left))) {
      if(msg->msg == CURLMSG_DONE) {
        c.transfers_done++;
        if(msg->data.result != CURLE_OK)
          result = msg->data.result;
      }
    }
  }

  if(c.transfers_done != 2) {
    curl_mfprintf(stderr, "FAIL: expected 2 transfers done, got %d\n",
            c.transfers_done);
    result = TEST_ERR_FAILURE;
  }

test_cleanup:
  if(e2) {
    curl_multi_remove_handle(multi, e2);
    curl_easy_cleanup(e2);
  }
  if(e1) {
    curl_multi_remove_handle(multi, e1);
    curl_easy_cleanup(e1);
  }
  curl_multi_cleanup(multi);
  curl_global_cleanup();
  return result;
}
