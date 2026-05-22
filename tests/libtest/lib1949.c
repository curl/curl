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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define MAX_FDS 64
struct ctx {
  CURLM         *multi;
  int            still_running;
  curl_socket_t  fds[MAX_FDS];
  int            actions[MAX_FDS];
  int            nfds;
  int            pause_fired;
  int            iterations;
};

static void fd_add(struct ctx *c, curl_socket_t s, int action)
{
  int i;
  for(i = 0; i < c->nfds; i++) {
    if(c->fds[i] == s) { c->actions[i] = action; return; }
  }
  if(c->nfds < MAX_FDS) {
    c->fds[c->nfds]     = s;
    c->actions[c->nfds] = action;
    c->nfds++;
  }
}

static void fd_del(struct ctx *c, curl_socket_t s)
{
  int i;
  for(i = 0; i < c->nfds; i++) {
    if(c->fds[i] == s) {
      c->nfds--;
      c->fds[i]     = c->fds[c->nfds];
      c->actions[i] = c->actions[c->nfds];
      return;
    }
  }
}

static int sock1949_cb(CURL *easy, curl_socket_t s, int what,
                       void *userp, void *socketp)
{
  struct ctx *c = userp;
  (void)socketp;
  if(what == CURL_POLL_REMOVE) {
    fd_del(c, s);
    return 0;
  }
  fd_add(c, s, what);

  if(!c->pause_fired && (what & CURL_POLL_IN)) {
    /*
     * The first POLL_IN may be the multi handle's internal wakeup pipe
     * (admin handle, conn==NULL); curl_easy_pause() returns
     * CURLE_BAD_FUNCTION_ARGUMENT and the re-entrant path is not taken.
     * Leave pause_fired=0 and retry on the next POLL_IN, which will be
     * the actual transfer socket (conn!=NULL).
     */
    CURLcode rc = curl_easy_pause(easy, CURLPAUSE_RECV);
    if(rc == CURLE_OK)
      c->pause_fired = 1;
  }
  return 0;
}

static int timer1949_cb(CURLM *m, long ms, void *u)
{
  (void)m;(void)ms;(void)u;
  return 0;
}
static size_t write1949_cb(char *p, size_t sz, size_t n, void *u)
{
  (void)p;(void)u;
  return sz*n;
}

static CURLcode test_lib1949(const char *URL)
{
  struct ctx c = {0};
  CURL *easy = NULL;
  curl_global_init(CURL_GLOBAL_DEFAULT);

  c.multi = curl_multi_init();
  if(!c.multi)
    goto test_cleanup;
  curl_multi_setopt(c.multi, CURLMOPT_SOCKETFUNCTION, sock1949_cb);
  curl_multi_setopt(c.multi, CURLMOPT_SOCKETDATA,     &c);
  curl_multi_setopt(c.multi, CURLMOPT_TIMERFUNCTION,  timer1949_cb);
  curl_multi_setopt(c.multi, CURLMOPT_TIMERDATA,      &c);

  easy = curl_easy_init();
  if(!easy)
    goto test_cleanup;
  curl_easy_setopt(easy, CURLOPT_URL,           URL);
  curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write1949_cb);
  curl_easy_setopt(easy, CURLOPT_VERBOSE,       1L);
  curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS,    500L);

  curl_multi_add_handle(c.multi, easy);
  curl_multi_socket_action(c.multi, CURL_SOCKET_TIMEOUT, 0, &c.still_running);

  while(c.still_running && c.iterations < 2000) {
    fd_set rfds, wfds;
    struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 };
    curl_socket_t maxfd = -1;
    int rc;
    curl_socket_t ready_s[MAX_FDS];
    int ready_ev[MAX_FDS];
    int nready = 0;
    int i;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    c.iterations++;
    for(i = 0; i < c.nfds; i++) {
      curl_socket_t s = c.fds[i];
      int a = c.actions[i];
      if(a & CURL_POLL_IN) {
        FD_SET(s, &rfds);
        if((int)s > maxfd)
          maxfd = s;
      }
      if(a & CURL_POLL_OUT) {
        FD_SET(s, &wfds);
        if((int)s > maxfd)
          maxfd = s;
      }
    }
    if(c.pause_fired)
      break;
    if(maxfd < 0) {
      usleep(5000);
      curl_multi_socket_action(c.multi, CURL_SOCKET_TIMEOUT, 0,
                               &c.still_running);
      continue;
    }
    rc = select(maxfd + 1, &rfds, &wfds, NULL, &tv);
    if(rc < 0) {
      if(errno == SOCKEINTR)
        continue;
      break;
    }
    if(rc == 0) {
      curl_multi_socket_action(c.multi, CURL_SOCKET_TIMEOUT, 0,
                               &c.still_running);
      continue;
    }

    for(i = 0; i < c.nfds && nready < MAX_FDS; i++) {
      curl_socket_t s = c.fds[i];
      int ev = 0;
      if(FD_ISSET(s, &rfds))
        ev |= CURL_CSELECT_IN;
      if(FD_ISSET(s, &wfds))
        ev |= CURL_CSELECT_OUT;
      if(ev) {
        ready_s[nready] = s;
        ready_ev[nready] = ev;
        nready++;
      }
    }
    for(i = 0; i < nready; i++)
      curl_multi_socket_action(c.multi, ready_s[i], ready_ev[i],
                               &c.still_running);
  }

test_cleanup:
  if(c.multi && easy)
    curl_multi_remove_handle(c.multi, easy);
  curl_easy_cleanup(easy);
  curl_multi_cleanup(c.multi);
  curl_global_cleanup();
  return 0;
}
