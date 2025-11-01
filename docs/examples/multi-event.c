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

/* <DESC>
 * multi_socket API using libevent
 * </DESC>
 */

#include <stdio.h>
#include <stdlib.h>
#include <event2/event.h>
#include <curl/curl.h>

static struct event_base *base;
static CURLM *multi;
static struct event *timeout;

struct curl_context {
  struct event *event;
  curl_socket_t sockfd;
};

static void curl_perform(int fd, short event, void *arg);

static struct curl_context *create_curl_context(curl_socket_t sockfd)
{
  struct curl_context *context;

  context = (struct curl_context *) malloc(sizeof(*context));

  context->sockfd = sockfd;

  context->event = event_new(base, sockfd, 0, curl_perform, context);

  return context;
}

static void destroy_curl_context(struct curl_context *context)
{
  event_del(context->event);
  event_free(context->event);
  free(context);
}

static void add_download(const char *url, int num)
{
  char filename[50];
  FILE *file;
  CURL *curl;

  snprintf(filename, sizeof(filename), "%d.download", num);

  file = fopen(filename, "wb");
  if(!file) {
    fprintf(stderr, "Error opening %s\n", filename);
    return;
  }

  curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
  curl_easy_setopt(curl, CURLOPT_PRIVATE, file);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_multi_add_handle(multi, curl);
  fprintf(stderr, "Added download %s -> %s\n", url, filename);
}

static void check_multi_info(void)
{
  char *done_url;
  CURLMsg *message;
  int pending;
  CURL *curl;
  FILE *file;

  while((message = curl_multi_info_read(multi, &pending))) {
    switch(message->msg) {
    case CURLMSG_DONE:
      /* Do not use message data after calling curl_multi_remove_handle() and
         curl_easy_cleanup(). As per curl_multi_info_read() docs:
         "WARNING: The data the returned pointer points to does not survive
         calling curl_multi_cleanup, curl_multi_remove_handle or
         curl_easy_cleanup." */
      curl = message->easy_handle;

      curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &done_url);
      curl_easy_getinfo(curl, CURLINFO_PRIVATE, &file);
      printf("%s DONE\n", done_url);

      curl_multi_remove_handle(multi, curl);
      curl_easy_cleanup(curl);
      if(file) {
        fclose(file);
      }
      break;

    default:
      fprintf(stderr, "CURLMSG default\n");
      break;
    }
  }
}

static void curl_perform(int fd, short event, void *arg)
{
  int running_handles;
  int flags = 0;
  struct curl_context *context;

  (void)fd;

  if(event & EV_READ)
    flags |= CURL_CSELECT_IN;
  if(event & EV_WRITE)
    flags |= CURL_CSELECT_OUT;

  context = (struct curl_context *) arg;

  curl_multi_socket_action(multi, context->sockfd, flags,
                           &running_handles);

  check_multi_info();
}

static void on_timeout(evutil_socket_t fd, short events, void *arg)
{
  int running_handles;
  (void)fd;
  (void)events;
  (void)arg;
  curl_multi_socket_action(multi, CURL_SOCKET_TIMEOUT, 0,
                           &running_handles);
  check_multi_info();
}

static int start_timeout(CURLM *multi, long timeout_ms, void *userp)
{
  (void)multi;
  (void)userp;
  if(timeout_ms < 0) {
    evtimer_del(timeout);
  }
  else {
    struct timeval tv;
    if(timeout_ms == 0)
      timeout_ms = 1; /* 0 means call socket_action asap */
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    evtimer_del(timeout);
    evtimer_add(timeout, &tv);
  }
  return 0;
}

static int handle_socket(CURL *curl, curl_socket_t s, int action, void *userp,
                         void *socketp)
{
  struct curl_context *curl_context;
  int events = 0;

  (void)curl;
  (void)userp;

  switch(action) {
  case CURL_POLL_IN:
  case CURL_POLL_OUT:
  case CURL_POLL_INOUT:
    curl_context = socketp ?
      (struct curl_context *) socketp : create_curl_context(s);

    curl_multi_assign(multi, s, (void *) curl_context);

    if(action != CURL_POLL_IN)
      events |= EV_WRITE;
    if(action != CURL_POLL_OUT)
      events |= EV_READ;

    events |= EV_PERSIST;

    event_del(curl_context->event);
    event_assign(curl_context->event, base, curl_context->sockfd,
      (short)events, curl_perform, curl_context);
    event_add(curl_context->event, NULL);

    break;
  case CURL_POLL_REMOVE:
    if(socketp) {
      event_del(((struct curl_context*) socketp)->event);
      destroy_curl_context((struct curl_context*) socketp);
      curl_multi_assign(multi, s, NULL);
    }
    break;
  default:
    abort();
  }

  return 0;
}

int main(int argc, char **argv)
{
  CURLcode res;

  if(argc <= 1)
    return 0;

  res = curl_global_init(CURL_GLOBAL_ALL);
  if(res) {
    fprintf(stderr, "Could not init curl\n");
    return (int)res;
  }

  base = event_base_new();
  timeout = evtimer_new(base, on_timeout, NULL);

  multi = curl_multi_init();
  if(multi) {
    curl_multi_setopt(multi, CURLMOPT_SOCKETFUNCTION, handle_socket);
    curl_multi_setopt(multi, CURLMOPT_TIMERFUNCTION, start_timeout);

    while(argc-- > 1) {
      add_download(argv[argc], argc);
    }

    event_base_dispatch(base);

    curl_multi_cleanup(multi);
  }
  event_free(timeout);
  event_base_free(base);

  libevent_global_shutdown();
  curl_global_cleanup();

  return 0;
}
