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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/* <DESC>
 * multi_socket API using libevent
 * </DESC>
 */

#include <stdio.h>
#include <stdlib.h>
#include <event2/event.h>
#include <fetch/fetch.h>

static struct event_base *base;
static FETCHM *fetch_handle;
static struct event *timeout;

typedef struct fetch_context_s
{
  struct event *event;
  fetch_socket_t sockfd;
} fetch_context_t;

static void fetch_perform(int fd, short event, void *arg);

static fetch_context_t *create_fetch_context(fetch_socket_t sockfd)
{
  fetch_context_t *context;

  context = (fetch_context_t *)malloc(sizeof(*context));

  context->sockfd = sockfd;

  context->event = event_new(base, sockfd, 0, fetch_perform, context);

  return context;
}

static void destroy_fetch_context(fetch_context_t *context)
{
  event_del(context->event);
  event_free(context->event);
  free(context);
}

static void add_download(const char *url, int num)
{
  char filename[50];
  FILE *file;
  FETCH *handle;

  snprintf(filename, 50, "%d.download", num);

  file = fopen(filename, "wb");
  if (!file)
  {
    fprintf(stderr, "Error opening %s\n", filename);
    return;
  }

  handle = fetch_easy_init();
  fetch_easy_setopt(handle, FETCHOPT_WRITEDATA, file);
  fetch_easy_setopt(handle, FETCHOPT_PRIVATE, file);
  fetch_easy_setopt(handle, FETCHOPT_URL, url);
  fetch_multi_add_handle(fetch_handle, handle);
  fprintf(stderr, "Added download %s -> %s\n", url, filename);
}

static void check_multi_info(void)
{
  char *done_url;
  FETCHMsg *message;
  int pending;
  FETCH *easy_handle;
  FILE *file;

  while ((message = fetch_multi_info_read(fetch_handle, &pending)))
  {
    switch (message->msg)
    {
    case FETCHMSG_DONE:
      /* Do not use message data after calling fetch_multi_remove_handle() and
         fetch_easy_cleanup(). As per fetch_multi_info_read() docs:
         "WARNING: The data the returned pointer points to does not survive
         calling fetch_multi_cleanup, fetch_multi_remove_handle or
         fetch_easy_cleanup." */
      easy_handle = message->easy_handle;

      fetch_easy_getinfo(easy_handle, FETCHINFO_EFFECTIVE_URL, &done_url);
      fetch_easy_getinfo(easy_handle, FETCHINFO_PRIVATE, &file);
      printf("%s DONE\n", done_url);

      fetch_multi_remove_handle(fetch_handle, easy_handle);
      fetch_easy_cleanup(easy_handle);
      if (file)
      {
        fclose(file);
      }
      break;

    default:
      fprintf(stderr, "FETCHMSG default\n");
      break;
    }
  }
}

static void fetch_perform(int fd, short event, void *arg)
{
  int running_handles;
  int flags = 0;
  fetch_context_t *context;

  (void)fd;

  if (event & EV_READ)
    flags |= FETCH_CSELECT_IN;
  if (event & EV_WRITE)
    flags |= FETCH_CSELECT_OUT;

  context = (fetch_context_t *)arg;

  fetch_multi_socket_action(fetch_handle, context->sockfd, flags,
                            &running_handles);

  check_multi_info();
}

static void on_timeout(evutil_socket_t fd, short events, void *arg)
{
  int running_handles;
  (void)fd;
  (void)events;
  (void)arg;
  fetch_multi_socket_action(fetch_handle, FETCH_SOCKET_TIMEOUT, 0,
                            &running_handles);
  check_multi_info();
}

static int start_timeout(FETCHM *multi, long timeout_ms, void *userp)
{
  (void)multi;
  (void)userp;
  if (timeout_ms < 0)
  {
    evtimer_del(timeout);
  }
  else
  {
    struct timeval tv;
    if (timeout_ms == 0)
      timeout_ms = 1; /* 0 means call socket_action asap */
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    evtimer_del(timeout);
    evtimer_add(timeout, &tv);
  }
  return 0;
}

static int handle_socket(FETCH *easy, fetch_socket_t s, int action, void *userp,
                         void *socketp)
{
  fetch_context_t *fetch_context;
  int events = 0;

  (void)easy;
  (void)userp;

  switch (action)
  {
  case FETCH_POLL_IN:
  case FETCH_POLL_OUT:
  case FETCH_POLL_INOUT:
    fetch_context = socketp ? (fetch_context_t *)socketp : create_fetch_context(s);

    fetch_multi_assign(fetch_handle, s, (void *)fetch_context);

    if (action != FETCH_POLL_IN)
      events |= EV_WRITE;
    if (action != FETCH_POLL_OUT)
      events |= EV_READ;

    events |= EV_PERSIST;

    event_del(fetch_context->event);
    event_assign(fetch_context->event, base, fetch_context->sockfd,
                 (short)events, fetch_perform, fetch_context);
    event_add(fetch_context->event, NULL);

    break;
  case FETCH_POLL_REMOVE:
    if (socketp)
    {
      event_del(((fetch_context_t *)socketp)->event);
      destroy_fetch_context((fetch_context_t *)socketp);
      fetch_multi_assign(fetch_handle, s, NULL);
    }
    break;
  default:
    abort();
  }

  return 0;
}

int main(int argc, char **argv)
{
  if (argc <= 1)
    return 0;

  if (fetch_global_init(FETCH_GLOBAL_ALL))
  {
    fprintf(stderr, "Could not init fetch\n");
    return 1;
  }

  base = event_base_new();
  timeout = evtimer_new(base, on_timeout, NULL);

  fetch_handle = fetch_multi_init();
  fetch_multi_setopt(fetch_handle, FETCHMOPT_SOCKETFUNCTION, handle_socket);
  fetch_multi_setopt(fetch_handle, FETCHMOPT_TIMERFUNCTION, start_timeout);

  while (argc-- > 1)
  {
    add_download(argv[argc], argc);
  }

  event_base_dispatch(base);

  fetch_multi_cleanup(fetch_handle);
  event_free(timeout);
  event_base_free(base);

  libevent_global_shutdown();
  fetch_global_cleanup();

  return 0;
}
