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
 * are also available at https://fetch.se/docs/copyright.html.
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
 * multi_socket API using libuv
 * </DESC>
 */
/* Use the socket_action interface to download multiple files in parallel,
   powered by libuv.

   Requires libuv and (of course) libfetch.

   See https://docs.libuv.org/en/v1.x/index.html libuv API documentation
*/

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include <fetch/fetch.h>

/* object to pass to the callbacks */
struct datauv
{
  uv_timer_t timeout;
  uv_loop_t *loop;
  FETCHM *multi;
};

typedef struct fetch_context_s
{
  uv_poll_t poll_handle;
  fetch_socket_t sockfd;
  struct datauv *uv;
} fetch_context_t;

static fetch_context_t *create_fetch_context(fetch_socket_t sockfd,
                                             struct datauv *uv)
{
  fetch_context_t *context;

  context = (fetch_context_t *)malloc(sizeof(*context));

  context->sockfd = sockfd;
  context->uv = uv;

  uv_poll_init_socket(uv->loop, &context->poll_handle, sockfd);
  context->poll_handle.data = context;

  return context;
}

static void fetch_close_cb(uv_handle_t *handle)
{
  fetch_context_t *context = (fetch_context_t *)handle->data;
  free(context);
}

static void destroy_fetch_context(fetch_context_t *context)
{
  uv_close((uv_handle_t *)&context->poll_handle, fetch_close_cb);
}

static void add_download(const char *url, int num, FETCHM *multi)
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
  fetch_multi_add_handle(multi, handle);
  fprintf(stderr, "Added download %s -> %s\n", url, filename);
}

static void check_multi_info(fetch_context_t *context)
{
  char *done_url;
  FETCHMsg *message;
  int pending;
  FETCH *easy_handle;
  FILE *file;

  while ((message = fetch_multi_info_read(context->uv->multi, &pending)))
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

      fetch_multi_remove_handle(context->uv->multi, easy_handle);
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

/* callback from libuv on socket activity */
static void on_uv_socket(uv_poll_t *req, int status, int events)
{
  int running_handles;
  int flags = 0;
  fetch_context_t *context = (fetch_context_t *)req->data;
  (void)status;
  if (events & UV_READABLE)
    flags |= FETCH_CSELECT_IN;
  if (events & UV_WRITABLE)
    flags |= FETCH_CSELECT_OUT;

  fetch_multi_socket_action(context->uv->multi, context->sockfd, flags,
                            &running_handles);
  check_multi_info(context);
}

/* callback from libuv when timeout expires */
static void on_uv_timeout(uv_timer_t *req)
{
  fetch_context_t *context = (fetch_context_t *)req->data;
  if (context)
  {
    int running_handles;
    fetch_multi_socket_action(context->uv->multi, FETCH_SOCKET_TIMEOUT, 0,
                              &running_handles);
    check_multi_info(context);
  }
}

/* callback from libfetch to update the timeout expiry */
static int cb_timeout(FETCHM *multi, long timeout_ms,
                      struct datauv *uv)
{
  (void)multi;
  if (timeout_ms < 0)
    uv_timer_stop(&uv->timeout);
  else
  {
    if (timeout_ms == 0)
      timeout_ms = 1; /* 0 means call fetch_multi_socket_action asap but NOT
                         within the callback itself */
    uv_timer_start(&uv->timeout, on_uv_timeout, (uint64_t)timeout_ms,
                   0); /* do not repeat */
  }
  return 0;
}

/* callback from libfetch to update socket activity to wait for */
static int cb_socket(FETCH *easy, fetch_socket_t s, int action,
                     struct datauv *uv,
                     void *socketp)
{
  fetch_context_t *fetch_context;
  int events = 0;
  (void)easy;

  switch (action)
  {
  case FETCH_POLL_IN:
  case FETCH_POLL_OUT:
  case FETCH_POLL_INOUT:
    fetch_context = socketp ? (fetch_context_t *)socketp : create_fetch_context(s, uv);

    fetch_multi_assign(uv->multi, s, (void *)fetch_context);

    if (action != FETCH_POLL_IN)
      events |= UV_WRITABLE;
    if (action != FETCH_POLL_OUT)
      events |= UV_READABLE;

    uv_poll_start(&fetch_context->poll_handle, events, on_uv_socket);
    break;
  case FETCH_POLL_REMOVE:
    if (socketp)
    {
      uv_poll_stop(&((fetch_context_t *)socketp)->poll_handle);
      destroy_fetch_context((fetch_context_t *)socketp);
      fetch_multi_assign(uv->multi, s, NULL);
    }
    break;
  default:
    abort();
  }

  return 0;
}

int main(int argc, char **argv)
{
  struct datauv uv = {0};
  int running_handles;

  if (argc <= 1)
    return 0;

  fetch_global_init(FETCH_GLOBAL_ALL);

  uv.loop = uv_default_loop();
  uv_timer_init(uv.loop, &uv.timeout);

  uv.multi = fetch_multi_init();
  fetch_multi_setopt(uv.multi, FETCHMOPT_SOCKETFUNCTION, cb_socket);
  fetch_multi_setopt(uv.multi, FETCHMOPT_SOCKETDATA, &uv);
  fetch_multi_setopt(uv.multi, FETCHMOPT_TIMERFUNCTION, cb_timeout);
  fetch_multi_setopt(uv.multi, FETCHMOPT_TIMERDATA, &uv);

  while (argc-- > 1)
  {
    add_download(argv[argc], argc, uv.multi);
  }

  /* kickstart the thing */
  fetch_multi_socket_action(uv.multi, FETCH_SOCKET_TIMEOUT, 0, &running_handles);
  uv_run(uv.loop, UV_RUN_DEFAULT);
  fetch_multi_cleanup(uv.multi);

  return 0;
}
