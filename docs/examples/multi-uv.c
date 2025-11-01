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
 * multi_socket API using libuv
 * </DESC>
 */

/* Use the socket_action interface to download multiple files in parallel,
   powered by libuv.

   Requires libuv and (of course) libcurl.

   See https://docs.libuv.org/en/v1.x/index.html libuv API documentation
*/

/* Requires: USE_LIBUV */

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include <curl/curl.h>

/* object to pass to the callbacks */
struct datauv {
  uv_timer_t timeout;
  uv_loop_t *loop;
  CURLM *multi;
};

struct curl_context {
  uv_poll_t poll_handle;
  curl_socket_t sockfd;
  struct datauv *uv;
};

static struct curl_context *create_curl_context(curl_socket_t sockfd,
                                                struct datauv *uv)
{
  struct curl_context *context;

  context = (struct curl_context *) malloc(sizeof(*context));

  context->sockfd = sockfd;
  context->uv = uv;

  uv_poll_init_socket(uv->loop, &context->poll_handle, sockfd);
  context->poll_handle.data = context;

  return context;
}

static void curl_close_cb(uv_handle_t *handle)
{
  struct curl_context *context = (struct curl_context *) handle->data;
  free(context);
}

static void destroy_curl_context(struct curl_context *context)
{
  uv_close((uv_handle_t *) &context->poll_handle, curl_close_cb);
}

static void add_download(const char *url, int num, CURLM *multi)
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

static void check_multi_info(struct curl_context *context)
{
  char *done_url;
  CURLMsg *message;
  int pending;
  CURL *curl;
  FILE *file;

  while((message = curl_multi_info_read(context->uv->multi, &pending))) {
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

      curl_multi_remove_handle(context->uv->multi, curl);
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

/* callback from libuv on socket activity */
static void on_uv_socket(uv_poll_t *req, int status, int events)
{
  int running_handles;
  int flags = 0;
  struct curl_context *context = (struct curl_context *) req->data;
  (void)status;
  if(events & UV_READABLE)
    flags |= CURL_CSELECT_IN;
  if(events & UV_WRITABLE)
    flags |= CURL_CSELECT_OUT;

  curl_multi_socket_action(context->uv->multi, context->sockfd, flags,
                           &running_handles);
  check_multi_info(context);
}

/* callback from libuv when timeout expires */
static void on_uv_timeout(uv_timer_t *req)
{
  struct curl_context *context = (struct curl_context *) req->data;
  if(context) {
    int running_handles;
    curl_multi_socket_action(context->uv->multi, CURL_SOCKET_TIMEOUT, 0,
                             &running_handles);
    check_multi_info(context);
  }
}

/* callback from libcurl to update the timeout expiry */
static int cb_timeout(CURLM *multi, long timeout_ms, void *userp)
{
  struct datauv *uv = (struct datauv *)userp;
  (void)multi;
  if(timeout_ms < 0)
    uv_timer_stop(&uv->timeout);
  else {
    if(timeout_ms == 0)
      timeout_ms = 1; /* 0 means call curl_multi_socket_action asap but NOT
                         within the callback itself */
    uv_timer_start(&uv->timeout, on_uv_timeout, (uint64_t)timeout_ms,
                   0); /* do not repeat */
  }
  return 0;
}

/* callback from libcurl to update socket activity to wait for */
static int cb_socket(CURL *curl, curl_socket_t s, int action,
                     void *userp, void *socketp)
{
  struct datauv *uv = (struct datauv *)userp;
  struct curl_context *curl_context;
  int events = 0;
  (void)curl;

  switch(action) {
  case CURL_POLL_IN:
  case CURL_POLL_OUT:
  case CURL_POLL_INOUT:
    curl_context = socketp ?
      (struct curl_context *) socketp : create_curl_context(s, uv);

    curl_multi_assign(uv->multi, s, (void *) curl_context);

    if(action != CURL_POLL_IN)
      events |= UV_WRITABLE;
    if(action != CURL_POLL_OUT)
      events |= UV_READABLE;

    uv_poll_start(&curl_context->poll_handle, events, on_uv_socket);
    break;
  case CURL_POLL_REMOVE:
    if(socketp) {
      uv_poll_stop(&((struct curl_context*)socketp)->poll_handle);
      destroy_curl_context((struct curl_context*) socketp);
      curl_multi_assign(uv->multi, s, NULL);
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
  struct datauv uv = { 0 };
  int running_handles;

  if(argc <= 1)
    return 0;

  res = curl_global_init(CURL_GLOBAL_ALL);
  if(res)
    return (int)res;

  uv.loop = uv_default_loop();
  uv_timer_init(uv.loop, &uv.timeout);

  uv.multi = curl_multi_init();
  if(uv.multi) {
    curl_multi_setopt(uv.multi, CURLMOPT_SOCKETFUNCTION, cb_socket);
    curl_multi_setopt(uv.multi, CURLMOPT_SOCKETDATA, &uv);
    curl_multi_setopt(uv.multi, CURLMOPT_TIMERFUNCTION, cb_timeout);
    curl_multi_setopt(uv.multi, CURLMOPT_TIMERDATA, &uv);

    while(argc-- > 1) {
      add_download(argv[argc], argc, uv.multi);
    }

    /* kickstart the thing */
    curl_multi_socket_action(uv.multi, CURL_SOCKET_TIMEOUT, 0,
                             &running_handles);
    uv_run(uv.loop, UV_RUN_DEFAULT);
    curl_multi_cleanup(uv.multi);
  }
  curl_global_cleanup();

  return 0;
}
