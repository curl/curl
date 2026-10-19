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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

static int t1991_created(void *userp, curl_socket_t fd, curlsocktype purpose)
{
  (void)fd;
  (void)purpose;
  *(bool *)userp = TRUE;
  return CURL_SOCKOPT_OK;
}

static CURLcode test_lib1991(const char *URL)
{
  static const char response[] =
    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
  struct sockaddr_in addr;
  curl_socklen_t addrlen = sizeof(addr);
  curl_socket_t listener = CURL_SOCKET_BAD, peer = CURL_SOCKET_BAD;
  CURL *easy = NULL;
  CURLM *multi = NULL;
  CURLMsg *msg;
  CURLcode result = CURLE_FAILED_INIT;
  char url[80];
  int running = 1, left;
  bool created = FALSE, completed = FALSE;
  fd_set rd;
  struct timeval timeout;

  (void)URL;
  global_init(CURL_GLOBAL_ALL);
  listener = CURL_SOCKET(AF_INET, SOCK_STREAM, 0);
  if(listener == CURL_SOCKET_BAD)
    goto test_cleanup;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) ||
     getsockname(listener, (struct sockaddr *)&addr, &addrlen) ||
     listen(listener, 1))
    goto test_cleanup;
  curl_msnprintf(url, sizeof(url), "http://127.0.0.1:%u/",
                 (unsigned int)ntohs(addr.sin_port));
  easy_init(easy);
  multi = curl_multi_init();
  if(!multi)
    goto test_cleanup;
  easy_setopt(easy, CURLOPT_URL, url);
  easy_setopt(easy, CURLOPT_PROXY, "");
  easy_setopt(easy, CURLOPT_TIMEOUT_MS, 5000L);
  easy_setopt(easy, CURLOPT_SOCKOPTFUNCTION, t1991_created);
  easy_setopt(easy, CURLOPT_SOCKOPTDATA, &created);
  if(curl_multi_add_handle(multi, easy))
    goto test_cleanup;

  do {
    if(curl_multi_perform(multi, &running))
      goto test_cleanup;
    if(!created && curl_multi_poll(multi, NULL, 0, 100, NULL))
      goto test_cleanup;
  } while(!created && running);

  /* Respond and close before curl checks completion of the connect. */
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;
  FD_ZERO(&rd);
  FD_SET(listener, &rd);
  if(select((int)listener + 1, &rd, NULL, NULL, &timeout) != 1)
    goto test_cleanup;
  peer = CURL_ACCEPT(listener, NULL, NULL);
  if(peer == CURL_SOCKET_BAD ||
     swrite(peer, response, sizeof(response) - 1) !=
       (ssize_t)(sizeof(response) - 1))
    goto test_cleanup;
  sclose(peer);
  peer = CURL_SOCKET_BAD;
  curlx_wait_ms(100);

  while(running) {
    if(curl_multi_poll(multi, NULL, 0, 100, NULL) ||
       curl_multi_perform(multi, &running))
      goto test_cleanup;
  }
  while((msg = curl_multi_info_read(multi, &left))) {
    if(msg->msg == CURLMSG_DONE) {
      result = msg->data.result;
      completed = TRUE;
    }
  }

test_cleanup:
  if(!completed && !result)
    result = CURLE_FAILED_INIT;
  if(peer != CURL_SOCKET_BAD)
    sclose(peer);
  if(listener != CURL_SOCKET_BAD)
    sclose(listener);
  if(multi && easy)
    curl_multi_remove_handle(multi, easy);
  curl_easy_cleanup(easy);
  curl_multi_cleanup(multi);
  curl_global_cleanup();
  return result;
}
