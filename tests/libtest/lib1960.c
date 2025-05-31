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
#include "test.h"

#ifdef HAVE_INET_PTON

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "memdebug.h"

/* to prevent libcurl from closing our socket */
static int closesocket_cb(void *clientp, curl_socket_t item)
{
  (void)clientp;
  (void)item;
  return 0;
}

/* provide our own socket */
static curl_socket_t socket_cb(void *clientp,
                               curlsocktype purpose,
                               struct curl_sockaddr *address)
{
  int s = *(int *)clientp;
  (void)purpose;
  (void)address;
  return (curl_socket_t)s;
}

/* tell libcurl the socket is connected */
static int sockopt_cb(void *clientp,
                      curl_socket_t curlfd,
                      curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

#if defined(__AMIGA__)
#define my_inet_pton(x,y,z) inet_pton(x,(unsigned char *)y,z)
#else
#define my_inet_pton(x,y,z) inet_pton(x,y,z)
#endif


/* Expected args: URL IP PORT */
CURLcode test(char *URL)
{
  CURL *curl = NULL;
  CURLcode res = TEST_ERR_MAJOR_BAD;
  int status;
  curl_socket_t client_fd = CURL_SOCKET_BAD;
  struct sockaddr_in serv_addr;
  unsigned short port;

  if(!strcmp("check", URL))
    return CURLE_OK; /* no output makes it not skipped */

  port = (unsigned short)atoi(libtest_arg3);

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /*
   * This code connects to the TCP port "manually" so that we then can hand
   * over this socket as "already connected" to libcurl and make sure that
   * this works.
   */
  client_fd = socket(AF_INET, SOCK_STREAM, 0);
  if(client_fd == CURL_SOCKET_BAD) {
    curl_mfprintf(stderr, "socket creation error\n");
    goto test_cleanup;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  if(my_inet_pton(AF_INET, libtest_arg2, &serv_addr.sin_addr) <= 0) {
    curl_mfprintf(stderr, "inet_pton failed\n");
    goto test_cleanup;
  }

  status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
  if(status < 0) {
    curl_mfprintf(stderr, "connection failed\n");
    goto test_cleanup;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    goto test_cleanup;
  }

  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, socket_cb);
  test_setopt(curl, CURLOPT_OPENSOCKETDATA, &client_fd);
  test_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_cb);
  test_setopt(curl, CURLOPT_SOCKOPTDATA, NULL);
  test_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, closesocket_cb);
  test_setopt(curl, CURLOPT_CLOSESOCKETDATA, NULL);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);
  test_setopt(curl, CURLOPT_HEADER, 1L);
  test_setopt(curl, CURLOPT_URL, URL);

  res = curl_easy_perform(curl);

test_cleanup:
  curl_easy_cleanup(curl);
  if(client_fd != CURL_SOCKET_BAD)
    sclose(client_fd);
  curl_global_cleanup();

  return res;
}
#else
CURLcode test(char *URL)
{
  (void)URL;
  curl_mprintf("lacks inet_pton\n");
  return CURLE_OK;
}
#endif
