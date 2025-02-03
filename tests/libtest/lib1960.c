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
 * are also available at https://fetch.haxx.se/docs/copyright.html.
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
#include "test.h"

#include "inet_pton.h"
#include "memdebug.h"

/* to prevent libfetch from closing our socket */
static int closesocket_cb(void *clientp, fetch_socket_t item)
{
  (void)clientp;
  (void)item;
  return 0;
}

/* provide our own socket */
static fetch_socket_t socket_cb(void *clientp,
                               fetchsocktype purpose,
                               struct fetch_sockaddr *address)
{
  int s = *(int *)clientp;
  (void)purpose;
  (void)address;
  return (fetch_socket_t)s;
}

/* tell libfetch the socket is connected */
static int sockopt_cb(void *clientp,
                      fetch_socket_t fetchfd,
                      fetchsocktype purpose)
{
  (void)clientp;
  (void)fetchfd;
  (void)purpose;
  return FETCH_SOCKOPT_ALREADY_CONNECTED;
}

/* Expected args: URL IP PORT */
FETCHcode test(char *URL)
{
  FETCH *fetch = NULL;
  FETCHcode res = TEST_ERR_MAJOR_BAD;
  int status;
  fetch_socket_t client_fd = FETCH_SOCKET_BAD;
  struct sockaddr_in serv_addr;
  unsigned short port;

  if(!strcmp("check", URL))
    return FETCHE_OK; /* no output makes it not skipped */

  port = (unsigned short)atoi(libtest_arg3);

  if(fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK) {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /*
   * This code connects to the TCP port "manually" so that we then can hand
   * over this socket as "already connected" to libfetch and make sure that
   * this works.
   */
  client_fd = socket(AF_INET, SOCK_STREAM, 0);
  if(client_fd == FETCH_SOCKET_BAD) {
    fprintf(stderr, "socket creation error\n");
    goto test_cleanup;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  if(Fetch_inet_pton(AF_INET, libtest_arg2, &serv_addr.sin_addr) <= 0) {
    fprintf(stderr, "inet_pton failed\n");
    goto test_cleanup;
  }

  status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
  if(status < 0) {
    fprintf(stderr, "connection failed\n");
    goto test_cleanup;
  }

  fetch = fetch_easy_init();
  if(!fetch) {
    fprintf(stderr, "fetch_easy_init() failed\n");
    goto test_cleanup;
  }

  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_OPENSOCKETFUNCTION, socket_cb);
  test_setopt(fetch, FETCHOPT_OPENSOCKETDATA, &client_fd);
  test_setopt(fetch, FETCHOPT_SOCKOPTFUNCTION, sockopt_cb);
  test_setopt(fetch, FETCHOPT_SOCKOPTDATA, NULL);
  test_setopt(fetch, FETCHOPT_CLOSESOCKETFUNCTION, closesocket_cb);
  test_setopt(fetch, FETCHOPT_CLOSESOCKETDATA, NULL);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);
  test_setopt(fetch, FETCHOPT_URL, URL);

  res = fetch_easy_perform(fetch);

test_cleanup:
  fetch_easy_cleanup(fetch);
  if(client_fd != FETCH_SOCKET_BAD)
    sclose(client_fd);
  fetch_global_cleanup();

  return res;
}
