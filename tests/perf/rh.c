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
#include "rh.h"

curl_socket_t rh_opensocket(void *clientp, curlsocktype purpose,
                            struct curl_sockaddr *address)
{
  struct respctx *ctx = clientp;
  (void)purpose;
  (void)address;
  if(ctx->handed_out)
    return CURL_SOCKET_BAD; /* the one connection should be reused */
  ctx->handed_out = TRUE;
  return ctx->sock[0];
}

int rh_sockopt(void *clientp, curl_socket_t curlfd,
               curlsocktype purpose)
{
  (void)clientp;
  (void)curlfd;
  (void)purpose;
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

int rh_closesocket(void *clientp, curl_socket_t item)
{
  (void)clientp;
  (void)item;
  return 0; /* closed at the end of the test */
}

/* Called after the connection is picked, before the request is sent:
   discard the previous request and queue the next response. Doing it
   earlier would make the idle connection look dead. */
int rh_prereq(void *clientp, char *conn_primary_ip,
              char *conn_local_ip, int conn_primary_port,
              int conn_local_port)
{
  struct respctx *ctx = clientp;
  char buf[4096];
  size_t left = ctx->resplen;
  const char *p = ctx->resp;
  (void)conn_primary_ip;
  (void)conn_local_ip;
  (void)conn_primary_port;
  (void)conn_local_port;

  while(sread(ctx->sock[1], buf, sizeof(buf)) > 0)
    ;
  while(left) {
    ssize_t n = swrite(ctx->sock[1], p, left);
    if(n <= 0)
      return CURL_PREREQFUNC_ABORT;
    p += n;
    left -= (size_t)n;
  }
  return CURL_PREREQFUNC_OK;
}

/* The whole response is queued before libcurl reads any of it, so it must
   fit in the socket buffers. Ask for more room than the default, which is
   only 8 KiB on some systems, and check that a response fits. */
bool rh_fits(struct respctx *ctx)
{
  int size = 256 * 1024;
  char buf[4096];
  const char *p = ctx->resp;
  size_t left = ctx->resplen;
  size_t got = 0;

  (void)setsockopt(ctx->sock[1], SOL_SOCKET, SO_SNDBUF,
                   (void *)&size, sizeof(size));
  (void)setsockopt(ctx->sock[0], SOL_SOCKET, SO_RCVBUF,
                   (void *)&size, sizeof(size));
  while(left) {
    ssize_t n = swrite(ctx->sock[1], p, left);
    if(n <= 0)
      break;
    p += n;
    left -= (size_t)n;
  }
  /* read back what was written to leave the socket pair empty */
  while(got < ctx->resplen - left) {
    ssize_t n = sread(ctx->sock[0], buf, sizeof(buf));
    if(n <= 0)
      return FALSE;
    got += (size_t)n;
  }
  return !left;
}

size_t rh_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}
