#ifndef HEADER_PERF_RESPCTX_H
#define HEADER_PERF_RESPCTX_H
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
struct respctx {
  curl_socket_t sock[2]; /* [0] is curl's end, [1] is the "server" end */
  const char *resp;
  size_t resplen;
  bool handed_out;
};

curl_socket_t rh_opensocket(void *clientp, curlsocktype purpose,
                            struct curl_sockaddr *address);
int rh_sockopt(void *clientp, curl_socket_t curlfd,
               curlsocktype purpose);
size_t rh_write(char *ptr, size_t size, size_t nmemb, void *userdata);
bool rh_fits(struct respctx *ctx);
int rh_closesocket(void *clientp, curl_socket_t item);
int rh_prereq(void *clientp, char *conn_primary_ip,
              char *conn_local_ip, int conn_primary_port,
              int conn_local_port);

#endif /* HEADER_PERF_RESPCTX_H */
