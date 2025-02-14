#ifndef HEADER_CURL_MULTI_EV_H
#define HEADER_CURL_MULTI_EV_H
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

struct Curl_easy;
struct Curl_multi;
struct easy_pollset;

struct curl_multi_ev {
  struct Curl_hash sh_entries;
};

/* Expire all transfers operating on the given socket */
void Curl_multi_ev_expire_transfers(struct Curl_multi *multi,
                                    curl_socket_t s,
                                    int ev_bitmask,
                                    const struct curltime *nowp,
                                    bool *run_cpool);

/* Inform event handling about the current pollset for transfer `data`.
 * multi_ev will calculate the differences to a previous call and inform
 * the libcurl application via the socket callback of any changes to sockets.
 */
CURLMcode Curl_multi_ev_pollset(struct Curl_multi *multi,
                                struct Curl_easy *data,
                                struct easy_pollset *ps);

CURLMcode Curl_multi_ev_assign(struct Curl_multi *multi, curl_socket_t s,
                               void *user_data);

void Curl_multi_ev_init(struct Curl_multi *multi, size_t hashsize);
void Curl_multi_ev_cleanup(struct Curl_multi *multi);

/* Socket will be closed, forget anything we know about it. */
void Curl_multi_ev_will_close(struct Curl_multi *multi,
                              struct Curl_easy *data, curl_socket_t s);

#endif /* HEADER_CURL_MULTI_EV_H */
