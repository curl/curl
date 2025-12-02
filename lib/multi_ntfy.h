#ifndef HEADER_CURL_MULTI_NTFY_H
#define HEADER_CURL_MULTI_NTFY_H
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

#include "uint-bset.h"

struct Curl_easy;
struct Curl_multi;

struct curl_multi_ntfy {
  curl_notify_callback ntfy_cb;
  void *ntfy_cb_data;
  struct uint32_bset enabled;
  CURLMcode failure;
  struct mntfy_chunk *head;
  struct mntfy_chunk *tail;
};

void Curl_mntfy_init(struct Curl_multi *multi);
CURLMcode Curl_mntfy_resize(struct Curl_multi *multi);
void Curl_mntfy_cleanup(struct Curl_multi *multi);

CURLMcode Curl_mntfy_enable(struct Curl_multi *multi, unsigned int type);
CURLMcode Curl_mntfy_disable(struct Curl_multi *multi, unsigned int type);

void Curl_mntfy_add(struct Curl_easy *data, unsigned int type);

#define CURLM_NTFY(d,t) \
  do { if((d) && (d)->multi && (d)->multi->ntfy.ntfy_cb) \
       Curl_mntfy_add((d), (t)); } while(0)

CURLMcode Curl_mntfy_dispatch_all(struct Curl_multi *multi);


#endif /* HEADER_CURL_MULTI_NTFY_H */
