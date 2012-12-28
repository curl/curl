#ifndef HEADER_CURL_BUNDLES_H
#define HEADER_CURL_BUNDLES_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012, Linus Nielsen Feltzing, <linus@haxx.se>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

struct connectbundle {
  bool server_supports_pipelining; /* TRUE if server supports pipelining,
                                      set after first response */
  size_t num_connections;       /* Number of connections in the bundle */
  struct curl_llist *conn_list; /* The connectdata members of the bundle */
};

CURLcode Curl_bundle_create(struct SessionHandle *data,
                            struct connectbundle **cb_ptr);

void Curl_bundle_destroy(struct connectbundle *cb_ptr);

CURLcode Curl_bundle_add_conn(struct connectbundle *cb_ptr,
                              struct connectdata *conn);

int Curl_bundle_remove_conn(struct connectbundle *cb_ptr,
                            struct connectdata *conn);


#endif /* HEADER_CURL_BUNDLES_H */

