#ifndef HEADER_CURL_CONNCACHE_H
#define HEADER_CURL_CONNCACHE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2015 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2012 - 2014, Linus Nielsen Feltzing, <linus@haxx.se>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

struct conncache {
  struct curl_hash hash;
  size_t num_connections;
  long next_connection_id;
  struct timeval last_cleanup;
};

#define BUNDLE_NO_MULTIUSE -1
#define BUNDLE_UNKNOWN     0  /* initial value */
#define BUNDLE_PIPELINING  1
#define BUNDLE_MULTIPLEX   2

struct connectbundle {
  int multiuse;                 /* supports multi-use */
  size_t num_connections;       /* Number of connections in the bundle */
  struct curl_llist conn_list;  /* The connectdata members of the bundle */
};

int Curl_conncache_init(struct conncache *, int size);

void Curl_conncache_destroy(struct conncache *connc);

/* return the correct bundle, to a host or a proxy */
struct connectbundle *Curl_conncache_find_bundle(struct connectdata *conn,
                                                 struct conncache *connc);

CURLcode Curl_conncache_add_conn(struct conncache *connc,
                                 struct connectdata *conn);

void Curl_conncache_remove_conn(struct conncache *connc,
                                struct connectdata *conn);

void Curl_conncache_foreach(struct conncache *connc,
                            void *param,
                            int (*func)(struct connectdata *conn,
                                        void *param));

struct connectdata *
Curl_conncache_find_first_connection(struct conncache *connc);

void Curl_conncache_print(struct conncache *connc);

#endif /* HEADER_CURL_CONNCACHE_H */
