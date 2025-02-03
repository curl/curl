#ifndef HEADER_FETCH_HEADER_H
#define HEADER_FETCH_HEADER_H
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
 * are also available at https://fetch.se/docs/copyright.html.
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
#include "fetch_setup.h"

#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_HEADERS_API)

struct Fetch_header_store
{
  struct Fetch_llist_node node;
  char *name;         /* points into 'buffer' */
  char *value;        /* points into 'buffer */
  int request;        /* 0 is the first request, then 1.. 2.. */
  unsigned char type; /* FETCHH_* defines */
  char buffer[1];     /* this is the raw header blob */
};

/*
 * Initialize header collecting for a transfer.
 * Will add a client writer that catches CLIENTWRITE_HEADER writes.
 */
FETCHcode Fetch_headers_init(struct Fetch_easy *data);

/*
 * Fetch_headers_push() gets passed a full header to store.
 */
FETCHcode Fetch_headers_push(struct Fetch_easy *data, const char *header,
                            unsigned char type);

/*
 * Fetch_headers_cleanup(). Free all stored headers and associated memory.
 */
FETCHcode Fetch_headers_cleanup(struct Fetch_easy *data);

#else
#define Fetch_headers_init(x) FETCHE_OK
#define Fetch_headers_push(x, y, z) FETCHE_OK
#define Fetch_headers_cleanup(x) Fetch_nop_stmt
#endif

#endif /* HEADER_FETCH_HEADER_H */
