#ifndef HEADER_CURL_URLAPI_INT_H
#define HEADER_CURL_URLAPI_INT_H
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
#include "curl_setup.h"
#include <curl/urlapi.h>

/* Internal representation of CURLU. Point to URL-encoded strings. */
struct Curl_URL {
  char *scheme;
  char *user;
  char *password;
  char *options; /* IMAP only? */
  char *host;
  char *zoneid; /* for numerical IPv6 addresses */
  char *port;
  char *path;
  char *query;
  char *fragment;
  unsigned short portnum; /* the numerical version (if 'port' is set) */
  BIT(query_present);    /* to support blank */
  BIT(fragment_present); /* to support blank */
  BIT(guessed_scheme);   /* when a URL without scheme is parsed */
};

#define HOST_ERROR   (-1) /* out of memory */
#define HOST_NAME    1
#define HOST_IPV4    2
#define HOST_IPV6    3

#define QUERY_NO      2
#define QUERY_NOT_YET 3 /* allow to change to query */
#define QUERY_YES     4

size_t Curl_is_absolute_url(const char *url, char *buf, size_t buflen,
                            bool guess_scheme);

CURLUcode Curl_url_set_authority(CURLU *u, const char *authority);

CURLUcode Curl_junkscan(const char *url, size_t *urllen, bool allowspace);

#define U_CURLU_URLDECODE  (unsigned int)CURLU_URLDECODE
#define U_CURLU_PATH_AS_IS (unsigned int)CURLU_PATH_AS_IS

bool Curl_url_same_origin(CURLU *base, CURLU *href);

#endif /* HEADER_CURL_URLAPI_INT_H */
