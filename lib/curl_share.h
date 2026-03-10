#ifndef HEADER_CURL_SHARE_H
#define HEADER_CURL_SHARE_H
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

#include "curl_threads.h"
#include "cookie.h"
#include "psl.h"
#include "urldata.h"
#include "conncache.h"

struct Curl_easy;
struct Curl_ssl_scache;

#define CURL_GOOD_SHARE 0x7e117a1e
#define GOOD_SHARE_HANDLE(x) ((x) && (x)->magic == CURL_GOOD_SHARE)

#define CURL_SHARE_KEEP_CONNECT(s)                          \
  ((s) && ((s)->specifier & (1 << CURL_LOCK_DATA_CONNECT)))

/* this struct is libcurl-private, do not export details */
struct Curl_share {
  unsigned int magic; /* CURL_GOOD_SHARE */
  unsigned int specifier;

  uint32_t ref_count;
#ifdef USE_MUTEX
   /* do `ref_count` and `has_been_shared` checks using this mutex. */
  curl_mutex_t lock;
  int has_been_shared;
#else
  /* this only ever goes from FALSE -> TRUE once. We need to check
   * this without being able to use the `lockfunc`. */
  volatile int has_been_shared;
#endif
  curl_lock_function lockfunc;
  curl_unlock_function unlockfunc;
  void *clientdata;
  struct Curl_easy *admin;

  struct cpool cpool;
  struct Curl_dnscache dnscache; /* DNS cache */
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_COOKIES)
  struct CookieInfo *cookies;
#endif
#ifdef USE_LIBPSL
  struct PslCache psl;
#endif
#ifndef CURL_DISABLE_HSTS
  struct hsts *hsts;
#endif
#ifdef USE_SSL
  struct Curl_ssl_scache *ssl_scache;
#endif
};

CURLSHcode Curl_share_lock(struct Curl_easy *data, curl_lock_data type,
                           curl_lock_access accesstype);
CURLSHcode Curl_share_unlock(struct Curl_easy *data, curl_lock_data type);

/* convenience macro to check if this handle is using a shared SSL spool */
#define CURL_SHARE_ssl_scache(data) ((data)->share &&                    \
                                    ((data)->share->specifier &          \
                                     (1 << CURL_LOCK_DATA_SSL_SESSION)))

CURLcode Curl_share_easy_unlink(struct Curl_easy *data);
CURLcode Curl_share_easy_link(struct Curl_easy *data,
                              struct Curl_share *share);

#endif /* HEADER_CURL_SHARE_H */
