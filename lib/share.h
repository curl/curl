#ifndef HEADER_FETCH_SHARE_H
#define HEADER_FETCH_SHARE_H
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
#include <fetch/fetch.h>
#include "cookie.h"
#include "psl.h"
#include "urldata.h"
#include "conncache.h"

struct Fetch_ssl_scache;

#define FETCH_GOOD_SHARE 0x7e117a1e
#define GOOD_SHARE_HANDLE(x) ((x) && (x)->magic == FETCH_GOOD_SHARE)

#define FETCH_SHARE_KEEP_CONNECT(s) \
  ((s) && ((s)->specifier & (1 << FETCH_LOCK_DATA_CONNECT)))

/* this struct is libfetch-private, do not export details */
struct Fetch_share
{
  unsigned int magic; /* FETCH_GOOD_SHARE */
  unsigned int specifier;
  volatile unsigned int dirty;

  fetch_lock_function lockfunc;
  fetch_unlock_function unlockfunc;
  void *clientdata;
  struct cpool cpool;
  struct Fetch_hash hostcache;
#if !defined(FETCH_DISABLE_HTTP) && !defined(FETCH_DISABLE_COOKIES)
  struct CookieInfo *cookies;
#endif
#ifdef USE_LIBPSL
  struct PslCache psl;
#endif
#ifndef FETCH_DISABLE_HSTS
  struct hsts *hsts;
#endif
#ifdef USE_SSL
  struct Fetch_ssl_scache *ssl_scache;
#endif
};

FETCHSHcode Fetch_share_lock(struct Fetch_easy *, fetch_lock_data,
                            fetch_lock_access);
FETCHSHcode Fetch_share_unlock(struct Fetch_easy *, fetch_lock_data);

/* convenience macro to check if this handle is using a shared SSL spool */
#define FETCH_SHARE_ssl_scache(data) (data->share &&            \
                                      (data->share->specifier & \
                                       (1 << FETCH_LOCK_DATA_SSL_SESSION)))

#endif /* HEADER_FETCH_SHARE_H */
