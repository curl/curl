#ifndef HEADER_CURL_COOKIE_DB_H
#define HEADER_CURL_COOKIE_DB_H
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

#if defined(USE_SQLITE) && !defined(CURL_DISABLE_HTTP) && \
  !defined(CURL_DISABLE_COOKIES)

struct Curl_easy;
struct CookieInfo;
struct Cookie;

/*
 * The SQLite cookie store, CURLOPT_COOKIEDB. All functions must be called
 * with the cookie share lock held. Database errors are reported in the
 * verbose log and otherwise ignored, the in-memory cookies stay correct.
 */

/* Open the database at `path`, creating it with its table if needed. With
   `newsession`, the stored session cookies are dropped. A database already
   open at this path is kept. Nothing is loaded yet, see import. */
CURLcode Curl_cookie_db_open(struct Curl_easy *data, struct CookieInfo *ci,
                             const char *path, bool newsession);

/* Close the database, keeping the in-memory cookies */
void Curl_cookie_db_close(struct CookieInfo *ci);

/* Write the in-memory cookies to the database and replace them with all
   cookies of the database. Done when the database was just opened and,
   with `files` set, after cookie files were read. */
CURLcode Curl_cookie_db_import(struct Curl_easy *data, struct CookieInfo *ci,
                               bool files);

/* Reload the cookies when another connection changed the database */
CURLcode Curl_cookie_db_sync(struct Curl_easy *data, struct CookieInfo *ci);

/* Write a cookie to the database, replacing an existing row */
void Curl_cookie_db_store(struct CookieInfo *ci, const struct Cookie *co);

/* Remove a cookie from the database */
void Curl_cookie_db_remove(struct CookieInfo *ci, const struct Cookie *co);

/* Remove all cookies, or only the session cookies, from the database */
void Curl_cookie_db_clear(struct CookieInfo *ci, bool session_only);

#else
#define Curl_cookie_db_open(a, b, c, d) CURLE_OK
#define Curl_cookie_db_close(x) Curl_nop_stmt
#define Curl_cookie_db_import(a, b, c) CURLE_OK
#define Curl_cookie_db_sync(x, y) CURLE_OK
#define Curl_cookie_db_store(x, y) Curl_nop_stmt
#define Curl_cookie_db_remove(x, y) Curl_nop_stmt
#define Curl_cookie_db_clear(x, y) Curl_nop_stmt
#endif

#endif /* HEADER_CURL_COOKIE_DB_H */
