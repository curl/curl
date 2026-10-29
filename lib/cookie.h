#ifndef HEADER_CURL_COOKIE_H
#define HEADER_CURL_COOKIE_H
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

#include "llist.h"

struct Cookie {
  struct Curl_llist_node node;    /* for the main cookie list */
  struct Curl_llist_node getnode; /* for getlist */
  char *name;                     /* <this> = value */
  char *value;                    /* name = <this> */
  char *path;                     /* canonical path */
  char *domain;                   /* domain = <this> */
  char *partkey;                  /* partition key of a Partitioned cookie,
                                     the "scheme://host" it was set under,
                                     else NULL */
  curl_off_t expires;             /* expires = <this> */
  unsigned int creationtime;      /* time when the cookie was written */
  unsigned char samesite;         /* COOKIE_SAMESITE_* */
  BIT(tailmatch);                 /* tail-match the domain name */
  BIT(secure);                    /* the 'secure' keyword was used */
  BIT(livecookie);                /* updated from server, not a stored file */
  BIT(httponly);                  /* the httponly directive is present */
  BIT(prefix_secure);             /* secure prefix is set */
  BIT(prefix_host);               /* host prefix is set */
};

/* SameSite attribute values, RFC 6265bis section 5.4.7 */
#define COOKIE_SAMESITE_DEFAULT 0 /* no (valid) attribute, treated as Lax */
#define COOKIE_SAMESITE_NONE    1
#define COOKIE_SAMESITE_LAX     2
#define COOKIE_SAMESITE_STRICT  3

/*
 * Available cookie prefixes, as defined in
 * draft-ietf-httpbis-rfc6265bis-02
 */
#define COOKIE_PREFIX__SECURE (1 << 0)
#define COOKIE_PREFIX__HOST   (1 << 1)

#define COOKIE_HASH_SIZE 63

struct CookieInfo {
  /* linked lists of cookies we know of */
  struct Curl_llist cookielist[COOKIE_HASH_SIZE];
  curl_off_t next_expiration; /* the next time at which expiration happens */
  unsigned int numcookies;    /* number of cookies in the "jar" */
  unsigned int lastct;        /* last creation-time used in the jar */
  /* attributes read from a "#curl:" line, applied to the next cookie line */
  char *pending_partkey;
  unsigned char pending_samesite;
  BIT(pending);               /* a "#curl:" line was read */
  BIT(attrs_used);            /* SameSite/Partitioned attributes are in use,
                                 write them to the jar */
  BIT(running);               /* state info, for cookie adding information */
  BIT(newsession); /* new session, discard session cookies on load */
};

/* The maximum sizes we accept for cookies. RFC 6265 section 6.1 says
   "general-use user agents SHOULD provide each of the following minimum
   capabilities":

   - At least 4096 bytes per cookie (as measured by the sum of the length of
     the cookie's name, value, and attributes).
   In the 6265bis draft document section 5.4 it is phrased even stronger: "If
   the sum of the lengths of the name string and the value string is more than
   4096 octets, abort these steps and ignore the set-cookie-string entirely."
 */

/** Limits for INCOMING cookies **/

/* The longest we allow a line to be when reading a cookie from an HTTP header
   or from a cookie jar */
#define MAX_COOKIE_LINE 5000

/* Maximum length of an incoming cookie name or content we deal with. Longer
   cookies are ignored. */
#define MAX_NAME 4096

/* Maximum number of Set-Cookie: lines accepted in a single response. If more
   such header lines are received, they are ignored. This value must be less
   than 256 since an unsigned char is used to count. */
#define MAX_SET_COOKIE_AMOUNT 50

/** Limits for OUTGOING cookies **/

/* Maximum size for an outgoing cookie line libcurl will use in an http
   request. This is the default maximum length used in some versions of Apache
   httpd. */
#define MAX_COOKIE_HEADER_LEN 8190

/* Maximum number of cookies libcurl will send in a single request, even if
   there might be more cookies that match. One reason to cap the number is to
   keep the maximum HTTP request within the maximum allowed size. */
#define MAX_COOKIE_SEND_AMOUNT 150

struct Curl_easy;
struct connectdata;

bool Curl_secure_context(struct Curl_easy *data, const char *host);

/*
 * Add a cookie to the internal list of cookies. The domain and path arguments
 * are only used if the COOKIE_HTTPHEADER bit is set in the flags.
 */

#define COOKIE_HTTPHEADER (1<<0) /* if HTTP header-style line */
#define COOKIE_NOEXPIRE   (1<<1) /* skip remove_expired() */
#define COOKIE_SECURE     (1<<2) /* connection is over secure origin */
#define COOKIE_NOPSL      (1<<3) /* skip PSL check */
#define COOKIE_NOSESSION  (1<<6) /* drop session cookies */

CURLcode Curl_cookie_add(struct Curl_easy *data,
                         struct CookieInfo *ci,
                         const char *lineptr,
                         const char *domain,
                         const char *path,
                         const int flags) WARN_UNUSED_RESULT;
CURLcode Curl_cookie_getlist(struct Curl_easy *data,
                             bool *okay, const char *host,
                             struct Curl_llist *list) WARN_UNUSED_RESULT;
void Curl_cookie_clearall(struct CookieInfo *ci);
void Curl_cookie_clearsess(struct CookieInfo *ci);

#if defined(CURL_DISABLE_HTTP) || defined(CURL_DISABLE_COOKIES)
#define Curl_cookie_list(x)      NULL
#define Curl_cookie_loadfiles(x, y) CURLE_OK
#define Curl_cookie_init()       NULL
#define Curl_cookie_run(x)       Curl_nop_stmt
#define Curl_cookie_cleanup(x)   Curl_nop_stmt
#define Curl_flush_cookies(x, y) Curl_nop_stmt
#define Curl_cookie_site_ok(x)   TRUE
#else
bool Curl_cookie_site_ok(const char *site);
void Curl_flush_cookies(struct Curl_easy *data, bool cleanup);
void Curl_cookie_cleanup(struct CookieInfo *ci);
struct CookieInfo *Curl_cookie_init(void);
struct curl_slist *Curl_cookie_list(struct Curl_easy *data);
CURLcode Curl_cookie_loadfiles(struct Curl_easy *data,
                               int flags) WARN_UNUSED_RESULT;
void Curl_cookie_run(struct Curl_easy *data);
#endif

#endif /* HEADER_CURL_COOKIE_H */
