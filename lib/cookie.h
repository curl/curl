#ifndef __COOKIE_H
#define __COOKIE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2006, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

#include <stdio.h>
#if defined(WIN32)
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#endif

#include <curl/curl.h>

struct Cookie {
  struct Cookie *next; /* next in the chain */
  char *name;        /* <this> = value */
  char *value;       /* name = <this> */
  char *path;         /* path = <this> */
  char *domain;      /* domain = <this> */
  curl_off_t expires;  /* expires = <this> */
  char *expirestr;   /* the plain text version */
  bool tailmatch;    /* weather we do tail-matchning of the domain name */

  /* RFC 2109 keywords. Version=1 means 2109-compliant cookie sending */
  char *version;     /* Version = <value> */
  char *maxage;      /* Max-Age = <value> */

  bool secure;       /* whether the 'secure' keyword was used */
  bool livecookie;   /* updated from a server, not a stored file */
};

struct CookieInfo {
  /* linked list of cookies we know of */
  struct Cookie *cookies;

  char *filename;  /* file we read from/write to */
  bool running;    /* state info, for cookie adding information */
  long numcookies; /* number of cookies in the "jar" */
  bool newsession; /* new session, discard session cookies on load */
};

/* This is the maximum line length we accept for a cookie line. RFC 2109
   section 6.3 says:

   "at least 4096 bytes per cookie (as measured by the size of the characters
   that comprise the cookie non-terminal in the syntax description of the
   Set-Cookie header)"

*/
#define MAX_COOKIE_LINE 5000
#define MAX_COOKIE_LINE_TXT "4999"

/* This is the maximum length of a cookie name we deal with: */
#define MAX_NAME 1024
#define MAX_NAME_TXT "1023"

struct SessionHandle;
/*
 * Add a cookie to the internal list of cookies. The domain and path arguments
 * are only used if the header boolean is TRUE.
 */

struct Cookie *Curl_cookie_add(struct SessionHandle *data,
                               struct CookieInfo *, bool header, char *line,
                               char *domain, char *path);

struct CookieInfo *Curl_cookie_init(struct SessionHandle *data,
                                    char *, struct CookieInfo *, bool);
struct Cookie *Curl_cookie_getlist(struct CookieInfo *, char *, char *, bool);
void Curl_cookie_freelist(struct Cookie *);
void Curl_cookie_clearall(struct CookieInfo *cookies);
void Curl_cookie_clearsess(struct CookieInfo *cookies);
void Curl_cookie_cleanup(struct CookieInfo *);
int Curl_cookie_output(struct CookieInfo *, char *);

#if defined(CURL_DISABLE_HTTP) || defined(CURL_DISABLE_COOKIES)
#define Curl_cookie_list(x) NULL
#define Curl_cookie_loadfiles(x) do { } while (0)
#else
struct curl_slist *Curl_cookie_list(struct SessionHandle *data);
void Curl_cookie_loadfiles(struct SessionHandle *data);
#endif

#endif
