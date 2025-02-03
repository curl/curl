#ifndef FETCHINC_URLAPI_H
#define FETCHINC_URLAPI_H
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /* the error codes for the URL API */
  typedef enum
  {
    FETCHUE_OK,
    FETCHUE_BAD_HANDLE,         /* 1 */
    FETCHUE_BAD_PARTPOINTER,    /* 2 */
    FETCHUE_MALFORMED_INPUT,    /* 3 */
    FETCHUE_BAD_PORT_NUMBER,    /* 4 */
    FETCHUE_UNSUPPORTED_SCHEME, /* 5 */
    FETCHUE_URLDECODE,          /* 6 */
    FETCHUE_OUT_OF_MEMORY,      /* 7 */
    FETCHUE_USER_NOT_ALLOWED,   /* 8 */
    FETCHUE_UNKNOWN_PART,       /* 9 */
    FETCHUE_NO_SCHEME,          /* 10 */
    FETCHUE_NO_USER,            /* 11 */
    FETCHUE_NO_PASSWORD,        /* 12 */
    FETCHUE_NO_OPTIONS,         /* 13 */
    FETCHUE_NO_HOST,            /* 14 */
    FETCHUE_NO_PORT,            /* 15 */
    FETCHUE_NO_QUERY,           /* 16 */
    FETCHUE_NO_FRAGMENT,        /* 17 */
    FETCHUE_NO_ZONEID,          /* 18 */
    FETCHUE_BAD_FILE_URL,       /* 19 */
    FETCHUE_BAD_FRAGMENT,       /* 20 */
    FETCHUE_BAD_HOSTNAME,       /* 21 */
    FETCHUE_BAD_IPV6,           /* 22 */
    FETCHUE_BAD_LOGIN,          /* 23 */
    FETCHUE_BAD_PASSWORD,       /* 24 */
    FETCHUE_BAD_PATH,           /* 25 */
    FETCHUE_BAD_QUERY,          /* 26 */
    FETCHUE_BAD_SCHEME,         /* 27 */
    FETCHUE_BAD_SLASHES,        /* 28 */
    FETCHUE_BAD_USER,           /* 29 */
    FETCHUE_LACKS_IDN,          /* 30 */
    FETCHUE_TOO_LARGE,          /* 31 */
    FETCHUE_LAST
  } FETCHUcode;

  typedef enum
  {
    FETCHUPART_URL,
    FETCHUPART_SCHEME,
    FETCHUPART_USER,
    FETCHUPART_PASSWORD,
    FETCHUPART_OPTIONS,
    FETCHUPART_HOST,
    FETCHUPART_PORT,
    FETCHUPART_PATH,
    FETCHUPART_QUERY,
    FETCHUPART_FRAGMENT,
    FETCHUPART_ZONEID /* added in 7.65.0 */
  } FETCHUPart;

#define FETCHU_DEFAULT_PORT (1 << 0)       /* return default port number */
#define FETCHU_NO_DEFAULT_PORT (1 << 1)    /* act as if no port number was set, \
                                             if the port number matches the     \
                                             default for the scheme */
#define FETCHU_DEFAULT_SCHEME (1 << 2)     /* return default scheme if \
                                             missing */
#define FETCHU_NON_SUPPORT_SCHEME (1 << 3) /* allow non-supported scheme */
#define FETCHU_PATH_AS_IS (1 << 4)         /* leave dot sequences */
#define FETCHU_DISALLOW_USER (1 << 5)      /* no user+password allowed */
#define FETCHU_URLDECODE (1 << 6)          /* URL decode on get */
#define FETCHU_URLENCODE (1 << 7)          /* URL encode on set */
#define FETCHU_APPENDQUERY (1 << 8)        /* append a form style part */
#define FETCHU_GUESS_SCHEME (1 << 9)       /* legacy fetch-style guessing */
#define FETCHU_NO_AUTHORITY (1 << 10)      /* Allow empty authority when the \
                                             scheme is unknown. */
#define FETCHU_ALLOW_SPACE (1 << 11)       /* Allow spaces in the URL */
#define FETCHU_PUNYCODE (1 << 12)          /* get the hostname in punycode */
#define FETCHU_PUNY2IDN (1 << 13)          /* punycode => IDN conversion */
#define FETCHU_GET_EMPTY (1 << 14)         /* allow empty queries and fragments \
                                             when extracting the URL or the     \
                                             components */
#define FETCHU_NO_GUESS_SCHEME (1 << 15)   /* for get, do not accept a guess */

  typedef struct Curl_URL FETCHU;

  /*
   * fetch_url() creates a new FETCHU handle and returns a pointer to it.
   * Must be freed with fetch_url_cleanup().
   */
  FETCH_EXTERN FETCHU *fetch_url(void);

  /*
   * fetch_url_cleanup() frees the FETCHU handle and related resources used for
   * the URL parsing. It will not free strings previously returned with the URL
   * API.
   */
  FETCH_EXTERN void fetch_url_cleanup(FETCHU *handle);

  /*
   * fetch_url_dup() duplicates a FETCHU handle and returns a new copy. The new
   * handle must also be freed with fetch_url_cleanup().
   */
  FETCH_EXTERN FETCHU *fetch_url_dup(const FETCHU *in);

  /*
   * fetch_url_get() extracts a specific part of the URL from a FETCHU
   * handle. Returns error code. The returned pointer MUST be freed with
   * fetch_free() afterwards.
   */
  FETCH_EXTERN FETCHUcode fetch_url_get(const FETCHU *handle, FETCHUPart what,
                                        char **part, unsigned int flags);

  /*
   * fetch_url_set() sets a specific part of the URL in a FETCHU handle. Returns
   * error code. The passed in string will be copied. Passing a NULL instead of
   * a part string, clears that part.
   */
  FETCH_EXTERN FETCHUcode fetch_url_set(FETCHU *handle, FETCHUPart what,
                                        const char *part, unsigned int flags);

  /*
   * fetch_url_strerror() turns a FETCHUcode value into the equivalent human
   * readable error string. This is useful for printing meaningful error
   * messages.
   */
  FETCH_EXTERN const char *fetch_url_strerror(FETCHUcode);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* FETCHINC_URLAPI_H */
