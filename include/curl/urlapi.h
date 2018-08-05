#ifndef __CURL_URLAPI_H
#define __CURL_URLAPI_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef  __cplusplus
extern "C" {
#endif

/* the error codes for the URL API */
typedef enum {
  CURLURLE_OK,
  CURLURLE_BAD_HANDLE,          /* 1 */
  CURLURLE_BAD_PARTPOINTER,     /* 2 */
  CURLURLE_MALFORMED_INPUT,     /* 3 */
  CURLURLE_BAD_PORT_NUMBER,     /* 4 */
  CURLURLE_UNSUPPORTED_SCHEME,  /* 5 */
  CURLURLE_URLDECODE,           /* 6 */
  CURLURLE_RELATIVE,            /* 7 */
  CURLURLE_USER_NOT_ALLOWED,    /* 8 */
  CURLURLE_UNKNOWN_PART,        /* 9 */
  CURLURLE_NO_SCHEME,
  CURLURLE_NO_USER,
  CURLURLE_NO_PASSWORD,
  CURLURLE_NO_OPTIONS,
  CURLURLE_NO_HOST,
  CURLURLE_NO_PORT,
  CURLURLE_NO_PATH,
  CURLURLE_NO_QUERY,
  CURLURLE_NO_FRAGMENT,
  CURLURLE_OUT_OF_MEMORY,
} CURLUcode;

#define CURLURL_DEFAULT_PORT (1<<0)       /* return default port number (only works
                                             for schemes this libcurl supports) */
#define CURLURL_NO_DEFAULT_PORT (1<<1)    /* act as if no port number was set,
                                             if the port number matches the
                                             default for the scheme */
#define CURLURL_DEFAULT_SCHEME (1<<2)     /* return default scheme if
                                             missing */
#define CURLURL_NON_SUPPORT_SCHEME (1<<3) /* allow non-supported schemes */
#define CURLURL_VERIFY_ONLY (1<<4)        /* binary check of URL validity */
#define CURLURL_CONVERT_SPACES (1<<5)     /* convert ASCII spaces (0x20) to
                                             %20 */
#define CURLURL_CONVERT_8BIT   (1<<6)     /* convert >127 byte values to
                                             converted to %XX output */
#define CURLURL_URLDECODE (1<<7)          /* URL *decode* on read when getting
                                             a part */
#define CURLURL_PATH_AS_IS (1<<8)         /* do not remove ../ and ./
                                             sequences */
#define CURLURL_DISALLOW_USER (1<<9)      /* no user+password allowed in URL */

typedef struct Curl_URL CURLURL;

/*
 * curl_url() sets the URL (or NULL) to parse. Returns error code.  If
 * successful, stores a CURLURL handle pointer in the 'urlhandle' argument.
 * NULL is an acceptable input to let users add parts individually.
 *
 * The given input URL will be parsed and split up into its components and if
 * any syntax error is found, this function returns the applicable error code.
 * This will never trigger any network use. A URL deemed to be valid by this
 * function will be considered valid by other libcurl operations as well.
 *
 * Flags
 *
 * - CURLURL_NON_SUPPORT_SCHEME allows schemes this libcurl does not
 *   support. If not set, this function returns CURLURLE_UNSUPPORTED_SCHEME
 *   for those.
 * - CURLURL_VERIFY_ONLY makes this function *not* create an output handle but
 *   will still return OK/error regarding the URL syntax.
 * - CURLURL_CONVERT_SPACES tells the function to not consider ascii space to
 *   be an error and instead convert them to %20.
 * - CURLURL_CONVERT_8BIT tells this function to convert 8 bit (>127) byte
 *   values to %xx. URLs are typically 7 bit only so such input is nornally a
 *   mistake.
 * - CURLURL_CONVERT_SLASHES makes the parser allow scheme:/host and
 *   scheme:///host as if they were correct.
 */
CURL_EXTERN CURLUcode curl_url(char *URL, CURLURL **urlhandle, unsigned int flags);

/*
 * curl_url_cleanup() frees the CURLURL handle and related resources used for
 * the URL parsing. It will not free strings previously returned with the URL
 * API.
 */
CURL_EXTERN void curl_url_cleanup(CURLURL *handle);

/*
 * curl_url_dup() duplicates a CURLURL handle and returns a new copy. The new
 * handle must be freed with curl_url_cleanup() when the application is done
 * with it.
 */
CURL_EXTERN CURLURL *curl_url_dup(CURLURL *inhandle);

typedef enum {
  CURLUPART_URL,    /* used to extract the full URL or set a
                       new URL, that might be relative to the
                       formerly set one */

  CURLUPART_SCHEME,
  CURLUPART_USER,
  CURLUPART_PASSWORD,
  CURLUPART_OPTIONS,
  CURLUPART_HOST,
  CURLUPART_PORT,
  CURLUPART_PATH,
  CURLUPART_QUERY,
  CURLUPART_FRAGMENT
} CURLUPart;

/*
 * curl_url_get() extracts a specific part of the URL from a CURLURL
 * handle. Returns error code. The returned pointer MUST be freed with
 * curl_free() afterwards.
 *
 * Flags: the CURLURL_* bitmask defines described above.
 *
 * for all
 *
 * - CURLURL_URLDECODE returns the string URL decoded. If there's a %00
 *   in there then, curl_url_get() returns CURLURLE_URLDECODE.
 *
 * for URL
 *
 * - CURLURL_DEFAULT_SCHEME makes this function use "https" for scheme
 *   instead of failure if no scheme was set.
 * - CURLURL_DEFAULT_PORT makes this function insert the port number in the
 *   URL even if it matches the default for the used scheme.
 *
 * for SCHEME
 *
 * - CURLURL_DEFAULT_SCHEME makes this function return "https" instead of
 *   failure if no scheme was set.
 * - CURLURL_NON_SUPPORT_SCHEME allows this function to return a scheme name
 *   that is not supported by this libcurl.
 *
 * for PORT
 *
 * Note that the port, while being a number, will be returned as a string just
 * like all other URL parts.
 *
 * - CURLURL_DEFAULT_PORT makes this function return the default port number
 *   for the used scheme even if no explicit port number was used in the URL.
 *
 * for PATH
 *
 * Even if the URL was given without a slash after the host name, this will
 * return a slash as path.
 *
 */
CURL_EXTERN CURLUcode curl_url_get(CURLURL *handle, CURLUPart what,
                                   char **part, unsigned int flags);

/*
 * curl_url_set() sets a specific part of the URL in a CURLURL handle. Returns
 * error code. The passed in string will be copied. Passing a NULL instead of
 * a part string, clears that part.
 *
 * Flags: the CURLURL_* bitmask defines described above.
 *
 * for URL
 *
 * If a relative URL is set and there was a previous URL set, this will create
 * the new final URL. If there's not enough to "follow" or create a URL when
 * a relative URL is passed in, CURLURLE_RELATIVE is returned.
 *
 * for SCHEME
 *
 * - CURLURL_NON_SUPPORT_SCHEME allows this function to accept scheme names
 *   that are not supported by this libcurl.
 *
 *
 */
CURL_EXTERN CURLUcode curl_url_set(CURLURL *handle, CURLUPart what,
                                   char *part, unsigned int flags);


#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif
