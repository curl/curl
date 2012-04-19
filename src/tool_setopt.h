#ifndef HEADER_CURL_TOOL_SETOPT_H
#define HEADER_CURL_TOOL_SETOPT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "tool_setup.h"

/*
 * Macros used in operate()
 */

#define SETOPT_CHECK(v) do { \
  res = (v); \
  if(res) \
    goto show_error; \
} WHILE_FALSE

#ifndef CURL_DISABLE_LIBCURL_OPTION

/* Associate symbolic names with option values */
typedef struct {
  const char *name;
  long value;
} NameValue;

typedef struct {
  const char *name;
  unsigned long value;
} NameValueUnsigned;

extern const NameValue setopt_nv_CURLPROXY[];
extern const NameValue setopt_nv_CURL_HTTP_VERSION[];
extern const NameValue setopt_nv_CURL_SSLVERSION[];
extern const NameValue setopt_nv_CURL_TIMECOND[];
extern const NameValue setopt_nv_CURLFTPSSL_CCC[];
extern const NameValue setopt_nv_CURLPROTO[];
extern const NameValueUnsigned setopt_nv_CURLAUTH[];

/* Map options to NameValue sets */
#define setopt_nv_CURLOPT_HTTP_VERSION setopt_nv_CURL_HTTP_VERSION
#define setopt_nv_CURLOPT_HTTPAUTH setopt_nv_CURLAUTH
#define setopt_nv_CURLOPT_SSLVERSION setopt_nv_CURL_SSLVERSION
#define setopt_nv_CURLOPT_TIMECONDITION setopt_nv_CURL_TIMECOND
#define setopt_nv_CURLOPT_FTP_SSL_CCC setopt_nv_CURLFTPSSL_CCC
#define setopt_nv_CURLOPT_PROTOCOLS setopt_nv_CURLPROTO
#define setopt_nv_CURLOPT_REDIR_PROTOCOLS setopt_nv_CURLPROTO
#define setopt_nv_CURLOPT_PROXYTYPE setopt_nv_CURLPROXY
#define setopt_nv_CURLOPT_PROXYAUTH setopt_nv_CURLAUTH

/* Intercept setopt calls for --libcurl */

CURLcode tool_setopt_enum(CURL *curl, struct Configurable *config,
                          const char *name, CURLoption tag,
                          const NameValue *nv, long lval);
CURLcode tool_setopt_flags(CURL *curl, struct Configurable *config,
                           const char *name, CURLoption tag,
                           const NameValue *nv, long lval);
CURLcode tool_setopt_bitmask(CURL *curl, struct Configurable *config,
                             const char *name, CURLoption tag,
                             const NameValueUnsigned *nv, long lval);
CURLcode tool_setopt_httppost(CURL *curl, struct Configurable *config,
                              const char *name, CURLoption tag,
                              struct curl_httppost *httppost);
CURLcode tool_setopt_slist(CURL *curl, struct Configurable *config,
                           const char *name, CURLoption tag,
                           struct curl_slist *list);
CURLcode tool_setopt(CURL *curl, bool str, struct Configurable *config,
                     const char *name, CURLoption tag, ...);

#define my_setopt(x,y,z) \
  SETOPT_CHECK(tool_setopt(x, FALSE, config, #y, y, z))

#define my_setopt_str(x,y,z) \
  SETOPT_CHECK(tool_setopt(x, TRUE, config, #y, y, z))

#define my_setopt_enum(x,y,z) \
  SETOPT_CHECK(tool_setopt_enum(x, config, #y, y, setopt_nv_ ## y, z))

#define my_setopt_flags(x,y,z) \
  SETOPT_CHECK(tool_setopt_flags(x, config, #y, y, setopt_nv_ ## y, z))

#define my_setopt_bitmask(x,y,z) \
  SETOPT_CHECK(tool_setopt_bitmask(x, config, #y, y, setopt_nv_ ## y, z))

#define my_setopt_httppost(x,y,z) \
  SETOPT_CHECK(tool_setopt_httppost(x, config, #y, y, z))

#define my_setopt_slist(x,y,z) \
  SETOPT_CHECK(tool_setopt_slist(x, config, #y, y, z))

#define res_setopt(x,y,z) tool_setopt(x, FALSE, config, #y, y, z)

#define res_setopt_str(x,y,z) tool_setopt(x, TRUE, config, #y, y, z)

#else /* CURL_DISABLE_LIBCURL_OPTION */

/* No --libcurl, so pass options directly to library */

#define my_setopt(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))

#define my_setopt_str(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))

#define my_setopt_enum(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))

#define my_setopt_flags(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))

#define my_setopt_bitmask(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))

#define my_setopt_httppost(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))

#define my_setopt_slist(x,y,z) \
  SETOPT_CHECK(curl_easy_setopt(x, y, z))

#define res_setopt(x,y,z) curl_easy_setopt(x,y,z)

#define res_setopt_str(x,y,z) curl_easy_setopt(x,y,z)

#endif /* CURL_DISABLE_LIBCURL_OPTION */

#endif /* HEADER_CURL_TOOL_SETOPT_H */
