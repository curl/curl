#ifndef HEADER_FETCH_TOOL_SETOPT_H
#define HEADER_FETCH_TOOL_SETOPT_H
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
#include "tool_setup.h"

#include "tool_formparse.h"

/*
 * Macros used in operate()
 */

#define SETOPT_CHECK(v, opt) \
  do                         \
  {                          \
    result = (v);            \
  } while (0)

#ifndef FETCH_DISABLE_LIBFETCH_OPTION

/* Associate symbolic names with option values */
struct NameValue
{
  const char *name;
  long value;
};

struct NameValueUnsigned
{
  const char *name;
  unsigned long value;
};

extern const struct NameValue setopt_nv_FETCHPROXY[];
extern const struct NameValue setopt_nv_FETCH_SOCKS_PROXY[];
extern const struct NameValue setopt_nv_FETCH_HTTP_VERSION[];
extern const struct NameValue setopt_nv_FETCH_SSLVERSION[];
extern const struct NameValue setopt_nv_FETCH_SSLVERSION_MAX[];
extern const struct NameValue setopt_nv_FETCH_TIMECOND[];
extern const struct NameValue setopt_nv_FETCHFTPSSL_CCC[];
extern const struct NameValue setopt_nv_FETCHUSESSL[];
extern const struct NameValueUnsigned setopt_nv_FETCHSSLOPT[];
extern const struct NameValue setopt_nv_FETCH_NETRC[];
extern const struct NameValueUnsigned setopt_nv_FETCHAUTH[];
extern const struct NameValueUnsigned setopt_nv_FETCHHSTS[];

/* Map options to NameValue sets */
#define setopt_nv_FETCHOPT_HSTS_CTRL setopt_nv_FETCHHSTS
#define setopt_nv_FETCHOPT_HTTP_VERSION setopt_nv_FETCH_HTTP_VERSION
#define setopt_nv_FETCHOPT_HTTPAUTH setopt_nv_FETCHAUTH
#define setopt_nv_FETCHOPT_SSLVERSION setopt_nv_FETCH_SSLVERSION
#define setopt_nv_FETCHOPT_PROXY_SSLVERSION setopt_nv_FETCH_SSLVERSION
#define setopt_nv_FETCHOPT_TIMECONDITION setopt_nv_FETCH_TIMECOND
#define setopt_nv_FETCHOPT_FTP_SSL_CCC setopt_nv_FETCHFTPSSL_CCC
#define setopt_nv_FETCHOPT_USE_SSL setopt_nv_FETCHUSESSL
#define setopt_nv_FETCHOPT_SSL_OPTIONS setopt_nv_FETCHSSLOPT
#define setopt_nv_FETCHOPT_PROXY_SSL_OPTIONS setopt_nv_FETCHSSLOPT
#define setopt_nv_FETCHOPT_NETRC setopt_nv_FETCH_NETRC
#define setopt_nv_FETCHOPT_PROXYTYPE setopt_nv_FETCHPROXY
#define setopt_nv_FETCHOPT_PROXYAUTH setopt_nv_FETCHAUTH
#define setopt_nv_FETCHOPT_SOCKS5_AUTH setopt_nv_FETCHAUTH

/* Intercept setopt calls for --libfetch */

FETCHcode tool_setopt_enum(FETCH *fetch, struct GlobalConfig *config,
                           const char *name, FETCHoption tag,
                           const struct NameValue *nv, long lval);
FETCHcode tool_setopt_SSLVERSION(FETCH *fetch, struct GlobalConfig *config,
                                 const char *name, FETCHoption tag,
                                 long lval);
FETCHcode tool_setopt_flags(FETCH *fetch, struct GlobalConfig *config,
                            const char *name, FETCHoption tag,
                            const struct NameValue *nv, long lval);
FETCHcode tool_setopt_bitmask(FETCH *fetch, struct GlobalConfig *config,
                              const char *name, FETCHoption tag,
                              const struct NameValueUnsigned *nv, long lval);
FETCHcode tool_setopt_mimepost(FETCH *fetch, struct GlobalConfig *config,
                               const char *name, FETCHoption tag,
                               fetch_mime *mimepost);
FETCHcode tool_setopt_slist(FETCH *fetch, struct GlobalConfig *config,
                            const char *name, FETCHoption tag,
                            struct fetch_slist *list);
FETCHcode tool_setopt(FETCH *fetch, bool str, struct GlobalConfig *global,
                      struct OperationConfig *config,
                      const char *name, FETCHoption tag, ...);

#define my_setopt(x, y, z) \
  SETOPT_CHECK(tool_setopt(x, FALSE, global, config, #y, y, z), y)

#define my_setopt_str(x, y, z) \
  SETOPT_CHECK(tool_setopt(x, TRUE, global, config, #y, y, z), y)

#define my_setopt_enum(x, y, z) \
  SETOPT_CHECK(tool_setopt_enum(x, global, #y, y, setopt_nv_##y, z), y)

#define my_setopt_SSLVERSION(x, y, z) \
  SETOPT_CHECK(tool_setopt_SSLVERSION(x, global, #y, y, z), y)

#define my_setopt_bitmask(x, y, z) \
  SETOPT_CHECK(tool_setopt_bitmask(x, global, #y, y, setopt_nv_##y, z), y)

#define my_setopt_mimepost(x, y, z) \
  SETOPT_CHECK(tool_setopt_mimepost(x, global, #y, y, z), y)

#define my_setopt_slist(x, y, z) \
  SETOPT_CHECK(tool_setopt_slist(x, global, #y, y, z), y)

#define res_setopt(x, y, z) tool_setopt(x, FALSE, global, config, #y, y, z)

#define res_setopt_str(x, y, z) tool_setopt(x, TRUE, global, config, #y, y, z)

#else /* FETCH_DISABLE_LIBFETCH_OPTION */

/* No --libfetch, so pass options directly to library */

#define my_setopt(x, y, z) \
  SETOPT_CHECK(fetch_easy_setopt(x, y, z), y)

#define my_setopt_str(x, y, z) \
  SETOPT_CHECK(fetch_easy_setopt(x, y, z), y)

#define my_setopt_enum(x, y, z) \
  SETOPT_CHECK(fetch_easy_setopt(x, y, z), y)

#define my_setopt_SSLVERSION(x, y, z) \
  SETOPT_CHECK(fetch_easy_setopt(x, y, z), y)

#define my_setopt_bitmask(x, y, z) \
  SETOPT_CHECK(fetch_easy_setopt(x, y, z), y)

#define my_setopt_mimepost(x, y, z) \
  SETOPT_CHECK(fetch_easy_setopt(x, y, z), y)

#define my_setopt_slist(x, y, z) \
  SETOPT_CHECK(fetch_easy_setopt(x, y, z), y)

#define res_setopt(x, y, z) fetch_easy_setopt(x, y, z)

#define res_setopt_str(x, y, z) fetch_easy_setopt(x, y, z)

#endif /* FETCH_DISABLE_LIBFETCH_OPTION */

#endif /* HEADER_FETCH_TOOL_SETOPT_H */
