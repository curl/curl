#ifndef HEADER_CURL_LOG_H
#define HEADER_CURL_LOG_H
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

struct Curl_easy;
struct Curl_cfilter;

/**
 * Init logging, return != 0 on failure.
 */
CURLcode Curl_log_init(void);


void Curl_infof(struct Curl_easy *, const char *fmt, ...);
void Curl_failf(struct Curl_easy *, const char *fmt, ...);

#if defined(CURL_DISABLE_VERBOSE_STRINGS)

#if defined(HAVE_VARIADIC_MACROS_C99)
#define infof(...)  Curl_nop_stmt
#elif defined(HAVE_VARIADIC_MACROS_GCC)
#define infof(x...)  Curl_nop_stmt
#else
#error "missing VARIADIC macro define, fix and rebuild!"
#endif

#else /* CURL_DISABLE_VERBOSE_STRINGS */

#define infof Curl_infof

#endif /* CURL_DISABLE_VERBOSE_STRINGS */

#define failf Curl_failf


#define CURL_LOG_DEFAULT  0
#define CURL_LOG_DEBUG    1
#define CURL_LOG_TRACE    2


/* the function used to output verbose information */
void Curl_debug(struct Curl_easy *data, curl_infotype type,
                char *ptr, size_t size);

#ifdef DEBUGBUILD

/* explainer: we have some mix configuration and werror settings
 * that define HAVE_VARIADIC_MACROS_C99 even though C89 is enforced
 * on gnuc and some other compiler. Need to treat carefully.
 */
#if defined(HAVE_VARIADIC_MACROS_C99) && \
    defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)

#define LOG_CF(data, cf, ...) \
  do { if(Curl_log_cf_is_debug(cf, data)) \
         Curl_log_cf_debug(data, cf, __VA_ARGS__); } while(0)
#else
#define LOG_CF Curl_log_cf_debug
#endif

void Curl_log_cf_debug(struct Curl_easy *data, struct Curl_cfilter *cf,
#if defined(__GNUC__) && !defined(printf) &&                    \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
  !defined(__MINGW32__)
                       const char *fmt, ...)
                       __attribute__((format(printf, 3, 4)));
#else
                       const char *fmt, ...);
#endif

#define Curl_log_cf_is_debug(cf, data) \
    ((data) && (data)->set.verbose && \
     (cf) && (cf)->cft->log_level >= CURL_LOG_DEBUG)


#else /* !DEBUGBUILD */

#if defined(HAVE_VARIADIC_MACROS_C99) && \
    defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
#define LOG_CF(...)               Curl_nop_stmt
#define Curl_log_cf_debug(...)    Curl_nop_stmt
#elif defined(HAVE_VARIADIC_MACROS_GCC) && \
    defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
#define LOG_CF(x...)              Curl_nop_stmt
#define Curl_log_cf_debug(x...)   Curl_nop_stmt
#else
#define LOG_CF                    Curl_log_cf_debug
/* without c99, we seem unable to completely define away this function. */
void Curl_log_cf_debug(struct Curl_easy *data, struct Curl_cfilter *cf,
                       const char *fmt, ...);
#endif

#define Curl_log_cf_is_debug(x,y)   ((void)(x), (void)(y), FALSE)

#endif  /* !DEBUGBUILD */

#define LOG_CF_IS_DEBUG(cf, data)        Curl_log_cf_is_debug(cf, data)

#endif /* HEADER_CURL_LOG_H */
