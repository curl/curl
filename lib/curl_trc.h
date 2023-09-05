#ifndef HEADER_CURL_TRC_H
#define HEADER_CURL_TRC_H
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
CURLcode Curl_trc_init(void);

/**
 * Configure tracing. May be called several times during global
 * initialization. Later calls may not take effect.
 *
 * Configuration format supported:
 * - comma-separated list of component names to enable logging on.
 *   E.g. 'http/2,ssl'. Unknown names are ignored. Names are compared
 *   case-insensitive.
 * - component 'all' applies to all known log components
 * - prefixing a component with '+' or '-' will en-/disable logging for
 *   that component
 * Example: 'all,-ssl' would enable logging for all components but the
 * SSL filters.
 *
 * @param config configuration string
 */
CURLcode Curl_trc_opt(const char *config);

/* the function used to output verbose information */
void Curl_debug(struct Curl_easy *data, curl_infotype type,
                char *ptr, size_t size);

/**
 * Output an informational message when transfer's verbose logging is enabled.
 */
void Curl_infof(struct Curl_easy *data,
#if defined(__GNUC__) && !defined(printf) &&                    \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
  !defined(__MINGW32__)
                       const char *fmt, ...)
                       __attribute__((format(printf, 2, 3)));
#else
                       const char *fmt, ...);
#endif

/**
 * Output a failure message on registered callbacks for transfer.
 */
void Curl_failf(struct Curl_easy *data,
#if defined(__GNUC__) && !defined(printf) &&                    \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
  !defined(__MINGW32__)
                       const char *fmt, ...)
                       __attribute__((format(printf, 2, 3)));
#else
                       const char *fmt, ...);
#endif

#define failf Curl_failf

/**
 * Output an informational message when both transfer's verbose logging
 * and connection filters verbose logging are enabled.
 */
void Curl_trc_cf_infof(struct Curl_easy *data, struct Curl_cfilter *cf,
#if defined(__GNUC__) && !defined(printf) &&                    \
  defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
  !defined(__MINGW32__)
                       const char *fmt, ...)
                       __attribute__((format(printf, 3, 4)));
#else
                       const char *fmt, ...);
#endif

#define CURL_LOG_LVL_NONE  0
#define CURL_LOG_LVL_INFO  1


#if !defined(CURL_DISABLE_VERBOSE_STRINGS)
/* informational messages enabled */

#define Curl_trc_is_verbose(data)    ((data) && (data)->set.verbose)
#define Curl_trc_cf_is_verbose(cf, data) \
                            ((data) && (data)->set.verbose && \
                            (cf) && (cf)->cft->log_level >= CURL_LOG_LVL_INFO)

/* explainer: we have some mix configuration and werror settings
 * that define HAVE_VARIADIC_MACROS_C99 even though C89 is enforced
 * on gnuc and some other compiler. Need to treat carefully.
 */
#if defined(HAVE_VARIADIC_MACROS_C99) && \
    defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)

#define infof(data, ...) \
  do { if(Curl_trc_is_verbose(data)) \
         Curl_infof(data, __VA_ARGS__); } while(0)
#define CURL_TRC_CF(data, cf, ...) \
  do { if(Curl_trc_cf_is_verbose(cf, data)) \
         Curl_trc_cf_infof(data, cf, __VA_ARGS__); } while(0)

#else /* no variadic macro args */
#define infof Curl_infof
#define CURL_TRC_CF Curl_trc_cf_infof
#endif /* variadic macro args */

#else /* !CURL_DISABLE_VERBOSE_STRINGS */
/* All informational messages are not compiled in for size savings */

#define Curl_trc_is_verbose(d)        ((void)(d), FALSE)
#define Curl_trc_cf_is_verbose(x,y)   ((void)(x), (void)(y), FALSE)

#if defined(HAVE_VARIADIC_MACROS_C99)
#define infof(...)  Curl_nop_stmt
#define CURL_TRC_CF(...)  Curl_nop_stmt
#define Curl_trc_cf_infof(...)  Curl_nop_stmt
#elif defined(HAVE_VARIADIC_MACROS_GCC)
#define infof(x...)  Curl_nop_stmt
#define CURL_TRC_CF(x...)  Curl_nop_stmt
#define Curl_trc_cf_infof(x...)  Curl_nop_stmt
#else
#error "missing VARIADIC macro define, fix and rebuild!"
#endif

#endif /* CURL_DISABLE_VERBOSE_STRINGS */

#endif /* HEADER_CURL_TRC_H */
