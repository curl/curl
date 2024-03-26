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
 * Output a failure message on registered callbacks for transfer.
 */
void Curl_failf(struct Curl_easy *data,
                const char *fmt, ...) CURL_PRINTF(2, 3);

#define failf Curl_failf

#define CURL_LOG_LVL_NONE  0
#define CURL_LOG_LVL_INFO  1


#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define CURL_HAVE_C99
#endif

#ifdef CURL_HAVE_C99
#define infof(data, ...) \
  do { if(Curl_trc_is_verbose(data)) \
         Curl_infof(data, __VA_ARGS__); } while(0)
#define CURL_TRC_CF(data, cf, ...) \
  do { if(Curl_trc_cf_is_verbose(cf, data)) \
         Curl_trc_cf_infof(data, cf, __VA_ARGS__); } while(0)

#else
#define infof Curl_infof
#define CURL_TRC_CF Curl_trc_cf_infof
#endif

#ifndef CURL_DISABLE_VERBOSE_STRINGS
/* informational messages enabled */

struct curl_trc_feat {
  const char *name;
  int log_level;
};

#define Curl_trc_is_verbose(data) \
            ((data) && (data)->set.verbose && \
            (!(data)->state.feat || \
             ((data)->state.feat->log_level >= CURL_LOG_LVL_INFO)))
#define Curl_trc_cf_is_verbose(cf, data) \
            (Curl_trc_is_verbose(data) && \
            (cf) && (cf)->cft->log_level >= CURL_LOG_LVL_INFO)
#define Curl_trc_ft_is_verbose(data, ft) \
                            (Curl_trc_is_verbose(data) && \
                            (ft)->log_level >= CURL_LOG_LVL_INFO)

/**
 * Output an informational message when transfer's verbose logging is enabled.
 */
void Curl_infof(struct Curl_easy *data,
                const char *fmt, ...) CURL_PRINTF(2, 3);

/**
 * Output an informational message when both transfer's verbose logging
 * and connection filters verbose logging are enabled.
 */
void Curl_trc_cf_infof(struct Curl_easy *data, struct Curl_cfilter *cf,
                       const char *fmt, ...) CURL_PRINTF(3, 4);

#else /* defined(CURL_DISABLE_VERBOSE_STRINGS) */
/* All informational messages are not compiled in for size savings */

#define Curl_trc_is_verbose(d)        ((void)(d), FALSE)
#define Curl_trc_cf_is_verbose(x,y)   ((void)(x), (void)(y), FALSE)
#define Curl_trc_ft_is_verbose(x,y)   ((void)(x), (void)(y), FALSE)

static void Curl_infof(struct Curl_easy *data, const char *fmt, ...)
{
  (void)data; (void)fmt;
}

static void Curl_trc_cf_infof(struct Curl_easy *data,
                              struct Curl_cfilter *cf,
                              const char *fmt, ...)
{
  (void)data; (void)cf; (void)fmt;
}

#endif /* !defined(CURL_DISABLE_VERBOSE_STRINGS) */

#endif /* HEADER_CURL_TRC_H */
