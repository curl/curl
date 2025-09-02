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
                const char *ptr, size_t size);

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

/**
 * Output an informational message when transfer's verbose logging is enabled.
 */
void Curl_infof(struct Curl_easy *data,
                const char *fmt, ...) CURL_PRINTF(2, 3);

/**
 * Output an informational message when both transfer's verbose logging
 * and connection filters verbose logging are enabled.
 */
void Curl_trc_cf_infof(struct Curl_easy *data, const struct Curl_cfilter *cf,
                       const char *fmt, ...) CURL_PRINTF(3, 4);
void Curl_trc_multi(struct Curl_easy *data,
                    const char *fmt, ...) CURL_PRINTF(2, 3);
const char *Curl_trc_mstate_name(int state);
const char *Curl_trc_timer_name(int tid);
void Curl_trc_multi_timeouts(struct Curl_easy *data);

void Curl_trc_write(struct Curl_easy *data,
                    const char *fmt, ...) CURL_PRINTF(2, 3);
void Curl_trc_read(struct Curl_easy *data,
                   const char *fmt, ...) CURL_PRINTF(2, 3);
void Curl_trc_dns(struct Curl_easy *data,
                  const char *fmt, ...) CURL_PRINTF(2, 3);

#ifndef CURL_DISABLE_FTP
extern struct curl_trc_feat Curl_trc_feat_ftp;
void Curl_trc_ftp(struct Curl_easy *data,
                  const char *fmt, ...) CURL_PRINTF(2, 3);
#endif
#ifndef CURL_DISABLE_SMTP
extern struct curl_trc_feat Curl_trc_feat_smtp;
void Curl_trc_smtp(struct Curl_easy *data,
                   const char *fmt, ...) CURL_PRINTF(2, 3);
#endif
#ifdef USE_SSL
extern struct curl_trc_feat Curl_trc_feat_ssls;
void Curl_trc_ssls(struct Curl_easy *data,
                   const char *fmt, ...) CURL_PRINTF(2, 3);
#endif
#if !defined(CURL_DISABLE_WEBSOCKETS) && !defined(CURL_DISABLE_HTTP)
extern struct curl_trc_feat Curl_trc_feat_ws;
void Curl_trc_ws(struct Curl_easy *data,
                 const char *fmt, ...) CURL_PRINTF(2, 3);
#endif

#define CURL_TRC_M_is_verbose(data) \
  Curl_trc_ft_is_verbose(data, &Curl_trc_feat_multi)

#if defined(CURL_HAVE_C99) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
#define infof(data, ...) \
  do { if(Curl_trc_is_verbose(data)) \
         Curl_infof(data, __VA_ARGS__); } while(0)
#define CURL_TRC_M(data, ...) \
  do { if(CURL_TRC_M_is_verbose(data)) \
         Curl_trc_multi(data, __VA_ARGS__); } while(0)
#define CURL_TRC_CF(data, cf, ...) \
  do { if(Curl_trc_cf_is_verbose(cf, data)) \
         Curl_trc_cf_infof(data, cf, __VA_ARGS__); } while(0)
#define CURL_TRC_WRITE(data, ...) \
  do { if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_write)) \
         Curl_trc_write(data, __VA_ARGS__); } while(0)
#define CURL_TRC_READ(data, ...) \
  do { if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_read)) \
         Curl_trc_read(data, __VA_ARGS__); } while(0)
#define CURL_TRC_DNS(data, ...) \
  do { if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_dns)) \
         Curl_trc_dns(data, __VA_ARGS__); } while(0)

#ifndef CURL_DISABLE_FTP
#define CURL_TRC_FTP(data, ...) \
  do { if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_ftp)) \
         Curl_trc_ftp(data, __VA_ARGS__); } while(0)
#endif /* !CURL_DISABLE_FTP */
#ifndef CURL_DISABLE_SMTP
#define CURL_TRC_SMTP(data, ...) \
  do { if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_smtp)) \
         Curl_trc_smtp(data, __VA_ARGS__); } while(0)
#endif /* !CURL_DISABLE_SMTP */
#ifdef USE_SSL
#define CURL_TRC_SSLS(data, ...) \
  do { if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_ssls)) \
         Curl_trc_ssls(data, __VA_ARGS__); } while(0)
#endif /* USE_SSL */
#if !defined(CURL_DISABLE_WEBSOCKETS) && !defined(CURL_DISABLE_HTTP)
#define CURL_TRC_WS(data, ...)                             \
  do { if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_ws)) \
         Curl_trc_ws(data, __VA_ARGS__); } while(0)
#endif /* !CURL_DISABLE_WEBSOCKETS && !CURL_DISABLE_HTTP */

#else /* CURL_HAVE_C99 */

#define infof Curl_infof
#define CURL_TRC_M  Curl_trc_multi
#define CURL_TRC_CF Curl_trc_cf_infof
#define CURL_TRC_WRITE Curl_trc_write
#define CURL_TRC_READ  Curl_trc_read
#define CURL_TRC_DNS   Curl_trc_dns

#ifndef CURL_DISABLE_FTP
#define CURL_TRC_FTP   Curl_trc_ftp
#endif
#ifndef CURL_DISABLE_SMTP
#define CURL_TRC_SMTP  Curl_trc_smtp
#endif
#ifdef USE_SSL
#define CURL_TRC_SSLS  Curl_trc_ssls
#endif
#if !defined(CURL_DISABLE_WEBSOCKETS) && !defined(CURL_DISABLE_HTTP)
#define CURL_TRC_WS    Curl_trc_ws
#endif

#endif /* !CURL_HAVE_C99 */

struct curl_trc_feat {
  const char *name;
  int log_level;
};

#ifndef CURL_DISABLE_VERBOSE_STRINGS
/* informational messages enabled */

extern struct curl_trc_feat Curl_trc_feat_multi;
extern struct curl_trc_feat Curl_trc_feat_read;
extern struct curl_trc_feat Curl_trc_feat_write;
extern struct curl_trc_feat Curl_trc_feat_dns;

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
#define CURL_MSTATE_NAME(s)  Curl_trc_mstate_name((int)(s))
#define CURL_TIMER_NAME(t)   Curl_trc_timer_name((int)(t))
#define CURL_TRC_M_TIMEOUTS(data) \
  do { if(CURL_TRC_M_is_verbose(data)) \
         Curl_trc_multi_timeouts(data); } while(0)

#else /* CURL_DISABLE_VERBOSE_STRINGS */
/* All informational messages are not compiled in for size savings */

#define Curl_trc_is_verbose(d)        (FALSE)
#define Curl_trc_cf_is_verbose(x,y)   (FALSE)
#define Curl_trc_ft_is_verbose(x,y)   (FALSE)
#define CURL_MSTATE_NAME(x)           ((void)(x), "-")
#define CURL_TIMER_NAME(x)            ((void)(x), "-")
#define CURL_TRC_M_TIMEOUTS(x)        Curl_nop_stmt

#endif /* !CURL_DISABLE_VERBOSE_STRINGS */

#endif /* HEADER_CURL_TRC_H */
