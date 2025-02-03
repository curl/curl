#ifndef HEADER_FETCH_TRC_H
#define HEADER_FETCH_TRC_H
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
 * are also available at https://fetch.se/docs/copyright.html.
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

struct Fetch_easy;
struct Fetch_cfilter;

/**
 * Init logging, return != 0 on failure.
 */
FETCHcode Fetch_trc_init(void);

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
FETCHcode Fetch_trc_opt(const char *config);

/* the function used to output verbose information */
void Fetch_debug(struct Fetch_easy *data, fetch_infotype type,
                char *ptr, size_t size);

/**
 * Output a failure message on registered callbacks for transfer.
 */
void Fetch_failf(struct Fetch_easy *data,
                const char *fmt, ...) FETCH_PRINTF(2, 3);

#define failf Fetch_failf

#define FETCH_LOG_LVL_NONE 0
#define FETCH_LOG_LVL_INFO 1

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define FETCH_HAVE_C99
#endif

/**
 * Output an informational message when transfer's verbose logging is enabled.
 */
void Fetch_infof(struct Fetch_easy *data,
                const char *fmt, ...) FETCH_PRINTF(2, 3);

/**
 * Output an informational message when both transfer's verbose logging
 * and connection filters verbose logging are enabled.
 */
void Fetch_trc_cf_infof(struct Fetch_easy *data, struct Fetch_cfilter *cf,
                       const char *fmt, ...) FETCH_PRINTF(3, 4);
void Fetch_trc_write(struct Fetch_easy *data,
                    const char *fmt, ...) FETCH_PRINTF(2, 3);
void Fetch_trc_read(struct Fetch_easy *data,
                   const char *fmt, ...) FETCH_PRINTF(2, 3);

#ifndef FETCH_DISABLE_FTP
extern struct fetch_trc_feat Fetch_trc_feat_ftp;
void Fetch_trc_ftp(struct Fetch_easy *data,
                  const char *fmt, ...) FETCH_PRINTF(2, 3);
#endif
#ifndef FETCH_DISABLE_SMTP
extern struct fetch_trc_feat Fetch_trc_feat_smtp;
void Fetch_trc_smtp(struct Fetch_easy *data,
                   const char *fmt, ...) FETCH_PRINTF(2, 3);
#endif
#ifdef USE_SSL
extern struct fetch_trc_feat Fetch_trc_feat_ssls;
void Fetch_trc_ssls(struct Fetch_easy *data,
                   const char *fmt, ...) FETCH_PRINTF(2, 3);
#endif
#if !defined(FETCH_DISABLE_WEBSOCKETS) && !defined(FETCH_DISABLE_HTTP)
extern struct fetch_trc_feat Fetch_trc_feat_ws;
void Fetch_trc_ws(struct Fetch_easy *data,
                 const char *fmt, ...) FETCH_PRINTF(2, 3);
#endif

#if defined(FETCH_HAVE_C99) && !defined(FETCH_DISABLE_VERBOSE_STRINGS)
#define infof(data, ...)             \
  do                                 \
  {                                  \
    if (Fetch_trc_is_verbose(data))   \
      Fetch_infof(data, __VA_ARGS__); \
  } while (0)
#define FETCH_TRC_CF(data, cf, ...)             \
  do                                            \
  {                                             \
    if (Fetch_trc_cf_is_verbose(cf, data))       \
      Fetch_trc_cf_infof(data, cf, __VA_ARGS__); \
  } while (0)
#define FETCH_TRC_WRITE(data, ...)                          \
  do                                                        \
  {                                                         \
    if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_write)) \
      Fetch_trc_write(data, __VA_ARGS__);                    \
  } while (0)
#define FETCH_TRC_READ(data, ...)                          \
  do                                                       \
  {                                                        \
    if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_read)) \
      Fetch_trc_read(data, __VA_ARGS__);                    \
  } while (0)

#ifndef FETCH_DISABLE_FTP
#define FETCH_TRC_FTP(data, ...)                          \
  do                                                      \
  {                                                       \
    if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_ftp)) \
      Fetch_trc_ftp(data, __VA_ARGS__);                    \
  } while (0)
#endif /* !FETCH_DISABLE_FTP */
#ifndef FETCH_DISABLE_SMTP
#define FETCH_TRC_SMTP(data, ...)                          \
  do                                                       \
  {                                                        \
    if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_smtp)) \
      Fetch_trc_smtp(data, __VA_ARGS__);                    \
  } while (0)
#endif /* !FETCH_DISABLE_SMTP */
#ifdef USE_SSL
#define FETCH_TRC_SSLS(data, ...)                          \
  do                                                       \
  {                                                        \
    if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_ssls)) \
      Fetch_trc_ssls(data, __VA_ARGS__);                    \
  } while (0)
#endif /* USE_SSL */
#if !defined(FETCH_DISABLE_WEBSOCKETS) && !defined(FETCH_DISABLE_HTTP)
#define FETCH_TRC_WS(data, ...)                          \
  do                                                     \
  {                                                      \
    if (Fetch_trc_ft_is_verbose(data, &Fetch_trc_feat_ws)) \
      Fetch_trc_ws(data, __VA_ARGS__);                    \
  } while (0)
#endif /* !FETCH_DISABLE_WEBSOCKETS && !FETCH_DISABLE_HTTP */

#else /* FETCH_HAVE_C99 */

#define infof Fetch_infof
#define FETCH_TRC_CF Fetch_trc_cf_infof
#define FETCH_TRC_WRITE Fetch_trc_write
#define FETCH_TRC_READ Fetch_trc_read

#ifndef FETCH_DISABLE_FTP
#define FETCH_TRC_FTP Fetch_trc_ftp
#endif
#ifndef FETCH_DISABLE_SMTP
#define FETCH_TRC_SMTP Fetch_trc_smtp
#endif
#ifdef USE_SSL
#define FETCH_TRC_SSLS Fetch_trc_ssls
#endif
#if !defined(FETCH_DISABLE_WEBSOCKETS) && !defined(FETCH_DISABLE_HTTP)
#define FETCH_TRC_WS Fetch_trc_ws
#endif

#endif /* !FETCH_HAVE_C99 */

#ifndef FETCH_DISABLE_VERBOSE_STRINGS
/* informational messages enabled */

struct fetch_trc_feat
{
  const char *name;
  int log_level;
};
extern struct fetch_trc_feat Fetch_trc_feat_read;
extern struct fetch_trc_feat Fetch_trc_feat_write;

#define Fetch_trc_is_verbose(data)   \
  ((data) && (data)->set.verbose && \
   (!(data)->state.feat ||          \
    ((data)->state.feat->log_level >= FETCH_LOG_LVL_INFO)))
#define Fetch_trc_cf_is_verbose(cf, data) \
  (Fetch_trc_is_verbose(data) &&          \
   (cf) && (cf)->cft->log_level >= FETCH_LOG_LVL_INFO)
#define Fetch_trc_ft_is_verbose(data, ft) \
  (Fetch_trc_is_verbose(data) &&          \
   (ft)->log_level >= FETCH_LOG_LVL_INFO)

#else /* defined(FETCH_DISABLE_VERBOSE_STRINGS) */
/* All informational messages are not compiled in for size savings */

#define Fetch_trc_is_verbose(d) (FALSE)
#define Fetch_trc_cf_is_verbose(x, y) (FALSE)
#define Fetch_trc_ft_is_verbose(x, y) (FALSE)

#endif /* !defined(FETCH_DISABLE_VERBOSE_STRINGS) */

#endif /* HEADER_FETCH_TRC_H */
