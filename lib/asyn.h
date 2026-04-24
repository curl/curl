#ifndef HEADER_CURL_ASYN_H
#define HEADER_CURL_ASYN_H
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
#include "curl_setup.h"

#if defined(USE_HTTPSRR) && defined(USE_ARES)
#include "httpsrr.h"
#endif

struct Curl_easy;
struct Curl_dns_entry;
struct Curl_resolv_async;
struct Curl_multi;
struct easy_pollset;

#ifdef CURLRES_ASYNCH

#include "curl_addrinfo.h"

struct hostent;
struct connectdata;
struct easy_pollset;

#if defined(USE_RESOLV_ARES) && defined(USE_RESOLV_THREADED)
#error cannot have both USE_RESOLV_ARES and USE_RESOLV_THREADED defined
#endif

/*
 * This header defines all functions in the internal asynch resolver interface.
 * All asynch resolvers need to provide these functions.
 * asyn-ares.c and asyn-thread.c are the current implementations of asynch
 * resolver backends.
 */

/*
 * Curl_async_global_init()
 *
 * Called from curl_global_init() to initialize global resolver environment.
 * Returning anything else than CURLE_OK fails curl_global_init().
 */
int Curl_async_global_init(void);

/*
 * Curl_async_global_cleanup()
 * Called from curl_global_cleanup() to destroy global resolver environment.
 */
void Curl_async_global_cleanup(void);

/*
 * Curl_async_getaddrinfo() - when using this resolver
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'hostent' is returned and the fourth argument will point to
 * memory we need to free after use. That memory *MUST* be freed with
 * Curl_freeaddrinfo(), nothing else.
 *
 * Each resolver backend must of course make sure to return data in the
 * correct format to comply with this.
 */
CURLcode Curl_async_getaddrinfo(struct Curl_easy *data,
                                struct Curl_resolv_async *async);

const struct Curl_addrinfo *Curl_async_get_ai(struct Curl_easy *data,
                                              struct Curl_resolv_async *async,
                                              int ai_family,
                                              unsigned int index);

#ifdef USE_HTTPSRR
const struct Curl_https_rrinfo *Curl_async_get_https(
  struct Curl_easy *data,
  struct Curl_resolv_async *async);
bool Curl_async_knows_https(struct Curl_easy *data,
                            struct Curl_resolv_async *async);
#endif /* USE_HTTPSRR */

#ifdef USE_ARES
/* common functions for c-ares and threaded resolver with HTTPSRR */
#include <ares.h>

CURLcode Curl_ares_pollset(struct Curl_easy *data,
                           ares_channel channel,
                           struct easy_pollset *ps);

timediff_t Curl_ares_timeout_ms(struct Curl_easy *data,
                                struct Curl_resolv_async *async,
                                ares_channel channel);

int Curl_ares_perform(ares_channel channel, timediff_t timeout_ms);
#endif

#ifdef USE_RESOLV_ARES
/* async resolving implementation using c-ares alone */
struct async_ares_ctx {
  ares_channel channel;
  struct Curl_addrinfo *res_A;
  struct Curl_addrinfo *res_AAAA;
  int ares_status;               /* ARES_SUCCESS, ARES_ENOTFOUND, etc. */
  CURLcode result;               /* CURLE_OK or error handling response */
  struct curltime happy_eyeballs_dns_time; /* when this timer started, or 0 */
#ifdef USE_HTTPSRR
  struct Curl_https_rrinfo hinfo;
#endif
};

void Curl_async_ares_shutdown(struct Curl_easy *data,
                              struct Curl_resolv_async *async);
void Curl_async_ares_destroy(struct Curl_easy *data,
                             struct Curl_resolv_async *async);

#endif /* USE_RESOLV_ARES */

#ifdef USE_RESOLV_THREADED

struct async_thrdd_item;

/* Context for threaded resolver */
struct async_thrdd_ctx {
  struct async_thrdd_item *res_A; /* ipv4 result */
  struct async_thrdd_item *res_AAAA; /* ipv6 result */
#if defined(USE_HTTPSRR) && defined(USE_ARES)
  struct {
    ares_channel channel;
    struct Curl_https_rrinfo hinfo;
  } rr;
#endif
};

void Curl_async_thrdd_shutdown(struct Curl_easy *data,
                               struct Curl_resolv_async *async);
void Curl_async_thrdd_destroy(struct Curl_easy *data,
                              struct Curl_resolv_async *async);

CURLcode Curl_async_thrdd_multi_init(struct Curl_multi *multi,
                                     uint32_t min_threads,
                                     uint32_t max_threads,
                                     uint32_t idle_time_ms);
void Curl_async_thrdd_multi_destroy(struct Curl_multi *multi, bool join);
void Curl_async_thrdd_multi_process(struct Curl_multi *multi);

CURLcode Curl_async_thrdd_multi_set_props(struct Curl_multi *multi,
                                          uint32_t min_threads,
                                          uint32_t max_threads,
                                          uint32_t idle_time_ms);

#endif /* USE_RESOLV_THREADED */

#ifndef CURL_DISABLE_DOH
struct doh_probes;
#endif

/*
 * Curl_async_await()
 *
 * Waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 *
 * On return 'dns' is assigned the resolved dns (CURLE_OK or NULL otherwise.
 *
 * Returns CURLE_COULDNT_RESOLVE_HOST if the host was not resolved,
 * CURLE_OPERATION_TIMEDOUT if a time-out occurred, or other errors.
 */
CURLcode Curl_async_await(struct Curl_easy *data, uint32_t resolv_id,
                          struct Curl_dns_entry **pdns);

/*
 * Take the result of an async resolve operation.
 * Returns CURLE_OK with `*pdns` != NULL, CURLE_AGAIN while still
 * ongoing or an error code for a failed resolve.
 */
CURLcode Curl_async_take_result(struct Curl_easy *data,
                                struct Curl_resolv_async *async,
                                struct Curl_dns_entry **pdns);

/* Curl_async_pollset()
 *
 * This function is called from the Curl_multi_pollset() function.  'sock' is a
 * pointer to an array to hold the file descriptors, with 'numsock' being the
 * size of that array (in number of entries). This function is supposed to
 * return bitmask indicating what file descriptors (referring to array indexes
 * in the 'sock' array) to wait for, read/write.
 */
CURLcode Curl_async_pollset(struct Curl_easy *data,
                            struct Curl_resolv_async *async,
                            struct easy_pollset *ps);

#else /* CURLRES_ASYNCH */

/* convert these functions if an asynch resolver is not used */
#define Curl_async_global_init()        CURLE_OK
#define Curl_async_global_cleanup()     Curl_nop_stmt
#define Curl_async_get_ai(a, b, c, d)   NULL
#define Curl_async_await(a, b, c)       CURLE_COULDNT_RESOLVE_HOST
#define Curl_async_take_result(x, y, z) CURLE_COULDNT_RESOLVE_HOST
#define Curl_async_pollset(x, y, z)     CURLE_OK
#define Curl_async_get_https(x, y)      NULL
#define Curl_async_knows_https(x, y)    TRUE
#endif /* !CURLRES_ASYNCH */

#if defined(CURLRES_ASYNCH) || !defined(CURL_DISABLE_DOH)
#define USE_CURL_ASYNC
#endif

#ifdef USE_CURL_ASYNC

struct Curl_resolv_async {
  struct Curl_resolv_async *next;
#ifdef USE_RESOLV_ARES
  struct async_ares_ctx ares;
#elif defined(USE_RESOLV_THREADED)
  struct async_thrdd_ctx thrdd;
#endif
#ifndef CURL_DISABLE_DOH
  struct doh_probes *doh; /* DoH specific data for this request */
#endif
  struct curltime start;
  timediff_t interval_end;
  timediff_t timeout_ms;
  CURLcode result;
  uint32_t poll_interval;
  uint32_t id; /* unique id per easy handle of the resolve operation */
  /* what is being resolved */
  uint16_t port;
  uint8_t dns_queries; /* what queries are being performed */
  uint8_t dns_responses; /* what queries had responses so far. */
  uint8_t transport;
  uint8_t queries_ongoing;
  BIT(is_ipaddr);
  BIT(is_ipv4addr);
  BIT(for_proxy);
  BIT(done);
  BIT(shutdown);
  char hostname[1];
};

timediff_t Curl_async_timeleft_ms(struct Curl_easy *data,
                                  struct Curl_resolv_async *async);

/* Shut down the given async resolve. */
void Curl_async_shutdown(struct Curl_easy *data,
                         struct Curl_resolv_async *async);

/* Frees the resources of the given async resolve and the struct itself. */
void Curl_async_destroy(struct Curl_easy *data,
                        struct Curl_resolv_async *async);

CURLcode Curl_async_failed(struct Curl_easy *data,
                           struct Curl_resolv_async *async,
                           const char *detail);

#else /* !USE_CURL_ASYNC */
#define Curl_async_shutdown(x, y) Curl_nop_stmt
#endif /* USE_CURL_ASYNC */

/********** end of generic resolver interface functions *****************/
#endif /* HEADER_CURL_ASYN_H */
