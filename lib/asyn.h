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

#ifdef CURLRES_ASYNCH

#include "curl_addrinfo.h"

struct hostent;
struct connectdata;
struct easy_pollset;

#if defined(CURLRES_ARES) && defined(CURLRES_THREADED)
#error cannot have both CURLRES_ARES and CURLRES_THREADED defined
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
 * Curl_async_get_impl()
 * Get the resolver implementation instance (c-ares channel) or NULL
 * for passing to application callback.
 */
CURLcode Curl_async_get_impl(struct Curl_easy *easy,
                             struct Curl_resolv_async *async,
                             void **impl);

/* Curl_async_pollset()
 *
 * This function is called from the Curl_multi_pollset() function.  'sock' is a
 * pointer to an array to hold the file descriptors, with 'numsock' being the
 * size of that array (in number of entries). This function is supposed to
 * return bitmask indicating what file descriptors (referring to array indexes
 * in the 'sock' array) to wait for, read/write.
 */
CURLcode Curl_async_pollset(struct Curl_easy *data, struct easy_pollset *ps);

/*
 * Take the result of an async resolve operation.
 * Returns CURLE_OK with `*pdns` != NULL, CURLE_AGAIN while still
 * ongoing or an error code for a failed resolve.
 */
CURLcode Curl_async_take_result(struct Curl_easy *data,
                                struct Curl_resolv_async *async,
                                struct Curl_dns_entry **pdns);

/*
 * Curl_async_await()
 *
 * Waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 *
 * On return 'entry' is assigned the resolved dns (CURLE_OK or NULL otherwise.
 *
 * Returns CURLE_COULDNT_RESOLVE_HOST if the host was not resolved,
 * CURLE_OPERATION_TIMEDOUT if a time-out occurred, or other errors.
 */
CURLcode Curl_async_await(struct Curl_easy *data,
                          struct Curl_resolv_async *async,
                          struct Curl_dns_entry **pdns);

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

#ifdef USE_ARES
/* common functions for c-ares and threaded resolver with HTTPSRR */
#include <ares.h>

CURLcode Curl_ares_pollset(struct Curl_easy *data,
                           ares_channel channel,
                           struct easy_pollset *ps);

int Curl_ares_perform(ares_channel channel, timediff_t timeout_ms);
#endif

#ifdef CURLRES_ARES
/* async resolving implementation using c-ares alone */
struct async_ares_ctx {
  ares_channel channel;
  int num_pending;               /* number of outstanding c-ares requests */
  struct Curl_addrinfo *temp_ai; /* intermediary result while fetching c-ares
                                    parts */
  int ares_status;               /* ARES_SUCCESS, ARES_ENOTFOUND, etc. */
  CURLcode result;               /* CURLE_OK or error handling response */
#ifndef HAVE_CARES_GETADDRINFO
  struct curltime happy_eyeballs_dns_time; /* when this timer started, or 0 */
#endif
#ifdef USE_HTTPSRR
  struct Curl_https_rrinfo hinfo;
#endif
};

void Curl_async_ares_shutdown(struct Curl_easy *data,
                             struct Curl_resolv_async *async);
void Curl_async_ares_destroy(struct Curl_easy *data,
                             struct Curl_resolv_async *async);

/* Set the DNS server to use by ares, from `data` settings. */
CURLcode Curl_async_ares_set_dns_servers(struct Curl_easy *data);

/* Set the DNS interfacer to use by ares, from `data` settings. */
CURLcode Curl_async_ares_set_dns_interface(struct Curl_easy *data);

/* Set the local ipv4 address to use by ares, from `data` settings. */
CURLcode Curl_async_ares_set_dns_local_ip4(struct Curl_easy *data);

/* Set the local ipv6 address to use by ares, from `data` settings. */
CURLcode Curl_async_ares_set_dns_local_ip6(struct Curl_easy *data);

#endif /* CURLRES_ARES */

#ifdef CURLRES_THREADED

struct async_thrdd_item;

/* Context for threaded resolver */
struct async_thrdd_ctx {
  struct async_thrdd_item *resolved;
#if defined(USE_HTTPSRR) && defined(USE_ARES)
  struct {
    ares_channel channel;
    struct Curl_https_rrinfo hinfo;
    CURLcode result;
    BIT(done);
  } rr;
#endif
  BIT(queued);
  BIT(done);
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

#endif /* CURLRES_THREADED */

#ifndef CURL_DISABLE_DOH
struct doh_probes;
#endif

#else /* CURLRES_ASYNCH */

/* convert these functions if an asynch resolver is not used */
#define Curl_async_get_impl(x, y, z)    (*(z) = NULL, CURLE_OK)
#define Curl_async_take_result(x, y, z) CURLE_COULDNT_RESOLVE_HOST
#define Curl_async_await(x, y, z)       CURLE_COULDNT_RESOLVE_HOST
#define Curl_async_global_init()        CURLE_OK
#define Curl_async_global_cleanup()     Curl_nop_stmt

#endif /* !CURLRES_ASYNCH */

#if defined(CURLRES_ASYNCH) || !defined(CURL_DISABLE_DOH)
#define USE_CURL_ASYNC
#endif

#ifdef USE_CURL_ASYNC
struct Curl_resolv_async {
#ifdef CURLRES_ARES
  struct async_ares_ctx ares;
#elif defined(CURLRES_THREADED)
  struct async_thrdd_ctx thrdd;
#endif
#ifndef CURL_DISABLE_DOH
  struct doh_probes *doh; /* DoH specific data for this request */
#endif
  struct curltime start;
  timediff_t interval_end;
  timediff_t timeout_ms;
  uint32_t poll_interval;
   /* what is being resolved */
  uint16_t port;
  uint8_t ip_version;
  uint8_t transport;
  char hostname[1];
};

/*
 * Curl_async_shutdown().
 *
 * This shuts down all ongoing operations.
 */
void Curl_async_shutdown(struct Curl_easy *data);

/*
 * Curl_async_destroy().
 *
 * This frees the resources of any async resolve.
 */
void Curl_async_destroy(struct Curl_easy *data);
#else /* !USE_CURL_ASYNC */
#define Curl_async_shutdown(x) Curl_nop_stmt
#define Curl_async_destroy(x)  Curl_nop_stmt
#endif /* USE_CURL_ASYNC */

/********** end of generic resolver interface functions *****************/
#endif /* HEADER_CURL_ASYN_H */
