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

#ifdef USE_HTTPSRR
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

int Curl_async_ares_global_init(void);
void Curl_async_ares_global_cleanup(void);

timediff_t Curl_ares_timeout_ms(struct Curl_easy *data,
                                struct Curl_resolv_async *async,
                                ares_channel channel);

CURLcode Curl_async_ares_pollset(struct Curl_easy *data,
                                 struct Curl_resolv_async *async,
                                 struct easy_pollset *ps,
                                 timediff_t *ptimeout_ms);

timediff_t Curl_async_ares_poll_timeout(struct Curl_resolv_async *async,
                                        timediff_t timeout_ms);

int Curl_ares_perform(ares_channel channel, timediff_t timeout_ms);

void Curl_async_ares_shutdown(struct Curl_easy *data,
                              struct Curl_resolv_async *async);
void Curl_async_ares_destroy(struct Curl_easy *data,
                             struct Curl_resolv_async *async);

CURLcode Curl_async_ares_query_httpsrr(struct Curl_easy *data,
                                       struct Curl_resolv_async *async);

const char *Curl_async_ares_err_msg(struct Curl_resolv_async *async);

#endif /* USE_ARES */

#ifdef USE_RESOLV_THREADED

struct async_thrdd_item;

void Curl_async_thrdd_shutdown(struct Curl_easy *data,
                               struct Curl_resolv_async *async);
void Curl_async_thrdd_destroy(struct Curl_easy *data,
                              struct Curl_resolv_async *async);
CURLcode Curl_async_thrdd_pollset(struct Curl_easy *data,
                                  struct Curl_resolv_async *async,
                                  struct easy_pollset *ps,
                                  timediff_t *ptimeout_ms);


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

#endif /* !CURLRES_ASYNCH */

#if defined(CURLRES_ASYNCH) || !defined(CURL_DISABLE_DOH)
#define USE_CURL_ASYNC
#endif

#ifdef USE_CURL_ASYNC

struct Curl_resolv_async {
  struct Curl_resolv_async *next;
  struct Curl_addrinfo *res_A; /* answers to A type query */
  struct Curl_addrinfo *res_AAAA; /* answers to AAAA type query */
#ifdef USE_ARES
  struct {
    ares_channel channel;
    int status;
  } ares;
#endif
#ifndef CURL_DISABLE_DOH
  struct doh_probes *doh; /* DoH specific data for this request */
#endif
#ifdef USE_HTTPSRR
  char *httpsrr_name;
  struct Curl_https_rrinfo *httpsrr;
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
  BIT(started);
  BIT(shutdown);
  char hostname[1];
};

timediff_t Curl_async_timeleft_ms(struct Curl_easy *data,
                                  struct Curl_resolv_async *async);

#endif /* USE_CURL_ASYNC */

/********** end of generic resolver interface functions *****************/
#endif /* HEADER_CURL_ASYN_H */
