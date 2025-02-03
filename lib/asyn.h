#ifndef HEADER_FETCH_ASYN_H
#define HEADER_FETCH_ASYN_H
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

#include "fetch_setup.h"
#include "fetch_addrinfo.h"
#include "httpsrr.h"

struct addrinfo;
struct hostent;
struct Fetch_easy;
struct connectdata;
struct Fetch_dns_entry;

#ifdef FETCHRES_THREADED
#include "fetch_threads.h"

/* Data for synchronization between resolver thread and its parent */
struct thread_sync_data
{
  fetch_mutex_t *mtx;
  bool done;
  int port;
  char *hostname; /* hostname to resolve, Fetch_async.hostname
                     duplicate */
#ifndef FETCH_DISABLE_SOCKETPAIR
  struct Fetch_easy *data;
  fetch_socket_t sock_pair[2]; /* eventfd/pipes/socket pair */
#endif
  int sock_error;
  struct Fetch_addrinfo *res;
#ifdef HAVE_GETADDRINFO
  struct addrinfo hints;
#endif
  struct thread_data *td; /* for thread-self cleanup */
};

struct thread_data
{
  fetch_thread_t thread_hnd;
  unsigned int poll_interval;
  timediff_t interval_end;
  struct thread_sync_data tsd;
#if defined(USE_HTTPSRR) && defined(USE_ARES)
  struct Fetch_https_rrinfo hinfo;
  ares_channel channel;
#endif
};

#elif defined(FETCHRES_ARES) /* FETCHRES_THREADED */

struct thread_data
{
  int num_pending;               /* number of outstanding c-ares requests */
  struct Fetch_addrinfo *temp_ai; /* intermediary result while fetching c-ares
                                    parts */
  int last_status;
#ifndef HAVE_CARES_GETADDRINFO
  struct fetchtime happy_eyeballs_dns_time; /* when this timer started, or 0 */
#endif
#ifdef USE_HTTPSRR
  struct Fetch_https_rrinfo hinfo;
#endif
  char hostname[1];
};

#endif /* FETCHRES_ARES */

#ifdef USE_ARES
#include <ares.h>

/* for HTTPS RR purposes as well */
int Fetch_ares_getsock(struct Fetch_easy *data,
                      ares_channel channel,
                      fetch_socket_t *socks);
int Fetch_ares_perform(ares_channel channel,
                      timediff_t timeout_ms);
#endif

/*
 * This header defines all functions in the internal asynch resolver interface.
 * All asynch resolvers need to provide these functions.
 * asyn-ares.c and asyn-thread.c are the current implementations of asynch
 * resolver backends.
 */

/*
 * Fetch_resolver_global_init()
 *
 * Called from fetch_global_init() to initialize global resolver environment.
 * Returning anything else than FETCHE_OK fails fetch_global_init().
 */
int Fetch_resolver_global_init(void);

/*
 * Fetch_resolver_global_cleanup()
 * Called from fetch_global_cleanup() to destroy global resolver environment.
 */
void Fetch_resolver_global_cleanup(void);

/*
 * Fetch_resolver_init()
 * Called from fetch_easy_init() -> Fetch_open() to initialize resolver
 * URL-state specific environment ('resolver' member of the UrlState
 * structure). Should fill the passed pointer by the initialized handler.
 * Returning anything else than FETCHE_OK fails fetch_easy_init() with the
 * correspondent code.
 */
FETCHcode Fetch_resolver_init(struct Fetch_easy *easy, void **resolver);

/*
 * Fetch_resolver_cleanup()
 * Called from fetch_easy_cleanup() -> Fetch_close() to cleanup resolver
 * URL-state specific environment ('resolver' member of the UrlState
 * structure). Should destroy the handler and free all resources connected to
 * it.
 */
void Fetch_resolver_cleanup(void *resolver);

/*
 * Fetch_resolver_duphandle()
 * Called from fetch_easy_duphandle() to duplicate resolver URL-state specific
 * environment ('resolver' member of the UrlState structure). Should
 * duplicate the 'from' handle and pass the resulting handle to the 'to'
 * pointer. Returning anything else than FETCHE_OK causes failed
 * fetch_easy_duphandle() call.
 */
FETCHcode Fetch_resolver_duphandle(struct Fetch_easy *easy, void **to,
                                  void *from);

/*
 * Fetch_resolver_cancel().
 *
 * It is called from inside other functions to cancel currently performing
 * resolver request. Should also free any temporary resources allocated to
 * perform a request. This never waits for resolver threads to complete.
 *
 * It is safe to call this when conn is in any state.
 */
void Fetch_resolver_cancel(struct Fetch_easy *data);

/*
 * Fetch_resolver_kill().
 *
 * This acts like Fetch_resolver_cancel() except it will block until any threads
 * associated with the resolver are complete. This never blocks for resolvers
 * that do not use threads. This is intended to be the "last chance" function
 * that cleans up an in-progress resolver completely (before its owner is about
 * to die).
 *
 * It is safe to call this when conn is in any state.
 */
void Fetch_resolver_kill(struct Fetch_easy *data);

/* Fetch_resolver_getsock()
 *
 * This function is called from the multi_getsock() function.  'sock' is a
 * pointer to an array to hold the file descriptors, with 'numsock' being the
 * size of that array (in number of entries). This function is supposed to
 * return bitmask indicating what file descriptors (referring to array indexes
 * in the 'sock' array) to wait for, read/write.
 */
int Fetch_resolver_getsock(struct Fetch_easy *data, fetch_socket_t *sock);

/*
 * Fetch_resolver_is_resolved()
 *
 * Called repeatedly to check if a previous name resolve request has
 * completed. It should also make sure to time-out if the operation seems to
 * take too long.
 *
 * Returns normal FETCHcode errors.
 */
FETCHcode Fetch_resolver_is_resolved(struct Fetch_easy *data,
                                    struct Fetch_dns_entry **dns);

/*
 * Fetch_resolver_wait_resolv()
 *
 * Waits for a resolve to finish. This function should be avoided since using
 * this risk getting the multi interface to "hang".
 *
 * If 'entry' is non-NULL, make it point to the resolved dns entry
 *
 * Returns FETCHE_COULDNT_RESOLVE_HOST if the host was not resolved,
 * FETCHE_OPERATION_TIMEDOUT if a time-out occurred, or other errors.
 */
FETCHcode Fetch_resolver_wait_resolv(struct Fetch_easy *data,
                                    struct Fetch_dns_entry **dnsentry);

/*
 * Fetch_resolver_getaddrinfo() - when using this resolver
 *
 * Returns name information about the given hostname and port number. If
 * successful, the 'hostent' is returned and the fourth argument will point to
 * memory we need to free after use. That memory *MUST* be freed with
 * Fetch_freeaddrinfo(), nothing else.
 *
 * Each resolver backend must of course make sure to return data in the
 * correct format to comply with this.
 */
struct Fetch_addrinfo *Fetch_resolver_getaddrinfo(struct Fetch_easy *data,
                                                const char *hostname,
                                                int port,
                                                int *waitp);

#ifndef FETCHRES_ASYNCH
/* convert these functions if an asynch resolver is not used */
#define Fetch_resolver_cancel(x) Fetch_nop_stmt
#define Fetch_resolver_kill(x) Fetch_nop_stmt
#define Fetch_resolver_is_resolved(x, y) FETCHE_COULDNT_RESOLVE_HOST
#define Fetch_resolver_wait_resolv(x, y) FETCHE_COULDNT_RESOLVE_HOST
#define Fetch_resolver_duphandle(x, y, z) FETCHE_OK
#define Fetch_resolver_init(x, y) FETCHE_OK
#define Fetch_resolver_global_init() FETCHE_OK
#define Fetch_resolver_global_cleanup() Fetch_nop_stmt
#define Fetch_resolver_cleanup(x) Fetch_nop_stmt
#endif

#ifdef FETCHRES_ASYNCH
#define Fetch_resolver_asynch() 1
#else
#define Fetch_resolver_asynch() 0
#endif

/********** end of generic resolver interface functions *****************/
#endif /* HEADER_FETCH_ASYN_H */
