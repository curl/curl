#ifndef HEADER_FETCH_CONNECT_H
#define HEADER_FETCH_CONNECT_H
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

#include "nonblock.h" /* for fetchx_nonblock(), formerly Fetch_nonblock() */
#include "sockaddr.h"
#include "timeval.h"

struct Fetch_dns_entry;
struct ip_quadruple;

enum alpnid Fetch_alpn2alpnid(char *name, size_t len);

/* generic function that returns how much time there is left to run, according
   to the timeouts set */
timediff_t Fetch_timeleft(struct Fetch_easy *data,
                         struct fetchtime *nowp,
                         bool duringconnect);

#define DEFAULT_CONNECT_TIMEOUT 300000 /* milliseconds == five minutes */

#define DEFAULT_SHUTDOWN_TIMEOUT_MS (2 * 1000)

void Fetch_shutdown_start(struct Fetch_easy *data, int sockindex,
                         struct fetchtime *nowp);

/* return how much time there is left to shutdown the connection at
 * sockindex. Returns 0 if there is no limit or shutdown has not started. */
timediff_t Fetch_shutdown_timeleft(struct connectdata *conn, int sockindex,
                                  struct fetchtime *nowp);

/* return how much time there is left to shutdown the connection.
 * Returns 0 if there is no limit or shutdown has not started. */
timediff_t Fetch_conn_shutdown_timeleft(struct connectdata *conn,
                                       struct fetchtime *nowp);

void Fetch_shutdown_clear(struct Fetch_easy *data, int sockindex);

/* TRUE iff shutdown has been started */
bool Fetch_shutdown_started(struct Fetch_easy *data, int sockindex);

/*
 * Used to extract socket and connectdata struct for the most recent
 * transfer on the given Fetch_easy.
 *
 * The returned socket will be FETCH_SOCKET_BAD in case of failure!
 */
fetch_socket_t Fetch_getconnectinfo(struct Fetch_easy *data,
                                   struct connectdata **connp);

bool Fetch_addr2string(struct sockaddr *sa, fetch_socklen_t salen,
                      char *addr, int *port);

/*
 * Fetch_conncontrol() marks the end of a connection/stream. The 'closeit'
 * argument specifies if it is the end of a connection or a stream.
 *
 * For stream-based protocols (such as HTTP/2), a stream close will not cause
 * a connection close. Other protocols will close the connection for both
 * cases.
 *
 * It sets the bit.close bit to TRUE (with an explanation for debug builds),
 * when the connection will close.
 */

#define CONNCTRL_KEEP 0 /* undo a marked closure */
#define CONNCTRL_CONNECTION 1
#define CONNCTRL_STREAM 2

void Fetch_conncontrol(struct connectdata *conn,
                      int closeit
#if defined(DEBUGBUILD) && !defined(FETCH_DISABLE_VERBOSE_STRINGS)
                      ,
                      const char *reason
#endif
);

#if defined(DEBUGBUILD) && !defined(FETCH_DISABLE_VERBOSE_STRINGS)
#define streamclose(x, y) Fetch_conncontrol(x, CONNCTRL_STREAM, y)
#define connclose(x, y) Fetch_conncontrol(x, CONNCTRL_CONNECTION, y)
#define connkeep(x, y) Fetch_conncontrol(x, CONNCTRL_KEEP, y)
#else /* if !DEBUGBUILD || FETCH_DISABLE_VERBOSE_STRINGS */
#define streamclose(x, y) Fetch_conncontrol(x, CONNCTRL_STREAM)
#define connclose(x, y) Fetch_conncontrol(x, CONNCTRL_CONNECTION)
#define connkeep(x, y) Fetch_conncontrol(x, CONNCTRL_KEEP)
#endif

/**
 * Create a cfilter for making an "ip" connection to the
 * given address, using parameters from `conn`. The "ip" connection
 * can be a TCP socket, a UDP socket or even a QUIC connection.
 *
 * It MUST use only the supplied `ai` for its connection attempt.
 *
 * Such a filter may be used in "happy eyeball" scenarios, and its
 * `connect` implementation needs to support non-blocking. Once connected,
 * it MAY be installed in the connection filter chain to serve transfers.
 */
typedef FETCHcode cf_ip_connect_create(struct Fetch_cfilter **pcf,
                                       struct Fetch_easy *data,
                                       struct connectdata *conn,
                                       const struct Fetch_addrinfo *ai,
                                       int transport);

FETCHcode Fetch_cf_setup_insert_after(struct Fetch_cfilter *cf_at,
                                     struct Fetch_easy *data,
                                     const struct Fetch_dns_entry *remotehost,
                                     int transport,
                                     int ssl_mode);

/**
 * Setup the cfilters at `sockindex` in connection `conn`.
 * If no filter chain is installed yet, inspects the configuration
 * in `data` and `conn? to install a suitable filter chain.
 */
FETCHcode Fetch_conn_setup(struct Fetch_easy *data,
                          struct connectdata *conn,
                          int sockindex,
                          const struct Fetch_dns_entry *remotehost,
                          int ssl_mode);

extern struct Fetch_cftype Fetch_cft_happy_eyeballs;
extern struct Fetch_cftype Fetch_cft_setup;

#ifdef UNITTESTS
void Fetch_debug_set_transport_provider(int transport,
                                       cf_ip_connect_create *cf_create);
#endif

#endif /* HEADER_FETCH_CONNECT_H */
