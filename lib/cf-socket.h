#ifndef HEADER_FETCH_CF_SOCKET_H
#define HEADER_FETCH_CF_SOCKET_H
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

struct Fetch_addrinfo;
struct Fetch_cfilter;
struct Fetch_easy;
struct connectdata;
struct Fetch_sockaddr_ex;
struct ip_quadruple;

/*
 * The Fetch_sockaddr_ex structure is basically libfetch's external API
 * fetch_sockaddr structure with enough space available to directly hold any
 * protocol-specific address structures. The variable declared here will be
 * used to pass / receive data to/from the fopensocket callback if this has
 * been set, before that, it is initialized from parameters.
 */
struct Fetch_sockaddr_ex
{
  int family;
  int socktype;
  int protocol;
  unsigned int addrlen;
  union
  {
    struct sockaddr addr;
    struct Fetch_sockaddr_storage buff;
  } _sa_ex_u;
};
#define fetch_sa_addr _sa_ex_u.addr

/*
 * Parse interface option, and return the interface name and the host part.
 */
FETCHcode Fetch_parse_interface(const char *input,
                               char **dev, char **iface, char **host);

/*
 * Create a socket based on info from 'conn' and 'ai'.
 *
 * Fill in 'addr' and 'sockfd' accordingly if OK is returned. If the open
 * socket callback is set, used that!
 *
 */
FETCHcode Fetch_socket_open(struct Fetch_easy *data,
                           const struct Fetch_addrinfo *ai,
                           struct Fetch_sockaddr_ex *addr,
                           int transport,
                           fetch_socket_t *sockfd);

int Fetch_socket_close(struct Fetch_easy *data, struct connectdata *conn,
                      fetch_socket_t sock);

#ifdef USE_WINSOCK
/* When you run a program that uses the Windows Sockets API, you may
   experience slow performance when you copy data to a TCP server.

   https://support.microsoft.com/kb/823764

   Work-around: Make the Socket Send Buffer Size Larger Than the Program Send
   Buffer Size

*/
void Fetch_sndbuf_init(fetch_socket_t sockfd);
#else
#define Fetch_sndbuf_init(y) Fetch_nop_stmt
#endif

/**
 * Assign the address `ai` to the Fetch_sockaddr_ex `dest` and
 * set the transport used.
 */
FETCHcode Fetch_sock_assign_addr(struct Fetch_sockaddr_ex *dest,
                                const struct Fetch_addrinfo *ai,
                                int transport);

/**
 * Creates a cfilter that opens a TCP socket to the given address
 * when calling its `connect` implementation.
 * The filter will not touch any connection/data flags and can be
 * used in happy eyeballing. Once selected for use, its `_active()`
 * method needs to be called.
 */
FETCHcode Fetch_cf_tcp_create(struct Fetch_cfilter **pcf,
                             struct Fetch_easy *data,
                             struct connectdata *conn,
                             const struct Fetch_addrinfo *ai,
                             int transport);

/**
 * Creates a cfilter that opens a UDP socket to the given address
 * when calling its `connect` implementation.
 * The filter will not touch any connection/data flags and can be
 * used in happy eyeballing. Once selected for use, its `_active()`
 * method needs to be called.
 */
FETCHcode Fetch_cf_udp_create(struct Fetch_cfilter **pcf,
                             struct Fetch_easy *data,
                             struct connectdata *conn,
                             const struct Fetch_addrinfo *ai,
                             int transport);

/**
 * Creates a cfilter that opens a UNIX socket to the given address
 * when calling its `connect` implementation.
 * The filter will not touch any connection/data flags and can be
 * used in happy eyeballing. Once selected for use, its `_active()`
 * method needs to be called.
 */
FETCHcode Fetch_cf_unix_create(struct Fetch_cfilter **pcf,
                              struct Fetch_easy *data,
                              struct connectdata *conn,
                              const struct Fetch_addrinfo *ai,
                              int transport);

/**
 * Creates a cfilter that keeps a listening socket.
 */
FETCHcode Fetch_conn_tcp_listen_set(struct Fetch_easy *data,
                                   struct connectdata *conn,
                                   int sockindex,
                                   fetch_socket_t *s);

/**
 * Return TRUE iff the last filter at `sockindex` was set via
 * Fetch_conn_tcp_listen_set().
 */
bool Fetch_conn_is_tcp_listen(struct Fetch_easy *data,
                             int sockindex);

/**
 * Peek at the socket and remote ip/port the socket filter is using.
 * The filter owns all returned values.
 * @param psock             pointer to hold socket descriptor or NULL
 * @param paddr             pointer to hold addr reference or NULL
 * @param pip               pointer to get IP quadruple or NULL
 * Returns error if the filter is of invalid type.
 */
FETCHcode Fetch_cf_socket_peek(struct Fetch_cfilter *cf,
                              struct Fetch_easy *data,
                              fetch_socket_t *psock,
                              const struct Fetch_sockaddr_ex **paddr,
                              struct ip_quadruple *pip);

extern struct Fetch_cftype Fetch_cft_tcp;
extern struct Fetch_cftype Fetch_cft_udp;
extern struct Fetch_cftype Fetch_cft_unix;
extern struct Fetch_cftype Fetch_cft_tcp_accept;

#endif /* HEADER_FETCH_CF_SOCKET_H */
