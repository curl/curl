#ifndef HEADER_FETCH_CFILTERS_H
#define HEADER_FETCH_CFILTERS_H
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

#include "timediff.h"

struct Fetch_cfilter;
struct Fetch_easy;
struct Fetch_dns_entry;
struct connectdata;
struct ip_quadruple;

/* Callback to destroy resources held by this filter instance.
 * Implementations MUST NOT chain calls to cf->next.
 */
typedef void Fetch_cft_destroy_this(struct Fetch_cfilter *cf,
                                   struct Fetch_easy *data);

/* Callback to close the connection immediately. */
typedef void Fetch_cft_close(struct Fetch_cfilter *cf,
                            struct Fetch_easy *data);

/* Callback to close the connection filter gracefully, non-blocking.
 * Implementations MUST NOT chain calls to cf->next.
 */
typedef FETCHcode Fetch_cft_shutdown(struct Fetch_cfilter *cf,
                                    struct Fetch_easy *data,
                                    bool *done);

typedef FETCHcode Fetch_cft_connect(struct Fetch_cfilter *cf,
                                   struct Fetch_easy *data,
                                   bool blocking, bool *done);

/* Return the hostname and port the connection goes to.
 * This may change with the connection state of filters when tunneling
 * is involved.
 * @param cf     the filter to ask
 * @param data   the easy handle currently active
 * @param phost  on return, points to the relevant, real hostname.
 *               this is owned by the connection.
 * @param pdisplay_host  on return, points to the printable hostname.
 *               this is owned by the connection.
 * @param pport  on return, contains the port number
 */
typedef void Fetch_cft_get_host(struct Fetch_cfilter *cf,
                               struct Fetch_easy *data,
                               const char **phost,
                               const char **pdisplay_host,
                               int *pport);

struct easy_pollset;

/* Passing in an easy_pollset for monitoring of sockets, let
 * filters add or remove sockets actions (FETCH_POLL_OUT, FETCH_POLL_IN).
 * This may add a socket or, in case no actions remain, remove
 * a socket from the set.
 *
 * Filter implementations need to call filters "below" *after* they have
 * made their adjustments. This allows lower filters to override "upper"
 * actions. If a "lower" filter is unable to write, it needs to be able
 * to disallow POLL_OUT.
 *
 * A filter without own restrictions/preferences should not modify
 * the pollset. Filters, whose filter "below" is not connected, should
 * also do no adjustments.
 *
 * Examples: a TLS handshake, while ongoing, might remove POLL_IN when it
 * needs to write, or vice versa. An HTTP/2 filter might remove POLL_OUT when
 * a stream window is exhausted and a WINDOW_UPDATE needs to be received first
 * and add instead POLL_IN.
 *
 * @param cf     the filter to ask
 * @param data   the easy handle the pollset is about
 * @param ps     the pollset (inout) for the easy handle
 */
typedef void Fetch_cft_adjust_pollset(struct Fetch_cfilter *cf,
                                     struct Fetch_easy *data,
                                     struct easy_pollset *ps);

typedef bool Fetch_cft_data_pending(struct Fetch_cfilter *cf,
                                   const struct Fetch_easy *data);

typedef ssize_t Fetch_cft_send(struct Fetch_cfilter *cf,
                              struct Fetch_easy *data, /* transfer */
                              const void *buf,        /* data to write */
                              size_t len,             /* amount to write */
                              bool eos,               /* last chunk */
                              FETCHcode *err);        /* error to return */

typedef ssize_t Fetch_cft_recv(struct Fetch_cfilter *cf,
                              struct Fetch_easy *data, /* transfer */
                              char *buf,              /* store data here */
                              size_t len,             /* amount to read */
                              FETCHcode *err);        /* error to return */

typedef bool Fetch_cft_conn_is_alive(struct Fetch_cfilter *cf,
                                    struct Fetch_easy *data,
                                    bool *input_pending);

typedef FETCHcode Fetch_cft_conn_keep_alive(struct Fetch_cfilter *cf,
                                           struct Fetch_easy *data);

/**
 * Events/controls for connection filters, their arguments and
 * return code handling. Filter callbacks are invoked "top down".
 * Return code handling:
 * "first fail" meaning that the first filter returning != FETCHE_OK, will
 *              abort further event distribution and determine the result.
 * "ignored" meaning return values are ignored and the event is distributed
 *           to all filters in the chain. Overall result is always FETCHE_OK.
 */
/*      data event                          arg1       arg2     return */
#define CF_CTRL_DATA_SETUP 4     /* 0          NULL     first fail */
#define CF_CTRL_DATA_IDLE 5      /* 0          NULL     first fail */
#define CF_CTRL_DATA_PAUSE 6     /* on/off     NULL     first fail */
#define CF_CTRL_DATA_DONE 7      /* premature  NULL     ignored */
#define CF_CTRL_DATA_DONE_SEND 8 /* 0          NULL     ignored */
/* update conn info at connection and data */
#define CF_CTRL_CONN_INFO_UPDATE (256 + 0) /* 0          NULL     ignored */
#define CF_CTRL_FORGET_SOCKET (256 + 1)    /* 0          NULL     ignored */
#define CF_CTRL_FLUSH (256 + 2)            /* 0          NULL     first fail */

/**
 * Handle event/control for the filter.
 * Implementations MUST NOT chain calls to cf->next.
 */
typedef FETCHcode Fetch_cft_cntrl(struct Fetch_cfilter *cf,
                                 struct Fetch_easy *data,
                                 int event, int arg1, void *arg2);

/**
 * Queries to ask via a `Fetch_cft_query *query` method on a cfilter chain.
 * - MAX_CONCURRENT: the maximum number of parallel transfers the filter
 *                   chain expects to handle at the same time.
 *                   default: 1 if no filter overrides.
 * - CONNECT_REPLY_MS: milliseconds until the first indication of a server
 *                   response was received on a connect. For TCP, this
 *                   reflects the time until the socket connected. On UDP
 *                   this gives the time the first bytes from the server
 *                   were received.
 *                   -1 if not determined yet.
 * - CF_QUERY_SOCKET: the socket used by the filter chain
 * - CF_QUERY_NEED_FLUSH: TRUE iff any of the filters have unsent data
 * - CF_QUERY_IP_INFO: res1 says if connection used IPv6, res2 is the
 *                   ip quadruple
 */
/*      query                             res1       res2     */
#define CF_QUERY_MAX_CONCURRENT 1   /* number     -        */
#define CF_QUERY_CONNECT_REPLY_MS 2 /* number     -        */
#define CF_QUERY_SOCKET 3           /* -          fetch_socket_t */
#define CF_QUERY_TIMER_CONNECT 4    /* -          struct fetchtime */
#define CF_QUERY_TIMER_APPCONNECT 5 /* -          struct fetchtime */
#define CF_QUERY_STREAM_ERROR 6     /* error code - */
#define CF_QUERY_NEED_FLUSH 7       /* TRUE/FALSE - */
#define CF_QUERY_IP_INFO 8          /* TRUE/FALSE struct ip_quadruple */
#define CF_QUERY_HTTP_VERSION 9     /* number (10/11/20/30)   -  */

/**
 * Query the cfilter for properties. Filters ignorant of a query will
 * pass it "down" the filter chain.
 */
typedef FETCHcode Fetch_cft_query(struct Fetch_cfilter *cf,
                                 struct Fetch_easy *data,
                                 int query, int *pres1, void *pres2);

/**
 * Type flags for connection filters. A filter can have none, one or
 * many of those. Use to evaluate state/capabilities of a filter chain.
 *
 * CF_TYPE_IP_CONNECT: provides an IP connection or sth equivalent, like
 *                     a CONNECT tunnel, a UNIX domain socket, a QUIC
 *                     connection, etc.
 * CF_TYPE_SSL:        provide SSL/TLS
 * CF_TYPE_MULTIPLEX:  provides multiplexing of easy handles
 * CF_TYPE_PROXY       provides proxying
 * CF_TYPE_HTTP        implement a version of the HTTP protocol
 */
#define CF_TYPE_IP_CONNECT (1 << 0)
#define CF_TYPE_SSL (1 << 1)
#define CF_TYPE_MULTIPLEX (1 << 2)
#define CF_TYPE_PROXY (1 << 3)
#define CF_TYPE_HTTP (1 << 4)

/* A connection filter type, e.g. specific implementation. */
struct Fetch_cftype
{
  const char *name;                        /* name of the filter type */
  int flags;                               /* flags of filter type */
  int log_level;                           /* log level for such filters */
  Fetch_cft_destroy_this *destroy;          /* destroy resources of this cf */
  Fetch_cft_connect *do_connect;            /* establish connection */
  Fetch_cft_close *do_close;                /* close conn */
  Fetch_cft_shutdown *do_shutdown;          /* shutdown conn */
  Fetch_cft_get_host *get_host;             /* host filter talks to */
  Fetch_cft_adjust_pollset *adjust_pollset; /* adjust transfer poll set */
  Fetch_cft_data_pending *has_data_pending; /* conn has data pending */
  Fetch_cft_send *do_send;                  /* send data */
  Fetch_cft_recv *do_recv;                  /* receive data */
  Fetch_cft_cntrl *cntrl;                   /* events/control */
  Fetch_cft_conn_is_alive *is_alive;        /* FALSE if conn is dead, Jim! */
  Fetch_cft_conn_keep_alive *keep_alive;    /* try to keep it alive */
  Fetch_cft_query *query;                   /* query filter chain */
};

/* A connection filter instance, e.g. registered at a connection */
struct Fetch_cfilter
{
  const struct Fetch_cftype *cft; /* the type providing implementation */
  struct Fetch_cfilter *next;     /* next filter in chain */
  void *ctx;                     /* filter type specific settings */
  struct connectdata *conn;      /* the connection this filter belongs to */
  int sockindex;                 /* the index the filter is installed at */
  BIT(connected);                /* != 0 iff this filter is connected */
  BIT(shutdown);                 /* != 0 iff this filter has shut down */
};

/* Default implementations for the type functions, implementing nop. */
void Fetch_cf_def_destroy_this(struct Fetch_cfilter *cf,
                              struct Fetch_easy *data);

/* Default implementations for the type functions, implementing pass-through
 * the filter chain. */
void Fetch_cf_def_get_host(struct Fetch_cfilter *cf, struct Fetch_easy *data,
                          const char **phost, const char **pdisplay_host,
                          int *pport);
void Fetch_cf_def_adjust_pollset(struct Fetch_cfilter *cf,
                                struct Fetch_easy *data,
                                struct easy_pollset *ps);
bool Fetch_cf_def_data_pending(struct Fetch_cfilter *cf,
                              const struct Fetch_easy *data);
ssize_t Fetch_cf_def_send(struct Fetch_cfilter *cf, struct Fetch_easy *data,
                         const void *buf, size_t len, bool eos,
                         FETCHcode *err);
ssize_t Fetch_cf_def_recv(struct Fetch_cfilter *cf, struct Fetch_easy *data,
                         char *buf, size_t len, FETCHcode *err);
FETCHcode Fetch_cf_def_cntrl(struct Fetch_cfilter *cf,
                            struct Fetch_easy *data,
                            int event, int arg1, void *arg2);
bool Fetch_cf_def_conn_is_alive(struct Fetch_cfilter *cf,
                               struct Fetch_easy *data,
                               bool *input_pending);
FETCHcode Fetch_cf_def_conn_keep_alive(struct Fetch_cfilter *cf,
                                      struct Fetch_easy *data);
FETCHcode Fetch_cf_def_query(struct Fetch_cfilter *cf,
                            struct Fetch_easy *data,
                            int query, int *pres1, void *pres2);
FETCHcode Fetch_cf_def_shutdown(struct Fetch_cfilter *cf,
                               struct Fetch_easy *data, bool *done);

/**
 * Create a new filter instance, unattached to the filter chain.
 * Use Fetch_conn_cf_add() to add it to the chain.
 * @param pcf  on success holds the created instance
 * @param cft   the filter type
 * @param ctx  the type specific context to use
 */
FETCHcode Fetch_cf_create(struct Fetch_cfilter **pcf,
                         const struct Fetch_cftype *cft,
                         void *ctx);

/**
 * Add a filter instance to the `sockindex` filter chain at connection
 * `conn`. The filter must not already be attached. It is inserted at
 * the start of the chain (top).
 */
void Fetch_conn_cf_add(struct Fetch_easy *data,
                      struct connectdata *conn,
                      int sockindex,
                      struct Fetch_cfilter *cf);

/**
 * Insert a filter (chain) after `cf_at`.
 * `cf_new` must not already be attached.
 */
void Fetch_conn_cf_insert_after(struct Fetch_cfilter *cf_at,
                               struct Fetch_cfilter *cf_new);

/**
 * Discard, e.g. remove and destroy `discard` iff
 * it still is in the filter chain below `cf`. If `discard`
 * is no longer found beneath `cf` return FALSE.
 * if `destroy_always` is TRUE, will call `discard`s destroy
 * function and free it even if not found in the subchain.
 */
bool Fetch_conn_cf_discard_sub(struct Fetch_cfilter *cf,
                              struct Fetch_cfilter *discard,
                              struct Fetch_easy *data,
                              bool destroy_always);

/**
 * Discard all cfilters starting with `*pcf` and clearing it afterwards.
 */
void Fetch_conn_cf_discard_chain(struct Fetch_cfilter **pcf,
                                struct Fetch_easy *data);

/**
 * Remove and destroy all filters at chain `sockindex` on connection `conn`.
 */
void Fetch_conn_cf_discard_all(struct Fetch_easy *data,
                              struct connectdata *conn,
                              int sockindex);

FETCHcode Fetch_conn_cf_connect(struct Fetch_cfilter *cf,
                               struct Fetch_easy *data,
                               bool blocking, bool *done);
void Fetch_conn_cf_close(struct Fetch_cfilter *cf, struct Fetch_easy *data);
ssize_t Fetch_conn_cf_send(struct Fetch_cfilter *cf, struct Fetch_easy *data,
                          const void *buf, size_t len, bool eos,
                          FETCHcode *err);
ssize_t Fetch_conn_cf_recv(struct Fetch_cfilter *cf, struct Fetch_easy *data,
                          char *buf, size_t len, FETCHcode *err);
FETCHcode Fetch_conn_cf_cntrl(struct Fetch_cfilter *cf,
                             struct Fetch_easy *data,
                             bool ignore_result,
                             int event, int arg1, void *arg2);

/**
 * Determine if the connection filter chain is using SSL to the remote host
 * (or will be once connected).
 */
bool Fetch_conn_cf_is_ssl(struct Fetch_cfilter *cf);

/**
 * Get the socket used by the filter chain starting at `cf`.
 * Returns FETCH_SOCKET_BAD if not available.
 */
fetch_socket_t Fetch_conn_cf_get_socket(struct Fetch_cfilter *cf,
                                       struct Fetch_easy *data);

FETCHcode Fetch_conn_cf_get_ip_info(struct Fetch_cfilter *cf,
                                   struct Fetch_easy *data,
                                   int *is_ipv6, struct ip_quadruple *ipquad);

bool Fetch_conn_cf_needs_flush(struct Fetch_cfilter *cf,
                              struct Fetch_easy *data);

#define FETCH_CF_SSL_DEFAULT -1
#define FETCH_CF_SSL_DISABLE 0
#define FETCH_CF_SSL_ENABLE 1

/**
 * Bring the filter chain at `sockindex` for connection `data->conn` into
 * connected state. Which will set `*done` to TRUE.
 * This can be called on an already connected chain with no side effects.
 * When not `blocking`, calls may return without error and `*done != TRUE`,
 * while the individual filters negotiated the connection.
 */
FETCHcode Fetch_conn_connect(struct Fetch_easy *data, int sockindex,
                            bool blocking, bool *done);

/**
 * Check if the filter chain at `sockindex` for connection `conn` is
 * completely connected.
 */
bool Fetch_conn_is_connected(struct connectdata *conn, int sockindex);

/**
 * Determine if we have reached the remote host on IP level, e.g.
 * have a TCP connection. This turns TRUE before a possible SSL
 * handshake has been started/done.
 */
bool Fetch_conn_is_ip_connected(struct Fetch_easy *data, int sockindex);

/**
 * Determine if the connection is using SSL to the remote host
 * (or will be once connected). This will return FALSE, if SSL
 * is only used in proxying and not for the tunnel itself.
 */
bool Fetch_conn_is_ssl(struct connectdata *conn, int sockindex);

/**
 * Connection provides multiplexing of easy handles at `socketindex`.
 */
bool Fetch_conn_is_multiplex(struct connectdata *conn, int sockindex);

/**
 * Return the HTTP version used on the FIRSTSOCKET connection filters
 * or 0 if unknown. Value otherwise is 09, 10, 11, etc.
 */
unsigned char Fetch_conn_http_version(struct Fetch_easy *data);

/**
 * Close the filter chain at `sockindex` for connection `data->conn`.
 * Filters remain in place and may be connected again afterwards.
 */
void Fetch_conn_close(struct Fetch_easy *data, int sockindex);

/**
 * Shutdown the connection at `sockindex` non-blocking, using timeout
 * from `data->set.shutdowntimeout`, default DEFAULT_SHUTDOWN_TIMEOUT_MS.
 * Will return FETCHE_OK and *done == FALSE if not finished.
 */
FETCHcode Fetch_conn_shutdown(struct Fetch_easy *data, int sockindex, bool *done);

/**
 * Return if data is pending in some connection filter at chain
 * `sockindex` for connection `data->conn`.
 */
bool Fetch_conn_data_pending(struct Fetch_easy *data,
                            int sockindex);

/**
 * Return TRUE if any of the connection filters at chain `sockindex`
 * have data still to send.
 */
bool Fetch_conn_needs_flush(struct Fetch_easy *data, int sockindex);

/**
 * Flush any pending data on the connection filters at chain `sockindex`.
 */
FETCHcode Fetch_conn_flush(struct Fetch_easy *data, int sockindex);

/**
 * Return the socket used on data's connection for the index.
 * Returns FETCH_SOCKET_BAD if not available.
 */
fetch_socket_t Fetch_conn_get_socket(struct Fetch_easy *data, int sockindex);

/**
 * Tell filters to forget about the socket at sockindex.
 */
void Fetch_conn_forget_socket(struct Fetch_easy *data, int sockindex);

/**
 * Adjust the pollset for the filter chain startgin at `cf`.
 */
void Fetch_conn_cf_adjust_pollset(struct Fetch_cfilter *cf,
                                 struct Fetch_easy *data,
                                 struct easy_pollset *ps);

/**
 * Adjust pollset from filters installed at transfer's connection.
 */
void Fetch_conn_adjust_pollset(struct Fetch_easy *data,
                              struct easy_pollset *ps);

/**
 * Fetch_poll() the filter chain at `cf` with timeout `timeout_ms`.
 * Returns 0 on timeout, negative on error or number of sockets
 * with requested poll events.
 */
int Fetch_conn_cf_poll(struct Fetch_cfilter *cf,
                      struct Fetch_easy *data,
                      timediff_t timeout_ms);

/**
 * Receive data through the filter chain at `sockindex` for connection
 * `data->conn`. Copy at most `len` bytes into `buf`. Return the
 * actual number of bytes copied or a negative value on error.
 * The error code is placed into `*code`.
 */
ssize_t Fetch_cf_recv(struct Fetch_easy *data, int sockindex, char *buf,
                     size_t len, FETCHcode *code);

/**
 * Send `len` bytes of data from `buf` through the filter chain `sockindex`
 * at connection `data->conn`. Return the actual number of bytes written
 * or a negative value on error.
 * The error code is placed into `*code`.
 */
ssize_t Fetch_cf_send(struct Fetch_easy *data, int sockindex,
                     const void *buf, size_t len, bool eos, FETCHcode *code);

/**
 * Notify connection filters that they need to setup data for
 * a transfer.
 */
FETCHcode Fetch_conn_ev_data_setup(struct Fetch_easy *data);

/**
 * Notify connection filters that now would be a good time to
 * perform any idle, e.g. time related, actions.
 */
FETCHcode Fetch_conn_ev_data_idle(struct Fetch_easy *data);

/**
 * Notify connection filters that the transfer represented by `data`
 * is done with sending data (e.g. has uploaded everything).
 */
void Fetch_conn_ev_data_done_send(struct Fetch_easy *data);

/**
 * Notify connection filters that the transfer represented by `data`
 * is finished - eventually premature, e.g. before being complete.
 */
void Fetch_conn_ev_data_done(struct Fetch_easy *data, bool premature);

/**
 * Notify connection filters that the transfer of data is paused/unpaused.
 */
FETCHcode Fetch_conn_ev_data_pause(struct Fetch_easy *data, bool do_pause);

/**
 * Check if FIRSTSOCKET's cfilter chain deems connection alive.
 */
bool Fetch_conn_is_alive(struct Fetch_easy *data, struct connectdata *conn,
                        bool *input_pending);

/**
 * Try to upkeep the connection filters at sockindex.
 */
FETCHcode Fetch_conn_keep_alive(struct Fetch_easy *data,
                               struct connectdata *conn,
                               int sockindex);

#ifdef UNITTESTS
void Fetch_cf_def_close(struct Fetch_cfilter *cf, struct Fetch_easy *data);
#endif
void Fetch_conn_get_host(struct Fetch_easy *data, int sockindex,
                        const char **phost, const char **pdisplay_host,
                        int *pport);

/**
 * Get the maximum number of parallel transfers the connection
 * expects to be able to handle at `sockindex`.
 */
size_t Fetch_conn_get_max_concurrent(struct Fetch_easy *data,
                                    struct connectdata *conn,
                                    int sockindex);

/**
 * Get the underlying error code for a transfer stream or 0 if not known.
 */
int Fetch_conn_get_stream_error(struct Fetch_easy *data,
                               struct connectdata *conn,
                               int sockindex);

/**
 * Get the index of the given socket in the connection's sockets.
 * Useful in calling `Fetch_conn_send()/Fetch_conn_recv()` with the
 * correct socket index.
 */
int Fetch_conn_sockindex(struct Fetch_easy *data, fetch_socket_t sockfd);

/*
 * Receive data on the connection, using FIRSTSOCKET/SECONDARYSOCKET.
 * Will return FETCHE_AGAIN iff blocked on receiving.
 */
FETCHcode Fetch_conn_recv(struct Fetch_easy *data, int sockindex,
                         char *buf, size_t buffersize,
                         ssize_t *pnread);

/*
 * Send data on the connection, using FIRSTSOCKET/SECONDARYSOCKET.
 * Will return FETCHE_AGAIN iff blocked on sending.
 */
FETCHcode Fetch_conn_send(struct Fetch_easy *data, int sockindex,
                         const void *buf, size_t blen, bool eos,
                         size_t *pnwritten);

void Fetch_pollset_reset(struct Fetch_easy *data,
                        struct easy_pollset *ps);

/* Change the poll flags (FETCH_POLL_IN/FETCH_POLL_OUT) to the poll set for
 * socket `sock`. If the socket is not already part of the poll set, it
 * will be added.
 * If the socket is present and all poll flags are cleared, it will be removed.
 */
void Fetch_pollset_change(struct Fetch_easy *data,
                         struct easy_pollset *ps, fetch_socket_t sock,
                         int add_flags, int remove_flags);

void Fetch_pollset_set(struct Fetch_easy *data,
                      struct easy_pollset *ps, fetch_socket_t sock,
                      bool do_in, bool do_out);

#define Fetch_pollset_add_in(data, ps, sock) \
  Fetch_pollset_change((data), (ps), (sock), FETCH_POLL_IN, 0)
#define Fetch_pollset_add_out(data, ps, sock) \
  Fetch_pollset_change((data), (ps), (sock), FETCH_POLL_OUT, 0)
#define Fetch_pollset_add_inout(data, ps, sock) \
  Fetch_pollset_change((data), (ps), (sock),    \
                      FETCH_POLL_IN | FETCH_POLL_OUT, 0)
#define Fetch_pollset_set_in_only(data, ps, sock) \
  Fetch_pollset_change((data), (ps), (sock),      \
                      FETCH_POLL_IN, FETCH_POLL_OUT)
#define Fetch_pollset_set_out_only(data, ps, sock) \
  Fetch_pollset_change((data), (ps), (sock),       \
                      FETCH_POLL_OUT, FETCH_POLL_IN)

void Fetch_pollset_add_socks(struct Fetch_easy *data,
                            struct easy_pollset *ps,
                            int (*get_socks_cb)(struct Fetch_easy *data,
                                                fetch_socket_t *socks));

/**
 * Check if the pollset, as is, wants to read and/or write regarding
 * the given socket.
 */
void Fetch_pollset_check(struct Fetch_easy *data,
                        struct easy_pollset *ps, fetch_socket_t sock,
                        bool *pwant_read, bool *pwant_write);

/**
 * Types and macros used to keep the current easy handle in filter calls,
 * allowing for nested invocations. See #10336.
 *
 * `cf_call_data` is intended to be a member of the cfilter's `ctx` type.
 * A filter defines the macro `CF_CTX_CALL_DATA` to give access to that.
 *
 * With all values 0, the default, this indicates that there is no cfilter
 * call with `data` ongoing.
 * Macro `CF_DATA_SAVE` preserves the current `cf_call_data` in a local
 * variable and sets the `data` given, incrementing the `depth` counter.
 *
 * Macro `CF_DATA_RESTORE` restores the old values from the local variable,
 * while checking that `depth` values are as expected (debug build), catching
 * cases where a "lower" RESTORE was not called.
 *
 * Finally, macro `CF_DATA_CURRENT` gives the easy handle of the current
 * invocation.
 */
struct cf_call_data
{
  struct Fetch_easy *data;
#ifdef DEBUGBUILD
  int depth;
#endif
};

/**
 * define to access the `struct cf_call_data for a cfilter. Normally
 * a member in the cfilter's `ctx`.
 *
 * #define CF_CTX_CALL_DATA(cf)   -> struct cf_call_data instance
 */

#ifdef DEBUGBUILD

#define CF_DATA_SAVE(save, cf, data)                      \
  do                                                      \
  {                                                       \
    (save) = CF_CTX_CALL_DATA(cf);                        \
    DEBUGASSERT((save).data == NULL || (save).depth > 0); \
    CF_CTX_CALL_DATA(cf).depth++;                         \
    CF_CTX_CALL_DATA(cf).data = (struct Fetch_easy *)data; \
  } while (0)

#define CF_DATA_RESTORE(cf, save)                                \
  do                                                             \
  {                                                              \
    DEBUGASSERT(CF_CTX_CALL_DATA(cf).depth == (save).depth + 1); \
    DEBUGASSERT((save).data == NULL || (save).depth > 0);        \
    CF_CTX_CALL_DATA(cf) = (save);                               \
  } while (0)

#else /* DEBUGBUILD */

#define CF_DATA_SAVE(save, cf, data)                      \
  do                                                      \
  {                                                       \
    (save) = CF_CTX_CALL_DATA(cf);                        \
    CF_CTX_CALL_DATA(cf).data = (struct Fetch_easy *)data; \
  } while (0)

#define CF_DATA_RESTORE(cf, save)  \
  do                               \
  {                                \
    CF_CTX_CALL_DATA(cf) = (save); \
  } while (0)

#endif /* !DEBUGBUILD */

#define CF_DATA_CURRENT(cf) \
  ((cf) ? (CF_CTX_CALL_DATA(cf).data) : NULL)

#endif /* HEADER_FETCH_CFILTERS_H */
