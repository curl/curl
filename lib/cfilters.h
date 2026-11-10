#ifndef HEADER_CURL_CFILTERS_H
#define HEADER_CURL_CFILTERS_H
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
#include "curlx/timediff.h"

struct bufq;
struct Curl_cfilter;
struct Curl_easy;
struct Curl_dns_entry;
struct connectdata;
struct ip_quadruple;
struct curl_tlssessioninfo;

/* Callback to destroy resources held by this filter instance.
 * Implementations MUST NOT chain calls to cf->next.
 */
typedef void     Curl_cft_destroy_this(struct Curl_cfilter *cf,
                                       struct Curl_easy *data);

/* Callback to close the connection filter gracefully, non-blocking.
 * Implementations MUST NOT chain calls to cf->next.
 */
typedef CURLcode Curl_cft_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool *done);

typedef CURLcode Curl_cft_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *done);

struct easy_pollset;

/* Passing in an easy_pollset for monitoring of sockets, let
 * filters add or remove sockets actions (CURL_POLL_OUT, CURL_POLL_IN).
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
typedef CURLcode Curl_cft_adjust_pollset(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct easy_pollset *ps);

typedef bool     Curl_cft_data_pending(struct Curl_cfilter *cf,
                                       const struct Curl_easy *data);

typedef CURLcode Curl_cft_send(struct Curl_cfilter *cf,
                               struct Curl_easy *data, /* transfer */
                               const uint8_t *buf,     /* data to write */
                               size_t len,             /* amount to write */
                               bool eos,               /* last chunk */
                               size_t *pnwritten);     /* how much sent */

typedef CURLcode Curl_cft_recv(struct Curl_cfilter *cf,
                               struct Curl_easy *data, /* transfer */
                               char *buf,              /* store data here */
                               size_t len,             /* amount to read */
                               size_t *pnread);        /* how much received */

typedef bool     Curl_cft_conn_is_alive(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        bool *input_pending);

typedef CURLcode Curl_cft_conn_keep_alive(struct Curl_cfilter *cf,
                                          struct Curl_easy *data);

/**
 * Events/controls for connection filters, their arguments and
 * return code handling. Filter callbacks are invoked "top down".
 * Return code handling:
 * "first fail" meaning that the first filter returning != CURLE_OK, will
 *              abort further event distribution and determine the result.
 * "ignored" meaning return values are ignored and the event is distributed
 *           to all filters in the chain. Overall result is always CURLE_OK.
 */
/*      data event                            arg1       arg2     return */
#define CF_CTRL_DATA_SETUP              4  /* 0          NULL     first fail */
/* unused now                           5 */
#define CF_CTRL_DATA_PAUSE              6  /* on/off     NULL     first fail */
#define CF_CTRL_DATA_DONE               7  /* premature  NULL     ignored */
#define CF_CTRL_DATA_DONE_SEND          8  /* 0          NULL     ignored */
/* update conn info at connection and data */
#define CF_CTRL_CONN_INFO_UPDATE (256 + 0) /* 0          NULL     ignored */
#define CF_CTRL_FORGET_SOCKET    (256 + 1) /* 0          NULL     ignored */
#define CF_CTRL_FLUSH            (256 + 2) /* 0          NULL     first fail */
#define CF_CTRL_REPORT_STATS     (256 + 3) /* 0          NULL     ignored */
#define CF_CTRL_MAINTENANCE      (256 + 4) /* 0          NULL     ignored */

/**
 * Handle event/control for the filter.
 * Implementations MUST NOT chain calls to cf->next.
 */
typedef CURLcode Curl_cft_cntrl(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int event, int arg1, void *arg2);

/**
 * Queries to ask via a `Curl_cft_query *query` method on a cfilter chain.
 * - MAX_CONCURRENT: the maximum number of parallel transfers the filter
 *                   chain expects to handle at the same time.
 *                   default: 1 if no filter overrides.
 * - CONNECT_REPLY_MS: milliseconds until the first indication of a server
 *                   response was received on a connect. For TCP, this
 *                   reflects the time until the socket connected. On UDP
 *                   this gives the time the first bytes from the server
 *                   were received.
 *                   -1 if not determined yet.
 * - CF_QUERY_NEED_FLUSH: TRUE iff any of the filters have unsent data
 * - CF_QUERY_IP_INFO: res1 says if connection used IPv6, res2 is the
 *                   ip quadruple
 * - CF_QUERY_HOST_PORT: the remote hostname and port a filter talks to
 * - CF_QUERY_SSL_INFO: fill out the passed curl_tlssessioninfo with the
 *                      internal from the SSL secured connection when
 *                      available.
 * - CF_QUERY_SSL_CTX_INFO: same as CF_QUERY_SSL_INFO, but give the SSL_CTX
 *                      when available, or the same internal pointer
 *                      when the TLS stack does not differentiate.
 * - CF_QUERY_ALPN_NEGOTIATED: The ALPN selected by the server as
                        null-terminated string or NULL if none
                        selected/handshake not done. Implemented by filter
                        types CF_TYPE_SSL or CF_TYPE_IP_CONNECT.
 * - CF_QUERY_REALLY_CONNECTED: implemented in socket filters to return
 *                      if a reply from a server has really arrived. For
 *                      non-UDP sockets this is TRUE when the socket became
 *                      writable. For UDP sockets, this is TRUE when the
 *                      first byte from the peer was received.
 */
/*      query                             res1       res2     */
#define CF_QUERY_MAX_CONCURRENT     1  /* number     -        */
#define CF_QUERY_CONNECT_REPLY_MS   2  /* number     -        */
/* unused 3 + 4 + 5 */
#define CF_QUERY_STREAM_ERROR       6  /* error code - */
#define CF_QUERY_NEED_FLUSH         7  /* TRUE/FALSE - */
#define CF_QUERY_IP_INFO            8  /* TRUE/FALSE struct ip_quadruple */
#define CF_QUERY_HTTP_VERSION       9  /* number (10/11/20/30)   - */
/* pass in a `const struct Curl_sockaddr_ex **` as `pres2`. Gets set
 * to NULL when not connected. */
#define CF_QUERY_REMOTE_ADDR       10  /* -          `Curl_sockaddr_ex *` */
#define CF_QUERY_HOST_PORT         11  /* port       const char * */
#define CF_QUERY_SSL_INFO          12  /* -    struct curl_tlssessioninfo * */
#define CF_QUERY_SSL_CTX_INFO      13  /* -    struct curl_tlssessioninfo * */
#define CF_QUERY_TRANSPORT         14  /* TRNSPRT_*  - * */
#define CF_QUERY_ALPN_NEGOTIATED   15  /* -          const char * */
#define CF_QUERY_REALLY_CONNECTED  16  /* TRUE/FALSE - */

/**
 * Query the cfilter for properties. Filters ignorant of a query will
 * pass it "down" the filter chain.
 */
typedef CURLcode Curl_cft_query(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
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
 * CF_TYPE_SETUP       filter is only needed for connection setup and
 *                     can be removed once connected
 * CF_TYPE_DNS         filter managing DNS resolve operations
 * CF_TYPE_MAINTENANCE filter wants "maintenance" calls when transfers
 *                     are blocked/ratelimited.
 * CF_TYPE_SAFE_EOS    filter handles End-Of-Stream safely
 */
#define CF_TYPE_IP_CONNECT  (1 << 0)
#define CF_TYPE_SSL         (1 << 1)
#define CF_TYPE_MULTIPLEX   (1 << 2)
#define CF_TYPE_PROXY       (1 << 3)
#define CF_TYPE_HTTP        (1 << 4)
#define CF_TYPE_SETUP       (1 << 5)
#define CF_TYPE_DNS         (1 << 6)
#define CF_TYPE_MAINTENANCE (1 << 7)
#define CF_TYPE_SAFE_EOS    (1 << 8)

/* A connection filter type, e.g. specific implementation. */
struct Curl_cftype {
  const char *name;                        /* name of the filter type */
  int flags;                               /* flags of filter type */
  int log_level;                           /* log level for such filters */
  Curl_cft_destroy_this *destroy;          /* destroy resources of this cf */
  Curl_cft_connect *do_connect;            /* establish connection */
  Curl_cft_shutdown *do_shutdown;          /* shutdown conn */
  Curl_cft_adjust_pollset *adjust_pollset; /* adjust transfer poll set */
  Curl_cft_data_pending *has_data_pending; /* conn has data pending */
  Curl_cft_send *do_send;                  /* send data */
  Curl_cft_recv *do_recv;                  /* receive data */
  Curl_cft_cntrl *cntrl;                   /* events/control */
  Curl_cft_conn_is_alive *is_alive;        /* FALSE if conn is dead, Jim! */
  Curl_cft_conn_keep_alive *keep_alive;    /* try to keep it alive */
  Curl_cft_query *query;                   /* query filter chain */
};

/* A connection filter instance, e.g. registered at a connection */
struct Curl_cfilter {
  const struct Curl_cftype *cft; /* the type providing implementation */
  struct Curl_cfilter *next;     /* next filter in chain */
  void *ctx;                     /* filter type specific settings */
  struct Curl_cfchain *chain;   /* chain filter is part of or NULL */
  BIT(connected);                /* != 0 iff this filter is connected */
  BIT(shutdown);                 /* != 0 iff this filter has shut down */
};

/* A struct holding a filter chain and its properties */
struct Curl_cfchain {
  struct Curl_cfilter *cf;       /* first filter in chain */
  struct connectdata *conn;      /* connectdata this chain belongs to */
  struct Curl_cfchain *parent;  /* parent chain or NULL */
  timediff_t shutdown_start_ms; /* when filter shutdown started */
  timediff_t shutdown_timeout_ms; /* 0 means no timeout */
  curl_socket_t sock;            /* main socket of this chain */
  BIT(primary);                  /* primary chain of a connection */
  BIT(ipv6);                     /* sock is using IPv6 */
};

#define CF_CONN(cf)             (cf)->chain->conn
#define CF_IS_PRIMARY(cf)       (bool)(cf)->chain->primary

/* Default implementations for the type functions, implementing nop. */
void Curl_cf_def_destroy_this(struct Curl_cfilter *cf,
                              struct Curl_easy *data);

/* Default implementations for the type functions, implementing pass-through
 * the filter chain. */
CURLcode Curl_cf_def_adjust_pollset(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct easy_pollset *ps);
bool     Curl_cf_def_data_pending(struct Curl_cfilter *cf,
                                  const struct Curl_easy *data);
CURLcode Curl_cf_def_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const uint8_t *buf, size_t len, bool eos,
                          size_t *pnwritten);
CURLcode Curl_cf_def_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, size_t *pnread);
CURLcode Curl_cf_def_cntrl(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           int event, int arg1, void *arg2);
bool     Curl_cf_def_conn_is_alive(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool *input_pending);
CURLcode Curl_cf_def_conn_keep_alive(struct Curl_cfilter *cf,
                                     struct Curl_easy *data);
CURLcode Curl_cf_def_query(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           int query, int *pres1, void *pres2);
CURLcode Curl_cf_def_shutdown(struct Curl_cfilter *cf,
                              struct Curl_easy *data, bool *done);
CURLcode Curl_cf_def_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data, bool *done);

/**
 * Create a new filter instance, unattached to the filter chain.
 * Use Curl_cfchain_add() to add it to a filter chain.
 * @param pcf  on success holds the created instance
 * @param cft   the filter type
 * @param ctx  the type specific context to use
 */
CURLcode Curl_cf_create(struct Curl_cfilter **pcf,
                        const struct Curl_cftype *cft,
                        void *ctx);

void Curl_conn_cf_insert_after(struct Curl_cfilter *cf_at,
                               struct Curl_cfilter *cf_new);

void Curl_cfchain_init(struct Curl_cfchain *chain,
                       struct connectdata *conn,
                       bool primary);

void Curl_cfchain_init_child(struct Curl_cfchain *chain,
                             struct Curl_cfchain *parent);

void Curl_cfchain_cleanup(struct Curl_cfchain *chain,
                          struct Curl_easy *data);

void Curl_cfchain_reset(struct Curl_cfchain *chain,
                        struct Curl_easy *data);

/* Add the filter to the start of the chain */
void Curl_cfchain_add(struct Curl_cfchain *chain,
                      struct Curl_cfilter *cf);

/**
 * Move the filter chain after `cf_at`, emptying `chain`.
 */
void Curl_cfchain_merge(struct Curl_cfchain *dest,
                        struct Curl_cfchain *chain);


/**
 * Extract filter `*pcf` from its connection filter chain.
 * Destroy `*pcf`, even if it was not part of the chain and NULL it.
 * Returns TRUE of cf has been part of chain.
 */
bool Curl_conn_cf_discard(struct Curl_cfilter **pcf,
                          struct Curl_easy *data);

/**
 * Discard all cfilters starting with `*pcf` and clearing it afterwards.
 */
void Curl_conn_cf_discard_chain(struct Curl_cfilter **pcf,
                                struct Curl_easy *data);

CURLcode Curl_conn_cf_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool *done);
CURLcode Curl_conn_cf_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                           const uint8_t *buf, size_t len, bool eos,
                           size_t *pnwritten);
CURLcode Curl_conn_cf_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                           char *buf, size_t len, size_t *pnread);
CURLcode Curl_conn_cf_cntrl(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            bool ignore_result,
                            int event, int arg1, void *arg2);

CURLcode Curl_conn_cf_get_ip_info(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *is_ipv6, struct ip_quadruple *ipquad);

bool Curl_conn_cf_is_ip_connected(struct Curl_cfilter *cf,
                                  struct Curl_easy *data);

unsigned char Curl_conn_cf_get_transport(struct Curl_cfilter *cf,
                                         struct Curl_easy *data);

int Curl_socktype_for_transport(uint8_t transport);
int Curl_protocol_for_transport(uint8_t transport);

const char *Curl_conn_cf_get_alpn_negotiated(struct Curl_cfilter *cf,
                                             struct Curl_easy *data);

#define CURL_CF_SSL_DEFAULT  (-1)
#define CURL_CF_SSL_DISABLE  0
#define CURL_CF_SSL_ENABLE   1

/* Check if the first connection filter chain is completely connected. */
bool Curl_conn_is_connected(struct connectdata *conn);
/* Check if the filter chain is completely connected. */
bool Curl_cfchain_is_connected(struct Curl_cfchain *chain);

/**
 * Determine if we have reached the remote host on IP level, e.g.
 * have a TCP connection. This turns TRUE before a possible SSL
 * handshake has been started/done.
 */
bool Curl_cfchain_is_ip_connected(struct Curl_cfchain *chain);

/**
 * Determine if the connection is using SSL to the remote host
 * (or will be once connected). This will return FALSE, if SSL
 * is only used in proxying and not for the tunnel itself.
 */
bool Curl_conn_is_ssl(struct connectdata *conn);
bool Curl_cfchain_is_ssl(struct Curl_cfchain *chain);

/* Determine if the connection has one or more proxy filters.
 * e.g. is tunneling on its primary chain. */
bool Curl_conn_is_tunneling(struct connectdata *conn);

/*
 * Fill `info` with information about the TLS instance securing the connection
 * when available, otherwise e.g. when Curl_conn_is_ssl() is FALSE, return
 * FALSE. 'query' should be CF_QUERY_SSL_INFO or CF_QUERY_SSL_CTX_INFO.
 */
bool Curl_conn_get_ssl_info(struct Curl_easy *data,
                            struct connectdata *conn,
                            int query,
                            struct curl_tlssessioninfo *info);

CURLcode Curl_conn_get_ip_info(struct Curl_easy *data,
                               struct connectdata *conn,
                               bool *is_ipv6,
                               struct ip_quadruple *ipquad);

/* Connection provides multiplexing on primary chain. */
bool Curl_conn_is_multiplex(struct connectdata *conn);

/* TRUE if any filters are of type CF_TYPE_MAINTENANCE */
bool Curl_cfchain_wants_maintenance(struct Curl_cfchain *chain);

/* Connection handles EOS safely, no over-read possible. */
bool Curl_conn_has_safe_eos(struct connectdata *conn);

/**
 * Return the HTTP version used on the primary connection filter chain
 * or 0 if unknown. Value otherwise is 09, 10, 11, etc.
 */
uint8_t Curl_conn_http_version(struct Curl_easy *data,
                               struct connectdata *conn);

/* Return the HTTP version used on the connection filter chain
 * or 0 if unknown. Value otherwise is 09, 10, 11, etc. */
uint8_t Curl_conn_cf_http_version(struct Curl_easy *data,
                                  struct Curl_cfilter *cf);

/* Get the TRNSPRT_* the connection is using */
unsigned char Curl_conn_get_transport(struct Curl_easy *data,
                                      struct connectdata *conn);

void Curl_conn_cntrl_update_info(struct Curl_easy *data,
                                 struct connectdata *conn);

void Curl_cfchain_cntrl_report_stats(struct Curl_easy *data,
                                     struct Curl_cfchain *chain);

void Curl_cfchain_remove_setup_filters(struct Curl_easy *data,
                                       struct Curl_cfchain *chain);

/* Return if data is pending in some connection filter at the
 * primary chain of `data->conn`.  */
bool Curl_conn_data_pending(struct Curl_easy *data);
bool Curl_cfchain_data_pending(struct Curl_easy *data,
                               struct Curl_cfchain *chain);

/* TRUE if any of the connection filters at chain have data still to send. */
bool Curl_cfchain_needs_flush(struct Curl_easy *data,
                              struct Curl_cfchain *chain);

/* Flush any pending data on the connection filters at chain. */
CURLcode Curl_cfchain_flush(struct Curl_easy *data,
                            struct Curl_cfchain *chain);

/* Perform maintenance on the connection filters.
 * Sends CF_CTRL_MAINTENANCE to filters. */
CURLcode Curl_conn_do_maintenance(struct Curl_easy *data);

/* Get first filter instance of given type in the primary chain */
struct Curl_cfilter *Curl_conn_get_first_cf(struct connectdata *conn,
                                            const struct Curl_cftype *cft);

/* Return a pointer to the connected socket address or NULL. */
const struct Curl_sockaddr_ex *
Curl_conn_get_remote_addr(struct Curl_easy *data);

/**
 * Adjust the pollset for the filter chain starting at `cf`.
 */
CURLcode Curl_conn_cf_adjust_pollset(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct easy_pollset *ps);
CURLcode Curl_cfchain_adjust_pollset(struct Curl_easy *data,
                                     struct Curl_cfchain *chain,
                                     struct easy_pollset *ps);
/**
 * Adjust pollset from filters installed at transfer's connection.
 */
CURLcode Curl_conn_adjust_pollset(struct Curl_easy *data,
                                  struct connectdata *conn,
                                  struct easy_pollset *ps);

/**
 * Curl_poll() the filter chain at `cf` with timeout `timeout_ms`.
 * Returns 0 on timeout, negative on error or number of sockets
 * with requested poll events.
 */
int Curl_conn_cf_poll(struct Curl_cfilter *cf,
                      struct Curl_easy *data,
                      timediff_t timeout_ms);

/**
 * Receive data through the primary filter chain for connection
 * `data->conn`. Copy at most `len` bytes into `buf`. Return the
 * actual number of bytes copied in `*pnread`or an error.
 */
CURLcode Curl_cf_recv(struct Curl_easy *data,
                      char *buf, size_t len,
                      size_t *pnread);

/**
 * Send `len` bytes of data from `buf` through the primary filter chain
 * at connection `data->conn`. Return the actual number of bytes written
 * in `*pnwritten` or on error.
 */
CURLcode Curl_cf_send(struct Curl_easy *data,
                      const uint8_t *buf, size_t len, bool eos,
                      size_t *pnwritten);

/**
 * Receive bytes from connection filter `cf` into `bufq`.
 * Convenience wrapper around `Curl_bufq_sipn()`,
 * so users do not have to implement a callback.
 */
CURLcode Curl_cf_recv_bufq(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct bufq *bufq,
                           size_t maxlen,
                           size_t *pnread);

/**
 * Send bytes in `bufq` using connection filter `cf`.
 * A convenience wrapper around `Curl_bufq_write_pass()`,
 * so users do not have to implement a callback.
 */
CURLcode Curl_cf_send_bufq(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct bufq *bufq,
                           const unsigned char *buf, size_t blen,
                           size_t *pnwritten);

/**
 * Notify connection filters that they need to setup data for
 * a transfer.
 */
CURLcode Curl_conn_ev_data_setup(struct Curl_easy *data);

/**
 * Notify connection filters that the transfer represented by `data`
 * is done with sending data (e.g. has uploaded everything).
 */
void Curl_conn_ev_data_done_send(struct Curl_easy *data);

/**
 * Notify connection filters that the transfer represented by `data`
 * is finished - eventually premature, e.g. before being complete.
 */
void Curl_conn_ev_data_done(struct Curl_easy *data, bool premature);

/**
 * Notify connection filters that the transfer of data is paused/unpaused.
 */
CURLcode Curl_conn_ev_data_pause(struct Curl_easy *data, bool do_pause);

/**
 * Check if primary cfilter chain deems connection alive.
 */
bool Curl_conn_is_alive(struct Curl_easy *data, struct connectdata *conn,
                        bool *input_pending);

/**
 * Try to upkeep the connection filters.
 */
CURLcode Curl_conn_keep_alive(struct Curl_easy *data,
                              struct connectdata *conn);

/**
 * Get the remote hostname and port that the connection is currently
 * talking to (or will talk to).
 * Once connected or before connect starts,
 * it is `conn->origin->hostname` and `conn->origin->port`.
 * During connect, when tunneling proxies are involved (http or socks),
 * it will be the name and port the proxy currently negotiates with.
 */
void Curl_conn_get_current_host(struct Curl_easy *data,
                                const char **phost, int *pport);

/**
 * Get the maximum number of parallel transfers the connection
 * expects to be able to handle.
 */
size_t Curl_conn_get_max_concurrent(struct Curl_easy *data,
                                    struct connectdata *conn);

/**
 * Get the underlying error code for a transfer stream or 0 if not known.
 */
int Curl_conn_get_stream_error(struct Curl_easy *data,
                               struct connectdata *conn);

#ifdef CURLVERBOSE
void Curl_cfchain_trc(struct Curl_easy *data,
                      struct Curl_cfchain *chain, const char *info);
#endif

/*
 * Receive data on the connection.
 * Return CURLE_AGAIN iff blocked on receiving.
 */
CURLcode Curl_conn_recv(struct Curl_easy *data,
                        char *buf, size_t len,
                        size_t *pnread);

/*
 * Send data on the connection.
 * Return CURLE_AGAIN iff blocked on sending.
 */
CURLcode Curl_conn_send(struct Curl_easy *data,
                        const void *buf, size_t len, bool eos,
                        size_t *pnwritten);

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
struct cf_call_data {
  struct Curl_easy *data;
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

#define CF_DATA_SAVE(save, cf, data) \
  do { \
    (save) = CF_CTX_CALL_DATA(cf); \
    DEBUGASSERT(!(save).data || (save).depth > 0); \
    CF_CTX_CALL_DATA(cf).depth++;  \
    CF_CTX_CALL_DATA(cf).data = (struct Curl_easy *)CURL_UNCONST(data); \
  } while(0)

#define CF_DATA_RESTORE(cf, save) \
  do { \
    DEBUGASSERT(CF_CTX_CALL_DATA(cf).depth == (save).depth + 1); \
    DEBUGASSERT(!(save).data || (save).depth > 0); \
    CF_CTX_CALL_DATA(cf) = (save); \
  } while(0)

#else /* DEBUGBUILD */

#define CF_DATA_SAVE(save, cf, data) \
  do { \
    (save) = CF_CTX_CALL_DATA(cf); \
    CF_CTX_CALL_DATA(cf).data = (struct Curl_easy *)CURL_UNCONST(data); \
  } while(0)

#define CF_DATA_RESTORE(cf, save) \
  do { \
    CF_CTX_CALL_DATA(cf) = (save); \
  } while(0)

#endif /* !DEBUGBUILD */

#define CF_DATA_CURRENT(cf) ((cf) ? (CF_CTX_CALL_DATA(cf).data) : NULL)

#endif /* HEADER_CURL_CFILTERS_H */
