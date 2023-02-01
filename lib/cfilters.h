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


struct Curl_cfilter;
struct Curl_easy;
struct Curl_dns_entry;
struct connectdata;

/* Callback to destroy resources held by this filter instance.
 * Implementations MUST NOT chain calls to cf->next.
 */
typedef void     Curl_cft_destroy_this(struct Curl_cfilter *cf,
                                       struct Curl_easy *data);

typedef void     Curl_cft_close(struct Curl_cfilter *cf,
                                struct Curl_easy *data);

typedef CURLcode Curl_cft_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
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
typedef void     Curl_cft_get_host(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  const char **phost,
                                  const char **pdisplay_host,
                                  int *pport);

/* Filters may return sockets and fdset flags they are waiting for.
 * The passes array has room for up to MAX_SOCKSPEREASYHANDLE sockets.
 * @return read/write fdset for index in socks
 *         or GETSOCK_BLANK when nothing to wait on
 */
typedef int      Curl_cft_get_select_socks(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           curl_socket_t *socks);

typedef bool     Curl_cft_data_pending(struct Curl_cfilter *cf,
                                       const struct Curl_easy *data);

typedef ssize_t  Curl_cft_send(struct Curl_cfilter *cf,
                               struct Curl_easy *data, /* transfer */
                               const void *buf,        /* data to write */
                               size_t len,             /* amount to write */
                               CURLcode *err);         /* error to return */

typedef ssize_t  Curl_cft_recv(struct Curl_cfilter *cf,
                               struct Curl_easy *data, /* transfer */
                               char *buf,              /* store data here */
                               size_t len,             /* amount to read */
                               CURLcode *err);         /* error to return */

typedef bool     Curl_cft_conn_is_alive(struct Curl_cfilter *cf,
                                        struct Curl_easy *data);

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
/*      data event                          arg1       arg2     return */
#define CF_CTRL_DATA_ATTACH           1  /* 0          NULL     ignored */
#define CF_CTRL_DATA_DETACH           2  /* 0          NULL     ignored */
#define CF_CTRL_DATA_SETUP            4  /* 0          NULL     first fail */
#define CF_CTRL_DATA_IDLE             5  /* 0          NULL     first fail */
#define CF_CTRL_DATA_PAUSE            6  /* on/off     NULL     first fail */
#define CF_CTRL_DATA_DONE             7  /* premature  NULL     ignored */
#define CF_CTRL_DATA_DONE_SEND        8  /* 0          NULL     ignored */
/* update conn info at connection and data */
#define CF_CTRL_CONN_INFO_UPDATE (256+0) /* 0          NULL     ignored */
/* report conn statistics (timers) for connection and data */
#define CF_CTRL_CONN_REPORT_STATS (256+1) /* 0         NULL     ignored */

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
 * - CF_QUERY_SOCKET: the socket used by the filter chain
 */
/*      query                             res1       res2     */
#define CF_QUERY_MAX_CONCURRENT     1  /* number     -        */
#define CF_QUERY_CONNECT_REPLY_MS   2  /* number     -        */
#define CF_QUERY_SOCKET             3  /* -          curl_socket_t */

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
 */
#define CF_TYPE_IP_CONNECT  (1 << 0)
#define CF_TYPE_SSL         (1 << 1)
#define CF_TYPE_MULTIPLEX   (1 << 2)

/* A connection filter type, e.g. specific implementation. */
struct Curl_cftype {
  const char *name;                       /* name of the filter type */
  int flags;                              /* flags of filter type */
  int log_level;                          /* log level for such filters */
  Curl_cft_destroy_this *destroy;         /* destroy resources of this cf */
  Curl_cft_connect *connect;              /* establish connection */
  Curl_cft_close *close;                  /* close conn */
  Curl_cft_get_host *get_host;            /* host filter talks to */
  Curl_cft_get_select_socks *get_select_socks;/* sockets to select on */
  Curl_cft_data_pending *has_data_pending;/* conn has data pending */
  Curl_cft_send *do_send;                 /* send data */
  Curl_cft_recv *do_recv;                 /* receive data */
  Curl_cft_cntrl *cntrl;                  /* events/control */
  Curl_cft_conn_is_alive *is_alive;       /* FALSE if conn is dead, Jim! */
  Curl_cft_conn_keep_alive *keep_alive;   /* try to keep it alive */
  Curl_cft_query *query;                  /* query filter chain */
};

/* A connection filter instance, e.g. registered at a connection */
struct Curl_cfilter {
  const struct Curl_cftype *cft; /* the type providing implementation */
  struct Curl_cfilter *next;     /* next filter in chain */
  void *ctx;                     /* filter type specific settings */
  struct connectdata *conn;      /* the connection this filter belongs to */
  int sockindex;                 /* the index the filter is installed at */
  BIT(connected);                /* != 0 iff this filter is connected */
};

/* Default implementations for the type functions, implementing nop. */
void Curl_cf_def_destroy_this(struct Curl_cfilter *cf,
                              struct Curl_easy *data);

/* Default implementations for the type functions, implementing pass-through
 * the filter chain. */
void     Curl_cf_def_close(struct Curl_cfilter *cf, struct Curl_easy *data);
CURLcode Curl_cf_def_connect(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             bool blocking, bool *done);
void     Curl_cf_def_get_host(struct Curl_cfilter *cf, struct Curl_easy *data,
                              const char **phost, const char **pdisplay_host,
                              int *pport);
int      Curl_cf_def_get_select_socks(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      curl_socket_t *socks);
bool     Curl_cf_def_data_pending(struct Curl_cfilter *cf,
                                  const struct Curl_easy *data);
ssize_t  Curl_cf_def_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err);
ssize_t  Curl_cf_def_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err);
CURLcode Curl_cf_def_cntrl(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int event, int arg1, void *arg2);
bool     Curl_cf_def_conn_is_alive(struct Curl_cfilter *cf,
                                   struct Curl_easy *data);
CURLcode Curl_cf_def_conn_keep_alive(struct Curl_cfilter *cf,
                                     struct Curl_easy *data);
CURLcode Curl_cf_def_query(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           int query, int *pres1, void *pres2);

/**
 * Create a new filter instance, unattached to the filter chain.
 * Use Curl_conn_cf_add() to add it to the chain.
 * @param pcf  on success holds the created instance
 * @parm cft   the filter type
 * @param ctx  the type specific context to use
 */
CURLcode Curl_cf_create(struct Curl_cfilter **pcf,
                        const struct Curl_cftype *cft,
                        void *ctx);

/**
 * Add a filter instance to the `sockindex` filter chain at connection
 * `conn`. The filter must not already be attached. It is inserted at
 * the start of the chain (top).
 */
void Curl_conn_cf_add(struct Curl_easy *data,
                      struct connectdata *conn,
                      int sockindex,
                      struct Curl_cfilter *cf);

/**
 * Insert a filter (chain) after `cf_at`.
 * `cf_new` must not already be attached.
 */
void Curl_conn_cf_insert_after(struct Curl_cfilter *cf_at,
                               struct Curl_cfilter *cf_new);

/**
 * Discard, e.g. remove and destroy a specific filter instance.
 * If the filter is attached to a connection, it will be removed before
 * it is destroyed.
 */
void Curl_conn_cf_discard(struct Curl_cfilter *cf, struct Curl_easy *data);

/**
 * Discard all cfilters starting with `*pcf` and clearing it afterwards.
 */
void Curl_conn_cf_discard_chain(struct Curl_cfilter **pcf,
                                struct Curl_easy *data);

/**
 * Remove and destroy all filters at chain `sockindex` on connection `conn`.
 */
void Curl_conn_cf_discard_all(struct Curl_easy *data,
                              struct connectdata *conn,
                              int sockindex);


CURLcode Curl_conn_cf_connect(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool blocking, bool *done);
void Curl_conn_cf_close(struct Curl_cfilter *cf, struct Curl_easy *data);
int Curl_conn_cf_get_select_socks(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  curl_socket_t *socks);
bool Curl_conn_cf_data_pending(struct Curl_cfilter *cf,
                               const struct Curl_easy *data);
ssize_t Curl_conn_cf_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err);
ssize_t Curl_conn_cf_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err);
CURLcode Curl_conn_cf_cntrl(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            bool ignore_result,
                            int event, int arg1, void *arg2);

/**
 * Get the socket used by the filter chain starting at `cf`.
 * Returns CURL_SOCKET_BAD if not available.
 */
curl_socket_t Curl_conn_cf_get_socket(struct Curl_cfilter *cf,
                                      struct Curl_easy *data);


#define CURL_CF_SSL_DEFAULT  -1
#define CURL_CF_SSL_DISABLE  0
#define CURL_CF_SSL_ENABLE   1

/**
 * Bring the filter chain at `sockindex` for connection `data->conn` into
 * connected state. Which will set `*done` to TRUE.
 * This can be called on an already connected chain with no side effects.
 * When not `blocking`, calls may return without error and `*done != TRUE`,
 * while the individual filters negotiated the connection.
 */
CURLcode Curl_conn_connect(struct Curl_easy *data, int sockindex,
                           bool blocking, bool *done);

/**
 * Check if the filter chain at `sockindex` for connection `conn` is
 * completely connected.
 */
bool Curl_conn_is_connected(struct connectdata *conn, int sockindex);

/**
 * Determine if we have reached the remote host on IP level, e.g.
 * have a TCP connection. This turns TRUE before a possible SSL
 * handshake has been started/done.
 */
bool Curl_conn_is_ip_connected(struct Curl_easy *data, int sockindex);

/**
 * Determine if the connection is using SSL to the remote host
 * (or will be once connected). This will return FALSE, if SSL
 * is only used in proxying and not for the tunnel itself.
 */
bool Curl_conn_is_ssl(struct connectdata *conn, int sockindex);

/**
 * Connection provides multiplexing of easy handles at `socketindex`.
 */
bool Curl_conn_is_multiplex(struct connectdata *conn, int sockindex);

/**
 * Close the filter chain at `sockindex` for connection `data->conn`.
  * Filters remain in place and may be connected again afterwards.
 */
void Curl_conn_close(struct Curl_easy *data, int sockindex);

/**
 * Return if data is pending in some connection filter at chain
 * `sockindex` for connection `data->conn`.
 */
bool Curl_conn_data_pending(struct Curl_easy *data,
                            int sockindex);

/**
 * Return the socket used on data's connection for the index.
 * Returns CURL_SOCKET_BAD if not available.
 */
curl_socket_t Curl_conn_get_socket(struct Curl_easy *data, int sockindex);

/**
 * Get any select fd flags and the socket filters at chain `sockindex`
 * at connection `conn` might be waiting for.
 */
int Curl_conn_get_select_socks(struct Curl_easy *data, int sockindex,
                               curl_socket_t *socks);

/**
 * Receive data through the filter chain at `sockindex` for connection
 * `data->conn`. Copy at most `len` bytes into `buf`. Return the
 * actuel number of bytes copied or a negative value on error.
 * The error code is placed into `*code`.
 */
ssize_t Curl_conn_recv(struct Curl_easy *data, int sockindex, char *buf,
                       size_t len, CURLcode *code);

/**
 * Send `len` bytes of data from `buf` through the filter chain `sockindex`
 * at connection `data->conn`. Return the actual number of bytes written
 * or a negative value on error.
 * The error code is placed into `*code`.
 */
ssize_t Curl_conn_send(struct Curl_easy *data, int sockindex,
                       const void *buf, size_t len, CURLcode *code);

/**
 * The easy handle `data` is being attached to `conn`. This does
 * not mean that data will actually do a transfer. Attachment is
 * also used for temporary actions on the connection.
 */
void Curl_conn_ev_data_attach(struct connectdata *conn,
                              struct Curl_easy *data);

/**
 * The easy handle `data` is being detached (no longer served)
 * by connection `conn`. All filters are informed to release any resources
 * related to `data`.
 * Note: there may be several `data` attached to a connection at the same
 * time.
 */
void Curl_conn_ev_data_detach(struct connectdata *conn,
                              struct Curl_easy *data);

/**
 * Notify connection filters that they need to setup data for
 * a transfer.
 */
CURLcode Curl_conn_ev_data_setup(struct Curl_easy *data);

/**
 * Notify connection filters that now would be a good time to
 * perform any idle, e.g. time related, actions.
 */
CURLcode Curl_conn_ev_data_idle(struct Curl_easy *data);

/**
 * Notify connection filters that the transfer represented by `data`
 * is donw with sending data (e.g. has uploaded everything).
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
 * Inform connection filters to update their info in `conn`.
 */
void Curl_conn_ev_update_info(struct Curl_easy *data,
                              struct connectdata *conn);

/**
 * Inform connection filters to report statistics.
 */
void Curl_conn_ev_report_stats(struct Curl_easy *data,
                               struct connectdata *conn);

/**
 * Check if FIRSTSOCKET's cfilter chain deems connection alive.
 */
bool Curl_conn_is_alive(struct Curl_easy *data, struct connectdata *conn);

/**
 * Try to upkeep the connection filters at sockindex.
 */
CURLcode Curl_conn_keep_alive(struct Curl_easy *data,
                              struct connectdata *conn,
                              int sockindex);

void Curl_conn_get_host(struct Curl_easy *data, int sockindex,
                        const char **phost, const char **pdisplay_host,
                        int *pport);

/**
 * Get the maximum number of parallel transfers the connection
 * expects to be able to handle at `sockindex`.
 */
size_t Curl_conn_get_max_concurrent(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int sockindex);


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
    DEBUGASSERT((save).data == NULL || (save).depth > 0); \
    CF_CTX_CALL_DATA(cf).depth++;  \
    CF_CTX_CALL_DATA(cf).data = (struct Curl_easy *)data; \
  } while(0)

#define CF_DATA_RESTORE(cf, save) \
  do { \
    DEBUGASSERT(CF_CTX_CALL_DATA(cf).depth == (save).depth + 1); \
    DEBUGASSERT((save).data == NULL || (save).depth > 0); \
    CF_CTX_CALL_DATA(cf) = (save); \
  } while(0)

#else /* DEBUGBUILD */

#define CF_DATA_SAVE(save, cf, data) \
  do { \
    (save) = CF_CTX_CALL_DATA(cf); \
    CF_CTX_CALL_DATA(cf).data = (struct Curl_easy *)data; \
  } while(0)

#define CF_DATA_RESTORE(cf, save) \
  do { \
    CF_CTX_CALL_DATA(cf) = (save); \
  } while(0)

#endif /* !DEBUGBUILD */

#define CF_DATA_CURRENT(cf) \
  ((cf)? (CF_CTX_CALL_DATA(cf).data) : NULL)

#endif /* HEADER_CURL_CFILTERS_H */
