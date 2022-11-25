#ifndef HEADER_CURL_CFILTERS_H
#define HEADER_CURL_CFILTERS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* Setup the connection for `data`, using destination `remotehost`.
 */
typedef CURLcode Curl_cft_setup(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const struct Curl_dns_entry *remotehost);
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

typedef void     Curl_cft_attach_data(struct Curl_cfilter *cf,
                                      struct Curl_easy *data);
typedef void     Curl_cft_detach_data(struct Curl_cfilter *cf,
                                      struct Curl_easy *data);

/**
 * The easy handle `data` is being detached (no longer served)
 * by connection `conn`. All filters are informed to release any resources
 * related to `data`.
 * Note: there may be several `data` attached to a connection at the same
 * time.
 */
void Curl_conn_detach(struct connectdata *conn, struct Curl_easy *data);

#define CF_TYPE_IP_CONNECT  (1 << 0)
#define CF_TYPE_SSL         (1 << 1)

/* A connection filter type, e.g. specific implementation. */
struct Curl_cftype {
  const char *name;                       /* name of the filter type */
  long flags;                             /* flags of filter type */
  Curl_cft_destroy_this *destroy;         /* destroy resources of this cf */
  Curl_cft_setup *setup;                  /* setup for a connection */
  Curl_cft_connect *connect;              /* establish connection */
  Curl_cft_close *close;                  /* close conn */
  Curl_cft_get_host *get_host;            /* host filter talks to */
  Curl_cft_get_select_socks *get_select_socks;/* sockets to select on */
  Curl_cft_data_pending *has_data_pending;/* conn has data pending */
  Curl_cft_send *do_send;                 /* send data */
  Curl_cft_recv *do_recv;                 /* receive data */
  Curl_cft_attach_data *attach_data;      /* data is being handled here */
  Curl_cft_detach_data *detach_data;      /* data is no longer handled here */
};

/* A connection filter instance, e.g. registered at a connection */
struct Curl_cfilter {
  const struct Curl_cftype *cft; /* the type providing implementation */
  struct Curl_cfilter *next;     /* next filter in chain */
  void *ctx;                     /* filter type specific settings */
  struct connectdata *conn;      /* the connection this filter belongs to */
  int sockindex;                 /* TODO: like to get rid off this */
  BIT(connected);                /* != 0 iff this filter is connected */
};

/* Default implementations for the type functions, implementing nop. */
void Curl_cf_def_destroy_this(struct Curl_cfilter *cf,
                              struct Curl_easy *data);

/* Default implementations for the type functions, implementing pass-through
 * the filter chain. */
CURLcode Curl_cf_def_setup(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           const struct Curl_dns_entry *remotehost);
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
void     Curl_cf_def_attach_data(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);
void     Curl_cf_def_detach_data(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);

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
 * `data->conn`. The filter must not already be attached. It is inserted at
 * the start of the chain (top).
 */
void Curl_conn_cf_add(struct Curl_easy *data,
                      struct connectdata *conn,
                      int sockindex,
                      struct Curl_cfilter *cf);

/**
 * Remove and destroy all filters at chain `sockindex` on connection `conn`.
 */
void Curl_conn_cf_discard_all(struct Curl_easy *data,
                              struct connectdata *conn,
                              int sockindex);

/**
 * Discard, e.g. remove and destroy a specific filter instance.
 * If the filter is attached to a connection, it will be removed before
 * it is destroyed.
 */
void Curl_conn_cf_discard(struct Curl_cfilter *cf, struct Curl_easy *data);


ssize_t Curl_conn_cf_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err);
ssize_t Curl_conn_cf_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t len, CURLcode *err);

#define CURL_CF_SSL_DEFAULT  -1
#define CURL_CF_SSL_DISABLE  0
#define CURL_CF_SSL_ENABLE   1

/**
 * Setup the filter chain at `sockindex` in connection `conn`, invoking
 * the instance `setup(remotehost)` methods. If no filter chain is
 * installed yet, inspects the configuration in `data` to install a
 * suitable filter chain.
 */
CURLcode Curl_conn_setup(struct Curl_easy *data,
                         struct connectdata *conn,
                         int sockindex,
                         const struct Curl_dns_entry *remotehost,
                         int ssl_mode);

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
bool Curl_conn_is_ssl(struct Curl_easy *data, int sockindex);

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
 * The easy handle `data` is being attached (served) by connection `conn`.
 * All filters are informed to adapt to handling `data`.
 * Note: there may be several `data` attached to a connection at the same
 * time.
 */
void Curl_conn_attach_data(struct connectdata *conn,
                           struct Curl_easy *data);

/**
 * The easy handle `data` is being detached (no longer served)
 * by connection `conn`. All filters are informed to release any resources
 * related to `data`.
 * Note: there may be several `data` attached to a connection at the same
 * time.
 */
void Curl_conn_detach_data(struct connectdata *conn,
                           struct Curl_easy *data);

void Curl_conn_get_host(struct Curl_easy *data, int sockindex,
                        const char **phost, const char **pdisplay_host,
                        int *pport);


#endif /* HEADER_CURL_CFILTERS_H */
