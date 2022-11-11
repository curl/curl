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

/* Destroy a filter instance. Implementations MUST NOT chain calls to cf->next.
 */
typedef void     Curl_cf_destroy(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);

/* Setup the connection for `data`, using destination `remotehost`.
 */
typedef CURLcode Curl_cf_setup(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const struct Curl_dns_entry *remotehost);
typedef void     Curl_cf_close(struct Curl_cfilter *cf,
                               struct Curl_easy *data);

typedef CURLcode Curl_cf_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool blocking, bool *done);

/* Filters may return sockets and fdset flags they are waiting for.
 * The passes array has room for up to MAX_SOCKSPEREASYHANDLE sockets.
 * @return read/write fdset for index in socks
 *         or GETSOCK_BLANK when nothing to wait on
 */
typedef int      Curl_cf_get_select_socks(struct Curl_cfilter *cf,
                                          struct Curl_easy *data,
                                          curl_socket_t *socks);

typedef bool     Curl_cf_data_pending(struct Curl_cfilter *cf,
                                      const struct Curl_easy *data);

typedef ssize_t  Curl_cf_send(struct Curl_cfilter *cf,
                              struct Curl_easy *data, /* transfer */
                              const void *buf,        /* data to write */
                              size_t len,             /* max amount to write */
                              CURLcode *err);         /* error to return */

typedef ssize_t  Curl_cf_recv(struct Curl_cfilter *cf,
                              struct Curl_easy *data, /* transfer */
                              char *buf,              /* store data here */
                              size_t len,             /* max amount to read */
                              CURLcode *err);         /* error to return */

typedef void     Curl_cf_attach_data(struct Curl_cfilter *cf,
                                     struct Curl_easy *data);
typedef void     Curl_cf_detach_data(struct Curl_cfilter *cf,
                                     struct Curl_easy *data);

/**
 * The easy handle `data` is being detached (no longer served)
 * by connection `conn`. All filters are informed to release any resources
 * related to `data`.
 * Note: there may be several `data` attached to a connection at the same
 * time.
 */
void Curl_cfilter_detach(struct connectdata *conn, struct Curl_easy *data);

/* A connection filter type, e.g. specific implementation. */
struct Curl_cftype {
  const char *name;                      /* name of the filter type */
  Curl_cf_destroy *destroy;              /* destroy resources held */
  Curl_cf_attach_data *attach_data;      /* data is being handled here */
  Curl_cf_detach_data *detach_data;      /* data is no longer handled here */
  Curl_cf_setup *setup;                  /* setup for a connection */
  Curl_cf_close *close;                  /* close conn */
  Curl_cf_connect *connect;              /* establish connection */
  Curl_cf_get_select_socks *get_select_socks;/* sockets to select on */
  Curl_cf_data_pending *has_data_pending;/* conn has data pending */
  Curl_cf_send *do_send;                 /* send data */
  Curl_cf_recv *do_recv;                 /* receive data */
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
void Curl_cf_def_destroy(struct Curl_cfilter *cf,
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


CURLcode Curl_cfilter_create(struct Curl_cfilter **pcf,
                             struct Curl_easy *data,
                             struct connectdata *conn,
                             int sockindex,
                             const struct Curl_cftype *cft,
                             void *ctx);

void Curl_cfilter_destroy(struct Curl_easy *data,
                          struct connectdata *conn, int index);

void Curl_cfilter_add(struct Curl_easy *data,
                      struct connectdata *conn, int index,
                      struct Curl_cfilter *cf);


#define CURL_CF_SSL_DEFAULT  -1
#define CURL_CF_SSL_DISABLE  0
#define CURL_CF_SSL_ENABLE   1

CURLcode Curl_cfilter_setup(struct Curl_easy *data,
                            struct connectdata *conn, int sockindex,
                            const struct Curl_dns_entry *remotehost,
                            int ssl_mode);
CURLcode Curl_cfilter_connect(struct Curl_easy *data,
                              struct connectdata *conn, int sockindex,
                              bool blocking, bool *done);
bool Curl_cfilter_is_connected(struct Curl_easy *data,
                               struct connectdata *conn, int sockindex);

void Curl_cfilter_close(struct Curl_easy *data,
                        struct connectdata *conn, int index);

bool Curl_cfilter_data_pending(const struct Curl_easy *data,
                               struct connectdata *conn, int sockindex);

/**
 * Get any select fd flags and the socket filters might be waiting for.
 */
int Curl_cfilter_get_select_socks(struct Curl_easy *data,
                                  struct connectdata *conn, int sockindex,
                                  curl_socket_t *socks);

/* Helper function to migrate conn->recv, conn->send callback to filters */
ssize_t Curl_cfilter_recv(struct Curl_easy *data, int num, char *buf,
                          size_t len, CURLcode *code);
ssize_t Curl_cfilter_send(struct Curl_easy *data, int num,
                          const void *mem, size_t len, CURLcode *code);

/**
 * The easy handle `data` is being attached (served) by connection `conn`.
 * All filters are informed to adapt to handling `data`.
 * Note: there may be several `data` attached to a connection at the same
 * time.
 */
void Curl_cfilter_attach_data(struct connectdata *conn,
                              struct Curl_easy *data);

/**
 * The easy handle `data` is being detached (no longer served)
 * by connection `conn`. All filters are informed to release any resources
 * related to `data`.
 * Note: there may be several `data` attached to a connection at the same
 * time.
 */
void Curl_cfilter_detach_data(struct connectdata *conn,
                              struct Curl_easy *data);

#endif /* HEADER_CURL_CFILTERS_H */
