#ifndef HEADER_CURL_VTLS_INT_H
#define HEADER_CURL_VTLS_INT_H
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
#include "cfilters.h"
#include "urldata.h"

#ifdef USE_SSL

/* see https://www.iana.org/assignments/tls-extensiontype-values/ */
#define ALPN_HTTP_1_1_LENGTH 8
#define ALPN_HTTP_1_1 "http/1.1"
#define ALPN_HTTP_1_0_LENGTH 8
#define ALPN_HTTP_1_0 "http/1.0"
#define ALPN_H2_LENGTH 2
#define ALPN_H2 "h2"
#define ALPN_H3_LENGTH 2
#define ALPN_H3 "h3"

/* conservative sizes on the ALPN entries and count we are handling,
 * we can increase these if we ever feel the need or have to accommodate
 * ALPN strings from the "outside". */
#define ALPN_NAME_MAX     10
#define ALPN_ENTRIES_MAX  3
#define ALPN_PROTO_BUF_MAX   (ALPN_ENTRIES_MAX * (ALPN_NAME_MAX + 1))

struct alpn_spec {
  const char entries[ALPN_ENTRIES_MAX][ALPN_NAME_MAX];
  size_t count; /* number of entries */
};

struct alpn_proto_buf {
  unsigned char data[ALPN_PROTO_BUF_MAX];
  int len;
};

CURLcode Curl_alpn_to_proto_buf(struct alpn_proto_buf *buf,
                                const struct alpn_spec *spec);
CURLcode Curl_alpn_to_proto_str(struct alpn_proto_buf *buf,
                                const struct alpn_spec *spec);

CURLcode Curl_alpn_set_negotiated(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  const unsigned char *proto,
                                  size_t proto_len);

/* Information in each SSL cfilter context: cf->ctx */
struct ssl_connect_data {
  ssl_connection_state state;
  ssl_connect_state connecting_state;
  char *hostname;                   /* hostname for verification */
  char *dispname;                   /* display version of hostname */
  const struct alpn_spec *alpn;     /* ALPN to use or NULL for none */
  void *backend;                    /* vtls backend specific props */
  struct cf_call_data call_data;    /* data handle used in current call */
  struct curltime handshake_done;   /* time when handshake finished */
  int port;                         /* remote port at origin */
  BIT(use_alpn);                    /* if ALPN shall be used in handshake */
};


#undef CF_CTX_CALL_DATA
#define CF_CTX_CALL_DATA(cf)  \
  ((struct ssl_connect_data *)(cf)->ctx)->call_data


/* Definitions for SSL Implementations */

struct Curl_ssl {
  /*
   * This *must* be the first entry to allow returning the list of available
   * backends in curl_global_sslset().
   */
  curl_ssl_backend info;
  unsigned int supports; /* bitfield, see above */
  size_t sizeof_ssl_backend_data;

  int (*init)(void);
  void (*cleanup)(void);

  size_t (*version)(char *buffer, size_t size);
  int (*check_cxn)(struct Curl_cfilter *cf, struct Curl_easy *data);
  int (*shut_down)(struct Curl_cfilter *cf,
                   struct Curl_easy *data);
  bool (*data_pending)(struct Curl_cfilter *cf,
                       const struct Curl_easy *data);

  /* return 0 if a find random is filled in */
  CURLcode (*random)(struct Curl_easy *data, unsigned char *entropy,
                     size_t length);
  bool (*cert_status_request)(void);

  CURLcode (*connect_blocking)(struct Curl_cfilter *cf,
                               struct Curl_easy *data);
  CURLcode (*connect_nonblocking)(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *done);

  /* If the SSL backend wants to read or write on this connection during a
     handshake, set socks[0] to the connection's FIRSTSOCKET, and return
     a bitmap indicating read or write with GETSOCK_WRITESOCK(0) or
     GETSOCK_READSOCK(0). Otherwise return GETSOCK_BLANK.
     Mandatory. */
  int (*get_select_socks)(struct Curl_cfilter *cf, struct Curl_easy *data,
                          curl_socket_t *socks);

  void *(*get_internals)(struct ssl_connect_data *connssl, CURLINFO info);
  void (*close)(struct Curl_cfilter *cf, struct Curl_easy *data);
  void (*close_all)(struct Curl_easy *data);
  void (*session_free)(void *ptr);

  CURLcode (*set_engine)(struct Curl_easy *data, const char *engine);
  CURLcode (*set_engine_default)(struct Curl_easy *data);
  struct curl_slist *(*engines_list)(struct Curl_easy *data);

  bool (*false_start)(void);
  CURLcode (*sha256sum)(const unsigned char *input, size_t inputlen,
                    unsigned char *sha256sum, size_t sha256sumlen);

  bool (*attach_data)(struct Curl_cfilter *cf, struct Curl_easy *data);
  void (*detach_data)(struct Curl_cfilter *cf, struct Curl_easy *data);

  void (*free_multi_ssl_backend_data)(struct multi_ssl_backend_data *mbackend);

  ssize_t (*recv_plain)(struct Curl_cfilter *cf, struct Curl_easy *data,
                        char *buf, size_t len, CURLcode *code);
  ssize_t (*send_plain)(struct Curl_cfilter *cf, struct Curl_easy *data,
                        const void *mem, size_t len, CURLcode *code);

};

extern const struct Curl_ssl *Curl_ssl;


int Curl_none_init(void);
void Curl_none_cleanup(void);
int Curl_none_shutdown(struct Curl_cfilter *cf, struct Curl_easy *data);
int Curl_none_check_cxn(struct Curl_cfilter *cf, struct Curl_easy *data);
CURLcode Curl_none_random(struct Curl_easy *data, unsigned char *entropy,
                          size_t length);
void Curl_none_close_all(struct Curl_easy *data);
void Curl_none_session_free(void *ptr);
bool Curl_none_data_pending(struct Curl_cfilter *cf,
                            const struct Curl_easy *data);
bool Curl_none_cert_status_request(void);
CURLcode Curl_none_set_engine(struct Curl_easy *data, const char *engine);
CURLcode Curl_none_set_engine_default(struct Curl_easy *data);
struct curl_slist *Curl_none_engines_list(struct Curl_easy *data);
bool Curl_none_false_start(void);
int Curl_ssl_get_select_socks(struct Curl_cfilter *cf, struct Curl_easy *data,
                              curl_socket_t *socks);

/**
 * Get the ssl_config_data in `data` that is relevant for cfilter `cf`.
 */
struct ssl_config_data *Curl_ssl_cf_get_config(struct Curl_cfilter *cf,
                                               struct Curl_easy *data);

/**
 * Get the primary config relevant for the filter from its connection.
 */
struct ssl_primary_config *
  Curl_ssl_cf_get_primary_config(struct Curl_cfilter *cf);

/**
 * Get the first SSL filter in the chain starting with `cf`, or NULL.
 */
struct Curl_cfilter *Curl_ssl_cf_get_ssl(struct Curl_cfilter *cf);

/**
 * Get the SSL filter below the given one or NULL if there is none.
 */
bool Curl_ssl_cf_is_proxy(struct Curl_cfilter *cf);

/* extract a session ID
 * Sessionid mutex must be locked (see Curl_ssl_sessionid_lock).
 * Caller must make sure that the ownership of returned sessionid object
 * is properly taken (e.g. its refcount is incremented
 * under sessionid mutex).
 */
bool Curl_ssl_getsessionid(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           void **ssl_sessionid,
                           size_t *idsize); /* set 0 if unknown */
/* add a new session ID
 * Sessionid mutex must be locked (see Curl_ssl_sessionid_lock).
 * Caller must ensure that it has properly shared ownership of this sessionid
 * object with cache (e.g. incrementing refcount on success)
 */
CURLcode Curl_ssl_addsessionid(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               void *ssl_sessionid,
                               size_t idsize,
                               bool *added);

#include "openssl.h"        /* OpenSSL versions */
#include "gtls.h"           /* GnuTLS versions */
#include "nssg.h"           /* NSS versions */
#include "gskit.h"          /* Global Secure ToolKit versions */
#include "wolfssl.h"        /* wolfSSL versions */
#include "schannel.h"       /* Schannel SSPI version */
#include "sectransp.h"      /* SecureTransport (Darwin) version */
#include "mbedtls.h"        /* mbedTLS versions */
#include "bearssl.h"        /* BearSSL versions */
#include "rustls.h"         /* rustls versions */

#endif /* USE_SSL */

#endif /* HEADER_CURL_VTLS_INT_H */
