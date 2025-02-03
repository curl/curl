#ifndef HEADER_FETCH_VTLS_H
#define HEADER_FETCH_VTLS_H
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

struct connectdata;
struct ssl_config_data;
struct ssl_primary_config;
struct Fetch_cfilter;
struct Fetch_easy;
struct dynbuf;

#define SSLSUPP_CA_PATH (1 << 0)            /* supports CAPATH */
#define SSLSUPP_CERTINFO (1 << 1)           /* supports FETCHOPT_CERTINFO */
#define SSLSUPP_PINNEDPUBKEY (1 << 2)       /* supports FETCHOPT_PINNEDPUBLICKEY */
#define SSLSUPP_SSL_CTX (1 << 3)            /* supports FETCHOPT_SSL_CTX */
#define SSLSUPP_HTTPS_PROXY (1 << 4)        /* supports access via HTTPS proxies */
#define SSLSUPP_TLS13_CIPHERSUITES (1 << 5) /* supports TLS 1.3 ciphersuites */
#define SSLSUPP_CAINFO_BLOB (1 << 6)
#define SSLSUPP_ECH (1 << 7)
#define SSLSUPP_CA_CACHE (1 << 8)
#define SSLSUPP_CIPHER_LIST (1 << 9) /* supports TLS 1.0-1.2 ciphersuites */

#ifdef USE_ECH
#include "fetch_base64.h"
#define ECH_ENABLED(__data__) \
  (__data__->set.tls_ech &&   \
   !(__data__->set.tls_ech & FETCHECH_DISABLE))
#endif /* USE_ECH */

#define ALPN_ACCEPTED "ALPN: server accepted "

#define VTLS_INFOF_NO_ALPN \
  "ALPN: server did not agree on a protocol. Uses default."
#define VTLS_INFOF_ALPN_OFFER_1STR \
  "ALPN: fetch offers %s"
#define VTLS_INFOF_ALPN_ACCEPTED \
  ALPN_ACCEPTED "%.*s"

#define VTLS_INFOF_NO_ALPN_DEFERRED \
  "ALPN: deferred handshake for early data without specific protocol."
#define VTLS_INFOF_ALPN_DEFERRED \
  "ALPN: deferred handshake for early data using '%.*s'."

/* IETF defined version numbers used in TLS protocol negotiation */
#define FETCH_IETF_PROTO_UNKNOWN 0x0
#define FETCH_IETF_PROTO_SSL3 0x0300
#define FETCH_IETF_PROTO_TLS1 0x0301
#define FETCH_IETF_PROTO_TLS1_1 0x0302
#define FETCH_IETF_PROTO_TLS1_2 0x0303
#define FETCH_IETF_PROTO_TLS1_3 0x0304
#define FETCH_IETF_PROTO_DTLS1 0xFEFF
#define FETCH_IETF_PROTO_DTLS1_2 0xFEFD

typedef enum
{
  FETCH_SSL_PEER_DNS,
  FETCH_SSL_PEER_IPV4,
  FETCH_SSL_PEER_IPV6
} ssl_peer_type;

struct ssl_peer
{
  char *hostname;     /* hostname for verification */
  char *dispname;     /* display version of hostname */
  char *sni;          /* SNI version of hostname or NULL if not usable */
  char *scache_key;   /* for lookups in session cache */
  ssl_peer_type type; /* type of the peer information */
  int port;           /* port we are talking to */
  int transport;      /* one of TRNSPRT_* defines */
};

FETCHsslset Fetch_init_sslset_nolock(fetch_sslbackend id, const char *name,
                                    const fetch_ssl_backend ***avail);

#ifndef MAX_PINNED_PUBKEY_SIZE
#define MAX_PINNED_PUBKEY_SIZE 1048576 /* 1MB */
#endif

#ifndef FETCH_SHA256_DIGEST_LENGTH
#define FETCH_SHA256_DIGEST_LENGTH 32 /* fixed size */
#endif

fetch_sslbackend Fetch_ssl_backend(void);

/**
 * Init ssl config for a new easy handle.
 */
void Fetch_ssl_easy_config_init(struct Fetch_easy *data);

/**
 * Init the `data->set.ssl` and `data->set.proxy_ssl` for
 * connection matching use.
 */
FETCHcode Fetch_ssl_easy_config_complete(struct Fetch_easy *data);

/**
 * Init SSL configs (main + proxy) for a new connection from the easy handle.
 */
FETCHcode Fetch_ssl_conn_config_init(struct Fetch_easy *data,
                                    struct connectdata *conn);

/**
 * Free allocated resources in SSL configs (main + proxy) for
 * the given connection.
 */
void Fetch_ssl_conn_config_cleanup(struct connectdata *conn);

/**
 * Return TRUE iff SSL configuration from `data` is functionally the
 * same as the one on `candidate`.
 * @param proxy   match the proxy SSL config or the main one
 */
bool Fetch_ssl_conn_config_match(struct Fetch_easy *data,
                                struct connectdata *candidate,
                                bool proxy);

/* Update certain connection SSL config flags after they have
 * been changed on the easy handle. Will work for `verifypeer`,
 * `verifyhost` and `verifystatus`. */
void Fetch_ssl_conn_config_update(struct Fetch_easy *data, bool for_proxy);

/**
 * Init SSL peer information for filter. Can be called repeatedly.
 */
FETCHcode Fetch_ssl_peer_init(struct ssl_peer *peer,
                             struct Fetch_cfilter *cf,
                             const char *tls_id,
                             int transport);
/**
 * Free all allocated data and reset peer information.
 */
void Fetch_ssl_peer_cleanup(struct ssl_peer *peer);

#ifdef USE_SSL
int Fetch_ssl_init(void);
void Fetch_ssl_cleanup(void);
/* tell the SSL stuff to close down all open information regarding
   connections (and thus session ID caching etc) */
void Fetch_ssl_close_all(struct Fetch_easy *data);
FETCHcode Fetch_ssl_set_engine(struct Fetch_easy *data, const char *engine);
/* Sets engine as default for all SSL operations */
FETCHcode Fetch_ssl_set_engine_default(struct Fetch_easy *data);
struct fetch_slist *Fetch_ssl_engines_list(struct Fetch_easy *data);

void Fetch_ssl_version(char *buffer, size_t size);

/* Certificate information list handling. */
#define FETCH_X509_STR_MAX 100000

void Fetch_ssl_free_certinfo(struct Fetch_easy *data);
FETCHcode Fetch_ssl_init_certinfo(struct Fetch_easy *data, int num);
FETCHcode Fetch_ssl_push_certinfo_len(struct Fetch_easy *data, int certnum,
                                     const char *label, const char *value,
                                     size_t valuelen);
FETCHcode Fetch_ssl_push_certinfo(struct Fetch_easy *data, int certnum,
                                 const char *label, const char *value);

/* Functions to be used by SSL library adaptation functions */

/* get N random bytes into the buffer */
FETCHcode Fetch_ssl_random(struct Fetch_easy *data, unsigned char *buffer,
                          size_t length);
/* Check pinned public key. */
FETCHcode Fetch_pin_peer_pubkey(struct Fetch_easy *data,
                               const char *pinnedpubkey,
                               const unsigned char *pubkey, size_t pubkeylen);

bool Fetch_ssl_cert_status_request(void);

bool Fetch_ssl_false_start(void);

/* The maximum size of the SSL channel binding is 85 bytes, as defined in
 * RFC 5929, Section 4.1. The 'tls-server-end-point:' prefix is 21 bytes long,
 * and SHA-512 is the longest supported hash algorithm, with a digest length of
 * 64 bytes.
 * The maximum size of the channel binding is therefore 21 + 64 = 85 bytes.
 */
#define SSL_CB_MAX_SIZE 85

/* Return the tls-server-end-point channel binding, including the
 * 'tls-server-end-point:' prefix.
 * If successful, the data is written to the dynbuf, and FETCHE_OK is returned.
 * The dynbuf MUST HAVE a minimum toobig size of SSL_CB_MAX_SIZE.
 * If the dynbuf is too small, FETCHE_OUT_OF_MEMORY is returned.
 * If channel binding is not supported, binding stays empty and FETCHE_OK is
 * returned.
 */
FETCHcode Fetch_ssl_get_channel_binding(struct Fetch_easy *data, int sockindex,
                                       struct dynbuf *binding);

#define SSL_SHUTDOWN_TIMEOUT 10000 /* ms */

FETCHcode Fetch_ssl_cfilter_add(struct Fetch_easy *data,
                               struct connectdata *conn,
                               int sockindex);

FETCHcode Fetch_cf_ssl_insert_after(struct Fetch_cfilter *cf_at,
                                   struct Fetch_easy *data);

FETCHcode Fetch_ssl_cfilter_remove(struct Fetch_easy *data,
                                  int sockindex, bool send_shutdown);

#ifndef FETCH_DISABLE_PROXY
FETCHcode Fetch_cf_ssl_proxy_insert_after(struct Fetch_cfilter *cf_at,
                                         struct Fetch_easy *data);
#endif /* !FETCH_DISABLE_PROXY */

/**
 * True iff the underlying SSL implementation supports the option.
 * Option is one of the defined SSLSUPP_* values.
 * `data` maybe NULL for the features of the default implementation.
 */
bool Fetch_ssl_supports(struct Fetch_easy *data, unsigned int ssl_option);

/**
 * Get the internal ssl instance (like OpenSSL's SSL*) from the filter
 * chain at `sockindex` of type specified by `info`.
 * For `n` == 0, the first active (top down) instance is returned.
 * 1 gives the second active, etc.
 * NULL is returned when no active SSL filter is present.
 */
void *Fetch_ssl_get_internals(struct Fetch_easy *data, int sockindex,
                             FETCHINFO info, int n);

/**
 * Get the ssl_config_data in `data` that is relevant for cfilter `cf`.
 */
struct ssl_config_data *Fetch_ssl_cf_get_config(struct Fetch_cfilter *cf,
                                               struct Fetch_easy *data);

/**
 * Get the primary config relevant for the filter from its connection.
 */
struct ssl_primary_config *
Fetch_ssl_cf_get_primary_config(struct Fetch_cfilter *cf);

extern struct Fetch_cftype Fetch_cft_ssl;
#ifndef FETCH_DISABLE_PROXY
extern struct Fetch_cftype Fetch_cft_ssl_proxy;
#endif

#else /* if not USE_SSL */

/* When SSL support is not present, just define away these function calls */
#define Fetch_ssl_init() 1
#define Fetch_ssl_cleanup() Fetch_nop_stmt
#define Fetch_ssl_close_all(x) Fetch_nop_stmt
#define Fetch_ssl_set_engine(x, y) FETCHE_NOT_BUILT_IN
#define Fetch_ssl_set_engine_default(x) FETCHE_NOT_BUILT_IN
#define Fetch_ssl_engines_list(x) NULL
#define Fetch_ssl_free_certinfo(x) Fetch_nop_stmt
#define Fetch_ssl_random(x, y, z) ((void)x, FETCHE_NOT_BUILT_IN)
#define Fetch_ssl_cert_status_request() FALSE
#define Fetch_ssl_false_start() FALSE
#define Fetch_ssl_get_internals(a, b, c, d) NULL
#define Fetch_ssl_supports(a, b) FALSE
#define Fetch_ssl_cfilter_add(a, b, c) FETCHE_NOT_BUILT_IN
#define Fetch_ssl_cfilter_remove(a, b, c) FETCHE_OK
#define Fetch_ssl_cf_get_config(a, b) NULL
#define Fetch_ssl_cf_get_primary_config(a) NULL
#endif

#endif /* HEADER_FETCH_VTLS_H */
