#ifndef HEADER_CURL_VTLS_H
#define HEADER_CURL_VTLS_H
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

struct connectdata;
struct ssl_config_data;
struct ssl_primary_config;
struct Curl_ssl_session;

#define SSLSUPP_CA_PATH      (1<<0) /* supports CAPATH */
#define SSLSUPP_CERTINFO     (1<<1) /* supports CURLOPT_CERTINFO */
#define SSLSUPP_PINNEDPUBKEY (1<<2) /* supports CURLOPT_PINNEDPUBLICKEY */
#define SSLSUPP_SSL_CTX      (1<<3) /* supports CURLOPT_SSL_CTX */
#define SSLSUPP_HTTPS_PROXY  (1<<4) /* supports access via HTTPS proxies */
#define SSLSUPP_TLS13_CIPHERSUITES (1<<5) /* supports TLS 1.3 ciphersuites */
#define SSLSUPP_CAINFO_BLOB  (1<<6)

#define ALPN_ACCEPTED "ALPN: server accepted "

#define VTLS_INFOF_NO_ALPN                                      \
  "ALPN: server did not agree on a protocol. Uses default."
#define VTLS_INFOF_ALPN_OFFER_1STR              \
  "ALPN: offers %s"
#define VTLS_INFOF_ALPN_ACCEPTED_1STR           \
  ALPN_ACCEPTED "%s"
#define VTLS_INFOF_ALPN_ACCEPTED_LEN_1STR       \
  ALPN_ACCEPTED "%.*s"

/* Curl_multi SSL backend-specific data; declared differently by each SSL
   backend */
struct multi_ssl_backend_data;
struct Curl_cfilter;

CURLsslset Curl_init_sslset_nolock(curl_sslbackend id, const char *name,
                                   const curl_ssl_backend ***avail);

#ifndef MAX_PINNED_PUBKEY_SIZE
#define MAX_PINNED_PUBKEY_SIZE 1048576 /* 1MB */
#endif

#ifndef CURL_SHA256_DIGEST_LENGTH
#define CURL_SHA256_DIGEST_LENGTH 32 /* fixed size */
#endif

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
 * we can increase these if we ever feel the need or have to accomodate
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

/**
 * Get the ALPN specification to use for talking to remote host.
 * May return NULL if ALPN is disabled on the connection.
 */
const struct alpn_spec *
Curl_alpn_get_spec(struct Curl_easy *data, struct connectdata *conn);

/**
 * Get the ALPN specification to use for talking to the proxy.
 * May return NULL if ALPN is disabled on the connection.
 */
const struct alpn_spec *
Curl_alpn_get_proxy_spec(struct Curl_easy *data, struct connectdata *conn);


char *Curl_ssl_snihost(struct Curl_easy *data, const char *host, size_t *olen);
bool Curl_ssl_config_matches(struct ssl_primary_config *data,
                             struct ssl_primary_config *needle);
bool Curl_clone_primary_ssl_config(struct ssl_primary_config *source,
                                   struct ssl_primary_config *dest);
void Curl_free_primary_ssl_config(struct ssl_primary_config *sslc);

curl_sslbackend Curl_ssl_backend(void);

#ifdef USE_SSL
int Curl_ssl_init(void);
void Curl_ssl_cleanup(void);
/* tell the SSL stuff to close down all open information regarding
   connections (and thus session ID caching etc) */
void Curl_ssl_close_all(struct Curl_easy *data);
CURLcode Curl_ssl_set_engine(struct Curl_easy *data, const char *engine);
/* Sets engine as default for all SSL operations */
CURLcode Curl_ssl_set_engine_default(struct Curl_easy *data);
struct curl_slist *Curl_ssl_engines_list(struct Curl_easy *data);

/* init the SSL session ID cache */
CURLcode Curl_ssl_initsessions(struct Curl_easy *, size_t);
void Curl_ssl_version(char *buffer, size_t size);

/* Certificate information list handling. */

void Curl_ssl_free_certinfo(struct Curl_easy *data);
CURLcode Curl_ssl_init_certinfo(struct Curl_easy *data, int num);
CURLcode Curl_ssl_push_certinfo_len(struct Curl_easy *data, int certnum,
                                    const char *label, const char *value,
                                    size_t valuelen);
CURLcode Curl_ssl_push_certinfo(struct Curl_easy *data, int certnum,
                                const char *label, const char *value);

/* Functions to be used by SSL library adaptation functions */

/* Lock session cache mutex.
 * Call this before calling other Curl_ssl_*session* functions
 * Caller should unlock this mutex as soon as possible, as it may block
 * other SSL connection from making progress.
 * The purpose of explicitly locking SSL session cache data is to allow
 * individual SSL engines to manage session lifetime in their specific way.
 */
void Curl_ssl_sessionid_lock(struct Curl_easy *data);

/* Unlock session cache mutex */
void Curl_ssl_sessionid_unlock(struct Curl_easy *data);

/* Kill a single session ID entry in the cache
 * Sessionid mutex must be locked (see Curl_ssl_sessionid_lock).
 * This will call engine-specific curlssl_session_free function, which must
 * take sessionid object ownership from sessionid cache
 * (e.g. decrement refcount).
 */
void Curl_ssl_kill_session(struct Curl_ssl_session *session);
/* delete a session from the cache
 * Sessionid mutex must be locked (see Curl_ssl_sessionid_lock).
 * This will call engine-specific curlssl_session_free function, which must
 * take sessionid object ownership from sessionid cache
 * (e.g. decrement refcount).
 */
void Curl_ssl_delsessionid(struct Curl_easy *data, void *ssl_sessionid);

/* get N random bytes into the buffer */
CURLcode Curl_ssl_random(struct Curl_easy *data, unsigned char *buffer,
                         size_t length);
/* Check pinned public key. */
CURLcode Curl_pin_peer_pubkey(struct Curl_easy *data,
                              const char *pinnedpubkey,
                              const unsigned char *pubkey, size_t pubkeylen);

bool Curl_ssl_cert_status_request(void);

bool Curl_ssl_false_start(struct Curl_easy *data);

void Curl_free_multi_ssl_backend_data(struct multi_ssl_backend_data *mbackend);

#define SSL_SHUTDOWN_TIMEOUT 10000 /* ms */

CURLcode Curl_ssl_cfilter_add(struct Curl_easy *data,
                              struct connectdata *conn,
                              int sockindex);

CURLcode Curl_cf_ssl_insert_after(struct Curl_cfilter *cf_at,
                                  struct Curl_easy *data);

CURLcode Curl_ssl_cfilter_remove(struct Curl_easy *data,
                                 int sockindex);

#ifndef CURL_DISABLE_PROXY
CURLcode Curl_ssl_cfilter_proxy_add(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int sockindex);
CURLcode Curl_cf_ssl_proxy_insert_after(struct Curl_cfilter *cf_at,
                                        struct Curl_easy *data);
#endif /* !CURL_DISABLE_PROXY */

/**
 * Get the SSL configuration that is used on the connection.
 * This returns NULL if no SSL is configured.
 * Otherwise it returns the config of the first (highest) one that is
 * either connected, in handshake or about to start
 * (e.g. all filters below it are connected). If SSL filters are present,
 * but neither can start operating, return the config of the lowest one
 * that will first come into effect when connecting.
 */
struct ssl_config_data *Curl_ssl_get_config(struct Curl_easy *data,
                                            int sockindex);

/**
 * Get the primary SSL configuration from the connection.
 * This returns NULL if no SSL is configured.
 * Otherwise it returns the config of the first (highest) one that is
 * either connected, in handshake or about to start
 * (e.g. all filters below it are connected). If SSL filters are present,
 * but neither can start operating, return the config of the lowest one
 * that will first come into effect when connecting.
 */
struct ssl_primary_config *
Curl_ssl_get_primary_config(struct Curl_easy *data,
                            struct connectdata *conn,
                            int sockindex);

/**
 * True iff the underlying SSL implementation supports the option.
 * Option is one of the defined SSLSUPP_* values.
 * `data` maybe NULL for the features of the default implementation.
 */
bool Curl_ssl_supports(struct Curl_easy *data, int ssl_option);

/**
 * Get the internal ssl instance (like OpenSSL's SSL*) from the filter
 * chain at `sockindex` of type specified by `info`.
 * For `n` == 0, the first active (top down) instance is returned.
 * 1 gives the second active, etc.
 * NULL is returned when no active SSL filter is present.
 */
void *Curl_ssl_get_internals(struct Curl_easy *data, int sockindex,
                             CURLINFO info, int n);

extern struct Curl_cftype Curl_cft_ssl;
extern struct Curl_cftype Curl_cft_ssl_proxy;

#else /* if not USE_SSL */

/* When SSL support is not present, just define away these function calls */
#define Curl_ssl_init() 1
#define Curl_ssl_cleanup() Curl_nop_stmt
#define Curl_ssl_close_all(x) Curl_nop_stmt
#define Curl_ssl_set_engine(x,y) CURLE_NOT_BUILT_IN
#define Curl_ssl_set_engine_default(x) CURLE_NOT_BUILT_IN
#define Curl_ssl_engines_list(x) NULL
#define Curl_ssl_initsessions(x,y) CURLE_OK
#define Curl_ssl_free_certinfo(x) Curl_nop_stmt
#define Curl_ssl_kill_session(x) Curl_nop_stmt
#define Curl_ssl_random(x,y,z) ((void)x, CURLE_NOT_BUILT_IN)
#define Curl_ssl_cert_status_request() FALSE
#define Curl_ssl_false_start(a) FALSE
#define Curl_ssl_get_internals(a,b,c,d) NULL
#define Curl_ssl_supports(a,b) FALSE
#define Curl_ssl_cfilter_add(a,b,c) CURLE_NOT_BUILT_IN
#define Curl_ssl_cfilter_proxy_add(a,b,c) CURLE_NOT_BUILT_IN
#define Curl_ssl_get_config(a,b) NULL
#define Curl_ssl_cfilter_remove(a,b) CURLE_OK
#endif

#endif /* HEADER_CURL_VTLS_H */
