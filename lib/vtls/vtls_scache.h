#ifndef HEADER_CURL_VTLS_SCACHE_H
#define HEADER_CURL_VTLS_SCACHE_H
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
#include "../curl_setup.h"
#include "../cfilters.h"
#include "../urldata.h"

#ifdef USE_SSL

struct Curl_cfilter;
struct Curl_easy;
struct Curl_ssl_scache;
struct Curl_ssl_session;
struct ssl_peer;

/* RFC 8446 (TLSv1.3) restrict lifetime to one week max, for
 * other, less secure versions, we restrict it to a day */
#define CURL_SCACHE_MAX_13_LIFETIME_SEC    (60*60*24*7)
#define CURL_SCACHE_MAX_12_LIFETIME_SEC    (60*60*24)

/* Create a session cache for up to max_peers endpoints with a total
 * of up to max_sessions SSL sessions per peer */
CURLcode Curl_ssl_scache_create(size_t max_peers,
                                size_t max_sessions_per_peer,
                                struct Curl_ssl_scache **pscache);

void Curl_ssl_scache_destroy(struct Curl_ssl_scache *scache);

/* Create a key from peer and TLS configuration information that is
 * unique for how the connection filter wants to establish a TLS
 * connection to the peer.
 * If the filter is a TLS proxy filter, it will use the proxy relevant
 * information.
 * @param cf      the connection filter wanting to use it
 * @param peer    the peer the filter wants to talk to
 * @param tls_id  identifier of TLS implementation for sessions. Should
 *                include full version if session data from other versions
 *                is to be avoided.
 * @param ppeer_key on successful return, the key generated
 */
CURLcode Curl_ssl_peer_key_make(struct Curl_cfilter *cf,
                                const struct ssl_peer *peer,
                                const char *tls_id,
                                char **ppeer_key);

/* Lock session cache mutex.
 * Call this before calling other Curl_ssl_*session* functions
 * Caller should unlock this mutex as soon as possible, as it may block
 * other SSL connection from making progress.
 * The purpose of explicitly locking SSL session cache data is to allow
 * individual SSL engines to manage session lifetime in their specific way.
 */
void Curl_ssl_scache_lock(struct Curl_easy *data);

/* Unlock session cache mutex */
void Curl_ssl_scache_unlock(struct Curl_easy *data);

/* Get TLS session object from the cache for the ssl_peer_ey.
 * scache mutex must be locked (see Curl_ssl_scache_lock).
 * Caller must make sure that the ownership of returned session object
 * is properly taken (e.g. its refcount is incremented
 * under scache mutex).
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_peer_key the key for lookup
 * @retval sobj   the object for the peer key or NULL
 */
void *Curl_ssl_scache_get_obj(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const char *ssl_peer_key);

typedef void Curl_ssl_scache_obj_dtor(void *sobj);

/* Add a TLS session related object to the cache.
 * Replaces an existing object with the same peer_key.
 * scache mutex must be locked (see Curl_ssl_scache_lock).
 * Call takes ownership of `sobj`, using `sobj_dtor_cb`
 * to deallocate it. Is called in all outcomes, either right away or
 * later when the session cache is cleaned up.
 * Caller must ensure that it has properly shared ownership of `sobj`
 * with cache (e.g. incrementing refcount on success)
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_peer_key the key for lookup
 * @param sobj    the TLS session object
 * @param sobj_free_cb callback to free the session objectt
 */
CURLcode Curl_ssl_scache_add_obj(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const char *ssl_peer_key,
                                 void *sobj,
                                 Curl_ssl_scache_obj_dtor *sobj_dtor_cb);

/* All about an SSL session ticket */
struct Curl_ssl_session {
  const void *sdata;           /* session ticket data, plain bytes */
  size_t sdata_len;            /* number of bytes in sdata */
  curl_off_t valid_until;      /* seconds since EPOCH until ticket expires */
  int ietf_tls_id;             /* TLS protocol identifier negotiated */
  char *alpn;                  /* APLN TLS negotiated protocol string */
  size_t earlydata_max;        /* max 0-RTT data supported by peer */
  const unsigned char *quic_tp; /* Optional QUIC transport param bytes */
  size_t quic_tp_len;          /* number of bytes in quic_tp */
  struct Curl_llist_node list; /*  internal storage handling */
};

/* Create a `session` instance. Does NOT need locking.
 * Takes ownership of `sdata` and `sobj` regardless of return code.
 * @param sdata     bytes of SSL session data or NULL (sobj then required)
 * @param sdata_len amount of session data bytes
 * @param ietf_tls_id  IETF protocol version, e.g. 0x304 for TLSv1.3
 * @param alpn      ALPN protocol selected or NULL
 * @param valid_until seconds since EPOCH when session expires, pass 0
 *                  in case this is not known.
 * @param psession on return the scached session instance created
 */
CURLcode
Curl_ssl_session_create(void *sdata, size_t sdata_len,
                        int ietf_tls_id, const char *alpn,
                        curl_off_t valid_until,
                        size_t earlydata_max,
                        struct Curl_ssl_session **psession);

/* Variation of session creation with quic transport parameter bytes,
 * Takes ownership of `quic_tp` regardless of return code. */
CURLcode
Curl_ssl_session_create2(void *sdata, size_t sdata_len,
                         int ietf_tls_id, const char *alpn,
                         curl_off_t valid_until,
                         size_t earlydata_max,
                         unsigned char *quic_tp, size_t quic_tp_len,
                         struct Curl_ssl_session **psession);

/* Destroy a `session` instance. Can be called with NULL.
 * Does NOT need locking. */
void Curl_ssl_session_destroy(struct Curl_ssl_session *s);

/* Put the scache session into the cache. Does NOT need locking.
 * Call takes ownership of `s` in all outcomes.
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_peer_key the key for lookup
 * @param s       the scache session object
 */
CURLcode Curl_ssl_scache_put(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             const char *ssl_peer_key,
                             struct Curl_ssl_session *s);

/* Take a matching scache session from the cache. Does NOT need locking.
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_peer_key the key for lookup
 * @param s       on return, the scache session object or NULL
 */
CURLcode Curl_ssl_scache_take(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const char *ssl_peer_key,
                              struct Curl_ssl_session **ps);

/* Return a taken scache session to the cache. Does NOT need locking.
 * Depending on TLS version and other criteria, it may cache it again
 * or destroy it. Maybe called with a NULL session.
 */
void Curl_ssl_scache_return(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            const char *ssl_peer_key,
                            struct Curl_ssl_session *s);

/* Remove all sessions and obj for the peer_key. Does NOT need locking. */
void Curl_ssl_scache_remove_all(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const char *ssl_peer_key);

#ifdef USE_SSLS_EXPORT

CURLcode Curl_ssl_session_import(struct Curl_easy *data,
                                 const char *ssl_peer_key,
                                 const unsigned char *shmac, size_t shmac_len,
                                 const void *sdata, size_t sdata_len);

CURLcode Curl_ssl_session_export(struct Curl_easy *data,
                                 curl_ssls_export_cb *export_fn,
                                 void *userptr);

#endif /* USE_SSLS_EXPORT */
#endif /* USE_SSL */

#endif /* HEADER_CURL_VTLS_SCACHE_H */
