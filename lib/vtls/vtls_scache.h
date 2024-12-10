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
#include "curl_setup.h"
#include "cfilters.h"
#include "urldata.h"

#ifdef USE_SSL

struct Curl_cfilter;
struct Curl_easy;
struct Curl_ssl_scache;

/* Create a session cache for up to max_entries SSL sessions */
CURLcode Curl_ssl_scache_create(size_t max_entries,
                                struct Curl_ssl_scache **pscache);

void Curl_ssl_scache_destroy(struct Curl_ssl_scache *scache);

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

/* Create a cryptographic hash of all SSL relevant paramters used
 * for the connection filter instance.
 * @param cf      the connection filter wanting to use it
 * @param peer    the peer the filter wants to talk to
 * @param phash   on successful return, the hash generated
 */
CURLcode Curl_ssl_scache_conn_hash(struct Curl_cfilter *cf,
                                   const struct ssl_peer *peer,
                                   char **phash);

/* Get TLS session data from the cache.
 * scache mutex must be locked (see Curl_ssl_scache_lock).
 * Caller must make sure that the ownership of returned session object
 * is properly taken (e.g. its refcount is incremented
 * under scache mutex).
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_conn_hash the key for lookup
 * @param sdata   on return the TLS session
 * @param sdata_len  on return the amount of bytes in sdata
 * @param palpn   on return the ALPN string used by the session,
 *                set to NULL when not interested
 */
bool Curl_ssl_scache_get(struct Curl_cfilter *cf,
                         struct Curl_easy *data,
                         const char *ssl_conn_hash,
                         unsigned char **sdata,
                         size_t *sdata_len,
                         char **palpn);

/* Add TLS session data to the cache.
 * Replaces an existing session data/object with the same hash.
 * scache mutex must be locked (see Curl_ssl_scache_lock).
 * Call takes ownership of `sdata` (must be allocated) in all outcomes.
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_conn_hash the key for lookup
 * @param sdata   the TLS session data, plain bytes
 * @param sdata_len the length of the TLS session data
 * @param alpn    the ALPN negotiated for the session or NULL
 */
CURLcode Curl_ssl_scache_add(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             const char *ssl_conn_hash,
                             unsigned char *sdata,
                             size_t sdata_len,
                             const char *alpn);

/* Get TLS session object from the cache.
 * scache mutex must be locked (see Curl_ssl_scache_lock).
 * Caller must make sure that the ownership of returned session object
 * is properly taken (e.g. its refcount is incremented
 * under scache mutex).
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_conn_hash the key for lookup
 * @param sdata   on return the TLS session
 * @param sdata_len  on return the amount of bytes in sdata
 * @param palpn   on return the ALPN string used by the session,
 *                set to NULL when not interested
 */
bool Curl_ssl_scache_get_obj(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             const char *ssl_conn_hash,
                             unsigned char **sobj,
                             char **palpn);

typedef void Curl_ssl_scache_obj_dtor(void *sobj);

/* Add a TLS session object to the cache.
 * Replaces an existing session data/object with the same hash.
 * scache mutex must be locked (see Curl_ssl_scache_lock).
 * Call takes ownership of `sobj`, using `sobj_dtor_cb`
 * to deallocate it. Is called in all outcomes, either right away or
 * later when the session cache is cleaned up.
 * Caller must ensure that it has properly shared ownership of `sobj`
 * with cache (e.g. incrementing refcount on success)
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_conn_hash the key for lookup
 * @param sobj    the TLS session object
 * @param sobj_free_cb callback to free the session objectt
 * @param alpn    the ALPN negotiated for the session or NULL
 */
CURLcode Curl_ssl_scache_add_obj(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const char *ssl_conn_hash,
                                 void *sobj,
                                 Curl_ssl_scache_obj_dtor *sobj_dtor_cb,
                                 const char *alpn);

/* Remove any session matching the hash from the cache.
 */
void Curl_ssl_scache_remove(struct Curl_easy *data,
                            const char *ssl_conn_hash);

#else /* USE_SSL */

#define Curl_ssl_scache_create(x,y) CURLE_OK
#define Curl_ssl_scache_destroy(x) CURLE_OK

#endif /* USE_SSL (else) */

#endif /* HEADER_CURL_VTLS_SCACHE_H */
