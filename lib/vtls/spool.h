#ifndef HEADER_CURL_VTLS_SPOOL_H
#define HEADER_CURL_VTLS_SPOOL_H
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
struct Curl_ssl_spool;

/* Create a session pool for up to max_entries SSL sessions */
CURLcode Curl_ssl_spool_create(size_t max_entries,
                               struct Curl_ssl_spool **pspool);

void Curl_ssl_spool_destroy(struct Curl_ssl_spool *spool);

/* Lock session pool mutex.
 * Call this before calling other Curl_ssl_*session* functions
 * Caller should unlock this mutex as soon as possible, as it may block
 * other SSL connection from making progress.
 * The purpose of explicitly locking SSL session cache data is to allow
 * individual SSL engines to manage session lifetime in their specific way.
 */
void Curl_ssl_spool_lock(struct Curl_easy *data);

/* Unlock session pool mutex */
void Curl_ssl_spool_unlock(struct Curl_easy *data);

/* Create a hash of printable chars for storage of TLS sessions suitable
 * for the given connection filter and peer. The key will reflect the
 * SSL config for the filter's connection (ssl verssions/options/ciphers etc.).
 * Config options using relative paths will be converted to absolute
 * ones. config options involving BLOBs will add the SHA256 hash of the
 * BLOB. In such configurations the key is not guarantueed to be unique,
 * but collisions are highly unlikely since they would involve the same
 * peer and matching other config options.
 * @param cf      the connection filter wanting to use it
 * @param peer    the peer the filter wants to talk to
 * @param phash   on successfull return, the hash generated
 */
CURLcode Curl_ssl_spool_hash(struct Curl_cfilter *cf,
                             const struct ssl_peer *peer,
                             char **phash);

/* extract a TLS session
 * spool mutex must be locked (see Curl_ssl_spool_lock).
 * Caller must make sure that the ownership of returned session object
 * is properly taken (e.g. its refcount is incremented
 * under spool mutex).
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_conn_hash the key for lookup
 * @param session on return the TLS session
 * @param session_len  on return the size of the session data
 * @param palpn   on return the ALPN string used by the session,
 *                set to NULL when not interested
 */
bool Curl_ssl_spool_get(struct Curl_cfilter *cf,
                        struct Curl_easy *data,
                        const char *ssl_conn_hash,
                        void **session, size_t *session_len,
                        char **palpn);

/* Add a TLS session for `ssl_conn_hash` to the pool. Replaces an existing
 * session with the same hash.
 * spool mutex must be locked (see Curl_ssl_spool_lock).
 * Call takes ownership of `session`, using `session_free_cb`
 * to deallocate it. Is called in all outcomes, either right away or
 * later when the session cache is cleaned up.
 * Caller must ensure that it has properly shared ownership of this session
 * object with cache (e.g. incrementing refcount on success)
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_conn_hash the key for lookup
 * @param session the TLS session data
 * @param session_len  on return the size of the session data
 * @param session_free_cb callback to free the session or NULL to use `free()`
 * @param alpn    the ALPN negotiated for the session or NULL
 */
CURLcode Curl_ssl_spool_add(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            const char *ssl_conn_hash,
                            void *session, size_t session_len,
                            Curl_ssl_session_dtor *session_free_cb,
                            const char *alpn);

#else /* USE_SSL */

#define Curl_ssl_spool_create(x,y) CURLE_OK
#define Curl_ssl_spool_destroy(x) CURLE_OK

#endif /* USE_SSL (else) */

#endif /* HEADER_CURL_VTLS_SPOOL_H */
