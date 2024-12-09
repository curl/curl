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

/* create a hash of the ssl connection paramter
 * Create a hash of printable chars for storage of TLS sessions suitable
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
CURLcode Curl_ssl_conn_hash_make(struct Curl_cfilter *cf,
                                 const struct ssl_peer *peer,
                                 char **phash);

/* Kill a single session ID entry in the cache
 * Sessionid mutex must be locked (see Curl_ssl_sessionid_lock).
 * This will call engine-specific curlssl_session_free function, which must
 * take sessionid object ownership from sessionid cache
 * (e.g. decrement refcount).
 */
void Curl_ssl_kill_session(struct Curl_ssl_session *entry);

/* extract a session ID
 * Sessionid mutex must be locked (see Curl_ssl_sessionid_lock).
 * Caller must make sure that the ownership of returned sessionid object
 * is properly taken (e.g. its refcount is incremented
 * under sessionid mutex).
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_conn_hash the key for lookup
 * @param session on return the TLS session
 * @param session_len  on return the size of the session data
 * @param palpn   on return the ALPN string used by the session,
 *                set to NULL when not interested
 */
bool Curl_ssl_get_session(struct Curl_cfilter *cf,
                          struct Curl_easy *data,
                          const char *ssl_conn_hash,
                          void **session, size_t *session_len,
                          char **palpn);

/* Add a TLS session for `ssl_conn_hash` to the cache. Replaces an existing
 * session ID with the same key.
 * Sessionid mutex must be locked (see Curl_ssl_sessionid_lock).
 * Call takes ownership of `session`, using `sessionid_free_cb`
 * to deallocate it. Is called in all outcomes, either right away or
 * later when the session cache is cleaned up.
 * Caller must ensure that it has properly shared ownership of this sessionid
 * object with cache (e.g. incrementing refcount on success)
 * @param cf      the connection filter wanting to use it
 * @param data    the transfer involved
 * @param ssl_conn_hash the key for lookup
 * @param session the TLS session data
 * @param session_len  on return the size of the session data
 * @param session_free_cb callback to free the session or NULL to use `free()`
 * @param alpn    the ALPN negotiated for the session or NULL
 */
CURLcode Curl_ssl_add_session(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const char *ssl_conn_hash,
                              void *session, size_t session_len,
                              Curl_ssl_sessionid_dtor *session_free_cb,
                              const char *alpn);

#endif /* USE_SSL */

#endif /* HEADER_CURL_VTLS_SPOOL_H */
