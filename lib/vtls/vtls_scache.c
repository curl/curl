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

#ifdef USE_SSL

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "../urldata.h"
#include "../cfilters.h"

#include "vtls.h" /* generic SSL protos etc */
#include "vtls_int.h"
#include "vtls_scache.h"
#include "vtls_spack.h"

#include "../strcase.h"
#include "../url.h"
#include "../llist.h"
#include "../share.h"
#include "../curl_trc.h"
#include "../curl_sha256.h"
#include "../rand.h"
#include "../curlx/warnless.h"
#include "../curl_printf.h"
#include "../strdup.h"

/* The last #include files should be: */
#include "../curl_memory.h"
#include "../memdebug.h"


static bool cf_ssl_peer_key_is_global(const char *peer_key);

/* a peer+tls-config we cache sessions for */
struct Curl_ssl_scache_peer {
  char *ssl_peer_key;      /* id for peer + relevant TLS configuration */
  char *clientcert;
  char *srp_username;
  char *srp_password;
  struct Curl_llist sessions;
  void *sobj;              /* object instance or NULL */
  Curl_ssl_scache_obj_dtor *sobj_free; /* free `sobj` callback */
  unsigned char key_salt[CURL_SHA256_DIGEST_LENGTH]; /* for entry export */
  unsigned char key_hmac[CURL_SHA256_DIGEST_LENGTH]; /* for entry export */
  size_t max_sessions;
  long age;                /* just a number, the higher the more recent */
  BIT(hmac_set);           /* if key_salt and key_hmac are present */
  BIT(exportable);         /* sessions for this peer can be exported */
};

#define CURL_SCACHE_MAGIC 0x000e1551

#define GOOD_SCACHE(x) ((x) && (x)->magic == CURL_SCACHE_MAGIC)

struct Curl_ssl_scache {
  unsigned int magic;
  struct Curl_ssl_scache_peer *peers;
  size_t peer_count;
  int default_lifetime_secs;
  long age;
};

static struct Curl_ssl_scache *cf_ssl_scache_get(struct Curl_easy *data)
{
  struct Curl_ssl_scache *scache = NULL;
  /* If a share is present, its ssl_scache has preference over the multi */
  if(data->share && data->share->ssl_scache)
    scache = data->share->ssl_scache;
  else if(data->multi && data->multi->ssl_scache)
    scache = data->multi->ssl_scache;
  if(scache && !GOOD_SCACHE(scache)) {
    failf(data, "transfer would use an invalid scache at %p, denied",
          (void *)scache);
    DEBUGASSERT(0);
    return NULL;
  }
  return scache;
}

static void cf_ssl_scache_session_ldestroy(void *udata, void *obj)
{
  struct Curl_ssl_session *s = obj;
  (void)udata;
  free(CURL_UNCONST(s->sdata));
  free(CURL_UNCONST(s->quic_tp));
  free((void *)s->alpn);
  free(s);
}

CURLcode
Curl_ssl_session_create(void *sdata, size_t sdata_len,
                        int ietf_tls_id, const char *alpn,
                        curl_off_t valid_until, size_t earlydata_max,
                        struct Curl_ssl_session **psession)
{
  return Curl_ssl_session_create2(sdata, sdata_len, ietf_tls_id, alpn,
                                  valid_until, earlydata_max,
                                  NULL, 0, psession);
}

CURLcode
Curl_ssl_session_create2(void *sdata, size_t sdata_len,
                         int ietf_tls_id, const char *alpn,
                         curl_off_t valid_until, size_t earlydata_max,
                         unsigned char *quic_tp, size_t quic_tp_len,
                         struct Curl_ssl_session **psession)
{
  struct Curl_ssl_session *s;

  if(!sdata || !sdata_len) {
    free(sdata);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  *psession = NULL;
  s = calloc(1, sizeof(*s));
  if(!s) {
    free(sdata);
    free(quic_tp);
    return CURLE_OUT_OF_MEMORY;
  }

  s->ietf_tls_id = ietf_tls_id;
  s->valid_until = valid_until;
  s->earlydata_max = earlydata_max;
  s->sdata = sdata;
  s->sdata_len = sdata_len;
  s->quic_tp = quic_tp;
  s->quic_tp_len = quic_tp_len;
  if(alpn) {
    s->alpn = strdup(alpn);
    if(!s->alpn) {
      cf_ssl_scache_session_ldestroy(NULL, s);
      return CURLE_OUT_OF_MEMORY;
    }
  }
  *psession = s;
  return CURLE_OK;
}

void Curl_ssl_session_destroy(struct Curl_ssl_session *s)
{
  if(s) {
    /* if in the list, the list destructor takes care of it */
    if(Curl_node_llist(&s->list))
      Curl_node_remove(&s->list);
    else {
      cf_ssl_scache_session_ldestroy(NULL, s);
    }
  }
}

static void cf_ssl_scache_clear_peer(struct Curl_ssl_scache_peer *peer)
{
  Curl_llist_destroy(&peer->sessions, NULL);
  if(peer->sobj) {
    DEBUGASSERT(peer->sobj_free);
    if(peer->sobj_free)
      peer->sobj_free(peer->sobj);
    peer->sobj = NULL;
  }
  peer->sobj_free = NULL;
  Curl_safefree(peer->clientcert);
#ifdef USE_TLS_SRP
  Curl_safefree(peer->srp_username);
  Curl_safefree(peer->srp_password);
#endif
  Curl_safefree(peer->ssl_peer_key);
  peer->age = 0;
  peer->hmac_set = FALSE;
}

static void cf_ssl_scache_peer_set_obj(struct Curl_ssl_scache_peer *peer,
                                       void *sobj,
                                       Curl_ssl_scache_obj_dtor *sobj_free)
{
  DEBUGASSERT(peer);
  if(peer->sobj_free) {
    peer->sobj_free(peer->sobj);
  }
  peer->sobj = sobj;
  peer->sobj_free = sobj_free;
}

static void cf_ssl_cache_peer_update(struct Curl_ssl_scache_peer *peer)
{
  /* The sessions of this peer are exportable if
   * - it has no confidential information
   * - its peer key is not yet known, because sessions were
   *   imported using only the salt+hmac
   * - the peer key is global, e.g. carrying no relative paths */
  peer->exportable = (!peer->clientcert && !peer->srp_username &&
                      !peer->srp_password &&
                      (!peer->ssl_peer_key ||
                       cf_ssl_peer_key_is_global(peer->ssl_peer_key)));
}

static CURLcode
cf_ssl_scache_peer_init(struct Curl_ssl_scache_peer *peer,
                        const char *ssl_peer_key,
                        const char *clientcert,
                        const char *srp_username,
                        const char *srp_password,
                        const unsigned char *salt,
                        const unsigned char *hmac)
{
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(!peer->ssl_peer_key);
  if(ssl_peer_key) {
    peer->ssl_peer_key = strdup(ssl_peer_key);
    if(!peer->ssl_peer_key)
      goto out;
    peer->hmac_set = FALSE;
  }
  else if(salt && hmac) {
    memcpy(peer->key_salt, salt, sizeof(peer->key_salt));
    memcpy(peer->key_hmac, hmac, sizeof(peer->key_hmac));
    peer->hmac_set = TRUE;
  }
  else {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  if(clientcert) {
    peer->clientcert = strdup(clientcert);
    if(!peer->clientcert)
      goto out;
  }
  if(srp_username) {
    peer->srp_username = strdup(srp_username);
    if(!peer->srp_username)
      goto out;
  }
  if(srp_password) {
    peer->srp_password = strdup(srp_password);
    if(!peer->srp_password)
      goto out;
  }

  cf_ssl_cache_peer_update(peer);
  result = CURLE_OK;
out:
  if(result)
    cf_ssl_scache_clear_peer(peer);
  return result;
}

static void cf_scache_session_remove(struct Curl_ssl_scache_peer *peer,
                                     struct Curl_ssl_session *s)
{
  (void)peer;
  DEBUGASSERT(Curl_node_llist(&s->list) == &peer->sessions);
  Curl_ssl_session_destroy(s);
}

static bool cf_scache_session_expired(struct Curl_ssl_session *s,
                                      curl_off_t now)
{
  return (s->valid_until > 0) && (s->valid_until < now);
}

static void cf_scache_peer_remove_expired(struct Curl_ssl_scache_peer *peer,
                                          curl_off_t now)
{
  struct Curl_llist_node *n = Curl_llist_head(&peer->sessions);
  while(n) {
    struct Curl_ssl_session *s = Curl_node_elem(n);
    n = Curl_node_next(n);
    if(cf_scache_session_expired(s, now))
      cf_scache_session_remove(peer, s);
  }
}

static void cf_scache_peer_remove_non13(struct Curl_ssl_scache_peer *peer)
{
  struct Curl_llist_node *n = Curl_llist_head(&peer->sessions);
  while(n) {
    struct Curl_ssl_session *s = Curl_node_elem(n);
    n = Curl_node_next(n);
    if(s->ietf_tls_id != CURL_IETF_PROTO_TLS1_3)
      cf_scache_session_remove(peer, s);
  }
}

CURLcode Curl_ssl_scache_create(size_t max_peers,
                                size_t max_sessions_per_peer,
                                struct Curl_ssl_scache **pscache)
{
  struct Curl_ssl_scache *scache;
  struct Curl_ssl_scache_peer *peers;
  size_t i;

  *pscache = NULL;
  peers = calloc(max_peers, sizeof(*peers));
  if(!peers)
    return CURLE_OUT_OF_MEMORY;

  scache = calloc(1, sizeof(*scache));
  if(!scache) {
    free(peers);
    return CURLE_OUT_OF_MEMORY;
  }

  scache->magic = CURL_SCACHE_MAGIC;
  scache->default_lifetime_secs = (24*60*60); /* 1 day */
  scache->peer_count = max_peers;
  scache->peers = peers;
  scache->age = 1;
  for(i = 0; i < scache->peer_count; ++i) {
    scache->peers[i].max_sessions = max_sessions_per_peer;
    Curl_llist_init(&scache->peers[i].sessions,
                    cf_ssl_scache_session_ldestroy);
  }

  *pscache = scache;
  return CURLE_OK;
}

void Curl_ssl_scache_destroy(struct Curl_ssl_scache *scache)
{
  if(scache && GOOD_SCACHE(scache)) {
    size_t i;
    scache->magic = 0;
    for(i = 0; i < scache->peer_count; ++i) {
      cf_ssl_scache_clear_peer(&scache->peers[i]);
    }
    free(scache->peers);
    free(scache);
  }
}

/* Lock shared SSL session data */
void Curl_ssl_scache_lock(struct Curl_easy *data)
{
  if(CURL_SHARE_ssl_scache(data))
    Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
}

/* Unlock shared SSL session data */
void Curl_ssl_scache_unlock(struct Curl_easy *data)
{
  if(CURL_SHARE_ssl_scache(data))
    Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);
}

static CURLcode cf_ssl_peer_key_add_path(struct dynbuf *buf,
                                          const char *name,
                                          char *path,
                                          bool *is_local)
{
  if(path && path[0]) {
    /* We try to add absolute paths, so that the session key can stay
     * valid when used in another process with different CWD. However,
     * when a path does not exist, this does not work. Then, we add
     * the path as is. */
#ifdef UNDER_CE
    (void)is_local;
    return curlx_dyn_addf(buf, ":%s-%s", name, path);
#elif defined(_WIN32)
    char abspath[_MAX_PATH];
    if(_fullpath(abspath, path, _MAX_PATH))
      return curlx_dyn_addf(buf, ":%s-%s", name, abspath);
    *is_local = TRUE;
#elif defined(HAVE_REALPATH)
    if(path[0] != '/') {
      char *abspath = realpath(path, NULL);
      if(abspath) {
        CURLcode r = curlx_dyn_addf(buf, ":%s-%s", name, abspath);
        (free)(abspath); /* allocated by libc, free without memdebug */
        return r;
      }
      *is_local = TRUE;
    }
#endif
    return curlx_dyn_addf(buf, ":%s-%s", name, path);
  }
  return CURLE_OK;
}

static CURLcode cf_ssl_peer_key_add_hash(struct dynbuf *buf,
                                          const char *name,
                                          struct curl_blob *blob)
{
  CURLcode r = CURLE_OK;
  if(blob && blob->len) {
    unsigned char hash[CURL_SHA256_DIGEST_LENGTH];
    size_t i;

    r = curlx_dyn_addf(buf, ":%s-", name);
    if(r)
      goto out;
    r = Curl_sha256it(hash, blob->data, blob->len);
    if(r)
      goto out;
    for(i = 0; i < CURL_SHA256_DIGEST_LENGTH; ++i) {
      r = curlx_dyn_addf(buf, "%02x", hash[i]);
      if(r)
        goto out;
    }
  }
out:
  return r;
}

#define CURL_SSLS_LOCAL_SUFFIX     ":L"
#define CURL_SSLS_GLOBAL_SUFFIX    ":G"

static bool cf_ssl_peer_key_is_global(const char *peer_key)
{
  size_t len = peer_key ? strlen(peer_key) : 0;
  return (len > 2) &&
         (peer_key[len - 1] == 'G') &&
         (peer_key[len - 2] == ':');
}

CURLcode Curl_ssl_peer_key_make(struct Curl_cfilter *cf,
                                const struct ssl_peer *peer,
                                const char *tls_id,
                                char **ppeer_key)
{
  struct ssl_primary_config *ssl = Curl_ssl_cf_get_primary_config(cf);
  struct dynbuf buf;
  size_t key_len;
  bool is_local = FALSE;
  CURLcode r;

  *ppeer_key = NULL;
  curlx_dyn_init(&buf, 10 * 1024);

  r = curlx_dyn_addf(&buf, "%s:%d", peer->hostname, peer->port);
  if(r)
    goto out;

  switch(peer->transport) {
  case TRNSPRT_TCP:
    break;
  case TRNSPRT_UDP:
    r = curlx_dyn_add(&buf, ":UDP");
    break;
  case TRNSPRT_QUIC:
    r = curlx_dyn_add(&buf, ":QUIC");
    break;
  case TRNSPRT_UNIX:
    r = curlx_dyn_add(&buf, ":UNIX");
    break;
  default:
    r = curlx_dyn_addf(&buf, ":TRNSPRT-%d", peer->transport);
    break;
  }
  if(r)
    goto out;

  if(!ssl->verifypeer) {
    r = curlx_dyn_add(&buf, ":NO-VRFY-PEER");
    if(r)
      goto out;
  }
  if(!ssl->verifyhost) {
    r = curlx_dyn_add(&buf, ":NO-VRFY-HOST");
    if(r)
      goto out;
  }
  if(ssl->verifystatus) {
    r = curlx_dyn_add(&buf, ":VRFY-STATUS");
    if(r)
      goto out;
  }
  if(!ssl->verifypeer || !ssl->verifyhost) {
    if(cf->conn->bits.conn_to_host) {
      r = curlx_dyn_addf(&buf, ":CHOST-%s", cf->conn->conn_to_host.name);
      if(r)
        goto out;
    }
    if(cf->conn->bits.conn_to_port) {
      r = curlx_dyn_addf(&buf, ":CPORT-%d", cf->conn->conn_to_port);
      if(r)
        goto out;
    }
  }

  if(ssl->version || ssl->version_max) {
    r = curlx_dyn_addf(&buf, ":TLSVER-%d-%d", ssl->version,
                      (ssl->version_max >> 16));
    if(r)
      goto out;
  }
  if(ssl->ssl_options) {
    r = curlx_dyn_addf(&buf, ":TLSOPT-%x", ssl->ssl_options);
    if(r)
      goto out;
  }
  if(ssl->cipher_list) {
    r = curlx_dyn_addf(&buf, ":CIPHER-%s", ssl->cipher_list);
    if(r)
      goto out;
  }
  if(ssl->cipher_list13) {
    r = curlx_dyn_addf(&buf, ":CIPHER13-%s", ssl->cipher_list13);
    if(r)
      goto out;
  }
  if(ssl->curves) {
    r = curlx_dyn_addf(&buf, ":CURVES-%s", ssl->curves);
    if(r)
      goto out;
  }
  if(ssl->verifypeer) {
    r = cf_ssl_peer_key_add_path(&buf, "CA", ssl->CAfile, &is_local);
    if(r)
      goto out;
    r = cf_ssl_peer_key_add_path(&buf, "CApath", ssl->CApath, &is_local);
    if(r)
      goto out;
    r = cf_ssl_peer_key_add_path(&buf, "CRL", ssl->CRLfile, &is_local);
    if(r)
      goto out;
    r = cf_ssl_peer_key_add_path(&buf, "Issuer", ssl->issuercert, &is_local);
    if(r)
      goto out;
    if(ssl->cert_blob) {
      r = cf_ssl_peer_key_add_hash(&buf, "CertBlob", ssl->cert_blob);
      if(r)
        goto out;
    }
    if(ssl->ca_info_blob) {
      r = cf_ssl_peer_key_add_hash(&buf, "CAInfoBlob", ssl->ca_info_blob);
      if(r)
        goto out;
    }
    if(ssl->issuercert_blob) {
      r = cf_ssl_peer_key_add_hash(&buf, "IssuerBlob", ssl->issuercert_blob);
      if(r)
        goto out;
    }
  }
  if(ssl->pinned_key && ssl->pinned_key[0]) {
    r = curlx_dyn_addf(&buf, ":Pinned-%s", ssl->pinned_key);
    if(r)
      goto out;
  }

  if(ssl->clientcert && ssl->clientcert[0]) {
    r = curlx_dyn_add(&buf, ":CCERT");
    if(r)
      goto out;
  }
#ifdef USE_TLS_SRP
  if(ssl->username || ssl->password) {
    r = curlx_dyn_add(&buf, ":SRP-AUTH");
    if(r)
      goto out;
  }
#endif

  if(!tls_id || !tls_id[0]) {
    r = CURLE_FAILED_INIT;
    goto out;
  }
  r = curlx_dyn_addf(&buf, ":IMPL-%s", tls_id);
  if(r)
    goto out;

  r = curlx_dyn_addf(&buf, is_local ?
                     CURL_SSLS_LOCAL_SUFFIX : CURL_SSLS_GLOBAL_SUFFIX);
  if(r)
    goto out;

  *ppeer_key = curlx_dyn_take(&buf, &key_len);
  /* we just added printable char, and dynbuf always null-terminates, no need
   * to track length */

out:
  curlx_dyn_free(&buf);
  return r;
}

static bool cf_ssl_scache_match_auth(struct Curl_ssl_scache_peer *peer,
                                     struct ssl_primary_config *conn_config)
{
  if(!conn_config) {
    if(peer->clientcert)
      return FALSE;
#ifdef USE_TLS_SRP
    if(peer->srp_username || peer->srp_password)
      return FALSE;
#endif
    return TRUE;
  }
  else if(!Curl_safecmp(peer->clientcert, conn_config->clientcert))
    return FALSE;
#ifdef USE_TLS_SRP
   if(Curl_timestrcmp(peer->srp_username, conn_config->username) ||
      Curl_timestrcmp(peer->srp_password, conn_config->password))
     return FALSE;
#endif
  return TRUE;
}

static CURLcode
cf_ssl_find_peer_by_key(struct Curl_easy *data,
                        struct Curl_ssl_scache *scache,
                        const char *ssl_peer_key,
                        struct ssl_primary_config *conn_config,
                        struct Curl_ssl_scache_peer **ppeer)
{
  size_t i, peer_key_len = 0;
  CURLcode result = CURLE_OK;

  *ppeer = NULL;
  if(!GOOD_SCACHE(scache)) {
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  CURL_TRC_SSLS(data, "find peer slot for %s among %zu slots",
                ssl_peer_key, scache->peer_count);

  /* check for entries with known peer_key */
  for(i = 0; scache && i < scache->peer_count; i++) {
    if(scache->peers[i].ssl_peer_key &&
       strcasecompare(ssl_peer_key, scache->peers[i].ssl_peer_key) &&
       cf_ssl_scache_match_auth(&scache->peers[i], conn_config)) {
      /* yes, we have a cached session for this! */
      *ppeer = &scache->peers[i];
      goto out;
    }
  }
  /* check for entries with HMAC set but no known peer_key */
  for(i = 0; scache && i < scache->peer_count; i++) {
    if(!scache->peers[i].ssl_peer_key &&
       scache->peers[i].hmac_set &&
       cf_ssl_scache_match_auth(&scache->peers[i], conn_config)) {
      /* possible entry with unknown peer_key, check hmac */
      unsigned char my_hmac[CURL_SHA256_DIGEST_LENGTH];
      if(!peer_key_len) /* we are lazy */
        peer_key_len = strlen(ssl_peer_key);
      result = Curl_hmacit(&Curl_HMAC_SHA256,
                           scache->peers[i].key_salt,
                           sizeof(scache->peers[i].key_salt),
                           (const unsigned char *)ssl_peer_key,
                           peer_key_len,
                           my_hmac);
      if(result)
        goto out;
      if(!memcmp(scache->peers[i].key_hmac, my_hmac, sizeof(my_hmac))) {
        /* remember peer_key for future lookups */
        CURL_TRC_SSLS(data, "peer entry %zu key recovered: %s",
                      i, ssl_peer_key);
        scache->peers[i].ssl_peer_key = strdup(ssl_peer_key);
        if(!scache->peers[i].ssl_peer_key) {
          result = CURLE_OUT_OF_MEMORY;
          goto out;
        }
        cf_ssl_cache_peer_update(&scache->peers[i]);
        *ppeer = &scache->peers[i];
        goto out;
      }
    }
  }
  CURL_TRC_SSLS(data, "peer not found for %s", ssl_peer_key);
out:
  return result;
}

static struct Curl_ssl_scache_peer *
cf_ssl_get_free_peer(struct Curl_ssl_scache *scache)
{
  struct Curl_ssl_scache_peer *peer = NULL;
  size_t i;

  /* find empty or oldest peer */
  for(i = 0; i < scache->peer_count; ++i) {
    /* free peer entry? */
    if(!scache->peers[i].ssl_peer_key && !scache->peers[i].hmac_set) {
      peer = &scache->peers[i];
      break;
    }
    /* peer without sessions and obj */
    if(!scache->peers[i].sobj &&
       !Curl_llist_count(&scache->peers[i].sessions)) {
      peer = &scache->peers[i];
      break;
    }
    /* remember "oldest" peer */
    if(!peer || (scache->peers[i].age < peer->age)) {
      peer = &scache->peers[i];
    }
  }
  DEBUGASSERT(peer);
  if(peer)
    cf_ssl_scache_clear_peer(peer);
  return peer;
}

static CURLcode
cf_ssl_add_peer(struct Curl_easy *data,
                struct Curl_ssl_scache *scache,
                const char *ssl_peer_key,
                struct ssl_primary_config *conn_config,
                struct Curl_ssl_scache_peer **ppeer)
{
  struct Curl_ssl_scache_peer *peer = NULL;
  CURLcode result = CURLE_OK;

  *ppeer = NULL;
  if(ssl_peer_key) {
    result = cf_ssl_find_peer_by_key(data, scache, ssl_peer_key, conn_config,
                                     &peer);
    if(result || !scache->peer_count)
      return result;
  }

  if(peer) {
    *ppeer = peer;
    return CURLE_OK;
  }

  peer = cf_ssl_get_free_peer(scache);
  if(peer) {
    const char *ccert = conn_config ? conn_config->clientcert : NULL;
    const char *username = NULL, *password = NULL;
#ifdef USE_TLS_SRP
    username = conn_config ? conn_config->username : NULL;
    password = conn_config ? conn_config->password : NULL;
#endif
    result = cf_ssl_scache_peer_init(peer, ssl_peer_key, ccert,
                                     username, password, NULL, NULL);
    if(result)
      goto out;
    /* all ready */
    *ppeer = peer;
    result = CURLE_OK;
  }

out:
  if(result) {
    cf_ssl_scache_clear_peer(peer);
  }
  return result;
}

static void cf_scache_peer_add_session(struct Curl_ssl_scache_peer *peer,
                                       struct Curl_ssl_session *s,
                                       curl_off_t now)
{
  /* A session not from TLSv1.3 replaces all other. */
  if(s->ietf_tls_id != CURL_IETF_PROTO_TLS1_3) {
    Curl_llist_destroy(&peer->sessions, NULL);
    Curl_llist_append(&peer->sessions, s, &s->list);
  }
  else {
    /* Expire existing, append, trim from head to obey max_sessions */
    cf_scache_peer_remove_expired(peer, now);
    cf_scache_peer_remove_non13(peer);
    Curl_llist_append(&peer->sessions, s, &s->list);
    while(Curl_llist_count(&peer->sessions) > peer->max_sessions) {
      Curl_node_remove(Curl_llist_head(&peer->sessions));
    }
  }
}

static CURLcode cf_scache_add_session(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      struct Curl_ssl_scache *scache,
                                      const char *ssl_peer_key,
                                      struct Curl_ssl_session *s)
{
  struct Curl_ssl_scache_peer *peer = NULL;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  CURLcode result = CURLE_OUT_OF_MEMORY;
  curl_off_t now = (curl_off_t)time(NULL);
  curl_off_t max_lifetime;

  if(!scache || !scache->peer_count) {
    Curl_ssl_session_destroy(s);
    return CURLE_OK;
  }

  if(s->valid_until <= 0)
    s->valid_until = now + scache->default_lifetime_secs;

  max_lifetime = (s->ietf_tls_id == CURL_IETF_PROTO_TLS1_3) ?
                 CURL_SCACHE_MAX_13_LIFETIME_SEC :
                 CURL_SCACHE_MAX_12_LIFETIME_SEC;
  if(s->valid_until > (now + max_lifetime))
    s->valid_until = now + max_lifetime;

  if(cf_scache_session_expired(s, now)) {
    CURL_TRC_SSLS(data, "add, session already expired");
    Curl_ssl_session_destroy(s);
    return CURLE_OK;
  }

  result = cf_ssl_add_peer(data, scache, ssl_peer_key, conn_config, &peer);
  if(result || !peer) {
    CURL_TRC_SSLS(data, "unable to add scache peer: %d", result);
    Curl_ssl_session_destroy(s);
    goto out;
  }

  cf_scache_peer_add_session(peer, s, now);

out:
  if(result) {
    failf(data, "[SCACHE] failed to add session for %s, error=%d",
          ssl_peer_key, result);
  }
  else
    CURL_TRC_SSLS(data, "added session for %s [proto=0x%x, "
                  "valid_secs=%" FMT_OFF_T ", alpn=%s, earlydata=%zu, "
                  "quic_tp=%s], peer has %zu sessions now",
                  ssl_peer_key, s->ietf_tls_id, s->valid_until - now,
                  s->alpn, s->earlydata_max, s->quic_tp ? "yes" : "no",
                  peer ? Curl_llist_count(&peer->sessions) : 0);
  return result;
}

CURLcode Curl_ssl_scache_put(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             const char *ssl_peer_key,
                             struct Curl_ssl_session *s)
{
  struct Curl_ssl_scache *scache = cf_ssl_scache_get(data);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  CURLcode result;
  DEBUGASSERT(ssl_config);

  if(!scache || !ssl_config->primary.cache_session) {
    Curl_ssl_session_destroy(s);
    return CURLE_OK;
  }

  Curl_ssl_scache_lock(data);
  result = cf_scache_add_session(cf, data, scache, ssl_peer_key, s);
  Curl_ssl_scache_unlock(data);
  return result;
}

void Curl_ssl_scache_return(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           const char *ssl_peer_key,
                           struct Curl_ssl_session *s)
{
  /* See RFC 8446 C.4:
   * "Clients SHOULD NOT reuse a ticket for multiple connections." */
  if(s && s->ietf_tls_id < 0x304)
    (void)Curl_ssl_scache_put(cf, data, ssl_peer_key, s);
  else
    Curl_ssl_session_destroy(s);
}

CURLcode Curl_ssl_scache_take(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const char *ssl_peer_key,
                              struct Curl_ssl_session **ps)
{
  struct Curl_ssl_scache *scache = cf_ssl_scache_get(data);
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_ssl_scache_peer *peer = NULL;
  struct Curl_llist_node *n;
  struct Curl_ssl_session *s = NULL;
  CURLcode result;

  *ps = NULL;
  if(!scache)
    return CURLE_OK;

  Curl_ssl_scache_lock(data);
  result = cf_ssl_find_peer_by_key(data, scache, ssl_peer_key, conn_config,
                                   &peer);
  if(!result && peer) {
    cf_scache_peer_remove_expired(peer, (curl_off_t)time(NULL));
    n = Curl_llist_head(&peer->sessions);
    if(n) {
      s = Curl_node_take_elem(n);
      (scache->age)++;            /* increase general age */
      peer->age = scache->age; /* set this as used in this age */
    }
  }
  Curl_ssl_scache_unlock(data);
  if(s) {
    *ps = s;
    CURL_TRC_SSLS(data, "took session for %s [proto=0x%x, "
                  "alpn=%s, earlydata=%zu, quic_tp=%s], %zu sessions remain",
                  ssl_peer_key, s->ietf_tls_id, s->alpn,
                  s->earlydata_max, s->quic_tp ? "yes" : "no",
                  Curl_llist_count(&peer->sessions));
  }
  else {
    CURL_TRC_SSLS(data, "no cached session for %s", ssl_peer_key);
  }
  return result;
}

CURLcode Curl_ssl_scache_add_obj(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const char *ssl_peer_key,
                                 void *sobj,
                                 Curl_ssl_scache_obj_dtor *sobj_free)
{
  struct Curl_ssl_scache *scache = cf_ssl_scache_get(data);
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_ssl_scache_peer *peer = NULL;
  CURLcode result;

  DEBUGASSERT(sobj);
  DEBUGASSERT(sobj_free);

  if(!scache) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  result = cf_ssl_add_peer(data, scache, ssl_peer_key, conn_config, &peer);
  if(result || !peer) {
    CURL_TRC_SSLS(data, "unable to add scache peer: %d", result);
    goto out;
  }

  cf_ssl_scache_peer_set_obj(peer, sobj, sobj_free);
  sobj = NULL;  /* peer took ownership */

out:
  if(sobj && sobj_free)
    sobj_free(sobj);
  return result;
}

void *Curl_ssl_scache_get_obj(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              const char *ssl_peer_key)
{
  struct Curl_ssl_scache *scache = cf_ssl_scache_get(data);
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_ssl_scache_peer *peer = NULL;
  CURLcode result;
  void *sobj;

  if(!scache)
    return NULL;

  result = cf_ssl_find_peer_by_key(data, scache, ssl_peer_key, conn_config,
                                   &peer);
  if(result)
    return NULL;

  sobj = peer ? peer->sobj : NULL;

  CURL_TRC_SSLS(data, "%s cached session for '%s'",
                sobj ? "Found" : "No", ssl_peer_key);
  return sobj;
}

void Curl_ssl_scache_remove_all(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const char *ssl_peer_key)
{
  struct Curl_ssl_scache *scache = cf_ssl_scache_get(data);
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_ssl_scache_peer *peer = NULL;
  CURLcode result;

  (void)cf;
  if(!scache)
    return;

  Curl_ssl_scache_lock(data);
  result = cf_ssl_find_peer_by_key(data, scache, ssl_peer_key, conn_config,
                                   &peer);
  if(!result && peer)
    cf_ssl_scache_clear_peer(peer);
  Curl_ssl_scache_unlock(data);
}

#ifdef USE_SSLS_EXPORT

#define CURL_SSL_TICKET_MAX   (16*1024)

static CURLcode cf_ssl_scache_peer_set_hmac(struct Curl_ssl_scache_peer *peer)
{
  CURLcode result;

  DEBUGASSERT(peer);
  if(!peer->ssl_peer_key)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  result = Curl_rand(NULL, peer->key_salt, sizeof(peer->key_salt));
  if(result)
    return result;

  result = Curl_hmacit(&Curl_HMAC_SHA256,
                       peer->key_salt, sizeof(peer->key_salt),
                       (const unsigned char *)peer->ssl_peer_key,
                       strlen(peer->ssl_peer_key),
                       peer->key_hmac);
  if(!result)
    peer->hmac_set = TRUE;
  return result;
}

static CURLcode
cf_ssl_find_peer_by_hmac(struct Curl_ssl_scache *scache,
                         const unsigned char *salt,
                         const unsigned char *hmac,
                         struct Curl_ssl_scache_peer **ppeer)
{
  size_t i;
  CURLcode result = CURLE_OK;

  *ppeer = NULL;
  if(!GOOD_SCACHE(scache))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* look for an entry that matches salt+hmac exactly or has a known
   * ssl_peer_key which salt+hmac's to the same. */
  for(i = 0; scache && i < scache->peer_count; i++) {
    struct Curl_ssl_scache_peer *peer = &scache->peers[i];
    if(!cf_ssl_scache_match_auth(peer, NULL))
      continue;
    if(scache->peers[i].hmac_set &&
       !memcmp(peer->key_salt, salt, sizeof(peer->key_salt)) &&
       !memcmp(peer->key_hmac, hmac, sizeof(peer->key_hmac))) {
      /* found exact match, return */
      *ppeer = peer;
      goto out;
    }
    else if(peer->ssl_peer_key) {
      unsigned char my_hmac[CURL_SHA256_DIGEST_LENGTH];
      /* compute hmac for the passed salt */
      result = Curl_hmacit(&Curl_HMAC_SHA256,
                           salt, sizeof(peer->key_salt),
                           (const unsigned char *)peer->ssl_peer_key,
                           strlen(peer->ssl_peer_key),
                           my_hmac);
      if(result)
        goto out;
      if(!memcmp(my_hmac, hmac, sizeof(my_hmac))) {
        /* cryptohash match, take over salt+hmac if no set and return */
        if(!peer->hmac_set) {
          memcpy(peer->key_salt, salt, sizeof(peer->key_salt));
          memcpy(peer->key_hmac, hmac, sizeof(peer->key_hmac));
          peer->hmac_set = TRUE;
        }
        *ppeer = peer;
        goto out;
      }
    }
  }
out:
  return result;
}

CURLcode Curl_ssl_session_import(struct Curl_easy *data,
                                 const char *ssl_peer_key,
                                 const unsigned char *shmac, size_t shmac_len,
                                 const void *sdata, size_t sdata_len)
{
  struct Curl_ssl_scache *scache = cf_ssl_scache_get(data);
  struct Curl_ssl_scache_peer *peer = NULL;
  struct Curl_ssl_session *s = NULL;
  bool locked = FALSE;
  CURLcode r;

  if(!scache) {
    r = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  if(!ssl_peer_key && (!shmac || !shmac_len)) {
    r = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  r = Curl_ssl_session_unpack(data, sdata, sdata_len, &s);
  if(r)
    goto out;

  Curl_ssl_scache_lock(data);
  locked = TRUE;

  if(ssl_peer_key) {
    r = cf_ssl_add_peer(data, scache, ssl_peer_key, NULL, &peer);
    if(r)
      goto out;
  }
  else if(shmac_len != (sizeof(peer->key_salt) + sizeof(peer->key_hmac))) {
    /* Either salt+hmac was garbled by caller or is from a curl version
     * that does things differently */
    r = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  else {
    const unsigned char *salt = shmac;
    const unsigned char *hmac = shmac + sizeof(peer->key_salt);

    r = cf_ssl_find_peer_by_hmac(scache, salt, hmac, &peer);
    if(r)
      goto out;
    if(!peer) {
      peer = cf_ssl_get_free_peer(scache);
      if(peer) {
        r = cf_ssl_scache_peer_init(peer, ssl_peer_key, NULL,
                                    NULL, NULL, salt, hmac);
        if(r)
          goto out;
      }
    }
  }

  if(peer) {
    cf_scache_peer_add_session(peer, s, time(NULL));
    s = NULL; /* peer is now owner */
    CURL_TRC_SSLS(data, "successfully imported ticket for peer %s, now "
                  "with %zu tickets",
                  peer->ssl_peer_key ? peer->ssl_peer_key : "without key",
                  Curl_llist_count(&peer->sessions));
  }

out:
  if(locked)
    Curl_ssl_scache_unlock(data);
  Curl_ssl_session_destroy(s);
  return r;
}

CURLcode Curl_ssl_session_export(struct Curl_easy *data,
                                 curl_ssls_export_cb *export_fn,
                                 void *userptr)
{
  struct Curl_ssl_scache *scache = cf_ssl_scache_get(data);
  struct Curl_ssl_scache_peer *peer;
  struct dynbuf sbuf, hbuf;
  struct Curl_llist_node *n;
  size_t i, npeers = 0, ntickets = 0;
  curl_off_t now = time(NULL);
  CURLcode r = CURLE_OK;

  if(!export_fn)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(!scache)
    return CURLE_OK;

  Curl_ssl_scache_lock(data);

  curlx_dyn_init(&hbuf, (CURL_SHA256_DIGEST_LENGTH * 2) + 1);
  curlx_dyn_init(&sbuf, CURL_SSL_TICKET_MAX);

  for(i = 0; scache && i < scache->peer_count; i++) {
    peer = &scache->peers[i];
    if(!peer->ssl_peer_key && !peer->hmac_set)
      continue;  /* skip free entry */
    if(!peer->exportable)
      continue;

    curlx_dyn_reset(&hbuf);
    cf_scache_peer_remove_expired(peer, now);
    n = Curl_llist_head(&peer->sessions);
    if(n)
      ++npeers;
    while(n) {
      struct Curl_ssl_session *s = Curl_node_elem(n);
      if(!peer->hmac_set) {
        r = cf_ssl_scache_peer_set_hmac(peer);
        if(r)
          goto out;
      }
      if(!curlx_dyn_len(&hbuf)) {
        r = curlx_dyn_addn(&hbuf, peer->key_salt, sizeof(peer->key_salt));
        if(r)
          goto out;
        r = curlx_dyn_addn(&hbuf, peer->key_hmac, sizeof(peer->key_hmac));
        if(r)
          goto out;
      }
      curlx_dyn_reset(&sbuf);
      r = Curl_ssl_session_pack(data, s, &sbuf);
      if(r)
        goto out;

      r = export_fn(data, userptr, peer->ssl_peer_key,
                    curlx_dyn_uptr(&hbuf), curlx_dyn_len(&hbuf),
                    curlx_dyn_uptr(&sbuf), curlx_dyn_len(&sbuf),
                    s->valid_until, s->ietf_tls_id,
                    s->alpn, s->earlydata_max);
      if(r)
        goto out;
      ++ntickets;
      n = Curl_node_next(n);
    }

  }
  r = CURLE_OK;
  CURL_TRC_SSLS(data, "exported %zu session tickets for %zu peers",
                ntickets, npeers);

out:
  Curl_ssl_scache_unlock(data);
  curlx_dyn_free(&hbuf);
  curlx_dyn_free(&sbuf);
  return r;
}

#endif /* USE_SSLS_EXPORT */

#endif /* USE_SSL */
