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

#include "urldata.h"
#include "cfilters.h"

#include "vtls.h" /* generic SSL protos etc */
#include "vtls_int.h"
#include "vtls_scache.h"
#include "vtls_spack.h"

#include "strcase.h"
#include "url.h"
#include "llist.h"
#include "share.h"
#include "fetch_trc.h"
#include "fetch_sha256.h"
#include "rand.h"
#include "warnless.h"
#include "fetch_printf.h"
#include "strdup.h"

/* The last #include files should be: */
#include "fetch_memory.h"
#include "memdebug.h"

/* a peer+tls-config we cache sessions for */
struct Fetch_ssl_scache_peer
{
  char *ssl_peer_key; /* id for peer + relevant TLS configuration */
  char *clientcert;
  char *srp_username;
  char *srp_password;
  struct Fetch_llist sessions;
  void *sobj;                                         /* object instance or NULL */
  Fetch_ssl_scache_obj_dtor *sobj_free;                /* free `sobj` callback */
  unsigned char key_salt[FETCH_SHA256_DIGEST_LENGTH]; /* for entry export */
  unsigned char key_hmac[FETCH_SHA256_DIGEST_LENGTH]; /* for entry export */
  size_t max_sessions;
  long age;      /* just a number, the higher the more recent */
  BIT(hmac_set); /* if key_salt and key_hmac are present */
};

struct Fetch_ssl_scache
{
  struct Fetch_ssl_scache_peer *peers;
  size_t peer_count;
  int default_lifetime_secs;
  long age;
};

static void cf_ssl_scache_clear_session(struct Fetch_ssl_session *s)
{
  if (s->sdata)
  {
    free((void *)s->sdata);
    s->sdata = NULL;
  }
  s->sdata_len = 0;
  if (s->quic_tp)
  {
    free((void *)s->quic_tp);
    s->quic_tp = NULL;
  }
  s->quic_tp_len = 0;
  s->ietf_tls_id = 0;
  s->valid_until = 0;
  Fetch_safefree(s->alpn);
}

static void cf_ssl_scache_sesssion_ldestroy(void *udata, void *s)
{
  (void)udata;
  cf_ssl_scache_clear_session(s);
  free(s);
}

FETCHcode
Fetch_ssl_session_create(unsigned char *sdata, size_t sdata_len,
                        int ietf_tls_id, const char *alpn,
                        fetch_off_t valid_until, size_t earlydata_max,
                        struct Fetch_ssl_session **psession)
{
  return Fetch_ssl_session_create2(sdata, sdata_len, ietf_tls_id, alpn,
                                  valid_until, earlydata_max,
                                  NULL, 0, psession);
}

FETCHcode
Fetch_ssl_session_create2(unsigned char *sdata, size_t sdata_len,
                         int ietf_tls_id, const char *alpn,
                         fetch_off_t valid_until, size_t earlydata_max,
                         unsigned char *quic_tp, size_t quic_tp_len,
                         struct Fetch_ssl_session **psession)
{
  struct Fetch_ssl_session *s;

  if (!sdata || !sdata_len)
  {
    free(sdata);
    return FETCHE_BAD_FUNCTION_ARGUMENT;
  }

  *psession = NULL;
  s = calloc(1, sizeof(*s));
  if (!s)
  {
    free(sdata);
    free(quic_tp);
    return FETCHE_OUT_OF_MEMORY;
  }

  s->ietf_tls_id = ietf_tls_id;
  s->valid_until = valid_until;
  s->earlydata_max = earlydata_max;
  s->sdata = sdata;
  s->sdata_len = sdata_len;
  s->quic_tp = quic_tp;
  s->quic_tp_len = quic_tp_len;
  if (alpn)
  {
    s->alpn = strdup(alpn);
    if (!s->alpn)
    {
      cf_ssl_scache_sesssion_ldestroy(NULL, s);
      return FETCHE_OUT_OF_MEMORY;
    }
  }
  *psession = s;
  return FETCHE_OK;
}

void Fetch_ssl_session_destroy(struct Fetch_ssl_session *s)
{
  if (s)
  {
    /* if in the list, the list destructor takes care of it */
    if (Fetch_node_llist(&s->list))
      Fetch_node_remove(&s->list);
    else
    {
      cf_ssl_scache_sesssion_ldestroy(NULL, s);
    }
  }
}

static void cf_ssl_scache_clear_peer(struct Fetch_ssl_scache_peer *peer)
{
  Fetch_llist_destroy(&peer->sessions, NULL);
  if (peer->sobj)
  {
    DEBUGASSERT(peer->sobj_free);
    if (peer->sobj_free)
      peer->sobj_free(peer->sobj);
    peer->sobj = NULL;
  }
  peer->sobj_free = NULL;
  Fetch_safefree(peer->clientcert);
#ifdef USE_TLS_SRP
  Fetch_safefree(peer->srp_username);
  Fetch_safefree(peer->srp_password);
#endif
  Fetch_safefree(peer->ssl_peer_key);
  peer->age = 0;
  peer->hmac_set = FALSE;
}

static void cf_ssl_scache_peer_set_obj(struct Fetch_ssl_scache_peer *peer,
                                       void *sobj,
                                       Fetch_ssl_scache_obj_dtor *sobj_free)
{
  DEBUGASSERT(peer);
  if (peer->sobj_free)
  {
    peer->sobj_free(peer->sobj);
  }
  peer->sobj = sobj;
  peer->sobj_free = sobj_free;
}

static FETCHcode
cf_ssl_scache_peer_init(struct Fetch_ssl_scache_peer *peer,
                        const char *ssl_peer_key,
                        const char *clientcert,
                        const char *srp_username,
                        const char *srp_password,
                        const unsigned char *salt,
                        const unsigned char *hmac)
{
  FETCHcode result = FETCHE_OUT_OF_MEMORY;

  DEBUGASSERT(!peer->ssl_peer_key);
  if (ssl_peer_key)
  {
    peer->ssl_peer_key = strdup(ssl_peer_key);
    if (!peer->ssl_peer_key)
      goto out;
    peer->hmac_set = FALSE;
  }
  else if (salt && hmac)
  {
    memcpy(peer->key_salt, salt, sizeof(peer->key_salt));
    memcpy(peer->key_hmac, hmac, sizeof(peer->key_hmac));
    peer->hmac_set = TRUE;
  }
  else
  {
    result = FETCHE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  if (clientcert)
  {
    peer->clientcert = strdup(clientcert);
    if (!peer->clientcert)
      goto out;
  }
  if (srp_username)
  {
    peer->srp_username = strdup(srp_username);
    if (!peer->srp_username)
      goto out;
  }
  if (srp_password)
  {
    peer->srp_password = strdup(srp_password);
    if (!peer->srp_password)
      goto out;
  }
  result = FETCHE_OK;
out:
  if (result)
    cf_ssl_scache_clear_peer(peer);
  return result;
}

static void cf_scache_session_remove(struct Fetch_ssl_scache_peer *peer,
                                     struct Fetch_ssl_session *s)
{
  (void)peer;
  DEBUGASSERT(Fetch_node_llist(&s->list) == &peer->sessions);
  Fetch_ssl_session_destroy(s);
}

static bool cf_scache_session_expired(struct Fetch_ssl_session *s,
                                      fetch_off_t now)
{
  return (s->valid_until > 0) && (s->valid_until < now);
}

static void cf_scache_peer_remove_expired(struct Fetch_ssl_scache_peer *peer,
                                          fetch_off_t now)
{
  struct Fetch_llist_node *n = Fetch_llist_head(&peer->sessions);
  while (n)
  {
    struct Fetch_ssl_session *s = Fetch_node_elem(n);
    n = Fetch_node_next(n);
    if (cf_scache_session_expired(s, now))
      cf_scache_session_remove(peer, s);
  }
}

static void cf_scache_peer_remove_non13(struct Fetch_ssl_scache_peer *peer)
{
  struct Fetch_llist_node *n = Fetch_llist_head(&peer->sessions);
  while (n)
  {
    struct Fetch_ssl_session *s = Fetch_node_elem(n);
    n = Fetch_node_next(n);
    if (s->ietf_tls_id != FETCH_IETF_PROTO_TLS1_3)
      cf_scache_session_remove(peer, s);
  }
}

FETCHcode Fetch_ssl_scache_create(size_t max_peers,
                                 size_t max_sessions_per_peer,
                                 struct Fetch_ssl_scache **pscache)
{
  struct Fetch_ssl_scache *scache;
  struct Fetch_ssl_scache_peer *peers;
  size_t i;

  *pscache = NULL;
  peers = calloc(max_peers, sizeof(*peers));
  if (!peers)
    return FETCHE_OUT_OF_MEMORY;

  scache = calloc(1, sizeof(*scache));
  if (!scache)
  {
    free(peers);
    return FETCHE_OUT_OF_MEMORY;
  }

  scache->default_lifetime_secs = (24 * 60 * 60); /* 1 day */
  scache->peer_count = max_peers;
  scache->peers = peers;
  scache->age = 1;
  for (i = 0; i < scache->peer_count; ++i)
  {
    scache->peers[i].max_sessions = max_sessions_per_peer;
    Fetch_llist_init(&scache->peers[i].sessions,
                    cf_ssl_scache_sesssion_ldestroy);
  }

  *pscache = scache;
  return FETCHE_OK;
}

void Fetch_ssl_scache_destroy(struct Fetch_ssl_scache *scache)
{
  if (scache)
  {
    size_t i;
    for (i = 0; i < scache->peer_count; ++i)
    {
      cf_ssl_scache_clear_peer(&scache->peers[i]);
    }
    free(scache->peers);
    free(scache);
  }
}

/* Lock shared SSL session data */
void Fetch_ssl_scache_lock(struct Fetch_easy *data)
{
  if (FETCH_SHARE_ssl_scache(data))
    Fetch_share_lock(data, FETCH_LOCK_DATA_SSL_SESSION, FETCH_LOCK_ACCESS_SINGLE);
}

/* Unlock shared SSL session data */
void Fetch_ssl_scache_unlock(struct Fetch_easy *data)
{
  if (FETCH_SHARE_ssl_scache(data))
    Fetch_share_unlock(data, FETCH_LOCK_DATA_SSL_SESSION);
}

static FETCHcode cf_ssl_peer_key_add_path(struct dynbuf *buf,
                                          const char *name,
                                          char *path)
{
  if (path && path[0])
  {
    /* We try to add absolute paths, so that the session key can stay
     * valid when used in another process with different CWD. However,
     * when a path does not exist, this does not work. Then, we add
     * the path as is. */
#ifdef _WIN32
    char abspath[_MAX_PATH];
    if (_fullpath(abspath, path, _MAX_PATH))
      return Fetch_dyn_addf(buf, ":%s-%s", name, abspath);
#else
    if (path[0] != '/')
    {
      char *abspath = realpath(path, NULL);
      if (abspath)
      {
        FETCHcode r = Fetch_dyn_addf(buf, ":%s-%s", name, abspath);
        (free)(abspath); /* allocated by libc, free without memdebug */
        return r;
      }
    }
#endif
    return Fetch_dyn_addf(buf, ":%s-%s", name, path);
  }
  return FETCHE_OK;
}

static FETCHcode cf_ssl_peer_key_add_hash(struct dynbuf *buf,
                                          const char *name,
                                          struct fetch_blob *blob)
{
  FETCHcode r = FETCHE_OK;
  if (blob && blob->len)
  {
    unsigned char hash[FETCH_SHA256_DIGEST_LENGTH];
    size_t i;

    r = Fetch_dyn_addf(buf, ":%s-", name);
    if (r)
      goto out;
    r = Fetch_sha256it(hash, blob->data, blob->len);
    if (r)
      goto out;
    for (i = 0; i < FETCH_SHA256_DIGEST_LENGTH; ++i)
    {
      r = Fetch_dyn_addf(buf, "%02x", hash[i]);
      if (r)
        goto out;
    }
  }
out:
  return r;
}

FETCHcode Fetch_ssl_peer_key_make(struct Fetch_cfilter *cf,
                                 const struct ssl_peer *peer,
                                 const char *tls_id,
                                 char **ppeer_key)
{
  struct ssl_primary_config *ssl = Fetch_ssl_cf_get_primary_config(cf);
  struct dynbuf buf;
  size_t key_len;
  FETCHcode r;

  *ppeer_key = NULL;
  Fetch_dyn_init(&buf, 10 * 1024);

  r = Fetch_dyn_addf(&buf, "%s:%d", peer->hostname, peer->port);
  if (r)
    goto out;

  switch (peer->transport)
  {
  case TRNSPRT_TCP:
    break;
  case TRNSPRT_UDP:
    r = Fetch_dyn_add(&buf, ":UDP");
    break;
  case TRNSPRT_QUIC:
    r = Fetch_dyn_add(&buf, ":QUIC");
    break;
  case TRNSPRT_UNIX:
    r = Fetch_dyn_add(&buf, ":UNIX");
    break;
  default:
    r = Fetch_dyn_addf(&buf, ":TRNSPRT-%d", peer->transport);
    break;
  }
  if (r)
    goto out;

  if (!ssl->verifypeer)
  {
    r = Fetch_dyn_add(&buf, ":NO-VRFY-PEER");
    if (r)
      goto out;
  }
  if (!ssl->verifyhost)
  {
    r = Fetch_dyn_add(&buf, ":NO-VRFY-HOST");
    if (r)
      goto out;
  }
  if (ssl->verifystatus)
  {
    r = Fetch_dyn_add(&buf, ":VRFY-STATUS");
    if (r)
      goto out;
  }
  if (!ssl->verifypeer || !ssl->verifyhost)
  {
    if (cf->conn->bits.conn_to_host)
    {
      r = Fetch_dyn_addf(&buf, ":CHOST-%s", cf->conn->conn_to_host.name);
      if (r)
        goto out;
    }
    if (cf->conn->bits.conn_to_port)
    {
      r = Fetch_dyn_addf(&buf, ":CPORT-%d", cf->conn->conn_to_port);
      if (r)
        goto out;
    }
  }

  if (ssl->version || ssl->version_max)
  {
    r = Fetch_dyn_addf(&buf, ":TLSVER-%d-%d", ssl->version,
                      (ssl->version_max >> 16));
    if (r)
      goto out;
  }
  if (ssl->ssl_options)
  {
    r = Fetch_dyn_addf(&buf, ":TLSOPT-%x", ssl->ssl_options);
    if (r)
      goto out;
  }
  if (ssl->cipher_list)
  {
    r = Fetch_dyn_addf(&buf, ":CIPHER-%s", ssl->cipher_list);
    if (r)
      goto out;
  }
  if (ssl->cipher_list13)
  {
    r = Fetch_dyn_addf(&buf, ":CIPHER13-%s", ssl->cipher_list13);
    if (r)
      goto out;
  }
  if (ssl->curves)
  {
    r = Fetch_dyn_addf(&buf, ":CURVES-%s", ssl->curves);
    if (r)
      goto out;
  }
  if (ssl->verifypeer)
  {
    r = cf_ssl_peer_key_add_path(&buf, "CA", ssl->CAfile);
    if (r)
      goto out;
    r = cf_ssl_peer_key_add_path(&buf, "CApath", ssl->CApath);
    if (r)
      goto out;
    r = cf_ssl_peer_key_add_path(&buf, "CRL", ssl->CRLfile);
    if (r)
      goto out;
    r = cf_ssl_peer_key_add_path(&buf, "Issuer", ssl->issuercert);
    if (r)
      goto out;
    if (ssl->cert_blob)
    {
      r = cf_ssl_peer_key_add_hash(&buf, "CertBlob", ssl->cert_blob);
      if (r)
        goto out;
    }
    if (ssl->ca_info_blob)
    {
      r = cf_ssl_peer_key_add_hash(&buf, "CAInfoBlob", ssl->ca_info_blob);
      if (r)
        goto out;
    }
    if (ssl->issuercert_blob)
    {
      r = cf_ssl_peer_key_add_hash(&buf, "IssuerBlob", ssl->issuercert_blob);
      if (r)
        goto out;
    }
  }
  if (ssl->pinned_key && ssl->pinned_key[0])
  {
    r = Fetch_dyn_addf(&buf, ":Pinned-%s", ssl->pinned_key);
    if (r)
      goto out;
  }

  if (ssl->clientcert && ssl->clientcert[0])
  {
    r = Fetch_dyn_add(&buf, ":CCERT");
    if (r)
      goto out;
  }
#ifdef USE_TLS_SRP
  if (ssl->username || ssl->password)
  {
    r = Fetch_dyn_add(&buf, ":SRP-AUTH");
    if (r)
      goto out;
  }
#endif

  if (!tls_id || !tls_id[0])
  {
    r = FETCHE_FAILED_INIT;
    goto out;
  }
  r = Fetch_dyn_addf(&buf, ":IMPL-%s", tls_id);
  if (r)
    goto out;

  *ppeer_key = Fetch_dyn_take(&buf, &key_len);
  /* we just added printable char, and dynbuf always 0 terminates,
   * no need to track length */

out:
  Fetch_dyn_free(&buf);
  return r;
}

static bool cf_ssl_scache_match_auth(struct Fetch_ssl_scache_peer *peer,
                                     struct ssl_primary_config *conn_config)
{
  if (!conn_config)
  {
    if (peer->clientcert)
      return FALSE;
#ifdef USE_TLS_SRP
    if (peer->srp_username || peer->srp_password)
      return FALSE;
#endif
    return TRUE;
  }
  else if (!Fetch_safecmp(peer->clientcert, conn_config->clientcert))
    return FALSE;
#ifdef USE_TLS_SRP
  if (Fetch_timestrcmp(peer->srp_username, conn_config->username) ||
      Fetch_timestrcmp(peer->srp_password, conn_config->password))
    return FALSE;
#endif
  return TRUE;
}

static FETCHcode
cf_ssl_find_peer_by_key(struct Fetch_easy *data,
                        struct Fetch_ssl_scache *scache,
                        const char *ssl_peer_key,
                        struct ssl_primary_config *conn_config,
                        struct Fetch_ssl_scache_peer **ppeer)
{
  size_t i, peer_key_len = 0;
  FETCHcode result = FETCHE_OK;

  *ppeer = NULL;
  /* check for entries with known peer_key */
  for (i = 0; scache && i < scache->peer_count; i++)
  {
    if (scache->peers[i].ssl_peer_key &&
        strcasecompare(ssl_peer_key, scache->peers[i].ssl_peer_key) &&
        cf_ssl_scache_match_auth(&scache->peers[i], conn_config))
    {
      /* yes, we have a cached session for this! */
      *ppeer = &scache->peers[i];
      goto out;
    }
  }
  /* check for entries with HMAC set but no known peer_key */
  for (i = 0; scache && i < scache->peer_count; i++)
  {
    if (!scache->peers[i].ssl_peer_key &&
        scache->peers[i].hmac_set &&
        cf_ssl_scache_match_auth(&scache->peers[i], conn_config))
    {
      /* possible entry with unknown peer_key, check hmac */
      unsigned char my_hmac[FETCH_SHA256_DIGEST_LENGTH];
      if (!peer_key_len) /* we are lazy */
        peer_key_len = strlen(ssl_peer_key);
      result = Fetch_hmacit(&Fetch_HMAC_SHA256,
                           scache->peers[i].key_salt,
                           sizeof(scache->peers[i].key_salt),
                           (const unsigned char *)ssl_peer_key,
                           peer_key_len,
                           my_hmac);
      if (result)
        goto out;
      if (!memcmp(scache->peers[i].key_hmac, my_hmac, sizeof(my_hmac)))
      {
        /* remember peer_key for future lookups */
        FETCH_TRC_SSLS(data, "peer entry %zu key recovered: %s",
                       i, ssl_peer_key);
        scache->peers[i].ssl_peer_key = strdup(ssl_peer_key);
        if (!scache->peers[i].ssl_peer_key)
        {
          result = FETCHE_OUT_OF_MEMORY;
          goto out;
        }
        *ppeer = &scache->peers[i];
        goto out;
      }
    }
  }
  FETCH_TRC_SSLS(data, "peer not found for %s", ssl_peer_key);
out:
  return result;
}

static struct Fetch_ssl_scache_peer *
cf_ssl_get_free_peer(struct Fetch_ssl_scache *scache)
{
  struct Fetch_ssl_scache_peer *peer = NULL;
  size_t i;

  /* find empty or oldest peer */
  for (i = 0; i < scache->peer_count; ++i)
  {
    /* free peer entry? */
    if (!scache->peers[i].ssl_peer_key && !scache->peers[i].hmac_set)
    {
      peer = &scache->peers[i];
      break;
    }
    /* peer without sessions and obj */
    if (!scache->peers[i].sobj &&
        !Fetch_llist_count(&scache->peers[i].sessions))
    {
      peer = &scache->peers[i];
      break;
    }
    /* remember "oldest" peer */
    if (!peer || (scache->peers[i].age < peer->age))
    {
      peer = &scache->peers[i];
    }
  }
  DEBUGASSERT(peer);
  if (peer)
    cf_ssl_scache_clear_peer(peer);
  return peer;
}

static FETCHcode
cf_ssl_add_peer(struct Fetch_easy *data,
                struct Fetch_ssl_scache *scache,
                const char *ssl_peer_key,
                struct ssl_primary_config *conn_config,
                struct Fetch_ssl_scache_peer **ppeer)
{
  struct Fetch_ssl_scache_peer *peer = NULL;
  FETCHcode result = FETCHE_OK;

  *ppeer = NULL;
  if (ssl_peer_key)
  {
    result = cf_ssl_find_peer_by_key(data, scache, ssl_peer_key, conn_config,
                                     &peer);
    if (result || !scache->peer_count)
      return result;
  }

  if (peer)
  {
    *ppeer = peer;
    return FETCHE_OK;
  }

  peer = cf_ssl_get_free_peer(scache);
  if (peer)
  {
    const char *ccert = conn_config ? conn_config->clientcert : NULL;
    const char *username = NULL, *password = NULL;
#ifdef USE_TLS_SRP
    username = conn_config ? conn_config->username : NULL;
    password = conn_config ? conn_config->password : NULL;
#endif
    result = cf_ssl_scache_peer_init(peer, ssl_peer_key, ccert,
                                     username, password, NULL, NULL);
    if (result)
      goto out;
    /* all ready */
    *ppeer = peer;
    result = FETCHE_OK;
  }

out:
  if (result)
  {
    cf_ssl_scache_clear_peer(peer);
  }
  return result;
}

static void cf_scache_peer_add_session(struct Fetch_ssl_scache_peer *peer,
                                       struct Fetch_ssl_session *s,
                                       fetch_off_t now)
{
  /* A session not from TLSv1.3 replaces all other. */
  if (s->ietf_tls_id != FETCH_IETF_PROTO_TLS1_3)
  {
    Fetch_llist_destroy(&peer->sessions, NULL);
    Fetch_llist_append(&peer->sessions, s, &s->list);
  }
  else
  {
    /* Expire existing, append, trim from head to obey max_sessions */
    cf_scache_peer_remove_expired(peer, now);
    cf_scache_peer_remove_non13(peer);
    Fetch_llist_append(&peer->sessions, s, &s->list);
    while (Fetch_llist_count(&peer->sessions) > peer->max_sessions)
    {
      Fetch_node_remove(Fetch_llist_head(&peer->sessions));
    }
  }
}

static FETCHcode cf_scache_add_session(struct Fetch_cfilter *cf,
                                       struct Fetch_easy *data,
                                       struct Fetch_ssl_scache *scache,
                                       const char *ssl_peer_key,
                                       struct Fetch_ssl_session *s)
{
  struct Fetch_ssl_scache_peer *peer = NULL;
  struct ssl_primary_config *conn_config = Fetch_ssl_cf_get_primary_config(cf);
  FETCHcode result = FETCHE_OUT_OF_MEMORY;
  fetch_off_t now = (fetch_off_t)time(NULL);
  fetch_off_t max_lifetime;

  if (!scache || !scache->peer_count)
  {
    Fetch_ssl_session_destroy(s);
    return FETCHE_OK;
  }

  if (s->valid_until <= 0)
    s->valid_until = now + scache->default_lifetime_secs;

  max_lifetime = (s->ietf_tls_id == FETCH_IETF_PROTO_TLS1_3) ? FETCH_SCACHE_MAX_13_LIFETIME_SEC : FETCH_SCACHE_MAX_12_LIFETIME_SEC;
  if (s->valid_until > (now + max_lifetime))
    s->valid_until = now + max_lifetime;

  if (cf_scache_session_expired(s, now))
  {
    FETCH_TRC_SSLS(data, "add, session already expired");
    Fetch_ssl_session_destroy(s);
    return FETCHE_OK;
  }

  result = cf_ssl_add_peer(data, scache, ssl_peer_key, conn_config, &peer);
  if (result || !peer)
  {
    FETCH_TRC_SSLS(data, "unable to add scache peer: %d", result);
    Fetch_ssl_session_destroy(s);
    goto out;
  }

  cf_scache_peer_add_session(peer, s, now);

out:
  if (result)
  {
    failf(data, "[SCACHE] failed to add session for %s, error=%d",
          ssl_peer_key, result);
  }
  else
    FETCH_TRC_SSLS(data, "added session for %s [proto=0x%x, "
                         "valid_secs=%" FMT_OFF_T ", alpn=%s, earlydata=%zu, "
                         "quic_tp=%s], peer has %zu sessions now",
                   ssl_peer_key, s->ietf_tls_id, s->valid_until - now,
                   s->alpn, s->earlydata_max, s->quic_tp ? "yes" : "no",
                   peer ? Fetch_llist_count(&peer->sessions) : 0);
  return result;
}

FETCHcode Fetch_ssl_scache_put(struct Fetch_cfilter *cf,
                              struct Fetch_easy *data,
                              const char *ssl_peer_key,
                              struct Fetch_ssl_session *s)
{
  struct Fetch_ssl_scache *scache = data->state.ssl_scache;
  struct ssl_config_data *ssl_config = Fetch_ssl_cf_get_config(cf, data);
  FETCHcode result;
  DEBUGASSERT(ssl_config);

  if (!scache || !ssl_config->primary.cache_session)
  {
    Fetch_ssl_session_destroy(s);
    return FETCHE_OK;
  }

  Fetch_ssl_scache_lock(data);
  result = cf_scache_add_session(cf, data, scache, ssl_peer_key, s);
  Fetch_ssl_scache_unlock(data);
  return result;
}

void Fetch_ssl_scache_return(struct Fetch_cfilter *cf,
                            struct Fetch_easy *data,
                            const char *ssl_peer_key,
                            struct Fetch_ssl_session *s)
{
  /* See RFC 8446 C.4:
   * "Clients SHOULD NOT reuse a ticket for multiple connections." */
  if (s && s->ietf_tls_id < 0x304)
    (void)Fetch_ssl_scache_put(cf, data, ssl_peer_key, s);
  else
    Fetch_ssl_session_destroy(s);
}

FETCHcode Fetch_ssl_scache_take(struct Fetch_cfilter *cf,
                               struct Fetch_easy *data,
                               const char *ssl_peer_key,
                               struct Fetch_ssl_session **ps)
{
  struct Fetch_ssl_scache *scache = data->state.ssl_scache;
  struct ssl_primary_config *conn_config = Fetch_ssl_cf_get_primary_config(cf);
  struct Fetch_ssl_scache_peer *peer = NULL;
  struct Fetch_llist_node *n;
  struct Fetch_ssl_session *s = NULL;
  FETCHcode result;

  *ps = NULL;
  if (!scache)
    return FETCHE_OK;

  Fetch_ssl_scache_lock(data);
  result = cf_ssl_find_peer_by_key(data, scache, ssl_peer_key, conn_config,
                                   &peer);
  if (!result && peer)
  {
    cf_scache_peer_remove_expired(peer, (fetch_off_t)time(NULL));
    n = Fetch_llist_head(&peer->sessions);
    if (n)
    {
      s = Fetch_node_take_elem(n);
      (scache->age)++;         /* increase general age */
      peer->age = scache->age; /* set this as used in this age */
    }
  }
  Fetch_ssl_scache_unlock(data);
  if (s)
  {
    *ps = s;
    FETCH_TRC_SSLS(data, "took session for %s [proto=0x%x, "
                         "alpn=%s, earlydata=%zu, quic_tp=%s], %zu sessions remain",
                   ssl_peer_key, s->ietf_tls_id, s->alpn,
                   s->earlydata_max, s->quic_tp ? "yes" : "no",
                   Fetch_llist_count(&peer->sessions));
  }
  else
  {
    FETCH_TRC_SSLS(data, "no cached session for %s", ssl_peer_key);
  }
  return result;
}

FETCHcode Fetch_ssl_scache_add_obj(struct Fetch_cfilter *cf,
                                  struct Fetch_easy *data,
                                  const char *ssl_peer_key,
                                  void *sobj,
                                  Fetch_ssl_scache_obj_dtor *sobj_free)
{
  struct Fetch_ssl_scache *scache = data->state.ssl_scache;
  struct ssl_primary_config *conn_config = Fetch_ssl_cf_get_primary_config(cf);
  struct Fetch_ssl_scache_peer *peer = NULL;
  FETCHcode result;

  DEBUGASSERT(sobj);
  DEBUGASSERT(sobj_free);

  result = cf_ssl_add_peer(data, scache, ssl_peer_key, conn_config, &peer);
  if (result || !peer)
  {
    FETCH_TRC_SSLS(data, "unable to add scache peer: %d", result);
    goto out;
  }

  cf_ssl_scache_peer_set_obj(peer, sobj, sobj_free);
  sobj = NULL; /* peer took ownership */

out:
  if (sobj && sobj_free)
    sobj_free(sobj);
  return result;
}

bool Fetch_ssl_scache_get_obj(struct Fetch_cfilter *cf,
                             struct Fetch_easy *data,
                             const char *ssl_peer_key,
                             void **sobj)
{
  struct Fetch_ssl_scache *scache = data->state.ssl_scache;
  struct ssl_primary_config *conn_config = Fetch_ssl_cf_get_primary_config(cf);
  struct Fetch_ssl_scache_peer *peer = NULL;
  FETCHcode result;

  *sobj = NULL;
  if (!scache)
    return FALSE;

  result = cf_ssl_find_peer_by_key(data, scache, ssl_peer_key, conn_config,
                                   &peer);
  if (result)
    return FALSE;

  if (peer)
    *sobj = peer->sobj;

  FETCH_TRC_SSLS(data, "%s cached session for '%s'",
                 *sobj ? "Found" : "No", ssl_peer_key);
  return !!*sobj;
}

void Fetch_ssl_scache_remove_all(struct Fetch_cfilter *cf,
                                struct Fetch_easy *data,
                                const char *ssl_peer_key)
{
  struct Fetch_ssl_scache *scache = data->state.ssl_scache;
  struct ssl_primary_config *conn_config = Fetch_ssl_cf_get_primary_config(cf);
  struct Fetch_ssl_scache_peer *peer = NULL;
  FETCHcode result;

  (void)cf;
  if (!scache)
    return;

  Fetch_ssl_scache_lock(data);
  result = cf_ssl_find_peer_by_key(data, scache, ssl_peer_key, conn_config,
                                   &peer);
  if (!result && peer)
    cf_ssl_scache_clear_peer(peer);
  Fetch_ssl_scache_unlock(data);
}

#ifdef USE_SSLS_EXPORT

#define FETCH_SSL_TICKET_MAX (16 * 1024)

static FETCHcode cf_ssl_scache_peer_set_hmac(struct Fetch_ssl_scache_peer *peer)
{
  FETCHcode result;

  DEBUGASSERT(peer);
  if (!peer->ssl_peer_key)
    return FETCHE_BAD_FUNCTION_ARGUMENT;

  result = Fetch_rand(NULL, peer->key_salt, sizeof(peer->key_salt));
  if (result)
    return result;

  result = Fetch_hmacit(&Fetch_HMAC_SHA256,
                       peer->key_salt, sizeof(peer->key_salt),
                       (const unsigned char *)peer->ssl_peer_key,
                       strlen(peer->ssl_peer_key),
                       peer->key_hmac);
  if (!result)
    peer->hmac_set = TRUE;
  return result;
}

static FETCHcode
cf_ssl_find_peer_by_hmac(struct Fetch_ssl_scache *scache,
                         const unsigned char *salt,
                         const unsigned char *hmac,
                         struct Fetch_ssl_scache_peer **ppeer)
{
  size_t i;
  FETCHcode result = FETCHE_OK;

  *ppeer = NULL;
  /* look for an entry that matches salt+hmac exactly or has a known
   * ssl_peer_key which salt+hmac's to the same. */
  for (i = 0; scache && i < scache->peer_count; i++)
  {
    struct Fetch_ssl_scache_peer *peer = &scache->peers[i];
    if (!cf_ssl_scache_match_auth(peer, NULL))
      continue;
    if (scache->peers[i].hmac_set &&
        !memcmp(peer->key_salt, salt, sizeof(peer->key_salt)) &&
        !memcmp(peer->key_hmac, hmac, sizeof(peer->key_hmac)))
    {
      /* found exact match, return */
      *ppeer = peer;
      goto out;
    }
    else if (peer->ssl_peer_key)
    {
      unsigned char my_hmac[FETCH_SHA256_DIGEST_LENGTH];
      /* compute hmac for the passed salt */
      result = Fetch_hmacit(&Fetch_HMAC_SHA256,
                           salt, sizeof(peer->key_salt),
                           (const unsigned char *)peer->ssl_peer_key,
                           strlen(peer->ssl_peer_key),
                           my_hmac);
      if (result)
        goto out;
      if (!memcmp(my_hmac, hmac, sizeof(my_hmac)))
      {
        /* cryptohash match, take over salt+hmac if no set and return */
        if (!peer->hmac_set)
        {
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

FETCHcode Fetch_ssl_session_import(struct Fetch_easy *data,
                                  const char *ssl_peer_key,
                                  const unsigned char *shmac, size_t shmac_len,
                                  const unsigned char *sdata, size_t sdata_len)
{
  struct Fetch_ssl_scache *scache = data->state.ssl_scache;
  struct Fetch_ssl_scache_peer *peer = NULL;
  struct Fetch_ssl_session *s = NULL;
  bool locked = FALSE;
  FETCHcode r;

  if (!scache)
  {
    r = FETCHE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  if (!ssl_peer_key && (!shmac || !shmac_len))
  {
    r = FETCHE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  r = Fetch_ssl_session_unpack(data, sdata, sdata_len, &s);
  if (r)
    goto out;

  Fetch_ssl_scache_lock(data);
  locked = TRUE;

  if (ssl_peer_key)
  {
    r = cf_ssl_add_peer(data, scache, ssl_peer_key, NULL, &peer);
    if (r)
      goto out;
  }
  else if (shmac_len != (sizeof(peer->key_salt) + sizeof(peer->key_hmac)))
  {
    /* Either salt+hmac was garbled by caller or is from a fetch version
     * that does things differently */
    r = FETCHE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }
  else
  {
    const unsigned char *salt = shmac;
    const unsigned char *hmac = shmac + sizeof(peer->key_salt);

    r = cf_ssl_find_peer_by_hmac(scache, salt, hmac, &peer);
    if (r)
      goto out;
    if (!peer)
    {
      peer = cf_ssl_get_free_peer(scache);
      if (peer)
      {
        r = cf_ssl_scache_peer_init(peer, ssl_peer_key, NULL,
                                    NULL, NULL, salt, hmac);
        if (r)
          goto out;
      }
    }
  }

  if (peer)
  {
    cf_scache_peer_add_session(peer, s, time(NULL));
    s = NULL; /* peer is now owner */
    FETCH_TRC_SSLS(data, "successfully imported ticket for peer %s, now "
                         "with %zu tickets",
                   peer->ssl_peer_key ? peer->ssl_peer_key : "without key",
                   Fetch_llist_count(&peer->sessions));
  }

out:
  if (locked)
    Fetch_ssl_scache_unlock(data);
  Fetch_ssl_session_destroy(s);
  return r;
}

FETCHcode Fetch_ssl_session_export(struct Fetch_easy *data,
                                  fetch_ssls_export_cb *export_fn,
                                  void *userptr)
{
  struct Fetch_ssl_scache *scache = data->state.ssl_scache;
  struct Fetch_ssl_scache_peer *peer;
  struct dynbuf sbuf, hbuf;
  struct Fetch_llist_node *n;
  size_t i, npeers = 0, ntickets = 0;
  fetch_off_t now = time(NULL);
  FETCHcode r = FETCHE_OK;

  if (!export_fn)
    return FETCHE_BAD_FUNCTION_ARGUMENT;
  if (!scache)
    return FETCHE_OK;

  Fetch_ssl_scache_lock(data);

  Fetch_dyn_init(&hbuf, (FETCH_SHA256_DIGEST_LENGTH * 2) + 1);
  Fetch_dyn_init(&sbuf, FETCH_SSL_TICKET_MAX);

  for (i = 0; scache && i < scache->peer_count; i++)
  {
    peer = &scache->peers[i];
    if (!peer->ssl_peer_key && !peer->hmac_set)
      continue; /* skip free entry */
    if (peer->clientcert || peer->srp_username || peer->srp_password)
      continue; /* not exporting those */

    Fetch_dyn_reset(&hbuf);
    cf_scache_peer_remove_expired(peer, now);
    n = Fetch_llist_head(&peer->sessions);
    if (n)
      ++npeers;
    while (n)
    {
      struct Fetch_ssl_session *s = Fetch_node_elem(n);
      if (!peer->hmac_set)
      {
        r = cf_ssl_scache_peer_set_hmac(peer);
        if (r)
          goto out;
      }
      if (!Fetch_dyn_len(&hbuf))
      {
        r = Fetch_dyn_addn(&hbuf, peer->key_salt, sizeof(peer->key_salt));
        if (r)
          goto out;
        r = Fetch_dyn_addn(&hbuf, peer->key_hmac, sizeof(peer->key_hmac));
        if (r)
          goto out;
      }
      Fetch_dyn_reset(&sbuf);
      r = Fetch_ssl_session_pack(data, s, &sbuf);
      if (r)
        goto out;

      r = export_fn(data, userptr, peer->ssl_peer_key,
                    Fetch_dyn_uptr(&hbuf), Fetch_dyn_len(&hbuf),
                    Fetch_dyn_uptr(&sbuf), Fetch_dyn_len(&sbuf),
                    s->valid_until, s->ietf_tls_id,
                    s->alpn, s->earlydata_max);
      if (r)
        goto out;
      ++ntickets;
      n = Fetch_node_next(n);
    }
  }
  r = FETCHE_OK;
  FETCH_TRC_SSLS(data, "exported %zu session tickets for %zu peers",
                 ntickets, npeers);

out:
  Fetch_ssl_scache_unlock(data);
  Fetch_dyn_free(&hbuf);
  Fetch_dyn_free(&sbuf);
  return r;
}

#endif /* USE_SSLS_EXPORT */

#endif /* USE_SSL */
