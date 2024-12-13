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

/* This file is for implementing all "generic" SSL functions that all libcurl
   internals should use. It is then responsible for calling the proper
   "backend" function.

   SSL-functions in libcurl should call functions in this source file, and not
   to any specific SSL-layer.

   Curl_ssl_ - prefix for generic ones

   Note that this source code uses the functions of the configured SSL
   backend via the global Curl_ssl instance.

   "SSL/TLS Strong Encryption: An Introduction"
   https://httpd.apache.org/docs/2.0/ssl/ssl_intro.html
*/

#include "curl_setup.h"

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

#include "strcase.h"
#include "url.h"
#include "share.h"
#include "curl_trc.h"
#include "curl_sha256.h"
#include "warnless.h"
#include "curl_printf.h"
#include "strdup.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"


/* information stored about one single SSL session */
struct Curl_ssl_scache_entry {
  char *ssl_peer_key;   /* id for peer + relevant TLS configuration */
  unsigned char key_salt[CURL_SHA256_DIGEST_LENGTH]; /* for entry export */
  unsigned char key_hmac[CURL_SHA256_DIGEST_LENGTH]; /* for entry export */
  unsigned char *sdata; /* session data, plain bytes */
  size_t sdata_len;     /* number of bytes in sdata */
  void *sobj;           /* session object instance or NULL */
  Curl_ssl_scache_obj_dtor *sobj_free; /* free `sobj` callback */
  long age;             /* just a number, the higher the more recent */
  curl_off_t time_received; /* seconds since EPOCH session was received */
  int lifetime_secs;    /* peer announced entry lifetime (-1 unknown) */
  int ietf_tls_id;      /* TLS protocol identifier negotiated */
  char *alpn;           /* APLN TLS negotiated protocol string */
  char *clientcert;
#ifdef USE_TLS_SRP
  char *srp_username;
  char *srp_password;
#endif
  BIT(hmac_set);        /* if key_salt and key_hmac are present */
};

struct Curl_ssl_scache {
  struct Curl_ssl_scache_entry *entries;
  size_t count;
  long age;
};

CURLcode Curl_ssl_scache_create(size_t max_entries,
                                struct Curl_ssl_scache **pspool)
{
  struct Curl_ssl_scache *spool;
  struct Curl_ssl_scache_entry *entries;

  *pspool = NULL;
  entries = calloc(max_entries, sizeof(*entries));
  if(!entries)
    return CURLE_OUT_OF_MEMORY;

  spool = calloc(1, sizeof(*spool));
  if(!spool) {
    free(entries);
    return CURLE_OUT_OF_MEMORY;
  }

  spool->count = max_entries;
  spool->entries = entries;
  spool->age = 1;
  *pspool = spool;
  return CURLE_OK;
}

static void cf_ssl_scache_clear_data(struct Curl_ssl_scache_entry *entry)
{
  if(entry->sdata)
    Curl_safefree(entry->sdata);
  entry->sdata_len = 0;
  if(entry->sobj) {
    DEBUGASSERT(entry->sobj_free);
    if(entry->sobj_free)
      entry->sobj_free(entry->sobj);
    entry->sobj = NULL;
  }
  entry->sobj_free = NULL;
}

static void cf_ssl_scache_clear_entry(struct Curl_ssl_scache_entry *entry)
{
  cf_ssl_scache_clear_data(entry);
  entry->age = 0; /* fresh */
  Curl_safefree(entry->alpn);
  Curl_safefree(entry->clientcert);
#ifdef USE_TLS_SRP
  Curl_safefree(entry->srp_username);
  Curl_safefree(entry->srp_password);
#endif
  Curl_safefree(entry->ssl_peer_key);
  entry->hmac_set = FALSE;
}

void Curl_ssl_scache_destroy(struct Curl_ssl_scache *spool)
{
  if(spool) {
    size_t i;
    for(i = 0; i < spool->count; ++i) {
      cf_ssl_scache_clear_entry(&spool->entries[i]);
    }
    free(spool->entries);
    free(spool);
  }
}

/*
 * Lock shared SSL session data
 */
void Curl_ssl_scache_lock(struct Curl_easy *data)
{
  if(CURL_SHARE_ssl_scache(data))
    Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
}

/*
 * Unlock shared SSL session data
 */
void Curl_ssl_scache_unlock(struct Curl_easy *data)
{
  if(CURL_SHARE_ssl_scache(data))
    Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);
}

static CURLcode cf_ssl_peer_key_add_path(struct dynbuf *buf,
                                          const char *name,
                                          char *path)
{
  if(path && path[0]) {
    /* We try to add absolute paths, so that the session key can stay
     * valid when used in another process with different CWD. However,
     * when a path does not exist, this does not work. Then, we add
     * the path as is. */
#ifdef _WIN32
    char abspath[_MAX_PATH];
    if(_fullpath(abspath, path, _MAX_PATH))
      return Curl_dyn_addf(buf, ":%s-%s", name, abspath);
#else
    if(path[0] != '/') {
      char *abspath = realpath(path, NULL);
      if(abspath) {
        CURLcode r = Curl_dyn_addf(buf, ":%s-%s", name, abspath);
        (free)(abspath); /* allocated by libc, free without memdebug */
        return r;
      }
    }
#endif
    return Curl_dyn_addf(buf, ":%s-%s", name, path);
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

    r = Curl_dyn_addf(buf, ":%s-", name);
    if(r)
      goto out;
    r = Curl_sha256it(hash, blob->data, blob->len);
    if(r)
      goto out;
    for(i = 0; i < CURL_SHA256_DIGEST_LENGTH; ++i) {
      r = Curl_dyn_addf(buf, "%02x", hash[i]);
      if(r)
        goto out;
    }
  }
out:
  return r;
}

CURLcode Curl_ssl_peer_key_make(struct Curl_cfilter *cf,
                                const struct ssl_peer *peer,
                                const char *tls_id,
                                char **ppeer_key)
{
  struct ssl_primary_config *ssl = Curl_ssl_cf_get_primary_config(cf);
  struct dynbuf buf;
  CURLcode r;

  *ppeer_key = NULL;
  Curl_dyn_init(&buf, 10 * 1024);

  r = Curl_dyn_addf(&buf, ":%s:%d", peer->hostname, peer->port);
  if(r)
    goto out;

  switch(peer->transport) {
  case TRNSPRT_TCP:
    break;
  case TRNSPRT_UDP:
    r = Curl_dyn_add(&buf, ":UDP");
    break;
  case TRNSPRT_QUIC:
    r = Curl_dyn_add(&buf, ":QUIC");
    break;
  case TRNSPRT_UNIX:
    r = Curl_dyn_add(&buf, ":UNIX");
    break;
  default:
    r = Curl_dyn_addf(&buf, ":TRNSPRT-%d", peer->transport);
    break;
  }
  if(r)
    goto out;

  if(!ssl->verifypeer) {
    r = Curl_dyn_add(&buf, ":NO-VRFY-PEER");
    if(r)
      goto out;
  }
  if(!ssl->verifyhost) {
    r = Curl_dyn_add(&buf, ":NO-VRFY-HOST");
    if(r)
      goto out;
  }
  if(ssl->verifystatus) {
    r = Curl_dyn_add(&buf, ":VRFY-STATUS");
    if(r)
      goto out;
  }
  if(!ssl->verifypeer || !ssl->verifyhost) {
    if(cf->conn->bits.conn_to_host) {
      r = Curl_dyn_addf(&buf, ":CHOST-%s", cf->conn->conn_to_host.name);
      if(r)
        goto out;
    }
    if(cf->conn->bits.conn_to_port) {
      r = Curl_dyn_addf(&buf, ":CPORT-%d", cf->conn->conn_to_port);
      if(r)
        goto out;
    }
  }

  if(ssl->version || ssl->version_max) {
    r = Curl_dyn_addf(&buf, ":TLSVER-%d-%d", ssl->version, ssl->version_max);
    if(r)
      goto out;
  }
  if(ssl->ssl_options) {
    r = Curl_dyn_addf(&buf, ":TLSOPT-%x", ssl->ssl_options);
    if(r)
      goto out;
  }
  if(ssl->cipher_list) {
    r = Curl_dyn_addf(&buf, ":CIPHER-%s", ssl->cipher_list);
    if(r)
      goto out;
  }
  if(ssl->cipher_list13) {
    r = Curl_dyn_addf(&buf, ":CIPHER13-%s", ssl->cipher_list13);
    if(r)
      goto out;
  }
  if(ssl->curves) {
    r = Curl_dyn_addf(&buf, ":CURVES-%s", ssl->curves);
    if(r)
      goto out;
  }
  r = cf_ssl_peer_key_add_path(&buf, "CA", ssl->CAfile);
  if(r)
    goto out;
  r = cf_ssl_peer_key_add_path(&buf, "CApath", ssl->CApath);
  if(r)
    goto out;
  r = cf_ssl_peer_key_add_path(&buf, "CRL", ssl->CRLfile);
  if(r)
    goto out;
  r = cf_ssl_peer_key_add_path(&buf, "Issuer", ssl->issuercert);
  if(r)
    goto out;
  if(ssl->pinned_key && ssl->pinned_key[0]) {
    r = Curl_dyn_addf(&buf, ":Pinned-%s", ssl->pinned_key);
    if(r)
      goto out;
  }
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

  if(ssl->clientcert && ssl->clientcert[0]) {
    r = Curl_dyn_add(&buf, ":CCERT");
    if(r)
      goto out;
  }
#ifdef USE_TLS_SRP
  if(ssl->username || ssl->password) {
    r = Curl_dyn_add(&buf, ":SRP-AUTH");
    if(r)
      goto out;
  }
#endif

  if(!tls_id || !tls_id[0]) {
    r = CURLE_FAILED_INIT;
    goto out;
  }
  r = Curl_dyn_addf(&buf, ":IMPL-%s", tls_id);
  if(r)
    goto out;

  *ppeer_key = Curl_dyn_strdup(&buf);
  if(!*ppeer_key)
    r = CURLE_OUT_OF_MEMORY;

out:
  Curl_dyn_free(&buf);
  return r;
}

static bool cf_ssl_scache_match_auth(struct Curl_ssl_scache_entry *entry,
                                     struct ssl_primary_config *conn_config)
{
  if(!Curl_safecmp(entry->clientcert, conn_config->clientcert))
    return FALSE;
#ifdef USE_TLS_SRP
   if(Curl_timestrcmp(entry->srp_username, conn_config->username) ||
      Curl_timestrcmp(entry->srp_password, conn_config->password))
     return FALSE;
#endif
  return TRUE;
}

static CURLcode cf_ssl_find_entry(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  const char *ssl_peer_key,
                                  struct Curl_ssl_scache_entry **pentry)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_ssl_scache *spool = data->state.ssl_scache;
  size_t i, peer_key_len = 0;

  *pentry = NULL;
  /* check for entries with known peer_key */
  for(i = 0; spool && i < spool->count; i++) {
    if(spool->entries[i].ssl_peer_key &&
       strcasecompare(ssl_peer_key, spool->entries[i].ssl_peer_key) &&
       cf_ssl_scache_match_auth(&spool->entries[i], conn_config)) {
      /* yes, we have a cached session for this! */
      *pentry = &spool->entries[i];
      return CURLE_OK;
    }
  }
  /* check for entries with HMAC set but no known peer_key */
  for(i = 0; spool && i < spool->count; i++) {
    if(!spool->entries[i].ssl_peer_key &&
       spool->entries[i].hmac_set &&
       cf_ssl_scache_match_auth(&spool->entries[i], conn_config)) {
      /* possible entry with unknown peer_key, check hmac */
      unsigned char my_hmac[CURL_SHA256_DIGEST_LENGTH];
      if(!peer_key_len) /* we are lazy */
        peer_key_len = strlen(ssl_peer_key);
      (void)Curl_hmacit(&Curl_HMAC_SHA256,
                        spool->entries[i].key_salt,
                        sizeof(spool->entries[i].key_salt),
                        (const unsigned char *)ssl_peer_key,
                        peer_key_len,
                        my_hmac);
      if(!memcmp(spool->entries[i].key_hmac, my_hmac, sizeof(my_hmac))) {
        /* remember peer_key for future lookups */
        spool->entries[i].ssl_peer_key = strdup(ssl_peer_key);
        if(!spool->entries[i].ssl_peer_key)
          return CURLE_OUT_OF_MEMORY;
        *pentry = &spool->entries[i];
        return CURLE_OK;
      }
    }
  }
  return CURLE_OK;
}

bool Curl_ssl_scache_get(struct Curl_cfilter *cf,
                        struct Curl_easy *data,
                        const char *ssl_peer_key,
                        const unsigned char **sdata, size_t *sdata_len,
                        char **palpn)
{
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct Curl_ssl_scache *spool = data->state.ssl_scache;
  struct Curl_ssl_scache_entry *entry = NULL;
  CURLcode result;

  *sdata = NULL;
  *sdata_len = 0;
  if(!ssl_config)
    return FALSE;

  DEBUGASSERT(ssl_config->primary.cache_session);
  if(!ssl_config->primary.cache_session || !spool)
    return FALSE;

  result = cf_ssl_find_entry(cf, data, ssl_peer_key, &entry);
  if(result) {
    CURL_TRC_CF(data, cf, "failure finding session: %d", result);
    return FALSE;
  }
  if(entry && entry->sdata) {
    DEBUGASSERT(entry->ssl_peer_key);
    (spool->age)++;            /* increase general age */
    entry->age = spool->age; /* set this as used in this age */
    *sdata = entry->sdata;
    *sdata_len = entry->sdata_len;
    if(palpn)
      *palpn = entry->alpn;
  }
  CURL_TRC_CF(data, cf, "%s cached session for '%s'",
              *sdata ? "Found" : "No", ssl_peer_key);
  return !!*sdata;
}

bool Curl_ssl_scache_get_obj(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             const char *ssl_peer_key,
                             void **sobj,
                             char **palpn)
{
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct Curl_ssl_scache *spool = data->state.ssl_scache;
  struct Curl_ssl_scache_entry *entry = NULL;
  CURLcode result;

  *sobj = NULL;
  if(!ssl_config)
    return FALSE;

  DEBUGASSERT(ssl_config->primary.cache_session);
  if(!ssl_config->primary.cache_session || !spool)
    return FALSE;

  result = cf_ssl_find_entry(cf, data, ssl_peer_key, &entry);
  if(result) {
    CURL_TRC_CF(data, cf, "failure finding session: %d", result);
    return FALSE;
  }
  if(entry && entry->sobj) {
    DEBUGASSERT(entry->ssl_peer_key);
    (spool->age)++;            /* increase general age */
    entry->age = spool->age; /* set this as used in this age */
    *sobj = entry->sobj;
    if(palpn)
      *palpn = entry->alpn;
  }
  CURL_TRC_CF(data, cf, "%s cached session for '%s'",
              *sobj ? "Found" : "No", ssl_peer_key);
  return !!*sobj;
}

static void cf_ssl_scache_data_free(void *session)
{
  free(session);
}

CURLcode Curl_ssl_scache_add(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             const char *ssl_peer_key,
                             unsigned char *sdata,
                             size_t sdata_len,
                             int lifetime_secs,
                             int ietf_tls_id,
                             const char *alpn)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_ssl_scache *spool = data->state.ssl_scache;
  struct Curl_ssl_scache_entry *entry = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(sdata);
  DEBUGASSERT(sdata_len);
  if(!spool || !spool->count || !sdata_len) {
    cf_ssl_scache_data_free(sdata);
    return CURLE_OK;
  }

  result = cf_ssl_find_entry(cf, data, ssl_peer_key, &entry);
  if(result) {
    CURL_TRC_CF(data, cf, "failure finding session: %d", result);
    goto out;
  }

  if(entry) {
    /* Have a matching entry. Does it hold the same sdata already? */
    if(entry->sdata && (entry->sdata_len == sdata_len) &&
        !memcmp(entry->sdata, sdata, sdata_len)) {
      cf_ssl_scache_data_free(sdata);
      return CURLE_OK;
    }
    /* real update, clear existing session data */
    cf_ssl_scache_clear_data(entry);
  }
  else {
    size_t i;

    /* find a free entry or the entry with the smallest `age` */
    for(i = 0; i < spool->count; ++i) {
      if(!spool->entries[i].ssl_peer_key && !spool->entries[i].hmac_set) {
        entry = &spool->entries[i];
        break;
      }
      if(!entry || (spool->entries[i].age < entry->age)) {
        entry = &spool->entries[i];
      }
    }

    result = CURLE_OUT_OF_MEMORY; /* default, pessimistic */
    DEBUGASSERT(entry);
    if(!entry) {
      cf_ssl_scache_data_free(sdata);
      return CURLE_OK;
    }
    cf_ssl_scache_clear_entry(entry);
    DEBUGASSERT(!entry->ssl_peer_key);

    /* setup entry with everything but the session data */
    entry->ietf_tls_id = ietf_tls_id;
    entry->time_received = (curl_off_t)time(NULL);
    entry->lifetime_secs = lifetime_secs;
    entry->ssl_peer_key = strdup(ssl_peer_key);
    if(!entry->ssl_peer_key)
      goto out;
    DEBUGASSERT(!entry->alpn);
    entry->alpn = alpn ? strdup(alpn) : NULL;
    if(alpn && !entry->alpn)
      goto out;
    /* If the connection uses TLS authentication data, we need to remember
     * it for lookups */
    if(conn_config->clientcert) {
      entry->clientcert = strdup(conn_config->clientcert);
      if(!entry->clientcert)
        goto out;
    }
#ifdef USE_TLS_SRP
    if(conn_config->username) {
      entry->srp_username = strdup(conn_config->username);
      if(!entry->srp_username)
        goto out;
    }
    if(conn_config->password) {
      entry->srp_password = strdup(conn_config->password);
      if(!entry->srp_password)
        goto out;
    }
#endif
  }

  /* entry has everything but the session data, add it */
  DEBUGASSERT(entry);
  DEBUGASSERT(entry->ssl_peer_key);
  DEBUGASSERT(!entry->sdata);
  DEBUGASSERT(!entry->sobj);
  entry->age = spool->age;
  entry->sdata = sdata;
  entry->sdata_len = sdata_len;
  result = CURLE_OK;

out:
  if(result) {
    failf(data, "Failed to add SSL Session to cache for %s", ssl_peer_key);
    cf_ssl_scache_data_free(sdata);
    if(entry)
      cf_ssl_scache_clear_entry(entry);
  }
  else
    CURL_TRC_CF(data, cf, "Added %sSSL Session to cache for '%s",
                Curl_ssl_cf_is_proxy(cf) ? "PROXY " : "", ssl_peer_key);
  return result;
}

CURLcode Curl_ssl_scache_add_obj(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const char *ssl_peer_key,
                                 void *sobj,
                                 Curl_ssl_scache_obj_dtor *sobj_dtor_cb,
                                 int lifetime_secs,
                                 int ietf_tls_id,
                                 const char *alpn)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_ssl_scache *spool = data->state.ssl_scache;
  struct Curl_ssl_scache_entry *entry = NULL;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  DEBUGASSERT(sobj);
  DEBUGASSERT(sobj_dtor_cb);
  if(!spool || !spool->count || !sobj) {
    if(sobj_dtor_cb)
      sobj_dtor_cb(sobj);
    return CURLE_OK;
  }

  result = cf_ssl_find_entry(cf, data, ssl_peer_key, &entry);
  if(result) {
    CURL_TRC_CF(data, cf, "failure finding session: %d", result);
    if(sobj_dtor_cb)
      sobj_dtor_cb(sobj);
    return result;
  }
  if(entry) {
    /* Have a matching entry. Does it hold the same session already? */
    if(entry->sobj == sobj) {
      if(sobj_dtor_cb)
        sobj_dtor_cb(sobj);
      return CURLE_OK;
    }
    /* real update, clear existing session data */
    cf_ssl_scache_clear_data(entry);
  }
  else {
    size_t i;

    /* find a free entry or the entry with the smallest `age` */
    for(i = 0; i < spool->count; ++i) {
      if(!spool->entries[i].ssl_peer_key) {  /* free entry */
        entry = &spool->entries[i];
        break;
      }
      if(!entry || (spool->entries[i].age < entry->age)) {
        entry = &spool->entries[i];
      }
    }

    DEBUGASSERT(entry);
    if(!entry)
      return CURLE_OK;

    entry->ietf_tls_id = ietf_tls_id;
    entry->time_received = (curl_off_t)time(NULL);
    entry->lifetime_secs = lifetime_secs;
    cf_ssl_scache_clear_entry(entry);
    DEBUGASSERT(!entry->ssl_peer_key);

    /* setup entry with everything but the session data */
    entry->ssl_peer_key = strdup(ssl_peer_key);
    if(!entry->ssl_peer_key)
      goto out;
    DEBUGASSERT(!entry->alpn);
    entry->alpn = alpn ? strdup(alpn) : NULL;
    if(alpn && !entry->alpn)
      goto out;
    /* If the connection uses TLS authentication data, we need to remember
     * it for lookups */
    if(conn_config->clientcert) {
      entry->clientcert = strdup(conn_config->clientcert);
      if(!entry->clientcert)
        goto out;
    }
#ifdef USE_TLS_SRP
    if(conn_config->username) {
      entry->srp_username = strdup(conn_config->username);
      if(!entry->srp_username)
        goto out;
    }
    if(conn_config->password) {
      entry->srp_password = strdup(conn_config->password);
      if(!entry->srp_password)
        goto out;
    }
#endif
  }

  /* entry has everything but the session data, add it */
  DEBUGASSERT(entry);
  DEBUGASSERT(entry->ssl_peer_key);
  DEBUGASSERT(!entry->sdata);
  DEBUGASSERT(!entry->sobj);
  entry->age = spool->age;
  entry->sobj = sobj;
  entry->sobj_free = sobj_dtor_cb;
  result = CURLE_OK;

out:
  if(result) {
    failf(data, "Failed to add SSL Session to cache for %s", ssl_peer_key);
    if(sobj_dtor_cb)
      sobj_dtor_cb(sobj);
    if(entry)
      cf_ssl_scache_clear_entry(entry);
  }
  else
    CURL_TRC_CF(data, cf, "Added %sSSL Session to cache for '%s",
                Curl_ssl_cf_is_proxy(cf) ? "PROXY " : "", ssl_peer_key);
  return result;
}

void Curl_ssl_scache_remove(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            const char *ssl_peer_key,
                            const unsigned char *sdata)
{
  struct Curl_ssl_scache *spool = data->state.ssl_scache;
  size_t i;

  (void)cf;
  if(!spool || !spool->count)
    return;

  for(i = 0; i < spool->count; ++i) {
    if(spool->entries[i].ssl_peer_key &&
       strcasecompare(ssl_peer_key, spool->entries[i].ssl_peer_key) &&
       spool->entries[i].sdata == sdata) {
      cf_ssl_scache_clear_entry(&spool->entries[i]);
    }
  }
}

void Curl_ssl_scache_remove_all(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                const char *ssl_peer_key)
{
  struct Curl_ssl_scache *spool = data->state.ssl_scache;
  size_t i;

  (void)cf;
  if(!spool || !spool->count)
    return;

  for(i = 0; i < spool->count; ++i) {
    if(spool->entries[i].ssl_peer_key &&
       strcasecompare(ssl_peer_key, spool->entries[i].ssl_peer_key)) {
      cf_ssl_scache_clear_entry(&spool->entries[i]);
    }
  }
}

#endif /* USE_SSL */
