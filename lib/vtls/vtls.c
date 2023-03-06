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
#include "slist.h"
#include "sendf.h"
#include "strcase.h"
#include "url.h"
#include "progress.h"
#include "share.h"
#include "multiif.h"
#include "timeval.h"
#include "curl_md5.h"
#include "warnless.h"
#include "curl_base64.h"
#include "curl_printf.h"
#include "strdup.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"


/* convenience macro to check if this handle is using a shared SSL session */
#define SSLSESSION_SHARED(data) (data->share &&                        \
                                 (data->share->specifier &             \
                                  (1<<CURL_LOCK_DATA_SSL_SESSION)))

#define CLONE_STRING(var)                    \
  do {                                       \
    if(source->var) {                        \
      dest->var = strdup(source->var);       \
      if(!dest->var)                         \
        return FALSE;                        \
    }                                        \
    else                                     \
      dest->var = NULL;                      \
  } while(0)

#define CLONE_BLOB(var)                        \
  do {                                         \
    if(blobdup(&dest->var, source->var))       \
      return FALSE;                            \
  } while(0)

static CURLcode blobdup(struct curl_blob **dest,
                        struct curl_blob *src)
{
  DEBUGASSERT(dest);
  DEBUGASSERT(!*dest);
  if(src) {
    /* only if there's data to dupe! */
    struct curl_blob *d;
    d = malloc(sizeof(struct curl_blob) + src->len);
    if(!d)
      return CURLE_OUT_OF_MEMORY;
    d->len = src->len;
    /* Always duplicate because the connection may survive longer than the
       handle that passed in the blob. */
    d->flags = CURL_BLOB_COPY;
    d->data = (void *)((char *)d + sizeof(struct curl_blob));
    memcpy(d->data, src->data, src->len);
    *dest = d;
  }
  return CURLE_OK;
}

/* returns TRUE if the blobs are identical */
static bool blobcmp(struct curl_blob *first, struct curl_blob *second)
{
  if(!first && !second) /* both are NULL */
    return TRUE;
  if(!first || !second) /* one is NULL */
    return FALSE;
  if(first->len != second->len) /* different sizes */
    return FALSE;
  return !memcmp(first->data, second->data, first->len); /* same data */
}


bool
Curl_ssl_config_matches(struct ssl_primary_config *data,
                        struct ssl_primary_config *needle)
{
  if((data->version == needle->version) &&
     (data->version_max == needle->version_max) &&
     (data->ssl_options == needle->ssl_options) &&
     (data->verifypeer == needle->verifypeer) &&
     (data->verifyhost == needle->verifyhost) &&
     (data->verifystatus == needle->verifystatus) &&
     blobcmp(data->cert_blob, needle->cert_blob) &&
     blobcmp(data->ca_info_blob, needle->ca_info_blob) &&
     blobcmp(data->issuercert_blob, needle->issuercert_blob) &&
     Curl_safecmp(data->CApath, needle->CApath) &&
     Curl_safecmp(data->CAfile, needle->CAfile) &&
     Curl_safecmp(data->issuercert, needle->issuercert) &&
     Curl_safecmp(data->clientcert, needle->clientcert) &&
#ifdef USE_TLS_SRP
     !Curl_timestrcmp(data->username, needle->username) &&
     !Curl_timestrcmp(data->password, needle->password) &&
#endif
     strcasecompare(data->cipher_list, needle->cipher_list) &&
     strcasecompare(data->cipher_list13, needle->cipher_list13) &&
     strcasecompare(data->curves, needle->curves) &&
     strcasecompare(data->CRLfile, needle->CRLfile) &&
     strcasecompare(data->pinned_key, needle->pinned_key))
    return TRUE;

  return FALSE;
}

bool
Curl_clone_primary_ssl_config(struct ssl_primary_config *source,
                              struct ssl_primary_config *dest)
{
  dest->version = source->version;
  dest->version_max = source->version_max;
  dest->verifypeer = source->verifypeer;
  dest->verifyhost = source->verifyhost;
  dest->verifystatus = source->verifystatus;
  dest->sessionid = source->sessionid;
  dest->ssl_options = source->ssl_options;

  CLONE_BLOB(cert_blob);
  CLONE_BLOB(ca_info_blob);
  CLONE_BLOB(issuercert_blob);
  CLONE_STRING(CApath);
  CLONE_STRING(CAfile);
  CLONE_STRING(issuercert);
  CLONE_STRING(clientcert);
  CLONE_STRING(cipher_list);
  CLONE_STRING(cipher_list13);
  CLONE_STRING(pinned_key);
  CLONE_STRING(curves);
  CLONE_STRING(CRLfile);
#ifdef USE_TLS_SRP
  CLONE_STRING(username);
  CLONE_STRING(password);
#endif

  return TRUE;
}

void Curl_free_primary_ssl_config(struct ssl_primary_config *sslc)
{
  Curl_safefree(sslc->CApath);
  Curl_safefree(sslc->CAfile);
  Curl_safefree(sslc->issuercert);
  Curl_safefree(sslc->clientcert);
  Curl_safefree(sslc->cipher_list);
  Curl_safefree(sslc->cipher_list13);
  Curl_safefree(sslc->pinned_key);
  Curl_safefree(sslc->cert_blob);
  Curl_safefree(sslc->ca_info_blob);
  Curl_safefree(sslc->issuercert_blob);
  Curl_safefree(sslc->curves);
  Curl_safefree(sslc->CRLfile);
#ifdef USE_TLS_SRP
  Curl_safefree(sslc->username);
  Curl_safefree(sslc->password);
#endif
}

#ifdef USE_SSL
static int multissl_setup(const struct Curl_ssl *backend);
#endif

curl_sslbackend Curl_ssl_backend(void)
{
#ifdef USE_SSL
  multissl_setup(NULL);
  return Curl_ssl->info.id;
#else
  return CURLSSLBACKEND_NONE;
#endif
}

#ifdef USE_SSL

/* "global" init done? */
static bool init_ssl = FALSE;

/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
int Curl_ssl_init(void)
{
  /* make sure this is only done once */
  if(init_ssl)
    return 1;
  init_ssl = TRUE; /* never again */

  return Curl_ssl->init();
}

#if defined(CURL_WITH_MULTI_SSL)
static const struct Curl_ssl Curl_ssl_multi;
#endif

/* Global cleanup */
void Curl_ssl_cleanup(void)
{
  if(init_ssl) {
    /* only cleanup if we did a previous init */
    Curl_ssl->cleanup();
#if defined(CURL_WITH_MULTI_SSL)
    Curl_ssl = &Curl_ssl_multi;
#endif
    init_ssl = FALSE;
  }
}

static bool ssl_prefs_check(struct Curl_easy *data)
{
  /* check for CURLOPT_SSLVERSION invalid parameter value */
  const unsigned char sslver = data->set.ssl.primary.version;
  if(sslver >= CURL_SSLVERSION_LAST) {
    failf(data, "Unrecognized parameter value passed via CURLOPT_SSLVERSION");
    return FALSE;
  }

  switch(data->set.ssl.primary.version_max) {
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_DEFAULT:
    break;

  default:
    if((data->set.ssl.primary.version_max >> 16) < sslver) {
      failf(data, "CURL_SSLVERSION_MAX incompatible with CURL_SSLVERSION");
      return FALSE;
    }
  }

  return TRUE;
}

static struct ssl_connect_data *cf_ctx_new(struct Curl_easy *data,
                                           const struct alpn_spec *alpn)
{
  struct ssl_connect_data *ctx;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx)
    return NULL;

  ctx->alpn = alpn;
  ctx->backend = calloc(1, Curl_ssl->sizeof_ssl_backend_data);
  if(!ctx->backend) {
    free(ctx);
    return NULL;
  }
  return ctx;
}

static void cf_ctx_free(struct ssl_connect_data *ctx)
{
  if(ctx) {
    free(ctx->backend);
    free(ctx);
  }
}

static CURLcode ssl_connect(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode result;

  if(!ssl_prefs_check(data))
    return CURLE_SSL_CONNECT_ERROR;

  /* mark this is being ssl-enabled from here on. */
  connssl->state = ssl_connection_negotiating;

  result = Curl_ssl->connect_blocking(cf, data);

  if(!result) {
    DEBUGASSERT(connssl->state == ssl_connection_complete);
  }

  return result;
}

static CURLcode
ssl_connect_nonblocking(struct Curl_cfilter *cf, struct Curl_easy *data,
                        bool *done)
{
  if(!ssl_prefs_check(data))
    return CURLE_SSL_CONNECT_ERROR;

  /* mark this is being ssl requested from here on. */
  return Curl_ssl->connect_nonblocking(cf, data, done);
}

/*
 * Lock shared SSL session data
 */
void Curl_ssl_sessionid_lock(struct Curl_easy *data)
{
  if(SSLSESSION_SHARED(data))
    Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, CURL_LOCK_ACCESS_SINGLE);
}

/*
 * Unlock shared SSL session data
 */
void Curl_ssl_sessionid_unlock(struct Curl_easy *data)
{
  if(SSLSESSION_SHARED(data))
    Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION);
}

/*
 * Check if there's a session ID for the given connection in the cache, and if
 * there's one suitable, it is provided. Returns TRUE when no entry matched.
 */
bool Curl_ssl_getsessionid(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           void **ssl_sessionid,
                           size_t *idsize) /* set 0 if unknown */
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct Curl_ssl_session *check;
  size_t i;
  long *general_age;
  bool no_match = TRUE;

  *ssl_sessionid = NULL;
  if(!ssl_config)
    return TRUE;

  DEBUGASSERT(ssl_config->primary.sessionid);

  if(!ssl_config->primary.sessionid || !data->state.session)
    /* session ID re-use is disabled or the session cache has not been
       setup */
    return TRUE;

  /* Lock if shared */
  if(SSLSESSION_SHARED(data))
    general_age = &data->share->sessionage;
  else
    general_age = &data->state.sessionage;

  for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++) {
    check = &data->state.session[i];
    if(!check->sessionid)
      /* not session ID means blank entry */
      continue;
    if(strcasecompare(connssl->hostname, check->name) &&
       ((!cf->conn->bits.conn_to_host && !check->conn_to_host) ||
        (cf->conn->bits.conn_to_host && check->conn_to_host &&
         strcasecompare(cf->conn->conn_to_host.name, check->conn_to_host))) &&
       ((!cf->conn->bits.conn_to_port && check->conn_to_port == -1) ||
        (cf->conn->bits.conn_to_port && check->conn_to_port != -1 &&
         cf->conn->conn_to_port == check->conn_to_port)) &&
       (connssl->port == check->remote_port) &&
       strcasecompare(cf->conn->handler->scheme, check->scheme) &&
       Curl_ssl_config_matches(conn_config, &check->ssl_config)) {
      /* yes, we have a session ID! */
      (*general_age)++;          /* increase general age */
      check->age = *general_age; /* set this as used in this age */
      *ssl_sessionid = check->sessionid;
      if(idsize)
        *idsize = check->idsize;
      no_match = FALSE;
      break;
    }
  }

  DEBUGF(infof(data, DMSG(data, "%s Session ID in cache for %s %s://%s:%d"),
               no_match? "Didn't find": "Found",
               Curl_ssl_cf_is_proxy(cf) ? "proxy" : "host",
               cf->conn->handler->scheme, connssl->hostname, connssl->port));
  return no_match;
}

/*
 * Kill a single session ID entry in the cache.
 */
void Curl_ssl_kill_session(struct Curl_ssl_session *session)
{
  if(session->sessionid) {
    /* defensive check */

    /* free the ID the SSL-layer specific way */
    Curl_ssl->session_free(session->sessionid);

    session->sessionid = NULL;
    session->age = 0; /* fresh */

    Curl_free_primary_ssl_config(&session->ssl_config);

    Curl_safefree(session->name);
    Curl_safefree(session->conn_to_host);
  }
}

/*
 * Delete the given session ID from the cache.
 */
void Curl_ssl_delsessionid(struct Curl_easy *data, void *ssl_sessionid)
{
  size_t i;

  for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++) {
    struct Curl_ssl_session *check = &data->state.session[i];

    if(check->sessionid == ssl_sessionid) {
      Curl_ssl_kill_session(check);
      break;
    }
  }
}

/*
 * Store session id in the session cache. The ID passed on to this function
 * must already have been extracted and allocated the proper way for the SSL
 * layer. Curl_XXXX_session_free() will be called to free/kill the session ID
 * later on.
 */
CURLcode Curl_ssl_addsessionid(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               void *ssl_sessionid,
                               size_t idsize,
                               bool *added)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  size_t i;
  struct Curl_ssl_session *store;
  long oldest_age;
  char *clone_host;
  char *clone_conn_to_host;
  int conn_to_port;
  long *general_age;

  if(added)
    *added = FALSE;

  if(!data->state.session)
    return CURLE_OK;

  store = &data->state.session[0];
  oldest_age = data->state.session[0].age; /* zero if unused */
  (void)ssl_config;
  DEBUGASSERT(ssl_config->primary.sessionid);

  clone_host = strdup(connssl->hostname);
  if(!clone_host)
    return CURLE_OUT_OF_MEMORY; /* bail out */

  if(cf->conn->bits.conn_to_host) {
    clone_conn_to_host = strdup(cf->conn->conn_to_host.name);
    if(!clone_conn_to_host) {
      free(clone_host);
      return CURLE_OUT_OF_MEMORY; /* bail out */
    }
  }
  else
    clone_conn_to_host = NULL;

  if(cf->conn->bits.conn_to_port)
    conn_to_port = cf->conn->conn_to_port;
  else
    conn_to_port = -1;

  /* Now we should add the session ID and the host name to the cache, (remove
     the oldest if necessary) */

  /* If using shared SSL session, lock! */
  if(SSLSESSION_SHARED(data)) {
    general_age = &data->share->sessionage;
  }
  else {
    general_age = &data->state.sessionage;
  }

  /* find an empty slot for us, or find the oldest */
  for(i = 1; (i < data->set.general_ssl.max_ssl_sessions) &&
        data->state.session[i].sessionid; i++) {
    if(data->state.session[i].age < oldest_age) {
      oldest_age = data->state.session[i].age;
      store = &data->state.session[i];
    }
  }
  if(i == data->set.general_ssl.max_ssl_sessions)
    /* cache is full, we must "kill" the oldest entry! */
    Curl_ssl_kill_session(store);
  else
    store = &data->state.session[i]; /* use this slot */

  /* now init the session struct wisely */
  store->sessionid = ssl_sessionid;
  store->idsize = idsize;
  store->age = *general_age;    /* set current age */
  /* free it if there's one already present */
  free(store->name);
  free(store->conn_to_host);
  store->name = clone_host;               /* clone host name */
  store->conn_to_host = clone_conn_to_host; /* clone connect to host name */
  store->conn_to_port = conn_to_port; /* connect to port number */
  /* port number */
  store->remote_port = connssl->port;
  store->scheme = cf->conn->handler->scheme;

  if(!Curl_clone_primary_ssl_config(conn_config, &store->ssl_config)) {
    Curl_free_primary_ssl_config(&store->ssl_config);
    store->sessionid = NULL; /* let caller free sessionid */
    free(clone_host);
    free(clone_conn_to_host);
    return CURLE_OUT_OF_MEMORY;
  }

  if(added)
    *added = TRUE;

  DEBUGF(infof(data, DMSG(data, "Added Session ID to cache for %s://%s:%d"
               " [%s]"), store->scheme, store->name, store->remote_port,
               Curl_ssl_cf_is_proxy(cf) ? "PROXY" : "server"));
  return CURLE_OK;
}

void Curl_free_multi_ssl_backend_data(struct multi_ssl_backend_data *mbackend)
{
  if(Curl_ssl->free_multi_ssl_backend_data && mbackend)
    Curl_ssl->free_multi_ssl_backend_data(mbackend);
}

void Curl_ssl_close_all(struct Curl_easy *data)
{
  /* kill the session ID cache if not shared */
  if(data->state.session && !SSLSESSION_SHARED(data)) {
    size_t i;
    for(i = 0; i < data->set.general_ssl.max_ssl_sessions; i++)
      /* the single-killer function handles empty table slots */
      Curl_ssl_kill_session(&data->state.session[i]);

    /* free the cache data */
    Curl_safefree(data->state.session);
  }

  Curl_ssl->close_all(data);
}

int Curl_ssl_get_select_socks(struct Curl_cfilter *cf, struct Curl_easy *data,
                              curl_socket_t *socks)
{
  struct ssl_connect_data *connssl = cf->ctx;
  curl_socket_t sock = Curl_conn_cf_get_socket(cf->next, data);

  if(sock != CURL_SOCKET_BAD) {
    if(connssl->connecting_state == ssl_connect_2_writing) {
      /* write mode */
      socks[0] = sock;
      return GETSOCK_WRITESOCK(0);
    }
    if(connssl->connecting_state == ssl_connect_2_reading) {
      /* read mode */
      socks[0] = sock;
      return GETSOCK_READSOCK(0);
    }
  }
  return GETSOCK_BLANK;
}

/* Selects an SSL crypto engine
 */
CURLcode Curl_ssl_set_engine(struct Curl_easy *data, const char *engine)
{
  return Curl_ssl->set_engine(data, engine);
}

/* Selects the default SSL crypto engine
 */
CURLcode Curl_ssl_set_engine_default(struct Curl_easy *data)
{
  return Curl_ssl->set_engine_default(data);
}

/* Return list of OpenSSL crypto engine names. */
struct curl_slist *Curl_ssl_engines_list(struct Curl_easy *data)
{
  return Curl_ssl->engines_list(data);
}

/*
 * This sets up a session ID cache to the specified size. Make sure this code
 * is agnostic to what underlying SSL technology we use.
 */
CURLcode Curl_ssl_initsessions(struct Curl_easy *data, size_t amount)
{
  struct Curl_ssl_session *session;

  if(data->state.session)
    /* this is just a precaution to prevent multiple inits */
    return CURLE_OK;

  session = calloc(amount, sizeof(struct Curl_ssl_session));
  if(!session)
    return CURLE_OUT_OF_MEMORY;

  /* store the info in the SSL section */
  data->set.general_ssl.max_ssl_sessions = amount;
  data->state.session = session;
  data->state.sessionage = 1; /* this is brand new */
  return CURLE_OK;
}

static size_t multissl_version(char *buffer, size_t size);

void Curl_ssl_version(char *buffer, size_t size)
{
#ifdef CURL_WITH_MULTI_SSL
  (void)multissl_version(buffer, size);
#else
  (void)Curl_ssl->version(buffer, size);
#endif
}

void Curl_ssl_free_certinfo(struct Curl_easy *data)
{
  struct curl_certinfo *ci = &data->info.certs;

  if(ci->num_of_certs) {
    /* free all individual lists used */
    int i;
    for(i = 0; i<ci->num_of_certs; i++) {
      curl_slist_free_all(ci->certinfo[i]);
      ci->certinfo[i] = NULL;
    }

    free(ci->certinfo); /* free the actual array too */
    ci->certinfo = NULL;
    ci->num_of_certs = 0;
  }
}

CURLcode Curl_ssl_init_certinfo(struct Curl_easy *data, int num)
{
  struct curl_certinfo *ci = &data->info.certs;
  struct curl_slist **table;

  /* Free any previous certificate information structures */
  Curl_ssl_free_certinfo(data);

  /* Allocate the required certificate information structures */
  table = calloc((size_t) num, sizeof(struct curl_slist *));
  if(!table)
    return CURLE_OUT_OF_MEMORY;

  ci->num_of_certs = num;
  ci->certinfo = table;

  return CURLE_OK;
}

/*
 * 'value' is NOT a null-terminated string
 */
CURLcode Curl_ssl_push_certinfo_len(struct Curl_easy *data,
                                    int certnum,
                                    const char *label,
                                    const char *value,
                                    size_t valuelen)
{
  struct curl_certinfo *ci = &data->info.certs;
  char *output;
  struct curl_slist *nl;
  CURLcode result = CURLE_OK;
  size_t labellen = strlen(label);
  size_t outlen = labellen + 1 + valuelen + 1; /* label:value\0 */

  output = malloc(outlen);
  if(!output)
    return CURLE_OUT_OF_MEMORY;

  /* sprintf the label and colon */
  msnprintf(output, outlen, "%s:", label);

  /* memcpy the value (it might not be null-terminated) */
  memcpy(&output[labellen + 1], value, valuelen);

  /* null-terminate the output */
  output[labellen + 1 + valuelen] = 0;

  nl = Curl_slist_append_nodup(ci->certinfo[certnum], output);
  if(!nl) {
    free(output);
    curl_slist_free_all(ci->certinfo[certnum]);
    result = CURLE_OUT_OF_MEMORY;
  }

  ci->certinfo[certnum] = nl;
  return result;
}

/*
 * This is a convenience function for push_certinfo_len that takes a zero
 * terminated value.
 */
CURLcode Curl_ssl_push_certinfo(struct Curl_easy *data,
                                int certnum,
                                const char *label,
                                const char *value)
{
  size_t valuelen = strlen(value);

  return Curl_ssl_push_certinfo_len(data, certnum, label, value, valuelen);
}

CURLcode Curl_ssl_random(struct Curl_easy *data,
                         unsigned char *entropy,
                         size_t length)
{
  return Curl_ssl->random(data, entropy, length);
}

/*
 * Curl_ssl_snihost() converts the input host name to a suitable SNI name put
 * in data->state.buffer. Returns a pointer to the name (or NULL if a problem)
 * and stores the new length in 'olen'.
 *
 * SNI fields must not have any trailing dot and while RFC 6066 section 3 says
 * the SNI field is case insensitive, browsers always send the data lowercase
 * and subsequently there are numerous servers out there that don't work
 * unless the name is lowercased.
 */

char *Curl_ssl_snihost(struct Curl_easy *data, const char *host, size_t *olen)
{
  size_t len = strlen(host);
  if(len && (host[len-1] == '.'))
    len--;
  if(len >= data->set.buffer_size)
    return NULL;

  Curl_strntolower(data->state.buffer, host, len);
  data->state.buffer[len] = 0;
  if(olen)
    *olen = len;
  return data->state.buffer;
}

/*
 * Public key pem to der conversion
 */

static CURLcode pubkey_pem_to_der(const char *pem,
                                  unsigned char **der, size_t *der_len)
{
  char *stripped_pem, *begin_pos, *end_pos;
  size_t pem_count, stripped_pem_count = 0, pem_len;
  CURLcode result;

  /* if no pem, exit. */
  if(!pem)
    return CURLE_BAD_CONTENT_ENCODING;

  begin_pos = strstr(pem, "-----BEGIN PUBLIC KEY-----");
  if(!begin_pos)
    return CURLE_BAD_CONTENT_ENCODING;

  pem_count = begin_pos - pem;
  /* Invalid if not at beginning AND not directly following \n */
  if(0 != pem_count && '\n' != pem[pem_count - 1])
    return CURLE_BAD_CONTENT_ENCODING;

  /* 26 is length of "-----BEGIN PUBLIC KEY-----" */
  pem_count += 26;

  /* Invalid if not directly following \n */
  end_pos = strstr(pem + pem_count, "\n-----END PUBLIC KEY-----");
  if(!end_pos)
    return CURLE_BAD_CONTENT_ENCODING;

  pem_len = end_pos - pem;

  stripped_pem = malloc(pem_len - pem_count + 1);
  if(!stripped_pem)
    return CURLE_OUT_OF_MEMORY;

  /*
   * Here we loop through the pem array one character at a time between the
   * correct indices, and place each character that is not '\n' or '\r'
   * into the stripped_pem array, which should represent the raw base64 string
   */
  while(pem_count < pem_len) {
    if('\n' != pem[pem_count] && '\r' != pem[pem_count])
      stripped_pem[stripped_pem_count++] = pem[pem_count];
    ++pem_count;
  }
  /* Place the null terminator in the correct place */
  stripped_pem[stripped_pem_count] = '\0';

  result = Curl_base64_decode(stripped_pem, der, der_len);

  Curl_safefree(stripped_pem);

  return result;
}

/*
 * Generic pinned public key check.
 */

CURLcode Curl_pin_peer_pubkey(struct Curl_easy *data,
                              const char *pinnedpubkey,
                              const unsigned char *pubkey, size_t pubkeylen)
{
  FILE *fp;
  unsigned char *buf = NULL, *pem_ptr = NULL;
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  /* if a path wasn't specified, don't pin */
  if(!pinnedpubkey)
    return CURLE_OK;
  if(!pubkey || !pubkeylen)
    return result;

  /* only do this if pinnedpubkey starts with "sha256//", length 8 */
  if(strncmp(pinnedpubkey, "sha256//", 8) == 0) {
    CURLcode encode;
    size_t encodedlen, pinkeylen;
    char *encoded, *pinkeycopy, *begin_pos, *end_pos;
    unsigned char *sha256sumdigest;

    if(!Curl_ssl->sha256sum) {
      /* without sha256 support, this cannot match */
      return result;
    }

    /* compute sha256sum of public key */
    sha256sumdigest = malloc(CURL_SHA256_DIGEST_LENGTH);
    if(!sha256sumdigest)
      return CURLE_OUT_OF_MEMORY;
    encode = Curl_ssl->sha256sum(pubkey, pubkeylen,
                        sha256sumdigest, CURL_SHA256_DIGEST_LENGTH);

    if(encode != CURLE_OK)
      return encode;

    encode = Curl_base64_encode((char *)sha256sumdigest,
                                CURL_SHA256_DIGEST_LENGTH, &encoded,
                                &encodedlen);
    Curl_safefree(sha256sumdigest);

    if(encode)
      return encode;

    infof(data, " public key hash: sha256//%s", encoded);

    /* it starts with sha256//, copy so we can modify it */
    pinkeylen = strlen(pinnedpubkey) + 1;
    pinkeycopy = malloc(pinkeylen);
    if(!pinkeycopy) {
      Curl_safefree(encoded);
      return CURLE_OUT_OF_MEMORY;
    }
    memcpy(pinkeycopy, pinnedpubkey, pinkeylen);
    /* point begin_pos to the copy, and start extracting keys */
    begin_pos = pinkeycopy;
    do {
      end_pos = strstr(begin_pos, ";sha256//");
      /*
       * if there is an end_pos, null terminate,
       * otherwise it'll go to the end of the original string
       */
      if(end_pos)
        end_pos[0] = '\0';

      /* compare base64 sha256 digests, 8 is the length of "sha256//" */
      if(encodedlen == strlen(begin_pos + 8) &&
         !memcmp(encoded, begin_pos + 8, encodedlen)) {
        result = CURLE_OK;
        break;
      }

      /*
       * change back the null-terminator we changed earlier,
       * and look for next begin
       */
      if(end_pos) {
        end_pos[0] = ';';
        begin_pos = strstr(end_pos, "sha256//");
      }
    } while(end_pos && begin_pos);
    Curl_safefree(encoded);
    Curl_safefree(pinkeycopy);
    return result;
  }

  fp = fopen(pinnedpubkey, "rb");
  if(!fp)
    return result;

  do {
    long filesize;
    size_t size, pem_len;
    CURLcode pem_read;

    /* Determine the file's size */
    if(fseek(fp, 0, SEEK_END))
      break;
    filesize = ftell(fp);
    if(fseek(fp, 0, SEEK_SET))
      break;
    if(filesize < 0 || filesize > MAX_PINNED_PUBKEY_SIZE)
      break;

    /*
     * if the size of our certificate is bigger than the file
     * size then it can't match
     */
    size = curlx_sotouz((curl_off_t) filesize);
    if(pubkeylen > size)
      break;

    /*
     * Allocate buffer for the pinned key
     * With 1 additional byte for null terminator in case of PEM key
     */
    buf = malloc(size + 1);
    if(!buf)
      break;

    /* Returns number of elements read, which should be 1 */
    if((int) fread(buf, size, 1, fp) != 1)
      break;

    /* If the sizes are the same, it can't be base64 encoded, must be der */
    if(pubkeylen == size) {
      if(!memcmp(pubkey, buf, pubkeylen))
        result = CURLE_OK;
      break;
    }

    /*
     * Otherwise we will assume it's PEM and try to decode it
     * after placing null terminator
     */
    buf[size] = '\0';
    pem_read = pubkey_pem_to_der((const char *)buf, &pem_ptr, &pem_len);
    /* if it wasn't read successfully, exit */
    if(pem_read)
      break;

    /*
     * if the size of our certificate doesn't match the size of
     * the decoded file, they can't be the same, otherwise compare
     */
    if(pubkeylen == pem_len && !memcmp(pubkey, pem_ptr, pubkeylen))
      result = CURLE_OK;
  } while(0);

  Curl_safefree(buf);
  Curl_safefree(pem_ptr);
  fclose(fp);

  return result;
}

/*
 * Check whether the SSL backend supports the status_request extension.
 */
bool Curl_ssl_cert_status_request(void)
{
  return Curl_ssl->cert_status_request();
}

/*
 * Check whether the SSL backend supports false start.
 */
bool Curl_ssl_false_start(struct Curl_easy *data)
{
  (void)data;
  return Curl_ssl->false_start();
}

/*
 * Default implementations for unsupported functions.
 */

int Curl_none_init(void)
{
  return 1;
}

void Curl_none_cleanup(void)
{ }

int Curl_none_shutdown(struct Curl_cfilter *cf UNUSED_PARAM,
                       struct Curl_easy *data UNUSED_PARAM)
{
  (void)data;
  (void)cf;
  return 0;
}

int Curl_none_check_cxn(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  (void)cf;
  (void)data;
  return -1;
}

CURLcode Curl_none_random(struct Curl_easy *data UNUSED_PARAM,
                          unsigned char *entropy UNUSED_PARAM,
                          size_t length UNUSED_PARAM)
{
  (void)data;
  (void)entropy;
  (void)length;
  return CURLE_NOT_BUILT_IN;
}

void Curl_none_close_all(struct Curl_easy *data UNUSED_PARAM)
{
  (void)data;
}

void Curl_none_session_free(void *ptr UNUSED_PARAM)
{
  (void)ptr;
}

bool Curl_none_data_pending(struct Curl_cfilter *cf UNUSED_PARAM,
                            const struct Curl_easy *data UNUSED_PARAM)
{
  (void)cf;
  (void)data;
  return 0;
}

bool Curl_none_cert_status_request(void)
{
  return FALSE;
}

CURLcode Curl_none_set_engine(struct Curl_easy *data UNUSED_PARAM,
                              const char *engine UNUSED_PARAM)
{
  (void)data;
  (void)engine;
  return CURLE_NOT_BUILT_IN;
}

CURLcode Curl_none_set_engine_default(struct Curl_easy *data UNUSED_PARAM)
{
  (void)data;
  return CURLE_NOT_BUILT_IN;
}

struct curl_slist *Curl_none_engines_list(struct Curl_easy *data UNUSED_PARAM)
{
  (void)data;
  return (struct curl_slist *)NULL;
}

bool Curl_none_false_start(void)
{
  return FALSE;
}

static int multissl_init(void)
{
  if(multissl_setup(NULL))
    return 1;
  return Curl_ssl->init();
}

static CURLcode multissl_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  if(multissl_setup(NULL))
    return CURLE_FAILED_INIT;
  return Curl_ssl->connect_blocking(cf, data);
}

static CURLcode multissl_connect_nonblocking(struct Curl_cfilter *cf,
                                             struct Curl_easy *data,
                                             bool *done)
{
  if(multissl_setup(NULL))
    return CURLE_FAILED_INIT;
  return Curl_ssl->connect_nonblocking(cf, data, done);
}

static int multissl_get_select_socks(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     curl_socket_t *socks)
{
  if(multissl_setup(NULL))
    return 0;
  return Curl_ssl->get_select_socks(cf, data, socks);
}

static void *multissl_get_internals(struct ssl_connect_data *connssl,
                                    CURLINFO info)
{
  if(multissl_setup(NULL))
    return NULL;
  return Curl_ssl->get_internals(connssl, info);
}

static void multissl_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  if(multissl_setup(NULL))
    return;
  Curl_ssl->close(cf, data);
}

static ssize_t multissl_recv_plain(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   char *buf, size_t len, CURLcode *code)
{
  if(multissl_setup(NULL))
    return CURLE_FAILED_INIT;
  return Curl_ssl->recv_plain(cf, data, buf, len, code);
}

static ssize_t multissl_send_plain(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   const void *mem, size_t len,
                                   CURLcode *code)
{
  if(multissl_setup(NULL))
    return CURLE_FAILED_INIT;
  return Curl_ssl->send_plain(cf, data, mem, len, code);
}

static const struct Curl_ssl Curl_ssl_multi = {
  { CURLSSLBACKEND_NONE, "multi" },  /* info */
  0, /* supports nothing */
  (size_t)-1, /* something insanely large to be on the safe side */

  multissl_init,                     /* init */
  Curl_none_cleanup,                 /* cleanup */
  multissl_version,                  /* version */
  Curl_none_check_cxn,               /* check_cxn */
  Curl_none_shutdown,                /* shutdown */
  Curl_none_data_pending,            /* data_pending */
  Curl_none_random,                  /* random */
  Curl_none_cert_status_request,     /* cert_status_request */
  multissl_connect,                  /* connect */
  multissl_connect_nonblocking,      /* connect_nonblocking */
  multissl_get_select_socks,         /* getsock */
  multissl_get_internals,            /* get_internals */
  multissl_close,                    /* close_one */
  Curl_none_close_all,               /* close_all */
  Curl_none_session_free,            /* session_free */
  Curl_none_set_engine,              /* set_engine */
  Curl_none_set_engine_default,      /* set_engine_default */
  Curl_none_engines_list,            /* engines_list */
  Curl_none_false_start,             /* false_start */
  NULL,                              /* sha256sum */
  NULL,                              /* associate_connection */
  NULL,                              /* disassociate_connection */
  NULL,                              /* free_multi_ssl_backend_data */
  multissl_recv_plain,               /* recv decrypted data */
  multissl_send_plain,               /* send data to encrypt */
};

const struct Curl_ssl *Curl_ssl =
#if defined(CURL_WITH_MULTI_SSL)
  &Curl_ssl_multi;
#elif defined(USE_WOLFSSL)
  &Curl_ssl_wolfssl;
#elif defined(USE_SECTRANSP)
  &Curl_ssl_sectransp;
#elif defined(USE_GNUTLS)
  &Curl_ssl_gnutls;
#elif defined(USE_GSKIT)
  &Curl_ssl_gskit;
#elif defined(USE_MBEDTLS)
  &Curl_ssl_mbedtls;
#elif defined(USE_NSS)
  &Curl_ssl_nss;
#elif defined(USE_RUSTLS)
  &Curl_ssl_rustls;
#elif defined(USE_OPENSSL)
  &Curl_ssl_openssl;
#elif defined(USE_SCHANNEL)
  &Curl_ssl_schannel;
#elif defined(USE_BEARSSL)
  &Curl_ssl_bearssl;
#else
#error "Missing struct Curl_ssl for selected SSL backend"
#endif

static const struct Curl_ssl *available_backends[] = {
#if defined(USE_WOLFSSL)
  &Curl_ssl_wolfssl,
#endif
#if defined(USE_SECTRANSP)
  &Curl_ssl_sectransp,
#endif
#if defined(USE_GNUTLS)
  &Curl_ssl_gnutls,
#endif
#if defined(USE_GSKIT)
  &Curl_ssl_gskit,
#endif
#if defined(USE_MBEDTLS)
  &Curl_ssl_mbedtls,
#endif
#if defined(USE_NSS)
  &Curl_ssl_nss,
#endif
#if defined(USE_OPENSSL)
  &Curl_ssl_openssl,
#endif
#if defined(USE_SCHANNEL)
  &Curl_ssl_schannel,
#endif
#if defined(USE_BEARSSL)
  &Curl_ssl_bearssl,
#endif
#if defined(USE_RUSTLS)
  &Curl_ssl_rustls,
#endif
  NULL
};

static size_t multissl_version(char *buffer, size_t size)
{
  static const struct Curl_ssl *selected;
  static char backends[200];
  static size_t backends_len;
  const struct Curl_ssl *current;

  current = Curl_ssl == &Curl_ssl_multi ? available_backends[0] : Curl_ssl;

  if(current != selected) {
    char *p = backends;
    char *end = backends + sizeof(backends);
    int i;

    selected = current;

    backends[0] = '\0';

    for(i = 0; available_backends[i]; ++i) {
      char vb[200];
      bool paren = (selected != available_backends[i]);

      if(available_backends[i]->version(vb, sizeof(vb))) {
        p += msnprintf(p, end - p, "%s%s%s%s", (p != backends ? " " : ""),
                       (paren ? "(" : ""), vb, (paren ? ")" : ""));
      }
    }

    backends_len = p - backends;
  }

  if(!size)
    return 0;

  if(size <= backends_len) {
    strncpy(buffer, backends, size - 1);
    buffer[size - 1] = '\0';
    return size - 1;
  }

  strcpy(buffer, backends);
  return backends_len;
}

static int multissl_setup(const struct Curl_ssl *backend)
{
  const char *env;
  char *env_tmp;

  if(Curl_ssl != &Curl_ssl_multi)
    return 1;

  if(backend) {
    Curl_ssl = backend;
    return 0;
  }

  if(!available_backends[0])
    return 1;

  env = env_tmp = curl_getenv("CURL_SSL_BACKEND");
#ifdef CURL_DEFAULT_SSL_BACKEND
  if(!env)
    env = CURL_DEFAULT_SSL_BACKEND;
#endif
  if(env) {
    int i;
    for(i = 0; available_backends[i]; i++) {
      if(strcasecompare(env, available_backends[i]->info.name)) {
        Curl_ssl = available_backends[i];
        free(env_tmp);
        return 0;
      }
    }
  }

  /* Fall back to first available backend */
  Curl_ssl = available_backends[0];
  free(env_tmp);
  return 0;
}

/* This function is used to select the SSL backend to use. It is called by
   curl_global_sslset (easy.c) which uses the global init lock. */
CURLsslset Curl_init_sslset_nolock(curl_sslbackend id, const char *name,
                                   const curl_ssl_backend ***avail)
{
  int i;

  if(avail)
    *avail = (const curl_ssl_backend **)&available_backends;

  if(Curl_ssl != &Curl_ssl_multi)
    return id == Curl_ssl->info.id ||
           (name && strcasecompare(name, Curl_ssl->info.name)) ?
           CURLSSLSET_OK :
#if defined(CURL_WITH_MULTI_SSL)
           CURLSSLSET_TOO_LATE;
#else
           CURLSSLSET_UNKNOWN_BACKEND;
#endif

  for(i = 0; available_backends[i]; i++) {
    if(available_backends[i]->info.id == id ||
       (name && strcasecompare(available_backends[i]->info.name, name))) {
      multissl_setup(available_backends[i]);
      return CURLSSLSET_OK;
    }
  }

  return CURLSSLSET_UNKNOWN_BACKEND;
}

#else /* USE_SSL */
CURLsslset Curl_init_sslset_nolock(curl_sslbackend id, const char *name,
                                   const curl_ssl_backend ***avail)
{
  (void)id;
  (void)name;
  (void)avail;
  return CURLSSLSET_NO_BACKENDS;
}

#endif /* !USE_SSL */

#ifdef USE_SSL

static void free_hostname(struct ssl_connect_data *connssl)
{
  if(connssl->dispname != connssl->hostname)
    free(connssl->dispname);
  free(connssl->hostname);
  connssl->hostname = connssl->dispname = NULL;
}

static void cf_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  if(connssl) {
    Curl_ssl->close(cf, data);
    connssl->state = ssl_connection_none;
    free_hostname(connssl);
  }
  cf->connected = FALSE;
}

static CURLcode reinit_hostname(struct Curl_cfilter *cf)
{
  struct ssl_connect_data *connssl = cf->ctx;
  const char *ehostname, *edispname;
  int eport;

  /* We need the hostname for SNI negotiation. Once handshaked, this
   * remains the SNI hostname for the TLS connection. But when the
   * connection is reused, the settings in cf->conn might change.
   * So we keep a copy of the hostname we use for SNI.
   */
#ifndef CURL_DISABLE_PROXY
  if(Curl_ssl_cf_is_proxy(cf)) {
    ehostname = cf->conn->http_proxy.host.name;
    edispname = cf->conn->http_proxy.host.dispname;
    eport = cf->conn->http_proxy.port;
  }
  else
#endif
  {
    ehostname = cf->conn->host.name;
    edispname = cf->conn->host.dispname;
    eport = cf->conn->remote_port;
  }

  /* change if ehostname changed */
  if(ehostname && (!connssl->hostname
                   || strcmp(ehostname, connssl->hostname))) {
    free_hostname(connssl);
    connssl->hostname = strdup(ehostname);
    if(!connssl->hostname) {
      free_hostname(connssl);
      return CURLE_OUT_OF_MEMORY;
    }
    if(!edispname || !strcmp(ehostname, edispname))
      connssl->dispname = connssl->hostname;
    else {
      connssl->dispname = strdup(edispname);
      if(!connssl->dispname) {
        free_hostname(connssl);
        return CURLE_OUT_OF_MEMORY;
      }
    }
  }
  connssl->port = eport;
  return CURLE_OK;
}

static void ssl_cf_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  cf_close(cf, data);
  CF_DATA_RESTORE(cf, save);
  cf_ctx_free(cf->ctx);
  cf->ctx = NULL;
}

static void ssl_cf_close(struct Curl_cfilter *cf,
                         struct Curl_easy *data)
{
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  cf_close(cf, data);
  cf->next->cft->close(cf->next, data);
  CF_DATA_RESTORE(cf, save);
}

static CURLcode ssl_cf_connect(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool blocking, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct cf_call_data save;
  CURLcode result;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);
  (void)connssl;
  DEBUGASSERT(data->conn);
  DEBUGASSERT(data->conn == cf->conn);
  DEBUGASSERT(connssl);
  DEBUGASSERT(cf->conn->host.name);

  result = cf->next->cft->connect(cf->next, data, blocking, done);
  if(result || !*done)
    goto out;

  *done = FALSE;
  result = reinit_hostname(cf);
  if(result)
    goto out;

  if(blocking) {
    result = ssl_connect(cf, data);
    *done = (result == CURLE_OK);
  }
  else {
    result = ssl_connect_nonblocking(cf, data, done);
  }

  if(!result && *done) {
    cf->connected = TRUE;
    connssl->handshake_done = Curl_now();
    DEBUGASSERT(connssl->state == ssl_connection_complete);
  }
out:
  CF_DATA_RESTORE(cf, save);
  return result;
}

static bool ssl_cf_data_pending(struct Curl_cfilter *cf,
                                const struct Curl_easy *data)
{
  struct cf_call_data save;
  bool result;

  CF_DATA_SAVE(save, cf, data);
  if(Curl_ssl->data_pending(cf, data))
    result = TRUE;
  else
    result = cf->next->cft->has_data_pending(cf->next, data);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static ssize_t ssl_cf_send(struct Curl_cfilter *cf,
                           struct Curl_easy *data, const void *buf, size_t len,
                           CURLcode *err)
{
  struct cf_call_data save;
  ssize_t nwritten;

  CF_DATA_SAVE(save, cf, data);
  *err = CURLE_OK;
  nwritten = Curl_ssl->send_plain(cf, data, buf, len, err);
  CF_DATA_RESTORE(cf, save);
  return nwritten;
}

static ssize_t ssl_cf_recv(struct Curl_cfilter *cf,
                           struct Curl_easy *data, char *buf, size_t len,
                           CURLcode *err)
{
  struct cf_call_data save;
  ssize_t nread;

  CF_DATA_SAVE(save, cf, data);
  *err = CURLE_OK;
  nread = Curl_ssl->recv_plain(cf, data, buf, len, err);
  CF_DATA_RESTORE(cf, save);
  return nread;
}

static int ssl_cf_get_select_socks(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   curl_socket_t *socks)
{
  struct cf_call_data save;
  int result;

  CF_DATA_SAVE(save, cf, data);
  result = Curl_ssl->get_select_socks(cf, data, socks);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode ssl_cf_cntrl(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             int event, int arg1, void *arg2)
{
  struct cf_call_data save;

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_ATTACH:
    if(Curl_ssl->attach_data) {
      CF_DATA_SAVE(save, cf, data);
      Curl_ssl->attach_data(cf, data);
      CF_DATA_RESTORE(cf, save);
    }
    break;
  case CF_CTRL_DATA_DETACH:
    if(Curl_ssl->detach_data) {
      CF_DATA_SAVE(save, cf, data);
      Curl_ssl->detach_data(cf, data);
      CF_DATA_RESTORE(cf, save);
    }
    break;
  default:
    break;
  }
  return CURLE_OK;
}

static CURLcode ssl_cf_query(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             int query, int *pres1, void *pres2)
{
  struct ssl_connect_data *connssl = cf->ctx;

  switch(query) {
  case CF_QUERY_TIMER_APPCONNECT: {
    struct curltime *when = pres2;
    if(cf->connected && !Curl_ssl_cf_is_proxy(cf))
      *when = connssl->handshake_done;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_ssl_is_alive(struct Curl_cfilter *cf, struct Curl_easy *data,
                            bool *input_pending)
{
  struct cf_call_data save;
  int result;
  /*
   * This function tries to determine connection status.
   *
   * Return codes:
   *     1 means the connection is still in place
   *     0 means the connection has been closed
   *    -1 means the connection status is unknown
   */
  CF_DATA_SAVE(save, cf, data);
  result = Curl_ssl->check_cxn(cf, data);
  CF_DATA_RESTORE(cf, save);
  if(result > 0) {
    *input_pending = TRUE;
    return TRUE;
  }
  if(result == 0) {
    *input_pending = FALSE;
    return FALSE;
  }
  /* ssl backend does not know */
  return cf->next?
    cf->next->cft->is_alive(cf->next, data, input_pending) :
    FALSE; /* pessimistic in absence of data */
}

struct Curl_cftype Curl_cft_ssl = {
  "SSL",
  CF_TYPE_SSL,
  CURL_LOG_DEFAULT,
  ssl_cf_destroy,
  ssl_cf_connect,
  ssl_cf_close,
  Curl_cf_def_get_host,
  ssl_cf_get_select_socks,
  ssl_cf_data_pending,
  ssl_cf_send,
  ssl_cf_recv,
  ssl_cf_cntrl,
  cf_ssl_is_alive,
  Curl_cf_def_conn_keep_alive,
  ssl_cf_query,
};

struct Curl_cftype Curl_cft_ssl_proxy = {
  "SSL-PROXY",
  CF_TYPE_SSL,
  CURL_LOG_DEFAULT,
  ssl_cf_destroy,
  ssl_cf_connect,
  ssl_cf_close,
  Curl_cf_def_get_host,
  ssl_cf_get_select_socks,
  ssl_cf_data_pending,
  ssl_cf_send,
  ssl_cf_recv,
  ssl_cf_cntrl,
  cf_ssl_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_ssl_create(struct Curl_cfilter **pcf,
                              struct Curl_easy *data,
                              struct connectdata *conn)
{
  struct Curl_cfilter *cf = NULL;
  struct ssl_connect_data *ctx;
  CURLcode result;

  DEBUGASSERT(data->conn);

  ctx = cf_ctx_new(data, Curl_alpn_get_spec(data, conn));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = Curl_cf_create(&cf, &Curl_cft_ssl, ctx);

out:
  if(result)
    cf_ctx_free(ctx);
  *pcf = result? NULL : cf;
  return result;
}

CURLcode Curl_ssl_cfilter_add(struct Curl_easy *data,
                              struct connectdata *conn,
                              int sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_ssl_create(&cf, data, conn);
  if(!result)
    Curl_conn_cf_add(data, conn, sockindex, cf);
  return result;
}

CURLcode Curl_cf_ssl_insert_after(struct Curl_cfilter *cf_at,
                                  struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_ssl_create(&cf, data, cf_at->conn);
  if(!result)
    Curl_conn_cf_insert_after(cf_at, cf);
  return result;
}

#ifndef CURL_DISABLE_PROXY
static CURLcode cf_ssl_proxy_create(struct Curl_cfilter **pcf,
                                    struct Curl_easy *data,
                                    struct connectdata *conn)
{
  struct Curl_cfilter *cf = NULL;
  struct ssl_connect_data *ctx;
  CURLcode result;

  ctx = cf_ctx_new(data, Curl_alpn_get_proxy_spec(data, conn));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  result = Curl_cf_create(&cf, &Curl_cft_ssl_proxy, ctx);

out:
  if(result)
    cf_ctx_free(ctx);
  *pcf = result? NULL : cf;
  return result;
}

CURLcode Curl_ssl_cfilter_proxy_add(struct Curl_easy *data,
                                    struct connectdata *conn,
                                    int sockindex)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_ssl_proxy_create(&cf, data, conn);
  if(!result)
    Curl_conn_cf_add(data, conn, sockindex, cf);
  return result;
}

CURLcode Curl_cf_ssl_proxy_insert_after(struct Curl_cfilter *cf_at,
                                        struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_ssl_proxy_create(&cf, data, cf_at->conn);
  if(!result)
    Curl_conn_cf_insert_after(cf_at, cf);
  return result;
}

#endif /* !CURL_DISABLE_PROXY */

bool Curl_ssl_supports(struct Curl_easy *data, int option)
{
  (void)data;
  return (Curl_ssl->supports & option)? TRUE : FALSE;
}

void *Curl_ssl_get_internals(struct Curl_easy *data, int sockindex,
                             CURLINFO info, int n)
{
  void *result = NULL;
  (void)n;
  if(data->conn) {
    struct Curl_cfilter *cf;
    /* get first filter in chain, if any is present */
    cf = Curl_ssl_cf_get_ssl(data->conn->cfilter[sockindex]);
    if(cf) {
      struct cf_call_data save;
      CF_DATA_SAVE(save, cf, data);
      result = Curl_ssl->get_internals(cf->ctx, info);
      CF_DATA_RESTORE(cf, save);
    }
  }
  return result;
}

CURLcode Curl_ssl_cfilter_remove(struct Curl_easy *data,
                                 int sockindex)
{
  struct Curl_cfilter *cf = data->conn? data->conn->cfilter[sockindex] : NULL;
  CURLcode result = CURLE_OK;

  (void)data;
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_ssl) {
      if(Curl_ssl->shut_down(cf, data))
        result = CURLE_SSL_SHUTDOWN_FAILED;
      Curl_conn_cf_discard(cf, data);
      break;
    }
  }
  return result;
}

static struct Curl_cfilter *get_ssl_cf_engaged(struct connectdata *conn,
                                               int sockindex)
{
  struct Curl_cfilter *cf, *lowest_ssl_cf = NULL;

  for(cf = conn->cfilter[sockindex]; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_ssl || cf->cft == &Curl_cft_ssl_proxy) {
      lowest_ssl_cf = cf;
      if(cf->connected || (cf->next && cf->next->connected)) {
        /* connected or about to start */
        return cf;
      }
    }
  }
  return lowest_ssl_cf;
}

bool Curl_ssl_cf_is_proxy(struct Curl_cfilter *cf)
{
  return (cf->cft == &Curl_cft_ssl_proxy);
}

struct ssl_config_data *
Curl_ssl_cf_get_config(struct Curl_cfilter *cf, struct Curl_easy *data)
{
#ifdef CURL_DISABLE_PROXY
  (void)cf;
  return &data->set.ssl;
#else
  return Curl_ssl_cf_is_proxy(cf)? &data->set.proxy_ssl : &data->set.ssl;
#endif
}

struct ssl_config_data *
Curl_ssl_get_config(struct Curl_easy *data, int sockindex)
{
  struct Curl_cfilter *cf;

  (void)data;
  DEBUGASSERT(data->conn);
  cf = get_ssl_cf_engaged(data->conn, sockindex);
  return cf? Curl_ssl_cf_get_config(cf, data) : &data->set.ssl;
}

struct ssl_primary_config *
Curl_ssl_cf_get_primary_config(struct Curl_cfilter *cf)
{
#ifdef CURL_DISABLE_PROXY
  return &cf->conn->ssl_config;
#else
  return Curl_ssl_cf_is_proxy(cf)?
    &cf->conn->proxy_ssl_config : &cf->conn->ssl_config;
#endif
}

struct ssl_primary_config *
Curl_ssl_get_primary_config(struct Curl_easy *data,
                            struct connectdata *conn,
                            int sockindex)
{
  struct Curl_cfilter *cf;

  (void)data;
  DEBUGASSERT(conn);
  cf = get_ssl_cf_engaged(conn, sockindex);
  return cf? Curl_ssl_cf_get_primary_config(cf) : NULL;
}

struct Curl_cfilter *Curl_ssl_cf_get_ssl(struct Curl_cfilter *cf)
{
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_ssl || cf->cft == &Curl_cft_ssl_proxy)
      return cf;
  }
  return NULL;
}

static const struct alpn_spec ALPN_SPEC_H10 = {
  { ALPN_HTTP_1_0 }, 1
};
static const struct alpn_spec ALPN_SPEC_H11 = {
  { ALPN_HTTP_1_1 }, 1
};
#ifdef USE_HTTP2
static const struct alpn_spec ALPN_SPEC_H2_H11 = {
  { ALPN_H2, ALPN_HTTP_1_1 }, 2
};
#endif

const struct alpn_spec *
Curl_alpn_get_spec(struct Curl_easy *data, struct connectdata *conn)
{
  if(!conn->bits.tls_enable_alpn)
    return NULL;
  if(data->state.httpwant == CURL_HTTP_VERSION_1_0)
    return &ALPN_SPEC_H10;
#ifdef USE_HTTP2
  if(data->state.httpwant >= CURL_HTTP_VERSION_2)
    return &ALPN_SPEC_H2_H11;
#endif
  return &ALPN_SPEC_H11;
}

const struct alpn_spec *
Curl_alpn_get_proxy_spec(struct Curl_easy *data, struct connectdata *conn)
{
  if(!conn->bits.tls_enable_alpn)
    return NULL;
  if(data->state.httpwant == CURL_HTTP_VERSION_1_0)
    return &ALPN_SPEC_H10;
  return &ALPN_SPEC_H11;
}

CURLcode Curl_alpn_to_proto_buf(struct alpn_proto_buf *buf,
                                const struct alpn_spec *spec)
{
  size_t i, len;
  int off = 0;
  unsigned char blen;

  memset(buf, 0, sizeof(*buf));
  for(i = 0; spec && i < spec->count; ++i) {
    len = strlen(spec->entries[i]);
    if(len >= ALPN_NAME_MAX)
      return CURLE_FAILED_INIT;
    blen = (unsigned  char)len;
    if(off + blen + 1 >= (int)sizeof(buf->data))
      return CURLE_FAILED_INIT;
    buf->data[off++] = blen;
    memcpy(buf->data + off, spec->entries[i], blen);
    off += blen;
  }
  buf->len = off;
  return CURLE_OK;
}

CURLcode Curl_alpn_to_proto_str(struct alpn_proto_buf *buf,
                                const struct alpn_spec *spec)
{
  size_t i, len;
  size_t off = 0;

  memset(buf, 0, sizeof(*buf));
  for(i = 0; spec && i < spec->count; ++i) {
    len = strlen(spec->entries[i]);
    if(len >= ALPN_NAME_MAX)
      return CURLE_FAILED_INIT;
    if(off + len + 2 >= (int)sizeof(buf->data))
      return CURLE_FAILED_INIT;
    if(off)
      buf->data[off++] = ',';
    memcpy(buf->data + off, spec->entries[i], len);
    off += len;
  }
  buf->data[off] = '\0';
  buf->len = (int)off;
  return CURLE_OK;
}

CURLcode Curl_alpn_set_negotiated(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  const unsigned char *proto,
                                  size_t proto_len)
{
  int can_multi = 0;

  if(proto && proto_len) {
    if(proto_len == ALPN_HTTP_1_1_LENGTH &&
            !memcmp(ALPN_HTTP_1_1, proto, ALPN_HTTP_1_1_LENGTH)) {
      cf->conn->alpn = CURL_HTTP_VERSION_1_1;
    }
    else if(proto_len == ALPN_HTTP_1_0_LENGTH &&
            !memcmp(ALPN_HTTP_1_0, proto, ALPN_HTTP_1_0_LENGTH)) {
      cf->conn->alpn = CURL_HTTP_VERSION_1_0;
    }
#ifdef USE_HTTP2
    else if(proto_len == ALPN_H2_LENGTH &&
            !memcmp(ALPN_H2, proto, ALPN_H2_LENGTH)) {
      cf->conn->alpn = CURL_HTTP_VERSION_2;
      can_multi = 1;
    }
#endif
#ifdef USE_HTTP3
    else if(proto_len == ALPN_H3_LENGTH &&
       !memcmp(ALPN_H3, proto, ALPN_H3_LENGTH)) {
      cf->conn->alpn = CURL_HTTP_VERSION_3;
      can_multi = 1;
    }
#endif
    else {
      cf->conn->alpn = CURL_HTTP_VERSION_NONE;
      failf(data, "unsupported ALPN protocol: '%.*s'", (int)proto_len, proto);
      /* TODO: do we want to fail this? Previous code just ignored it and
       * some vtls backends even ignore the return code of this function. */
      /* return CURLE_NOT_BUILT_IN; */
      goto out;
    }
    infof(data, VTLS_INFOF_ALPN_ACCEPTED_LEN_1STR, (int)proto_len, proto);
  }
  else {
    cf->conn->alpn = CURL_HTTP_VERSION_NONE;
    infof(data, VTLS_INFOF_NO_ALPN);
  }

out:
  Curl_multiuse_state(data, can_multi? BUNDLE_MULTIPLEX : BUNDLE_NO_MULTIUSE);
  return CURLE_OK;
}

#endif /* USE_SSL */
