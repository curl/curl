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

#include "urldata.h"
#include "setopt.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "vtls/vtls_config.h"


#define CLONE_STRING(var)                    \
  do {                                       \
    if(source->var) {                        \
      dest->var = curlx_strdup(source->var); \
      if(!dest->var)                         \
        return FALSE;                        \
    }                                        \
    else                                     \
      dest->var = NULL;                      \
  } while(0)

#define CLONE_BLOB(var)                  \
  do {                                   \
    if(blobdup(&dest->var, source->var)) \
      return FALSE;                      \
  } while(0)

static CURLcode blobdup(struct curl_blob **dest, struct curl_blob *src)
{
  DEBUGASSERT(dest);
  DEBUGASSERT(!*dest);
  if(src) {
    /* only if there is data to dupe! */
    struct curl_blob *d;
    d = curlx_malloc(sizeof(struct curl_blob) + src->len);
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

void Curl_ssl_config_init(struct ssl_easy_config *sslc)
{
  /*
   * libcurl 7.10 introduced SSL verification *by default*! This needs to be
   * switched off unless wanted.
   */
  sslc->verifypeer = TRUE;
  sslc->verifyhost = TRUE;
  sslc->cache_session = TRUE; /* caching by default */
}

void Curl_ssl_config_cleanup(struct ssl_filter_config *sslc)
{
  if(sslc->deep_copy) {
    curlx_safefree(sslc->CApath);
    curlx_safefree(sslc->CAfile);
    curlx_safefree(sslc->issuercert);
    curlx_safefree(sslc->clientcert);
    curlx_safefree(sslc->cipher_list);
    curlx_safefree(sslc->cipher_list13);
    curlx_safefree(sslc->pinned_key);
    curlx_safefree(sslc->cert_blob);
    curlx_safefree(sslc->ca_info_blob);
    curlx_safefree(sslc->issuercert_blob);
    curlx_safefree(sslc->key_blob);
    curlx_safefree(sslc->curves);
    curlx_safefree(sslc->signature_algorithms);
    curlx_safefree(sslc->CRLfile);
    curlx_safefree(sslc->cert_type);
    curlx_safefree(sslc->key);
    curlx_safefree(sslc->key_type);
    curlx_safefree(sslc->key_passwd);
    sslc->deep_copy = FALSE;
  }
}

static bool match_ssl_primary_config(struct Curl_easy *data,
                                     struct ssl_filter_config *c1,
                                     struct ssl_filter_config *c2)
{
  (void)data;
  if((c1->version == c2->version) &&
     (c1->version_max == c2->version_max) &&
     (c1->ssl_options == c2->ssl_options) &&
     (c1->native_ca_store == c2->native_ca_store) &&
     (c1->verifypeer == c2->verifypeer) &&
     (c1->verifyhost == c2->verifyhost) &&
     (c1->verifystatus == c2->verifystatus) &&
     (c1->auto_client_cert == c2->auto_client_cert) &&
     blobcmp(c1->cert_blob, c2->cert_blob) &&
     blobcmp(c1->ca_info_blob, c2->ca_info_blob) &&
     blobcmp(c1->issuercert_blob, c2->issuercert_blob) &&
     blobcmp(c1->key_blob, c2->key_blob) &&
     Curl_safecmp(c1->CApath, c2->CApath) &&
     Curl_safecmp(c1->CAfile, c2->CAfile) &&
     Curl_safecmp(c1->issuercert, c2->issuercert) &&
     Curl_safecmp(c1->clientcert, c2->clientcert) &&
     curl_strequal(c1->cipher_list, c2->cipher_list) &&
     curl_strequal(c1->cipher_list13, c2->cipher_list13) &&
     curl_strequal(c1->curves, c2->curves) &&
     curl_strequal(c1->signature_algorithms, c2->signature_algorithms) &&
     Curl_safecmp(c1->CRLfile, c2->CRLfile) &&
     Curl_safecmp(c1->pinned_key, c2->pinned_key) &&
     curl_strequal(c1->cert_type, c2->cert_type) &&
     Curl_safecmp(c1->key, c2->key) &&
     curl_strequal(c1->key_type, c2->key_type) &&
     !Curl_timestrcmp(c1->key_passwd, c2->key_passwd))
    return TRUE;

  return FALSE;
}

bool Curl_ssl_conn_config_match(struct Curl_easy *data,
                                struct ssl_filter_config *conn_config,
                                struct connectdata *candidate,
                                bool proxy)
{
#ifndef CURL_DISABLE_PROXY
  if(proxy)
    return match_ssl_primary_config(data, conn_config,
                                    &candidate->proxy_ssl_config);
#else
  (void)proxy;
#endif
  return match_ssl_primary_config(data, conn_config,
                                  &candidate->ssl_config);
}

static bool clone_ssl_primary_config(struct ssl_filter_config *source,
                                     struct ssl_filter_config *dest)
{
  DEBUGASSERT(!dest->deep_copy);
  dest->deep_copy = TRUE;
  dest->version = source->version;
  dest->version_max = source->version_max;
  dest->verifypeer = source->verifypeer;
  dest->verifyhost = source->verifyhost;
  dest->verifystatus = source->verifystatus;
  dest->ssl_options = source->ssl_options;
  dest->native_ca_store = source->native_ca_store;
  dest->cache_session = source->cache_session;
  dest->auto_client_cert = source->auto_client_cert;
  dest->earlydata = source->earlydata;
  dest->enable_beast = source->enable_beast;
  dest->no_partialchain = source->no_partialchain;
  dest->no_revoke = source->no_revoke;
  dest->revoke_best_effort = source->revoke_best_effort;

  CLONE_BLOB(cert_blob);
  CLONE_BLOB(ca_info_blob);
  CLONE_BLOB(issuercert_blob);
  CLONE_STRING(CApath);
  CLONE_STRING(CAfile);
  CLONE_STRING(issuercert);
  CLONE_STRING(cipher_list);
  CLONE_STRING(cipher_list13);
  CLONE_STRING(pinned_key);
  CLONE_STRING(curves);
  CLONE_STRING(signature_algorithms);
  CLONE_STRING(CRLfile);
  /* SSL credentials: client certificate */
  CLONE_STRING(clientcert);
  CLONE_STRING(cert_type);
  CLONE_STRING(key);
  CLONE_STRING(key_type);
  CLONE_STRING(key_passwd);
  CLONE_BLOB(key_blob);
  return TRUE;
}

static void
ssl_easy_config_compl_options(struct Curl_peer *origin,
                              struct Curl_peer *initial_origin,
                              struct ssl_easy_config *sslc,
                              struct ssl_filter_config *primary)
{
  uint8_t options = sslc->ssl_options;
  /* If set via CURLOPT_(PROXY_)SSL_OPTIONS, we definitely use it.
   * If not, we switch it on for supported backends if no custom
   * CA settings exist. */
  primary->native_ca_store = !!(options & CURLSSLOPT_NATIVE_CA);
  primary->earlydata = !!(options & CURLSSLOPT_EARLYDATA);
  primary->auto_client_cert =
    Curl_peer_equal(origin, initial_origin) &&
    !!(options & CURLSSLOPT_AUTO_CLIENT_CERT);
  primary->enable_beast = !!(options & CURLSSLOPT_ALLOW_BEAST);
  primary->no_partialchain = !!(options & CURLSSLOPT_NO_PARTIALCHAIN);
  primary->no_revoke = !!(options & CURLSSLOPT_NO_REVOKE);
  primary->revoke_best_effort = !!(options & CURLSSLOPT_REVOKE_BEST_EFFORT);
}

static char *ssl_easy_steal(struct Curl_easy *data, enum dupstring id)
{
  /* For connection matching, we borrow string references from data
   * THIS IS NOT REALLY NICE. */
  return CURL_UNCONST(CURL_EASY_STR(data, id));
}

CURLcode Curl_ssl_easy_config_complete(struct Curl_easy *data,
                                       struct Curl_peer *origin,
                                       struct ssl_filter_config *ssl_origin,
                                       struct ssl_filter_config *ssl_proxy)
{
  struct ssl_easy_config *sslc = &data->set.ssl;
#if defined(CURL_CA_PATH) || defined(CURL_CA_BUNDLE)
  CURLcode result;
#endif

  ssl_easy_config_compl_options(origin, data->state.initial_origin, sslc,
                                ssl_origin);

  if(Curl_ssl_backend() != CURLSSLBACKEND_SCHANNEL) {
#if defined(USE_APPLE_SECTRUST) || defined(CURL_CA_NATIVE)
    if(!sslc->custom_capath && !sslc->custom_cafile && !sslc->custom_cablob)
      ssl_origin->native_ca_store = TRUE;
#endif
#ifdef CURL_CA_PATH
    if(!sslc->custom_capath && !CURL_EASY_STR(data, STRING_SSL_CAPATH)) {
      result = Curl_setstropt(data, STRING_SSL_CAPATH, CURL_CA_PATH);
      if(result)
        return result;
    }
#endif
#ifdef CURL_CA_BUNDLE
    if(!sslc->custom_cafile && !CURL_EASY_STR(data, STRING_SSL_CAFILE)) {
      result = Curl_setstropt(data, STRING_SSL_CAFILE, CURL_CA_BUNDLE);
      if(result)
        return result;
    }
#endif
  }

  ssl_origin->version = sslc->version;
  ssl_origin->version_max = sslc->version_max;
  ssl_origin->verifypeer = sslc->verifypeer;
  ssl_origin->verifyhost = sslc->verifyhost;
  ssl_origin->verifystatus = sslc->verifystatus;
  ssl_origin->cache_session = sslc->cache_session;
  ssl_origin->ssl_options = sslc->ssl_options;
  ssl_origin->CAfile = ssl_easy_steal(data, STRING_SSL_CAFILE);
  ssl_origin->CRLfile = ssl_easy_steal(data, STRING_SSL_CRLFILE);
  ssl_origin->CApath = ssl_easy_steal(data, STRING_SSL_CAPATH);
  ssl_origin->cipher_list = ssl_easy_steal(data, STRING_SSL_CIPHER_LIST);
  ssl_origin->cipher_list13 = ssl_easy_steal(data, STRING_SSL_CIPHER13_LIST);
  ssl_origin->signature_algorithms =
    ssl_easy_steal(data, STRING_SSL_SIGNATURE_ALGORITHMS);
  ssl_origin->ca_info_blob = data->set.blobs[BLOB_CAINFO];
  ssl_origin->curves = ssl_easy_steal(data, STRING_SSL_EC_CURVES);
  /* Maybe these should not be used for another origin. But for
   * backwards compatibility, keep them in. */
  ssl_origin->issuercert = ssl_easy_steal(data, STRING_SSL_ISSUERCERT);
  ssl_origin->issuercert_blob = data->set.blobs[BLOB_SSL_ISSUERCERT];

  if(Curl_peer_equal(data->state.initial_origin, origin)) {
    ssl_origin->pinned_key =
      ssl_easy_steal(data, STRING_SSL_PINNEDPUBLICKEY);
    ssl_origin->cert_blob = data->set.blobs[BLOB_CERT];
    ssl_origin->cert_type = ssl_easy_steal(data, STRING_CERT_TYPE);
    ssl_origin->key = ssl_easy_steal(data, STRING_KEY);
    ssl_origin->key_type = ssl_easy_steal(data, STRING_KEY_TYPE);
    ssl_origin->key_passwd = ssl_easy_steal(data, STRING_KEY_PASSWD);
    ssl_origin->clientcert = ssl_easy_steal(data, STRING_CERT);
    ssl_origin->key_blob = data->set.blobs[BLOB_KEY];
  }
  else {
    ssl_origin->pinned_key = NULL;
    ssl_origin->cert_blob = NULL;
    ssl_origin->cert_type = NULL;
    ssl_origin->key = NULL;
    ssl_origin->key_type = NULL;
    ssl_origin->key_passwd = NULL;
    ssl_origin->clientcert = NULL;
    ssl_origin->key_blob = NULL;
  }

#ifndef CURL_DISABLE_PROXY
  sslc = &data->set.proxy_ssl;

  ssl_easy_config_compl_options(NULL, NULL, sslc, ssl_proxy);
  if((Curl_ssl_backend() != CURLSSLBACKEND_SCHANNEL)) {
    /* no initial origin for proxy, it is not changed for redirects */
#if defined(USE_APPLE_SECTRUST) || defined(CURL_CA_NATIVE)
    if(!sslc->custom_capath && !sslc->custom_cafile && !sslc->custom_cablob)
      ssl_proxy->native_ca_store = TRUE;
#endif
#ifdef CURL_CA_PATH
    if(!sslc->custom_capath &&
       !CURL_EASY_STR(data, STRING_SSL_CAPATH_PROXY)) {
      result = Curl_setstropt(data, STRING_SSL_CAPATH_PROXY, CURL_CA_PATH);
      if(result)
        return result;
    }
#endif
#ifdef CURL_CA_BUNDLE
    if(!sslc->custom_cafile &&
       !CURL_EASY_STR(data, STRING_SSL_CAFILE_PROXY)) {
      result = Curl_setstropt(data, STRING_SSL_CAFILE_PROXY, CURL_CA_BUNDLE);
      if(result)
        return result;
    }
#endif
  }

  ssl_proxy->version = sslc->version;
  ssl_proxy->version_max = sslc->version_max;
  ssl_proxy->verifypeer = sslc->verifypeer;
  ssl_proxy->verifyhost = sslc->verifyhost;
  ssl_proxy->verifystatus = sslc->verifystatus;
  ssl_proxy->cache_session = sslc->cache_session;
  ssl_proxy->ssl_options = sslc->ssl_options;
  ssl_proxy->CAfile = ssl_easy_steal(data, STRING_SSL_CAFILE_PROXY);
  ssl_proxy->CApath = ssl_easy_steal(data, STRING_SSL_CAPATH_PROXY);
  ssl_proxy->cipher_list =
    ssl_easy_steal(data, STRING_SSL_CIPHER_LIST_PROXY);
  ssl_proxy->cipher_list13 =
    ssl_easy_steal(data, STRING_SSL_CIPHER13_LIST_PROXY);
  ssl_proxy->pinned_key =
    ssl_easy_steal(data, STRING_SSL_PINNEDPUBLICKEY_PROXY);
  ssl_proxy->cert_blob = data->set.blobs[BLOB_CERT_PROXY];
  ssl_proxy->ca_info_blob = data->set.blobs[BLOB_CAINFO_PROXY];
  ssl_proxy->issuercert = ssl_easy_steal(data, STRING_SSL_ISSUERCERT_PROXY);
  ssl_proxy->issuercert_blob = data->set.blobs[BLOB_SSL_ISSUERCERT_PROXY];
  ssl_proxy->CRLfile = ssl_easy_steal(data, STRING_SSL_CRLFILE_PROXY);
  ssl_proxy->cert_type = ssl_easy_steal(data, STRING_CERT_TYPE_PROXY);
  ssl_proxy->key = ssl_easy_steal(data, STRING_KEY_PROXY);
  ssl_proxy->key_type = ssl_easy_steal(data, STRING_KEY_TYPE_PROXY);
  ssl_proxy->key_passwd = ssl_easy_steal(data, STRING_KEY_PASSWD_PROXY);
  ssl_proxy->clientcert = ssl_easy_steal(data, STRING_CERT_PROXY);
  ssl_proxy->key_blob = data->set.blobs[BLOB_KEY_PROXY];
#else
  (void)ssl_proxy;
  DEBUGASSERT(!ssl_proxy);
#endif /* CURL_DISABLE_PROXY */

  return CURLE_OK;
}

CURLcode Curl_ssl_conn_config_init(struct ssl_filter_config *ssl_config,
                                   struct ssl_filter_config *proxy_ssl_config,
                                   struct connectdata *conn)
{
  /* Clone "primary" SSL configurations from the easy handle to
   * the connection. They are used for connection cache matching and
   * probably outlive the easy handle */
  if(!clone_ssl_primary_config(ssl_config, &conn->ssl_config))
    return CURLE_OUT_OF_MEMORY;
#ifndef CURL_DISABLE_PROXY
  if(proxy_ssl_config &&
     !clone_ssl_primary_config(proxy_ssl_config, &conn->proxy_ssl_config))
    return CURLE_OUT_OF_MEMORY;
#else
  (void)proxy_ssl_config;
#endif
  return CURLE_OK;
}

void Curl_ssl_conn_config_cleanup(struct connectdata *conn)
{
  Curl_ssl_config_cleanup(&conn->ssl_config);
#ifndef CURL_DISABLE_PROXY
  Curl_ssl_config_cleanup(&conn->proxy_ssl_config);
#endif
}

void Curl_ssl_conn_config_update(struct Curl_easy *data, bool for_proxy)
{
  /* May be called on an easy that has no connection yet */
  if(data->conn) {
    struct ssl_easy_config *src;
    struct ssl_filter_config *dest;
#ifndef CURL_DISABLE_PROXY
    src = for_proxy ? &data->set.proxy_ssl : &data->set.ssl;
    dest = for_proxy ? &data->conn->proxy_ssl_config : &data->conn->ssl_config;
#else
    (void)for_proxy;
    src = &data->set.ssl;
    dest = &data->conn->ssl_config;
#endif
    dest->verifyhost = src->verifyhost;
    dest->verifypeer = src->verifypeer;
    dest->verifystatus = src->verifystatus;
  }
}
