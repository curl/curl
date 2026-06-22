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

void Curl_ssl_config_init(struct ssl_primary_config *sslc)
{
  /*
   * libcurl 7.10 introduced SSL verification *by default*! This needs to be
   * switched off unless wanted.
   */
  sslc->verifypeer = TRUE;
  sslc->verifyhost = TRUE;
  sslc->cache_session = TRUE; /* caching by default */
}

void Curl_ssl_config_cleanup(struct ssl_primary_config *sslc)
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
#ifdef USE_TLS_SRP
    curlx_safefree(sslc->username);
    curlx_safefree(sslc->password);
#endif
    sslc->deep_copy = FALSE;
  }
}

static bool match_ssl_primary_config(struct Curl_easy *data,
                                     struct ssl_primary_config *c1,
                                     struct ssl_primary_config *c2)
{
  (void)data;
  if((c1->version == c2->version) &&
     (c1->version_max == c2->version_max) &&
     (c1->ssl_options == c2->ssl_options) &&
     (c1->verifypeer == c2->verifypeer) &&
     (c1->verifyhost == c2->verifyhost) &&
     (c1->verifystatus == c2->verifystatus) &&
     blobcmp(c1->cert_blob, c2->cert_blob) &&
     blobcmp(c1->ca_info_blob, c2->ca_info_blob) &&
     blobcmp(c1->issuercert_blob, c2->issuercert_blob) &&
     blobcmp(c1->key_blob, c2->key_blob) &&
     Curl_safecmp(c1->CApath, c2->CApath) &&
     Curl_safecmp(c1->CAfile, c2->CAfile) &&
     Curl_safecmp(c1->issuercert, c2->issuercert) &&
     Curl_safecmp(c1->clientcert, c2->clientcert) &&
#ifdef USE_TLS_SRP
     !Curl_timestrcmp(c1->username, c2->username) &&
     !Curl_timestrcmp(c1->password, c2->password) &&
#endif
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
                                struct connectdata *candidate,
                                bool proxy)
{
#ifndef CURL_DISABLE_PROXY
  if(proxy)
    return match_ssl_primary_config(data, &data->set.proxy_ssl.primary,
                                    &candidate->proxy_ssl_config);
#else
  (void)proxy;
#endif
  return match_ssl_primary_config(data, &data->set.ssl.primary,
                                  &candidate->ssl_config);
}

static bool clone_ssl_primary_config(struct ssl_primary_config *source,
                                     struct ssl_primary_config *dest)
{
  DEBUGASSERT(!dest->deep_copy);
  dest->deep_copy = TRUE;
  dest->version = source->version;
  dest->version_max = source->version_max;
  dest->verifypeer = source->verifypeer;
  dest->verifyhost = source->verifyhost;
  dest->verifystatus = source->verifystatus;
  dest->cache_session = source->cache_session;
  dest->ssl_options = source->ssl_options;

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
  /* SSL credentials: client certificate, SRP auth */
  CLONE_STRING(clientcert);
  CLONE_STRING(cert_type);
  CLONE_STRING(key);
  CLONE_STRING(key_type);
  CLONE_STRING(key_passwd);
  CLONE_BLOB(key_blob);
#ifdef USE_TLS_SRP
  CLONE_STRING(username);
  CLONE_STRING(password);
#endif

  return TRUE;
}

static void ssl_easy_config_compl_options(struct Curl_peer *origin,
                                          struct Curl_peer *initial_origin,
                                          struct ssl_config_data *sslc)
{
  uint8_t options = sslc->primary.ssl_options;
  /* If set via CURLOPT_(PROXY_)SSL_OPTIONS, we definitely use it.
   * If not, we switch it on for supported backends if no custom
   * CA settings exist. */
  sslc->native_ca_store = !!(options & CURLSSLOPT_NATIVE_CA);
  sslc->enable_beast = !!(options & CURLSSLOPT_ALLOW_BEAST);
  sslc->no_partialchain = !!(options & CURLSSLOPT_NO_PARTIALCHAIN);
  sslc->no_revoke = !!(options & CURLSSLOPT_NO_REVOKE);
  sslc->revoke_best_effort = !!(options & CURLSSLOPT_REVOKE_BEST_EFFORT);
  sslc->earlydata = !!(options & CURLSSLOPT_EARLYDATA);

  sslc->auto_client_cert = Curl_peer_equal(origin, initial_origin) &&
                           !!(options & CURLSSLOPT_AUTO_CLIENT_CERT);
}

CURLcode Curl_ssl_easy_config_complete(struct Curl_easy *data,
                                       struct Curl_peer *origin)
{
  struct ssl_config_data *sslc = &data->set.ssl;
#if defined(CURL_CA_PATH) || defined(CURL_CA_BUNDLE)
  struct UserDefined *set = &data->set;
  CURLcode result;
#endif

  ssl_easy_config_compl_options(origin, data->state.initial_origin, sslc);

  if(Curl_ssl_backend() != CURLSSLBACKEND_SCHANNEL) {
#if defined(USE_APPLE_SECTRUST) || defined(CURL_CA_NATIVE)
    if(!sslc->custom_capath && !sslc->custom_cafile && !sslc->custom_cablob)
      sslc->native_ca_store = TRUE;
#endif
#ifdef CURL_CA_PATH
    if(!sslc->custom_capath && !set->str[STRING_SSL_CAPATH]) {
      result = Curl_setstropt(&set->str[STRING_SSL_CAPATH], CURL_CA_PATH);
      if(result)
        return result;
    }
#endif
#ifdef CURL_CA_BUNDLE
    if(!sslc->custom_cafile && !set->str[STRING_SSL_CAFILE]) {
      result = Curl_setstropt(&set->str[STRING_SSL_CAFILE], CURL_CA_BUNDLE);
      if(result)
        return result;
    }
#endif
  }
  sslc->primary.CAfile = data->set.str[STRING_SSL_CAFILE];
  sslc->primary.CRLfile = data->set.str[STRING_SSL_CRLFILE];
  sslc->primary.CApath = data->set.str[STRING_SSL_CAPATH];
  sslc->primary.cipher_list = data->set.str[STRING_SSL_CIPHER_LIST];
  sslc->primary.cipher_list13 = data->set.str[STRING_SSL_CIPHER13_LIST];
  sslc->primary.signature_algorithms =
    data->set.str[STRING_SSL_SIGNATURE_ALGORITHMS];
  sslc->primary.ca_info_blob = data->set.blobs[BLOB_CAINFO];
  sslc->primary.curves = data->set.str[STRING_SSL_EC_CURVES];
  /* Maybe these should not be used for another origin. But for
   * backwards compatibility, keep them in. */
  sslc->primary.issuercert = data->set.str[STRING_SSL_ISSUERCERT];
  sslc->primary.issuercert_blob = data->set.blobs[BLOB_SSL_ISSUERCERT];

  if(Curl_peer_equal(data->state.initial_origin, origin)) {
    sslc->primary.pinned_key = data->set.str[STRING_SSL_PINNEDPUBLICKEY];
    sslc->primary.cert_blob = data->set.blobs[BLOB_CERT];
    sslc->primary.cert_type = data->set.str[STRING_CERT_TYPE];
    sslc->primary.key = data->set.str[STRING_KEY];
    sslc->primary.key_type = data->set.str[STRING_KEY_TYPE];
    sslc->primary.key_passwd = data->set.str[STRING_KEY_PASSWD];
    sslc->primary.clientcert = data->set.str[STRING_CERT];
    sslc->primary.key_blob = data->set.blobs[BLOB_KEY];
#ifdef USE_TLS_SRP
    sslc->primary.username = data->set.str[STRING_TLSAUTH_USERNAME];
    sslc->primary.password = data->set.str[STRING_TLSAUTH_PASSWORD];
#endif
  }
  else {
    sslc->primary.pinned_key = NULL;
    sslc->primary.cert_blob = NULL;
    sslc->primary.cert_type = NULL;
    sslc->primary.key = NULL;
    sslc->primary.key_type = NULL;
    sslc->primary.key_passwd = NULL;
    sslc->primary.clientcert = NULL;
    sslc->primary.key_blob = NULL;
#ifdef USE_TLS_SRP
    sslc->primary.username = NULL;
    sslc->primary.password = NULL;
#endif
  }

#ifndef CURL_DISABLE_PROXY
  sslc = &data->set.proxy_ssl;
  /* no initial origin for proxy, it is not changed for redirects */
  ssl_easy_config_compl_options(NULL, NULL, sslc);

  if(Curl_ssl_backend() != CURLSSLBACKEND_SCHANNEL) {
#if defined(USE_APPLE_SECTRUST) || defined(CURL_CA_NATIVE)
    if(!sslc->custom_capath && !sslc->custom_cafile && !sslc->custom_cablob)
      sslc->native_ca_store = TRUE;
#endif
#ifdef CURL_CA_PATH
    if(!sslc->custom_capath && !set->str[STRING_SSL_CAPATH_PROXY]) {
      result = Curl_setstropt(&set->str[STRING_SSL_CAPATH_PROXY],
                              CURL_CA_PATH);
      if(result)
        return result;
    }
#endif
#ifdef CURL_CA_BUNDLE
    if(!sslc->custom_cafile && !set->str[STRING_SSL_CAFILE_PROXY]) {
      result = Curl_setstropt(&set->str[STRING_SSL_CAFILE_PROXY],
                              CURL_CA_BUNDLE);
      if(result)
        return result;
    }
#endif
  }
  sslc->primary.CAfile = data->set.str[STRING_SSL_CAFILE_PROXY];
  sslc->primary.CApath = data->set.str[STRING_SSL_CAPATH_PROXY];
  sslc->primary.cipher_list = data->set.str[STRING_SSL_CIPHER_LIST_PROXY];
  sslc->primary.cipher_list13 = data->set.str[STRING_SSL_CIPHER13_LIST_PROXY];
  sslc->primary.pinned_key = data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY];
  sslc->primary.cert_blob = data->set.blobs[BLOB_CERT_PROXY];
  sslc->primary.ca_info_blob = data->set.blobs[BLOB_CAINFO_PROXY];
  sslc->primary.issuercert = data->set.str[STRING_SSL_ISSUERCERT_PROXY];
  sslc->primary.issuercert_blob = data->set.blobs[BLOB_SSL_ISSUERCERT_PROXY];
  sslc->primary.CRLfile = data->set.str[STRING_SSL_CRLFILE_PROXY];
  sslc->primary.cert_type = data->set.str[STRING_CERT_TYPE_PROXY];
  sslc->primary.key = data->set.str[STRING_KEY_PROXY];
  sslc->primary.key_type = data->set.str[STRING_KEY_TYPE_PROXY];
  sslc->primary.key_passwd = data->set.str[STRING_KEY_PASSWD_PROXY];
  sslc->primary.clientcert = data->set.str[STRING_CERT_PROXY];
  sslc->primary.key_blob = data->set.blobs[BLOB_KEY_PROXY];
#ifdef USE_TLS_SRP
  sslc->primary.username = data->set.str[STRING_TLSAUTH_USERNAME_PROXY];
  sslc->primary.password = data->set.str[STRING_TLSAUTH_PASSWORD_PROXY];
#endif
#endif /* CURL_DISABLE_PROXY */

  return CURLE_OK;
}

CURLcode Curl_ssl_conn_config_init(struct Curl_easy *data,
                                   struct connectdata *conn)
{
  /* Clone "primary" SSL configurations from the easy handle to
   * the connection. They are used for connection cache matching and
   * probably outlive the easy handle */
  if(!clone_ssl_primary_config(&data->set.ssl.primary, &conn->ssl_config))
    return CURLE_OUT_OF_MEMORY;
#ifndef CURL_DISABLE_PROXY
  if(!clone_ssl_primary_config(&data->set.proxy_ssl.primary,
                               &conn->proxy_ssl_config))
    return CURLE_OUT_OF_MEMORY;
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
    struct ssl_primary_config *src, *dest;
#ifndef CURL_DISABLE_PROXY
    src = for_proxy ? &data->set.proxy_ssl.primary : &data->set.ssl.primary;
    dest = for_proxy ? &data->conn->proxy_ssl_config : &data->conn->ssl_config;
#else
    (void)for_proxy;
    src = &data->set.ssl.primary;
    dest = &data->conn->ssl_config;
#endif
    dest->verifyhost = src->verifyhost;
    dest->verifypeer = src->verifypeer;
    dest->verifystatus = src->verifystatus;
  }
}
