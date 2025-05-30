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

#include "../curl_setup.h"

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

#include "openssl.h"        /* OpenSSL versions */
#include "gtls.h"           /* GnuTLS versions */
#include "wolfssl.h"        /* wolfSSL versions */
#include "schannel.h"       /* Schannel SSPI version */
#include "sectransp.h"      /* Secure Transport (Darwin) version */
#include "mbedtls.h"        /* mbedTLS versions */
#include "bearssl.h"        /* BearSSL versions */
#include "rustls.h"         /* Rustls versions */

#include "../slist.h"
#include "../sendf.h"
#include "../strcase.h"
#include "../url.h"
#include "../progress.h"
#include "../share.h"
#include "../multiif.h"
#include "../curlx/timeval.h"
#include "../curl_md5.h"
#include "../curl_sha256.h"
#include "../curlx/warnless.h"
#include "../curlx/base64.h"
#include "../curl_printf.h"
#include "../curlx/inet_pton.h"
#include "../connect.h"
#include "../select.h"
#include "../strdup.h"
#include "../rand.h"

/* The last #include files should be: */
#include "../curl_memory.h"
#include "../memdebug.h"


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
    /* only if there is data to dupe! */
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

#ifdef USE_SSL
static const struct alpn_spec ALPN_SPEC_H11 = {
  { ALPN_HTTP_1_1 }, 1
};
#ifdef USE_HTTP2
static const struct alpn_spec ALPN_SPEC_H2 = {
  { ALPN_H2 }, 1
};
static const struct alpn_spec ALPN_SPEC_H2_H11 = {
  { ALPN_H2, ALPN_HTTP_1_1 }, 2
};
#endif

static const struct alpn_spec *
alpn_get_spec(http_majors allowed, bool use_alpn)
{
  if(!use_alpn)
    return NULL;
#ifdef USE_HTTP2
  if(allowed & CURL_HTTP_V2x) {
    if(allowed & CURL_HTTP_V1x)
      return &ALPN_SPEC_H2_H11;
    return &ALPN_SPEC_H2;
  }
#else
  (void)allowed;
#endif
  /* Use the ALPN protocol "http/1.1" for HTTP/1.x.
     Avoid "http/1.0" because some servers do not support it. */
  return &ALPN_SPEC_H11;
}
#endif /* USE_SSL */


void Curl_ssl_easy_config_init(struct Curl_easy *data)
{
  /*
   * libcurl 7.10 introduced SSL verification *by default*! This needs to be
   * switched off unless wanted.
   */
  data->set.ssl.primary.verifypeer = TRUE;
  data->set.ssl.primary.verifyhost = TRUE;
  data->set.ssl.primary.cache_session = TRUE; /* caching by default */
#ifndef CURL_DISABLE_PROXY
  data->set.proxy_ssl = data->set.ssl;
#endif
}

static bool
match_ssl_primary_config(struct Curl_easy *data,
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
     Curl_safecmp(c1->CApath, c2->CApath) &&
     Curl_safecmp(c1->CAfile, c2->CAfile) &&
     Curl_safecmp(c1->issuercert, c2->issuercert) &&
     Curl_safecmp(c1->clientcert, c2->clientcert) &&
#ifdef USE_TLS_SRP
     !Curl_timestrcmp(c1->username, c2->username) &&
     !Curl_timestrcmp(c1->password, c2->password) &&
#endif
     strcasecompare(c1->cipher_list, c2->cipher_list) &&
     strcasecompare(c1->cipher_list13, c2->cipher_list13) &&
     strcasecompare(c1->curves, c2->curves) &&
     strcasecompare(c1->signature_algorithms, c2->signature_algorithms) &&
     strcasecompare(c1->CRLfile, c2->CRLfile) &&
     strcasecompare(c1->pinned_key, c2->pinned_key))
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
  CLONE_STRING(clientcert);
  CLONE_STRING(cipher_list);
  CLONE_STRING(cipher_list13);
  CLONE_STRING(pinned_key);
  CLONE_STRING(curves);
  CLONE_STRING(signature_algorithms);
  CLONE_STRING(CRLfile);
#ifdef USE_TLS_SRP
  CLONE_STRING(username);
  CLONE_STRING(password);
#endif

  return TRUE;
}

static void free_primary_ssl_config(struct ssl_primary_config *sslc)
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
  Curl_safefree(sslc->signature_algorithms);
  Curl_safefree(sslc->CRLfile);
#ifdef USE_TLS_SRP
  Curl_safefree(sslc->username);
  Curl_safefree(sslc->password);
#endif
}

CURLcode Curl_ssl_easy_config_complete(struct Curl_easy *data)
{
  data->set.ssl.primary.CApath = data->set.str[STRING_SSL_CAPATH];
  data->set.ssl.primary.CAfile = data->set.str[STRING_SSL_CAFILE];
  data->set.ssl.primary.CRLfile = data->set.str[STRING_SSL_CRLFILE];
  data->set.ssl.primary.issuercert = data->set.str[STRING_SSL_ISSUERCERT];
  data->set.ssl.primary.issuercert_blob = data->set.blobs[BLOB_SSL_ISSUERCERT];
  data->set.ssl.primary.cipher_list =
    data->set.str[STRING_SSL_CIPHER_LIST];
  data->set.ssl.primary.cipher_list13 =
    data->set.str[STRING_SSL_CIPHER13_LIST];
  data->set.ssl.primary.signature_algorithms =
    data->set.str[STRING_SSL_SIGNATURE_ALGORITHMS];
  data->set.ssl.primary.pinned_key =
    data->set.str[STRING_SSL_PINNEDPUBLICKEY];
  data->set.ssl.primary.cert_blob = data->set.blobs[BLOB_CERT];
  data->set.ssl.primary.ca_info_blob = data->set.blobs[BLOB_CAINFO];
  data->set.ssl.primary.curves = data->set.str[STRING_SSL_EC_CURVES];
#ifdef USE_TLS_SRP
  data->set.ssl.primary.username = data->set.str[STRING_TLSAUTH_USERNAME];
  data->set.ssl.primary.password = data->set.str[STRING_TLSAUTH_PASSWORD];
#endif
  data->set.ssl.cert_type = data->set.str[STRING_CERT_TYPE];
  data->set.ssl.key = data->set.str[STRING_KEY];
  data->set.ssl.key_type = data->set.str[STRING_KEY_TYPE];
  data->set.ssl.key_passwd = data->set.str[STRING_KEY_PASSWD];
  data->set.ssl.primary.clientcert = data->set.str[STRING_CERT];
  data->set.ssl.key_blob = data->set.blobs[BLOB_KEY];

#ifndef CURL_DISABLE_PROXY
  data->set.proxy_ssl.primary.CApath = data->set.str[STRING_SSL_CAPATH_PROXY];
  data->set.proxy_ssl.primary.CAfile = data->set.str[STRING_SSL_CAFILE_PROXY];
  data->set.proxy_ssl.primary.cipher_list =
    data->set.str[STRING_SSL_CIPHER_LIST_PROXY];
  data->set.proxy_ssl.primary.cipher_list13 =
    data->set.str[STRING_SSL_CIPHER13_LIST_PROXY];
  data->set.proxy_ssl.primary.pinned_key =
    data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY];
  data->set.proxy_ssl.primary.cert_blob = data->set.blobs[BLOB_CERT_PROXY];
  data->set.proxy_ssl.primary.ca_info_blob =
    data->set.blobs[BLOB_CAINFO_PROXY];
  data->set.proxy_ssl.primary.issuercert =
    data->set.str[STRING_SSL_ISSUERCERT_PROXY];
  data->set.proxy_ssl.primary.issuercert_blob =
    data->set.blobs[BLOB_SSL_ISSUERCERT_PROXY];
  data->set.proxy_ssl.primary.CRLfile =
    data->set.str[STRING_SSL_CRLFILE_PROXY];
  data->set.proxy_ssl.cert_type = data->set.str[STRING_CERT_TYPE_PROXY];
  data->set.proxy_ssl.key = data->set.str[STRING_KEY_PROXY];
  data->set.proxy_ssl.key_type = data->set.str[STRING_KEY_TYPE_PROXY];
  data->set.proxy_ssl.key_passwd = data->set.str[STRING_KEY_PASSWD_PROXY];
  data->set.proxy_ssl.primary.clientcert = data->set.str[STRING_CERT_PROXY];
  data->set.proxy_ssl.key_blob = data->set.blobs[BLOB_KEY_PROXY];
#ifdef USE_TLS_SRP
  data->set.proxy_ssl.primary.username =
    data->set.str[STRING_TLSAUTH_USERNAME_PROXY];
  data->set.proxy_ssl.primary.password =
    data->set.str[STRING_TLSAUTH_PASSWORD_PROXY];
#endif
#endif /* CURL_DISABLE_PROXY */

  return CURLE_OK;
}

CURLcode Curl_ssl_conn_config_init(struct Curl_easy *data,
                                   struct connectdata *conn)
{
  /* Clone "primary" SSL configurations from the esay handle to
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
  free_primary_ssl_config(&conn->ssl_config);
#ifndef CURL_DISABLE_PROXY
  free_primary_ssl_config(&conn->proxy_ssl_config);
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

  if(Curl_ssl->init)
    return Curl_ssl->init();
  return 1;
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

  ctx->ssl_impl = Curl_ssl;
  ctx->alpn = alpn;
  Curl_bufq_init2(&ctx->earlydata, CURL_SSL_EARLY_MAX, 1, BUFQ_OPT_NO_SPARES);
  ctx->backend = calloc(1, ctx->ssl_impl->sizeof_ssl_backend_data);
  if(!ctx->backend) {
    free(ctx);
    return NULL;
  }
  return ctx;
}

static void cf_ctx_free(struct ssl_connect_data *ctx)
{
  if(ctx) {
    Curl_safefree(ctx->negotiated.alpn);
    Curl_bufq_free(&ctx->earlydata);
    free(ctx->backend);
    free(ctx);
  }
}

CURLcode Curl_ssl_get_channel_binding(struct Curl_easy *data, int sockindex,
                                       struct dynbuf *binding)
{
  if(Curl_ssl->get_channel_binding)
    return Curl_ssl->get_channel_binding(data, sockindex, binding);
  return CURLE_OK;
}

void Curl_ssl_close_all(struct Curl_easy *data)
{
  if(Curl_ssl->close_all)
    Curl_ssl->close_all(data);
}

void Curl_ssl_adjust_pollset(struct Curl_cfilter *cf, struct Curl_easy *data,
                              struct easy_pollset *ps)
{
  struct ssl_connect_data *connssl = cf->ctx;

  if(connssl->io_need) {
    curl_socket_t sock = Curl_conn_cf_get_socket(cf->next, data);
    if(sock != CURL_SOCKET_BAD) {
      if(connssl->io_need & CURL_SSL_IO_NEED_SEND) {
        Curl_pollset_set_out_only(data, ps, sock);
        CURL_TRC_CF(data, cf, "adjust_pollset, POLLOUT fd=%" FMT_SOCKET_T,
                    sock);
      }
      else {
        Curl_pollset_set_in_only(data, ps, sock);
        CURL_TRC_CF(data, cf, "adjust_pollset, POLLIN fd=%" FMT_SOCKET_T,
                    sock);
      }
    }
  }
}

/* Selects an SSL crypto engine
 */
CURLcode Curl_ssl_set_engine(struct Curl_easy *data, const char *engine)
{
  if(Curl_ssl->set_engine)
    return Curl_ssl->set_engine(data, engine);
  return CURLE_NOT_BUILT_IN;
}

/* Selects the default SSL crypto engine
 */
CURLcode Curl_ssl_set_engine_default(struct Curl_easy *data)
{
  if(Curl_ssl->set_engine_default)
    return Curl_ssl->set_engine_default(data);
  return CURLE_NOT_BUILT_IN;
}

/* Return list of OpenSSL crypto engine names. */
struct curl_slist *Curl_ssl_engines_list(struct Curl_easy *data)
{
  if(Curl_ssl->engines_list)
    return Curl_ssl->engines_list(data);
  return NULL;
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
    for(i = 0; i < ci->num_of_certs; i++) {
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
  struct curl_slist *nl;
  CURLcode result = CURLE_OK;
  struct dynbuf build;

  DEBUGASSERT(certnum < ci->num_of_certs);

  curlx_dyn_init(&build, CURL_X509_STR_MAX);

  if(curlx_dyn_add(&build, label) ||
     curlx_dyn_addn(&build, ":", 1) ||
     curlx_dyn_addn(&build, value, valuelen))
    return CURLE_OUT_OF_MEMORY;

  nl = Curl_slist_append_nodup(ci->certinfo[certnum],
                               curlx_dyn_ptr(&build));
  if(!nl) {
    curlx_dyn_free(&build);
    curl_slist_free_all(ci->certinfo[certnum]);
    result = CURLE_OUT_OF_MEMORY;
  }

  ci->certinfo[certnum] = nl;
  return result;
}

/* get length bytes of randomness */
CURLcode Curl_ssl_random(struct Curl_easy *data,
                         unsigned char *entropy,
                         size_t length)
{
  DEBUGASSERT(length == sizeof(int));
  if(Curl_ssl->random)
    return Curl_ssl->random(data, entropy, length);
  else
    return CURLE_NOT_BUILT_IN;
}

/*
 * Public key pem to der conversion
 */

static CURLcode pubkey_pem_to_der(const char *pem,
                                  unsigned char **der, size_t *der_len)
{
  char *begin_pos, *end_pos;
  size_t pem_count, pem_len;
  CURLcode result;
  struct dynbuf pbuf;

  /* if no pem, exit. */
  if(!pem)
    return CURLE_BAD_CONTENT_ENCODING;

  curlx_dyn_init(&pbuf, MAX_PINNED_PUBKEY_SIZE);

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

  /*
   * Here we loop through the pem array one character at a time between the
   * correct indices, and place each character that is not '\n' or '\r'
   * into the stripped_pem array, which should represent the raw base64 string
   */
  while(pem_count < pem_len) {
    if('\n' != pem[pem_count] && '\r' != pem[pem_count]) {
      result = curlx_dyn_addn(&pbuf, &pem[pem_count], 1);
      if(result)
        return result;
    }
    ++pem_count;
  }

  if(curlx_dyn_len(&pbuf)) {
    result = curlx_base64_decode(curlx_dyn_ptr(&pbuf), der, der_len);
    curlx_dyn_free(&pbuf);
  }
  else
    result = CURLE_BAD_CONTENT_ENCODING;

  return result;
}

/*
 * Generic pinned public key check.
 */

CURLcode Curl_pin_peer_pubkey(struct Curl_easy *data,
                              const char *pinnedpubkey,
                              const unsigned char *pubkey, size_t pubkeylen)
{
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
#ifdef CURL_DISABLE_VERBOSE_STRINGS
  (void)data;
#endif

  /* if a path was not specified, do not pin */
  if(!pinnedpubkey)
    return CURLE_OK;
  if(!pubkey || !pubkeylen)
    return result;

  /* only do this if pinnedpubkey starts with "sha256//", length 8 */
  if(!strncmp(pinnedpubkey, "sha256//", 8)) {
    CURLcode encode;
    size_t encodedlen = 0;
    char *encoded = NULL, *pinkeycopy, *begin_pos, *end_pos;
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

    if(!encode)
      encode = curlx_base64_encode((char *)sha256sumdigest,
                                   CURL_SHA256_DIGEST_LENGTH, &encoded,
                                   &encodedlen);
    Curl_safefree(sha256sumdigest);

    if(encode)
      return encode;

    infof(data, " public key hash: sha256//%s", encoded);

    /* it starts with sha256//, copy so we can modify it */
    pinkeycopy = strdup(pinnedpubkey);
    if(!pinkeycopy) {
      Curl_safefree(encoded);
      return CURLE_OUT_OF_MEMORY;
    }
    /* point begin_pos to the copy, and start extracting keys */
    begin_pos = pinkeycopy;
    do {
      end_pos = strstr(begin_pos, ";sha256//");
      /*
       * if there is an end_pos, null-terminate, otherwise it will go to the
       * end of the original string
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
  }
  else {
    long filesize;
    size_t size, pem_len;
    CURLcode pem_read;
    struct dynbuf buf;
    char unsigned *pem_ptr = NULL;
    size_t left;
    FILE *fp = fopen(pinnedpubkey, "rb");
    if(!fp)
      return result;

    curlx_dyn_init(&buf, MAX_PINNED_PUBKEY_SIZE);

    /* Determine the file's size */
    if(fseek(fp, 0, SEEK_END))
      goto end;
    filesize = ftell(fp);
    if(fseek(fp, 0, SEEK_SET))
      goto end;
    if(filesize < 0 || filesize > MAX_PINNED_PUBKEY_SIZE)
      goto end;

    /*
     * if the size of our certificate is bigger than the file
     * size then it cannot match
     */
    size = curlx_sotouz((curl_off_t) filesize);
    if(pubkeylen > size)
      goto end;

    /*
     * Read the file into the dynbuf
     */
    left = size;
    do {
      char buffer[1024];
      size_t want = left > sizeof(buffer) ? sizeof(buffer) : left;
      if(want != fread(buffer, 1, want, fp))
        goto end;
      if(curlx_dyn_addn(&buf, buffer, want))
        goto end;
      left -= want;
    } while(left);

    /* If the sizes are the same, it cannot be base64 encoded, must be der */
    if(pubkeylen == size) {
      if(!memcmp(pubkey, curlx_dyn_ptr(&buf), pubkeylen))
        result = CURLE_OK;
      goto end;
    }

    /*
     * Otherwise we will assume it is PEM and try to decode it after placing
     * null-terminator
     */
    pem_read = pubkey_pem_to_der(curlx_dyn_ptr(&buf), &pem_ptr, &pem_len);
    /* if it was not read successfully, exit */
    if(pem_read)
      goto end;

    /*
     * if the size of our certificate does not match the size of
     * the decoded file, they cannot be the same, otherwise compare
     */
    if(pubkeylen == pem_len && !memcmp(pubkey, pem_ptr, pubkeylen))
      result = CURLE_OK;
end:
    curlx_dyn_free(&buf);
    Curl_safefree(pem_ptr);
    fclose(fp);
  }

  return result;
}

/*
 * Check whether the SSL backend supports the status_request extension.
 */
bool Curl_ssl_cert_status_request(void)
{
  if(Curl_ssl->cert_status_request)
    return Curl_ssl->cert_status_request();
  return FALSE;
}

/*
 * Check whether the SSL backend supports false start.
 */
bool Curl_ssl_false_start(void)
{
  if(Curl_ssl->false_start)
    return Curl_ssl->false_start();
  return FALSE;
}

static int multissl_init(void)
{
  if(multissl_setup(NULL))
    return 1;
  if(Curl_ssl->init)
    return Curl_ssl->init();
  return 1;
}

static CURLcode multissl_connect(struct Curl_cfilter *cf,
                                 struct Curl_easy *data, bool *done)
{
  if(multissl_setup(NULL))
    return CURLE_FAILED_INIT;
  return Curl_ssl->do_connect(cf, data, done);
}

static void multissl_adjust_pollset(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct easy_pollset *ps)
{
  if(multissl_setup(NULL))
    return;
  Curl_ssl->adjust_pollset(cf, data, ps);
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
  NULL,                              /* cleanup */
  multissl_version,                  /* version */
  NULL,                              /* shutdown */
  NULL,                              /* data_pending */
  NULL,                              /* random */
  NULL,                              /* cert_status_request */
  multissl_connect,                  /* connect */
  multissl_adjust_pollset,           /* adjust_pollset */
  multissl_get_internals,            /* get_internals */
  multissl_close,                    /* close_one */
  NULL,                              /* close_all */
  NULL,                              /* set_engine */
  NULL,                              /* set_engine_default */
  NULL,                              /* engines_list */
  NULL,                              /* false_start */
  NULL,                              /* sha256sum */
  multissl_recv_plain,               /* recv decrypted data */
  multissl_send_plain,               /* send data to encrypt */
  NULL,                              /* get_channel_binding */
};

const struct Curl_ssl *Curl_ssl =
#if defined(CURL_WITH_MULTI_SSL)
  &Curl_ssl_multi;
#elif defined(USE_WOLFSSL)
  &Curl_ssl_wolfssl;
#elif defined(USE_GNUTLS)
  &Curl_ssl_gnutls;
#elif defined(USE_MBEDTLS)
  &Curl_ssl_mbedtls;
#elif defined(USE_RUSTLS)
  &Curl_ssl_rustls;
#elif defined(USE_OPENSSL)
  &Curl_ssl_openssl;
#elif defined(USE_SECTRANSP)
  &Curl_ssl_sectransp;
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
#if defined(USE_GNUTLS)
  &Curl_ssl_gnutls,
#endif
#if defined(USE_MBEDTLS)
  &Curl_ssl_mbedtls,
#endif
#if defined(USE_OPENSSL)
  &Curl_ssl_openssl,
#endif
#if defined(USE_SECTRANSP)
  &Curl_ssl_sectransp,
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

/* Global cleanup */
void Curl_ssl_cleanup(void)
{
  if(init_ssl) {
    /* only cleanup if we did a previous init */
    if(Curl_ssl->cleanup)
      Curl_ssl->cleanup();
#if defined(CURL_WITH_MULTI_SSL)
    Curl_ssl = &Curl_ssl_multi;
#endif
    init_ssl = FALSE;
  }
}

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

  if(size) {
    if(backends_len < size)
      strcpy(buffer, backends);
    else
      *buffer = 0; /* did not fit */
  }
  return 0;
}

static int multissl_setup(const struct Curl_ssl *backend)
{
  int i;
  char *env;

  if(Curl_ssl != &Curl_ssl_multi)
    return 1;

  if(backend) {
    Curl_ssl = backend;
    return 0;
  }

  if(!available_backends[0])
    return 1;

  env = curl_getenv("CURL_SSL_BACKEND");
  if(env) {
    for(i = 0; available_backends[i]; i++) {
      if(strcasecompare(env, available_backends[i]->info.name)) {
        Curl_ssl = available_backends[i];
        free(env);
        return 0;
      }
    }
  }

#ifdef CURL_DEFAULT_SSL_BACKEND
  for(i = 0; available_backends[i]; i++) {
    if(strcasecompare(CURL_DEFAULT_SSL_BACKEND,
                      available_backends[i]->info.name)) {
      Curl_ssl = available_backends[i];
      free(env);
      return 0;
    }
  }
#endif

  /* Fall back to first available backend */
  Curl_ssl = available_backends[0];
  free(env);
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

void Curl_ssl_peer_cleanup(struct ssl_peer *peer)
{
  Curl_safefree(peer->sni);
  if(peer->dispname != peer->hostname)
    free(peer->dispname);
  peer->dispname = NULL;
  Curl_safefree(peer->hostname);
  Curl_safefree(peer->scache_key);
  peer->type = CURL_SSL_PEER_DNS;
}

static void cf_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  if(connssl) {
    connssl->ssl_impl->close(cf, data);
    connssl->state = ssl_connection_none;
    Curl_ssl_peer_cleanup(&connssl->peer);
  }
  cf->connected = FALSE;
}

static ssl_peer_type get_peer_type(const char *hostname)
{
  if(hostname && hostname[0]) {
#ifdef USE_IPV6
    struct in6_addr addr;
#else
    struct in_addr addr;
#endif
    if(curlx_inet_pton(AF_INET, hostname, &addr))
      return CURL_SSL_PEER_IPV4;
#ifdef USE_IPV6
    else if(curlx_inet_pton(AF_INET6, hostname, &addr)) {
      return CURL_SSL_PEER_IPV6;
    }
#endif
  }
  return CURL_SSL_PEER_DNS;
}

CURLcode Curl_ssl_peer_init(struct ssl_peer *peer,
                            struct Curl_cfilter *cf,
                            const char *tls_id,
                            int transport)
{
  const char *ehostname, *edispname;
  CURLcode result = CURLE_OUT_OF_MEMORY;

  /* We expect a clean struct, e.g. called only ONCE */
  DEBUGASSERT(peer);
  DEBUGASSERT(!peer->hostname);
  DEBUGASSERT(!peer->dispname);
  DEBUGASSERT(!peer->sni);
  /* We need the hostname for SNI negotiation. Once handshaked, this remains
   * the SNI hostname for the TLS connection. When the connection is reused,
   * the settings in cf->conn might change. We keep a copy of the hostname we
   * use for SNI.
   */
  peer->transport = transport;
#ifndef CURL_DISABLE_PROXY
  if(Curl_ssl_cf_is_proxy(cf)) {
    ehostname = cf->conn->http_proxy.host.name;
    edispname = cf->conn->http_proxy.host.dispname;
    peer->port = cf->conn->http_proxy.port;
  }
  else
#endif
  {
    ehostname = cf->conn->host.name;
    edispname = cf->conn->host.dispname;
    peer->port = cf->conn->remote_port;
  }

  /* hostname MUST exist and not be empty */
  if(!ehostname || !ehostname[0]) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  peer->hostname = strdup(ehostname);
  if(!peer->hostname)
    goto out;
  if(!edispname || !strcmp(ehostname, edispname))
    peer->dispname = peer->hostname;
  else {
    peer->dispname = strdup(edispname);
    if(!peer->dispname)
      goto out;
  }
  peer->type = get_peer_type(peer->hostname);
  if(peer->type == CURL_SSL_PEER_DNS) {
    /* not an IP address, normalize according to RCC 6066 ch. 3,
     * max len of SNI is 2^16-1, no trailing dot */
    size_t len = strlen(peer->hostname);
    if(len && (peer->hostname[len-1] == '.'))
      len--;
    if(len < USHRT_MAX) {
      peer->sni = calloc(1, len + 1);
      if(!peer->sni)
        goto out;
      Curl_strntolower(peer->sni, peer->hostname, len);
      peer->sni[len] = 0;
    }
  }

  result = Curl_ssl_peer_key_make(cf, peer, tls_id, &peer->scache_key);

out:
  if(result)
    Curl_ssl_peer_cleanup(peer);
  return result;
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
  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
  CF_DATA_RESTORE(cf, save);
}

static CURLcode ssl_cf_connect(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct cf_call_data save;
  CURLcode result;

  if(cf->connected && (connssl->state != ssl_connection_deferred)) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(!cf->next) {
    *done = FALSE;
    return CURLE_FAILED_INIT;
  }

  if(!cf->next->connected) {
    result = cf->next->cft->do_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  CF_DATA_SAVE(save, cf, data);
  CURL_TRC_CF(data, cf, "cf_connect()");
  DEBUGASSERT(connssl);

  *done = FALSE;
  if(!connssl->peer.hostname) {
    char tls_id[80];
    connssl->ssl_impl->version(tls_id, sizeof(tls_id) - 1);
    result = Curl_ssl_peer_init(&connssl->peer, cf, tls_id, TRNSPRT_TCP);
    if(result)
      goto out;
  }

  if(!connssl->prefs_checked) {
    if(!ssl_prefs_check(data))
      return CURLE_SSL_CONNECT_ERROR;
    connssl->prefs_checked = TRUE;
  }

  result = connssl->ssl_impl->do_connect(cf, data, done);

  if(!result && *done) {
    cf->connected = TRUE;
    if(connssl->state == ssl_connection_complete)
      connssl->handshake_done = curlx_now();
    /* Connection can be deferred when sending early data */
    DEBUGASSERT(connssl->state == ssl_connection_complete ||
                connssl->state == ssl_connection_deferred);
    DEBUGASSERT(connssl->state != ssl_connection_deferred ||
                connssl->earlydata_state > ssl_earlydata_none);
  }
out:
  CURL_TRC_CF(data, cf, "cf_connect() -> %d, done=%d", result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode ssl_cf_set_earlydata(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     const void *buf, size_t blen)
{
  struct ssl_connect_data *connssl = cf->ctx;
  ssize_t nwritten = 0;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(connssl->earlydata_state == ssl_earlydata_await);
  DEBUGASSERT(Curl_bufq_is_empty(&connssl->earlydata));
  if(blen) {
    if(blen > connssl->earlydata_max)
      blen = connssl->earlydata_max;
    nwritten = Curl_bufq_write(&connssl->earlydata, buf, blen, &result);
    CURL_TRC_CF(data, cf, "ssl_cf_set_earlydata(len=%zu) -> %zd",
                blen, nwritten);
    if(nwritten < 0)
      return result;
  }
  return CURLE_OK;
}

static CURLcode ssl_cf_connect_deferred(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        const void *buf, size_t blen,
                                        bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(connssl->state == ssl_connection_deferred);
  *done = FALSE;
  if(connssl->earlydata_state == ssl_earlydata_await) {
    result = ssl_cf_set_earlydata(cf, data, buf, blen);
    if(result)
      return result;
    /* we buffered any early data we'd like to send. Actually
     * do the connect now which sends it and performs the handshake. */
    connssl->earlydata_state = ssl_earlydata_sending;
    connssl->earlydata_skip = Curl_bufq_len(&connssl->earlydata);
  }

  result = ssl_cf_connect(cf, data, done);

  if(!result && *done) {
    Curl_pgrsTimeWas(data, TIMER_APPCONNECT, connssl->handshake_done);
    switch(connssl->earlydata_state) {
    case ssl_earlydata_none:
      break;
    case ssl_earlydata_accepted:
      if(!Curl_ssl_cf_is_proxy(cf))
        Curl_pgrsEarlyData(data, (curl_off_t)connssl->earlydata_skip);
      infof(data, "Server accepted %zu bytes of TLS early data.",
            connssl->earlydata_skip);
      break;
    case ssl_earlydata_rejected:
      if(!Curl_ssl_cf_is_proxy(cf))
        Curl_pgrsEarlyData(data, -(curl_off_t)connssl->earlydata_skip);
      infof(data, "Server rejected TLS early data.");
      connssl->earlydata_skip = 0;
      break;
    default:
      /* This should not happen. Either we do not use early data or we
       * should know if it was accepted or not. */
      DEBUGASSERT(NULL);
      break;
    }
  }
  return result;
}

static bool ssl_cf_data_pending(struct Curl_cfilter *cf,
                                const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct cf_call_data save;
  bool result;

  CF_DATA_SAVE(save, cf, data);
  if(connssl->ssl_impl->data_pending &&
     connssl->ssl_impl->data_pending(cf, data))
    result = TRUE;
  else
    result = cf->next->cft->has_data_pending(cf->next, data);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static ssize_t ssl_cf_send(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           const void *buf, size_t blen,
                           bool eos, CURLcode *err)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct cf_call_data save;
  ssize_t nwritten = 0, early_written = 0;

  (void)eos;
  *err = CURLE_OK;
  CF_DATA_SAVE(save, cf, data);

  if(connssl->state == ssl_connection_deferred) {
    bool done = FALSE;
    *err = ssl_cf_connect_deferred(cf, data, buf, blen, &done);
    if(*err) {
      nwritten = -1;
      goto out;
    }
    else if(!done) {
      *err = CURLE_AGAIN;
      nwritten = -1;
      goto out;
    }
    DEBUGASSERT(connssl->state == ssl_connection_complete);
  }

  if(connssl->earlydata_skip) {
    if(connssl->earlydata_skip >= blen) {
      connssl->earlydata_skip -= blen;
      *err = CURLE_OK;
      nwritten = (ssize_t)blen;
      goto out;
    }
    else {
      early_written = connssl->earlydata_skip;
      buf = ((const char *)buf) + connssl->earlydata_skip;
      blen -= connssl->earlydata_skip;
      connssl->earlydata_skip = 0;
    }
  }

  /* OpenSSL and maybe other TLS libs do not like 0-length writes. Skip. */
  if(blen > 0)
    nwritten = connssl->ssl_impl->send_plain(cf, data, buf, blen, err);

  if(nwritten >= 0)
    nwritten += early_written;

out:
  CF_DATA_RESTORE(cf, save);
  return nwritten;
}

static ssize_t ssl_cf_recv(struct Curl_cfilter *cf,
                           struct Curl_easy *data, char *buf, size_t len,
                           CURLcode *err)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct cf_call_data save;
  ssize_t nread;

  CF_DATA_SAVE(save, cf, data);
  *err = CURLE_OK;
  if(connssl->state == ssl_connection_deferred) {
    bool done = FALSE;
    *err = ssl_cf_connect_deferred(cf, data, NULL, 0, &done);
    if(*err) {
      nread = -1;
      goto out;
    }
    else if(!done) {
      *err = CURLE_AGAIN;
      nread = -1;
      goto out;
    }
    DEBUGASSERT(connssl->state == ssl_connection_complete);
  }

  nread = connssl->ssl_impl->recv_plain(cf, data, buf, len, err);
  if(nread > 0) {
    DEBUGASSERT((size_t)nread <= len);
  }
  else if(nread == 0) {
    /* eof */
    *err = CURLE_OK;
  }

out:
  CURL_TRC_CF(data, cf, "cf_recv(len=%zu) -> %zd, %d", len,
              nread, *err);
  CF_DATA_RESTORE(cf, save);
  return nread;
}

static CURLcode ssl_cf_shutdown(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode result = CURLE_OK;

  *done = TRUE;
  /* If we have done the SSL handshake, shut down the connection cleanly */
  if(cf->connected && (connssl->state == ssl_connection_complete) &&
    !cf->shutdown && Curl_ssl->shut_down) {
    struct cf_call_data save;

    CF_DATA_SAVE(save, cf, data);
    result = connssl->ssl_impl->shut_down(cf, data, TRUE, done);
    CURL_TRC_CF(data, cf, "cf_shutdown -> %d, done=%d", result, *done);
    CF_DATA_RESTORE(cf, save);
    cf->shutdown = (result || *done);
  }
  return result;
}

static void ssl_cf_adjust_pollset(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct easy_pollset *ps)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  connssl->ssl_impl->adjust_pollset(cf, data, ps);
  CF_DATA_RESTORE(cf, save);
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
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_ssl_is_alive(struct Curl_cfilter *cf, struct Curl_easy *data,
                            bool *input_pending)
{
  /*
   * This function tries to determine connection status.
   */
  return cf->next ?
    cf->next->cft->is_alive(cf->next, data, input_pending) :
    FALSE; /* pessimistic in absence of data */
}

struct Curl_cftype Curl_cft_ssl = {
  "SSL",
  CF_TYPE_SSL,
  CURL_LOG_LVL_NONE,
  ssl_cf_destroy,
  ssl_cf_connect,
  ssl_cf_close,
  ssl_cf_shutdown,
  Curl_cf_def_get_host,
  ssl_cf_adjust_pollset,
  ssl_cf_data_pending,
  ssl_cf_send,
  ssl_cf_recv,
  Curl_cf_def_cntrl,
  cf_ssl_is_alive,
  Curl_cf_def_conn_keep_alive,
  ssl_cf_query,
};

#ifndef CURL_DISABLE_PROXY

struct Curl_cftype Curl_cft_ssl_proxy = {
  "SSL-PROXY",
  CF_TYPE_SSL|CF_TYPE_PROXY,
  CURL_LOG_LVL_NONE,
  ssl_cf_destroy,
  ssl_cf_connect,
  ssl_cf_close,
  ssl_cf_shutdown,
  Curl_cf_def_get_host,
  ssl_cf_adjust_pollset,
  ssl_cf_data_pending,
  ssl_cf_send,
  ssl_cf_recv,
  Curl_cf_def_cntrl,
  cf_ssl_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

#endif /* !CURL_DISABLE_PROXY */

static CURLcode cf_ssl_create(struct Curl_cfilter **pcf,
                              struct Curl_easy *data,
                              struct connectdata *conn)
{
  struct Curl_cfilter *cf = NULL;
  struct ssl_connect_data *ctx;
  CURLcode result;

  DEBUGASSERT(data->conn);

#ifdef CURL_DISABLE_HTTP
  /* We only support ALPN for HTTP so far. */
  DEBUGASSERT(!conn->bits.tls_enable_alpn);
  ctx = cf_ctx_new(data, NULL);
#else
  ctx = cf_ctx_new(data, alpn_get_spec(data->state.http_neg.wanted,
                                       conn->bits.tls_enable_alpn));
#endif
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = Curl_cf_create(&cf, &Curl_cft_ssl, ctx);

out:
  if(result)
    cf_ctx_free(ctx);
  *pcf = result ? NULL : cf;
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
  bool use_alpn = conn->bits.tls_enable_alpn;
  http_majors allowed = CURL_HTTP_V1x;

#ifdef USE_HTTP2
  if(conn->http_proxy.proxytype == CURLPROXY_HTTPS2) {
    use_alpn = TRUE;
    allowed = (CURL_HTTP_V1x|CURL_HTTP_V2x);
  }
#endif

  ctx = cf_ctx_new(data, alpn_get_spec(allowed, use_alpn));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  result = Curl_cf_create(&cf, &Curl_cft_ssl_proxy, ctx);

out:
  if(result)
    cf_ctx_free(ctx);
  *pcf = result ? NULL : cf;
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

bool Curl_ssl_supports(struct Curl_easy *data, unsigned int ssl_option)
{
  (void)data;
  return (Curl_ssl->supports & ssl_option);
}

static struct Curl_cfilter *get_ssl_filter(struct Curl_cfilter *cf)
{
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_ssl)
      return cf;
#ifndef CURL_DISABLE_PROXY
    if(cf->cft == &Curl_cft_ssl_proxy)
      return cf;
#endif
  }
  return NULL;
}


void *Curl_ssl_get_internals(struct Curl_easy *data, int sockindex,
                             CURLINFO info, int n)
{
  void *result = NULL;
  (void)n;
  if(data->conn) {
    struct Curl_cfilter *cf;
    /* get first SSL filter in chain, if any is present */
    cf = get_ssl_filter(data->conn->cfilter[sockindex]);
    if(cf) {
      struct ssl_connect_data *connssl = cf->ctx;
      struct cf_call_data save;
      CF_DATA_SAVE(save, cf, data);
      result = connssl->ssl_impl->get_internals(cf->ctx, info);
      CF_DATA_RESTORE(cf, save);
    }
  }
  return result;
}

static CURLcode vtls_shutdown_blocking(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;
  timediff_t timeout_ms;
  int what, loop = 10;

  if(cf->shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }
  CF_DATA_SAVE(save, cf, data);

  *done = FALSE;
  while(!result && !*done && loop--) {
    timeout_ms = Curl_shutdown_timeleft(cf->conn, cf->sockindex, NULL);

    if(timeout_ms < 0) {
      /* no need to continue if time is already up */
      failf(data, "SSL shutdown timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = connssl->ssl_impl->shut_down(cf, data, send_shutdown, done);
    if(result ||*done)
      goto out;

    if(connssl->io_need) {
      what = Curl_conn_cf_poll(cf, data, timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        result = CURLE_RECV_ERROR;
        goto out;
      }
      else if(0 == what) {
        /* timeout */
        failf(data, "SSL shutdown timeout");
        result = CURLE_OPERATION_TIMEDOUT;
        goto out;
      }
      /* socket is readable or writable */
    }
  }
out:
  CF_DATA_RESTORE(cf, save);
  cf->shutdown = (result || *done);
  return result;
}

CURLcode Curl_ssl_cfilter_remove(struct Curl_easy *data,
                                 int sockindex, bool send_shutdown)
{
  struct Curl_cfilter *cf, *head;
  CURLcode result = CURLE_OK;

  head = data->conn ? data->conn->cfilter[sockindex] : NULL;
  for(cf = head; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_ssl) {
      bool done;
      CURL_TRC_CF(data, cf, "shutdown and remove SSL, start");
      Curl_shutdown_start(data, sockindex, 0, NULL);
      result = vtls_shutdown_blocking(cf, data, send_shutdown, &done);
      Curl_shutdown_clear(data, sockindex);
      if(!result && !done) /* blocking failed? */
        result = CURLE_SSL_SHUTDOWN_FAILED;
      Curl_conn_cf_discard_sub(head, cf, data, FALSE);
      CURL_TRC_CF(data, cf, "shutdown and remove SSL, done -> %d", result);
      break;
    }
  }
  return result;
}

bool Curl_ssl_cf_is_proxy(struct Curl_cfilter *cf)
{
  return (cf->cft->flags & CF_TYPE_SSL) && (cf->cft->flags & CF_TYPE_PROXY);
}

struct ssl_config_data *
Curl_ssl_cf_get_config(struct Curl_cfilter *cf, struct Curl_easy *data)
{
#ifdef CURL_DISABLE_PROXY
  (void)cf;
  return &data->set.ssl;
#else
  return Curl_ssl_cf_is_proxy(cf) ? &data->set.proxy_ssl : &data->set.ssl;
#endif
}

struct ssl_primary_config *
Curl_ssl_cf_get_primary_config(struct Curl_cfilter *cf)
{
#ifdef CURL_DISABLE_PROXY
  return &cf->conn->ssl_config;
#else
  return Curl_ssl_cf_is_proxy(cf) ?
    &cf->conn->proxy_ssl_config : &cf->conn->ssl_config;
#endif
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
    if(off + len + 2 >= sizeof(buf->data))
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

bool Curl_alpn_contains_proto(const struct alpn_spec *spec,
                              const char *proto)
{
  size_t i, plen = proto ? strlen(proto) : 0;
  for(i = 0; spec && plen && i < spec->count; ++i) {
    size_t slen = strlen(spec->entries[i]);
    if((slen == plen) && !memcmp(proto, spec->entries[i], plen))
      return TRUE;
  }
  return FALSE;
}

void Curl_alpn_restrict_to(struct alpn_spec *spec, const char *proto)
{
  size_t plen = strlen(proto);
  DEBUGASSERT(plen < sizeof(spec->entries[0]));
  if(plen < sizeof(spec->entries[0])) {
    memcpy(spec->entries[0], proto, plen + 1);
    spec->count = 1;
  }
}

void Curl_alpn_copy(struct alpn_spec *dest, const struct alpn_spec *src)
{
  if(src)
    memcpy(dest, src, sizeof(*dest));
  else
    memset(dest, 0, sizeof(*dest));
}

CURLcode Curl_alpn_set_negotiated(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct ssl_connect_data *connssl,
                                  const unsigned char *proto,
                                  size_t proto_len)
{
  CURLcode result = CURLE_OK;
  unsigned char *palpn =
#ifndef CURL_DISABLE_PROXY
    (cf->conn->bits.tunnel_proxy && Curl_ssl_cf_is_proxy(cf)) ?
    &cf->conn->proxy_alpn : &cf->conn->alpn
#else
    &cf->conn->alpn
#endif
    ;

  if(connssl->negotiated.alpn) {
    /* When we ask for a specific ALPN protocol, we need the confirmation
     * of it by the server, as we have installed protocol handler and
     * connection filter chain for exactly this protocol. */
    if(!proto_len) {
      failf(data, "ALPN: asked for '%s' from previous session, "
            "but server did not confirm it. Refusing to continue.",
            connssl->negotiated.alpn);
      result = CURLE_SSL_CONNECT_ERROR;
      goto out;
    }
    else if((strlen(connssl->negotiated.alpn) != proto_len) ||
            memcmp(connssl->negotiated.alpn, proto, proto_len)) {
      failf(data, "ALPN: asked for '%s' from previous session, but server "
            "selected '%.*s'. Refusing to continue.",
            connssl->negotiated.alpn, (int)proto_len, proto);
      result = CURLE_SSL_CONNECT_ERROR;
      goto out;
    }
    /* ALPN is exactly what we asked for, done. */
    infof(data, "ALPN: server confirmed to use '%s'",
          connssl->negotiated.alpn);
    goto out;
  }

  if(proto && proto_len) {
    if(memchr(proto, '\0', proto_len)) {
      failf(data, "ALPN: server selected protocol contains NUL. "
            "Refusing to continue.");
      result = CURLE_SSL_CONNECT_ERROR;
      goto out;
    }
    connssl->negotiated.alpn = malloc(proto_len + 1);
    if(!connssl->negotiated.alpn)
      return CURLE_OUT_OF_MEMORY;
    memcpy(connssl->negotiated.alpn, proto, proto_len);
    connssl->negotiated.alpn[proto_len] = 0;
  }

  if(proto && proto_len) {
    if(proto_len == ALPN_HTTP_1_1_LENGTH &&
       !memcmp(ALPN_HTTP_1_1, proto, ALPN_HTTP_1_1_LENGTH)) {
      *palpn = CURL_HTTP_VERSION_1_1;
    }
#ifdef USE_HTTP2
    else if(proto_len == ALPN_H2_LENGTH &&
            !memcmp(ALPN_H2, proto, ALPN_H2_LENGTH)) {
      *palpn = CURL_HTTP_VERSION_2;
    }
#endif
#ifdef USE_HTTP3
    else if(proto_len == ALPN_H3_LENGTH &&
            !memcmp(ALPN_H3, proto, ALPN_H3_LENGTH)) {
      *palpn = CURL_HTTP_VERSION_3;
    }
#endif
    else {
      *palpn = CURL_HTTP_VERSION_NONE;
      failf(data, "unsupported ALPN protocol: '%.*s'", (int)proto_len, proto);
      /* Previous code just ignored it and some vtls backends even ignore the
       * return code of this function. */
      /* return CURLE_NOT_BUILT_IN; */
      goto out;
    }

    if(connssl->state == ssl_connection_deferred)
      infof(data, VTLS_INFOF_ALPN_DEFERRED, (int)proto_len, proto);
    else
      infof(data, VTLS_INFOF_ALPN_ACCEPTED, (int)proto_len, proto);
  }
  else {
    *palpn = CURL_HTTP_VERSION_NONE;
    if(connssl->state == ssl_connection_deferred)
      infof(data, VTLS_INFOF_NO_ALPN_DEFERRED);
    else
      infof(data, VTLS_INFOF_NO_ALPN);
  }

out:
  return result;
}

#endif /* USE_SSL */
