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

/*
 * Source file for all OpenSSL-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 */

#include "curl_setup.h"

#if defined(USE_QUICHE) || defined(USE_OPENSSL)

#include <limits.h>

/* Wincrypt must be included before anything that could include OpenSSL. */
#if defined(USE_WIN32_CRYPTO)
#include <wincrypt.h>
/* Undefine wincrypt conflicting symbols for BoringSSL. */
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif

#include "urldata.h"
#include "sendf.h"
#include "formdata.h" /* for the boundary function */
#include "url.h" /* for the ssl config check function */
#include "inet_pton.h"
#include "openssl.h"
#include "connect.h"
#include "slist.h"
#include "select.h"
#include "vtls.h"
#include "vtls_int.h"
#include "vauth/vauth.h"
#include "keylog.h"
#include "strcase.h"
#include "hostcheck.h"
#include "multiif.h"
#include "strerror.h"
#include "curl_printf.h"

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/conf.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pkcs12.h>
#include <openssl/tls1.h>
#include <openssl/evp.h>

#ifdef USE_ECH
# ifndef OPENSSL_IS_BORINGSSL
#  include <openssl/ech.h>
# endif
# include "curl_base64.h"
# define ECH_ENABLED(__data__) \
    (__data__->set.tls_ech && \
     !(__data__->set.tls_ech & CURLECH_DISABLE)\
    )
#endif /* USE_ECH */

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_OCSP)
#include <openssl/ocsp.h>
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x0090700fL) && /* 0.9.7 or later */     \
  !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_UI_CONSOLE)
#define USE_OPENSSL_ENGINE
#include <openssl/engine.h>
#endif

#include "warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

/* Uncomment the ALLOW_RENEG line to a real #define if you want to allow TLS
   renegotiations when built with BoringSSL. Renegotiating is non-compliant
   with HTTP/2 and "an extremely dangerous protocol feature". Beware.

#define ALLOW_RENEG 1
 */

#ifndef OPENSSL_VERSION_NUMBER
#error "OPENSSL_VERSION_NUMBER not defined"
#endif

#ifdef USE_OPENSSL_ENGINE
#include <openssl/ui.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x00909000L
#define SSL_METHOD_QUAL const
#else
#define SSL_METHOD_QUAL
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10000000L)
#define HAVE_ERR_REMOVE_THREAD_STATE 1
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && /* OpenSSL 1.1.0+ */ \
    !(defined(LIBRESSL_VERSION_NUMBER) && \
      LIBRESSL_VERSION_NUMBER < 0x20700000L)
#define SSLEAY_VERSION_NUMBER OPENSSL_VERSION_NUMBER
#define HAVE_X509_GET0_EXTENSIONS 1 /* added in 1.1.0 -pre1 */
#define HAVE_OPAQUE_EVP_PKEY 1 /* since 1.1.0 -pre3 */
#define HAVE_OPAQUE_RSA_DSA_DH 1 /* since 1.1.0 -pre5 */
#define CONST_EXTS const
#define HAVE_ERR_REMOVE_THREAD_STATE_DEPRECATED 1

/* funny typecast define due to difference in API */
#ifdef LIBRESSL_VERSION_NUMBER
#define ARG2_X509_signature_print (X509_ALGOR *)
#else
#define ARG2_X509_signature_print
#endif

#else
/* For OpenSSL before 1.1.0 */
#define ASN1_STRING_get0_data(x) ASN1_STRING_data(x)
#define X509_get0_notBefore(x) X509_get_notBefore(x)
#define X509_get0_notAfter(x) X509_get_notAfter(x)
#define CONST_EXTS /* nope */
#ifndef LIBRESSL_VERSION_NUMBER
#define OpenSSL_version_num() SSLeay()
#endif
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL) && /* 1.0.2 or later */ \
    !(defined(LIBRESSL_VERSION_NUMBER) && \
      LIBRESSL_VERSION_NUMBER < 0x20700000L)
#define HAVE_X509_GET0_SIGNATURE 1
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL) /* 1.0.2 or later */
#define HAVE_SSL_GET_SHUTDOWN 1
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10002003L && \
  OPENSSL_VERSION_NUMBER <= 0x10002FFFL && \
  !defined(OPENSSL_NO_COMP)
#define HAVE_SSL_COMP_FREE_COMPRESSION_METHODS 1
#endif

#if (OPENSSL_VERSION_NUMBER < 0x0090808fL)
/* not present in older OpenSSL */
#define OPENSSL_load_builtin_modules(x)
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#define HAVE_EVP_PKEY_GET_PARAMS 1
#endif

#ifdef HAVE_EVP_PKEY_GET_PARAMS
#include <openssl/core_names.h>
#define DECLARE_PKEY_PARAM_BIGNUM(name) BIGNUM *name = NULL
#define FREE_PKEY_PARAM_BIGNUM(name) BN_clear_free(name)
#else
#define DECLARE_PKEY_PARAM_BIGNUM(name) const BIGNUM *name
#define FREE_PKEY_PARAM_BIGNUM(name)
#endif

/*
 * Whether SSL_CTX_set_keylog_callback is available.
 * OpenSSL: supported since 1.1.1 https://github.com/openssl/openssl/pull/2287
 * BoringSSL: supported since d28f59c27bac (committed 2015-11-19)
 * LibreSSL: not supported. 3.5.0+ has a stub function that does nothing.
 */
#if (OPENSSL_VERSION_NUMBER >= 0x10101000L && \
     !defined(LIBRESSL_VERSION_NUMBER)) || \
    defined(OPENSSL_IS_BORINGSSL)
#define HAVE_KEYLOG_CALLBACK
#endif

/* Whether SSL_CTX_set_ciphersuites is available.
 * OpenSSL: supported since 1.1.1 (commit a53b5be6a05)
 * BoringSSL: no
 * LibreSSL: supported since 3.4.1 (released 2021-10-14)
 */
#if ((OPENSSL_VERSION_NUMBER >= 0x10101000L && \
      !defined(LIBRESSL_VERSION_NUMBER)) || \
     (defined(LIBRESSL_VERSION_NUMBER) && \
      LIBRESSL_VERSION_NUMBER >= 0x3040100fL)) && \
    !defined(OPENSSL_IS_BORINGSSL)
  #define HAVE_SSL_CTX_SET_CIPHERSUITES
  #if !defined(OPENSSL_IS_AWSLC)
    #define HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH
  #endif
#endif

/*
 * Whether SSL_CTX_set1_curves_list is available.
 * OpenSSL: supported since 1.0.2, see
 *   https://docs.openssl.org/master/man3/SSL_CTX_set1_curves/
 * BoringSSL: supported since 5fd1807d95f7 (committed 2016-09-30)
 * LibreSSL: since 2.5.3 (April 12, 2017)
 */
#if (OPENSSL_VERSION_NUMBER >= 0x10002000L) ||  \
  defined(OPENSSL_IS_BORINGSSL)
#define HAVE_SSL_CTX_SET_EC_CURVES
#endif

#if defined(LIBRESSL_VERSION_NUMBER)
#define OSSL_PACKAGE "LibreSSL"
#elif defined(OPENSSL_IS_BORINGSSL)
#define OSSL_PACKAGE "BoringSSL"
#elif defined(OPENSSL_IS_AWSLC)
#define OSSL_PACKAGE "AWS-LC"
#else
# if defined(USE_NGTCP2) && defined(USE_NGHTTP3)
#   define OSSL_PACKAGE "quictls"
# else
#   define OSSL_PACKAGE "OpenSSL"
#endif
#endif

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
typedef size_t numcert_t;
#else
typedef int numcert_t;
#endif
#define ossl_valsize_t numcert_t

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
/* up2date versions of OpenSSL maintain reasonably secure defaults without
 * breaking compatibility, so it is better not to override the defaults in curl
 */
#define DEFAULT_CIPHER_SELECTION NULL
#else
/* not the case with old versions of OpenSSL */
#define DEFAULT_CIPHER_SELECTION \
  "ALL:!EXPORT:!EXPORT40:!EXPORT56:!aNULL:!LOW:!RC4:@STRENGTH"
#endif

#ifdef HAVE_OPENSSL_SRP
/* the function exists */
#ifdef USE_TLS_SRP
/* the functionality is not disabled */
#define USE_OPENSSL_SRP
#endif
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define HAVE_RANDOM_INIT_BY_DEFAULT 1
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && \
    !(defined(LIBRESSL_VERSION_NUMBER) && \
      LIBRESSL_VERSION_NUMBER < 0x2070100fL) && \
    !defined(OPENSSL_IS_BORINGSSL) && \
    !defined(OPENSSL_IS_AWSLC)
#define HAVE_OPENSSL_VERSION
#endif

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
typedef uint32_t sslerr_t;
#else
typedef unsigned long sslerr_t;
#endif

/*
 * Whether the OpenSSL version has the API needed to support sharing an
 * X509_STORE between connections. The API is:
 * * `X509_STORE_up_ref`       -- Introduced: OpenSSL 1.1.0.
 */
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) /* OpenSSL >= 1.1.0 */
#define HAVE_SSL_X509_STORE_SHARE
#endif

/* What API version do we use? */
#if defined(LIBRESSL_VERSION_NUMBER)
#define USE_PRE_1_1_API (LIBRESSL_VERSION_NUMBER < 0x2070000f)
#else /* !LIBRESSL_VERSION_NUMBER */
#define USE_PRE_1_1_API (OPENSSL_VERSION_NUMBER < 0x10100000L)
#endif /* !LIBRESSL_VERSION_NUMBER */

#define push_certinfo(_label, _num)             \
do {                              \
  long info_len = BIO_get_mem_data(mem, &ptr); \
  Curl_ssl_push_certinfo_len(data, _num, _label, ptr, info_len); \
  if(1 != BIO_reset(mem))                                        \
    break;                                                       \
} while(0)

static void pubkey_show(struct Curl_easy *data,
                        BIO *mem,
                        int num,
                        const char *type,
                        const char *name,
                        const BIGNUM *bn)
{
  char *ptr;
  char namebuf[32];

  msnprintf(namebuf, sizeof(namebuf), "%s(%s)", type, name);

  if(bn)
    BN_print(mem, bn);
  push_certinfo(namebuf, num);
}

#ifdef HAVE_OPAQUE_RSA_DSA_DH
#define print_pubkey_BN(_type, _name, _num)              \
  pubkey_show(data, mem, _num, #_type, #_name, _name)

#else
#define print_pubkey_BN(_type, _name, _num)    \
do {                              \
  if(_type->_name) { \
    pubkey_show(data, mem, _num, #_type, #_name, _type->_name); \
  } \
} while(0)
#endif

static int asn1_object_dump(ASN1_OBJECT *a, char *buf, size_t len)
{
  int i, ilen;

  ilen = (int)len;
  if(ilen < 0)
    return 1; /* buffer too big */

  i = i2t_ASN1_OBJECT(buf, ilen, a);

  if(i >= ilen)
    return 1; /* buffer too small */

  return 0;
}

static void X509V3_ext(struct Curl_easy *data,
                       int certnum,
                       CONST_EXTS STACK_OF(X509_EXTENSION) *exts)
{
  int i;

  if((int)sk_X509_EXTENSION_num(exts) <= 0)
    /* no extensions, bail out */
    return;

  for(i = 0; i < (int)sk_X509_EXTENSION_num(exts); i++) {
    ASN1_OBJECT *obj;
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, (ossl_valsize_t)i);
    BUF_MEM *biomem;
    char namebuf[128];
    BIO *bio_out = BIO_new(BIO_s_mem());

    if(!bio_out)
      return;

    obj = X509_EXTENSION_get_object(ext);

    asn1_object_dump(obj, namebuf, sizeof(namebuf));

    if(!X509V3_EXT_print(bio_out, ext, 0, 0))
      ASN1_STRING_print(bio_out, (ASN1_STRING *)X509_EXTENSION_get_data(ext));

    BIO_get_mem_ptr(bio_out, &biomem);
    Curl_ssl_push_certinfo_len(data, certnum, namebuf, biomem->data,
                               biomem->length);
    BIO_free(bio_out);
  }
}

CURLcode Curl_ossl_certchain(struct Curl_easy *data, SSL *ssl)
{
  CURLcode result;
  STACK_OF(X509) *sk;
  int i;
  numcert_t numcerts;
  BIO *mem;

  DEBUGASSERT(ssl);

  sk = SSL_get_peer_cert_chain(ssl);
  if(!sk) {
    return CURLE_OUT_OF_MEMORY;
  }

  numcerts = sk_X509_num(sk);

  result = Curl_ssl_init_certinfo(data, (int)numcerts);
  if(result) {
    return result;
  }

  mem = BIO_new(BIO_s_mem());
  if(!mem) {
    return CURLE_OUT_OF_MEMORY;
  }

  for(i = 0; i < (int)numcerts; i++) {
    ASN1_INTEGER *num;
    X509 *x = sk_X509_value(sk, (ossl_valsize_t)i);
    EVP_PKEY *pubkey = NULL;
    int j;
    char *ptr;
    const ASN1_BIT_STRING *psig = NULL;

    X509_NAME_print_ex(mem, X509_get_subject_name(x), 0, XN_FLAG_ONELINE);
    push_certinfo("Subject", i);

    X509_NAME_print_ex(mem, X509_get_issuer_name(x), 0, XN_FLAG_ONELINE);
    push_certinfo("Issuer", i);

    BIO_printf(mem, "%lx", X509_get_version(x));
    push_certinfo("Version", i);

    num = X509_get_serialNumber(x);
    if(num->type == V_ASN1_NEG_INTEGER)
      BIO_puts(mem, "-");
    for(j = 0; j < num->length; j++)
      BIO_printf(mem, "%02x", num->data[j]);
    push_certinfo("Serial Number", i);

#if defined(HAVE_X509_GET0_SIGNATURE) && defined(HAVE_X509_GET0_EXTENSIONS)
    {
      const X509_ALGOR *sigalg = NULL;
      X509_PUBKEY *xpubkey = NULL;
      ASN1_OBJECT *pubkeyoid = NULL;

      X509_get0_signature(&psig, &sigalg, x);
      if(sigalg) {
        const ASN1_OBJECT *sigalgoid = NULL;
        X509_ALGOR_get0(&sigalgoid, NULL, NULL, sigalg);
        i2a_ASN1_OBJECT(mem, sigalgoid);
        push_certinfo("Signature Algorithm", i);
      }

      xpubkey = X509_get_X509_PUBKEY(x);
      if(xpubkey) {
        X509_PUBKEY_get0_param(&pubkeyoid, NULL, NULL, NULL, xpubkey);
        if(pubkeyoid) {
          i2a_ASN1_OBJECT(mem, pubkeyoid);
          push_certinfo("Public Key Algorithm", i);
        }
      }

      X509V3_ext(data, i, X509_get0_extensions(x));
    }
#else
    {
      /* before OpenSSL 1.0.2 */
      X509_CINF *cinf = x->cert_info;

      i2a_ASN1_OBJECT(mem, cinf->signature->algorithm);
      push_certinfo("Signature Algorithm", i);

      i2a_ASN1_OBJECT(mem, cinf->key->algor->algorithm);
      push_certinfo("Public Key Algorithm", i);

      X509V3_ext(data, i, cinf->extensions);

      psig = x->signature;
    }
#endif

    ASN1_TIME_print(mem, X509_get0_notBefore(x));
    push_certinfo("Start date", i);

    ASN1_TIME_print(mem, X509_get0_notAfter(x));
    push_certinfo("Expire date", i);

    pubkey = X509_get_pubkey(x);
    if(!pubkey)
      infof(data, "   Unable to load public key");
    else {
      int pktype;
#ifdef HAVE_OPAQUE_EVP_PKEY
      pktype = EVP_PKEY_id(pubkey);
#else
      pktype = pubkey->type;
#endif
      switch(pktype) {
      case EVP_PKEY_RSA:
      {
#ifndef HAVE_EVP_PKEY_GET_PARAMS
        RSA *rsa;
#ifdef HAVE_OPAQUE_EVP_PKEY
        rsa = EVP_PKEY_get0_RSA(pubkey);
#else
        rsa = pubkey->pkey.rsa;
#endif /* HAVE_OPAQUE_EVP_PKEY */
#endif /* !HAVE_EVP_PKEY_GET_PARAMS */

        {
#ifdef HAVE_OPAQUE_RSA_DSA_DH
          DECLARE_PKEY_PARAM_BIGNUM(n);
          DECLARE_PKEY_PARAM_BIGNUM(e);
#ifdef HAVE_EVP_PKEY_GET_PARAMS
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_N, &n);
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_RSA_E, &e);
#else
          RSA_get0_key(rsa, &n, &e, NULL);
#endif /* HAVE_EVP_PKEY_GET_PARAMS */
          BIO_printf(mem, "%d", n ? BN_num_bits(n) : 0);
#else
          BIO_printf(mem, "%d", rsa->n ? BN_num_bits(rsa->n) : 0);
#endif /* HAVE_OPAQUE_RSA_DSA_DH */
          push_certinfo("RSA Public Key", i);
          print_pubkey_BN(rsa, n, i);
          print_pubkey_BN(rsa, e, i);
          FREE_PKEY_PARAM_BIGNUM(n);
          FREE_PKEY_PARAM_BIGNUM(e);
        }

        break;
      }
      case EVP_PKEY_DSA:
      {
#ifndef OPENSSL_NO_DSA
#ifndef HAVE_EVP_PKEY_GET_PARAMS
        DSA *dsa;
#ifdef HAVE_OPAQUE_EVP_PKEY
        dsa = EVP_PKEY_get0_DSA(pubkey);
#else
        dsa = pubkey->pkey.dsa;
#endif /* HAVE_OPAQUE_EVP_PKEY */
#endif /* !HAVE_EVP_PKEY_GET_PARAMS */
        {
#ifdef HAVE_OPAQUE_RSA_DSA_DH
          DECLARE_PKEY_PARAM_BIGNUM(p);
          DECLARE_PKEY_PARAM_BIGNUM(q);
          DECLARE_PKEY_PARAM_BIGNUM(g);
          DECLARE_PKEY_PARAM_BIGNUM(pub_key);
#ifdef HAVE_EVP_PKEY_GET_PARAMS
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_FFC_P, &p);
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_FFC_Q, &q);
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_FFC_G, &g);
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key);
#else
          DSA_get0_pqg(dsa, &p, &q, &g);
          DSA_get0_key(dsa, &pub_key, NULL);
#endif /* HAVE_EVP_PKEY_GET_PARAMS */
#endif /* HAVE_OPAQUE_RSA_DSA_DH */
          print_pubkey_BN(dsa, p, i);
          print_pubkey_BN(dsa, q, i);
          print_pubkey_BN(dsa, g, i);
          print_pubkey_BN(dsa, pub_key, i);
          FREE_PKEY_PARAM_BIGNUM(p);
          FREE_PKEY_PARAM_BIGNUM(q);
          FREE_PKEY_PARAM_BIGNUM(g);
          FREE_PKEY_PARAM_BIGNUM(pub_key);
        }
#endif /* !OPENSSL_NO_DSA */
        break;
      }
      case EVP_PKEY_DH:
      {
#ifndef HAVE_EVP_PKEY_GET_PARAMS
        DH *dh;
#ifdef HAVE_OPAQUE_EVP_PKEY
        dh = EVP_PKEY_get0_DH(pubkey);
#else
        dh = pubkey->pkey.dh;
#endif /* HAVE_OPAQUE_EVP_PKEY */
#endif /* !HAVE_EVP_PKEY_GET_PARAMS */
        {
#ifdef HAVE_OPAQUE_RSA_DSA_DH
          DECLARE_PKEY_PARAM_BIGNUM(p);
          DECLARE_PKEY_PARAM_BIGNUM(q);
          DECLARE_PKEY_PARAM_BIGNUM(g);
          DECLARE_PKEY_PARAM_BIGNUM(pub_key);
#ifdef HAVE_EVP_PKEY_GET_PARAMS
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_FFC_P, &p);
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_FFC_Q, &q);
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_FFC_G, &g);
          EVP_PKEY_get_bn_param(pubkey, OSSL_PKEY_PARAM_PUB_KEY, &pub_key);
#else
          DH_get0_pqg(dh, &p, &q, &g);
          DH_get0_key(dh, &pub_key, NULL);
#endif /* HAVE_EVP_PKEY_GET_PARAMS */
          print_pubkey_BN(dh, p, i);
          print_pubkey_BN(dh, q, i);
          print_pubkey_BN(dh, g, i);
#else
          print_pubkey_BN(dh, p, i);
          print_pubkey_BN(dh, g, i);
#endif /* HAVE_OPAQUE_RSA_DSA_DH */
          print_pubkey_BN(dh, pub_key, i);
          FREE_PKEY_PARAM_BIGNUM(p);
          FREE_PKEY_PARAM_BIGNUM(q);
          FREE_PKEY_PARAM_BIGNUM(g);
          FREE_PKEY_PARAM_BIGNUM(pub_key);
        }
        break;
      }
      }
      EVP_PKEY_free(pubkey);
    }

    if(psig) {
      for(j = 0; j < psig->length; j++)
        BIO_printf(mem, "%02x:", psig->data[j]);
      push_certinfo("Signature", i);
    }

    PEM_write_bio_X509(mem, x);
    push_certinfo("Cert", i);
  }

  BIO_free(mem);

  return CURLE_OK;
}

#endif /* quiche or OpenSSL */

#ifdef USE_OPENSSL

#if USE_PRE_1_1_API
#if !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2070000fL
#define BIO_set_init(x,v)          ((x)->init=(v))
#define BIO_get_data(x)            ((x)->ptr)
#define BIO_set_data(x,v)          ((x)->ptr=(v))
#endif
#define BIO_get_shutdown(x)        ((x)->shutdown)
#define BIO_set_shutdown(x,v)      ((x)->shutdown=(v))
#endif /* USE_PRE_1_1_API */

static int ossl_bio_cf_create(BIO *bio)
{
  BIO_set_shutdown(bio, 1);
  BIO_set_init(bio, 1);
#if USE_PRE_1_1_API
  bio->num = -1;
#endif
  BIO_set_data(bio, NULL);
  return 1;
}

static int ossl_bio_cf_destroy(BIO *bio)
{
  if(!bio)
    return 0;
  return 1;
}

static long ossl_bio_cf_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
  struct Curl_cfilter *cf = BIO_get_data(bio);
  long ret = 1;

  (void)cf;
  (void)ptr;
  switch(cmd) {
  case BIO_CTRL_GET_CLOSE:
    ret = (long)BIO_get_shutdown(bio);
    break;
  case BIO_CTRL_SET_CLOSE:
    BIO_set_shutdown(bio, (int)num);
    break;
  case BIO_CTRL_FLUSH:
    /* we do no delayed writes, but if we ever would, this
     * needs to trigger it. */
    ret = 1;
    break;
  case BIO_CTRL_DUP:
    ret = 1;
    break;
#ifdef BIO_CTRL_EOF
  case BIO_CTRL_EOF:
    /* EOF has been reached on input? */
    return (!cf->next || !cf->next->connected);
#endif
  default:
    ret = 0;
    break;
  }
  return ret;
}

static int ossl_bio_cf_out_write(BIO *bio, const char *buf, int blen)
{
  struct Curl_cfilter *cf = BIO_get_data(bio);
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nwritten;
  CURLcode result = CURLE_SEND_ERROR;

  DEBUGASSERT(data);
  if(blen < 0)
    return 0;

  nwritten = Curl_conn_cf_send(cf->next, data, buf, (size_t)blen, &result);
  CURL_TRC_CF(data, cf, "ossl_bio_cf_out_write(len=%d) -> %d, err=%d",
              blen, (int)nwritten, result);
  BIO_clear_retry_flags(bio);
  octx->io_result = result;
  if(nwritten < 0) {
    if(CURLE_AGAIN == result)
      BIO_set_retry_write(bio);
  }
  return (int)nwritten;
}

static int ossl_bio_cf_in_read(BIO *bio, char *buf, int blen)
{
  struct Curl_cfilter *cf = BIO_get_data(bio);
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nread;
  CURLcode result = CURLE_RECV_ERROR;

  DEBUGASSERT(data);
  /* OpenSSL catches this case, so should we. */
  if(!buf)
    return 0;
  if(blen < 0)
    return 0;

  nread = Curl_conn_cf_recv(cf->next, data, buf, (size_t)blen, &result);
  CURL_TRC_CF(data, cf, "ossl_bio_cf_in_read(len=%d) -> %d, err=%d",
              blen, (int)nread, result);
  BIO_clear_retry_flags(bio);
  octx->io_result = result;
  if(nread < 0) {
    if(CURLE_AGAIN == result)
      BIO_set_retry_read(bio);
  }
  else if(nread == 0) {
    connssl->peer_closed = TRUE;
  }

  /* Before returning server replies to the SSL instance, we need
   * to have setup the x509 store or verification will fail. */
  if(!octx->x509_store_setup) {
    result = Curl_ssl_setup_x509_store(cf, data, octx->ssl_ctx);
    if(result) {
      octx->io_result = result;
      return -1;
    }
    octx->x509_store_setup = TRUE;
  }

  return (int)nread;
}

#if USE_PRE_1_1_API

static BIO_METHOD ossl_bio_cf_meth_1_0 = {
  BIO_TYPE_MEM,
  "OpenSSL CF BIO",
  ossl_bio_cf_out_write,
  ossl_bio_cf_in_read,
  NULL,                    /* puts is never called */
  NULL,                    /* gets is never called */
  ossl_bio_cf_ctrl,
  ossl_bio_cf_create,
  ossl_bio_cf_destroy,
  NULL
};

static BIO_METHOD *ossl_bio_cf_method_create(void)
{
  return &ossl_bio_cf_meth_1_0;
}

#define ossl_bio_cf_method_free(m) Curl_nop_stmt

#else

static BIO_METHOD *ossl_bio_cf_method_create(void)
{
  BIO_METHOD *m = BIO_meth_new(BIO_TYPE_MEM, "OpenSSL CF BIO");
  if(m) {
    BIO_meth_set_write(m, &ossl_bio_cf_out_write);
    BIO_meth_set_read(m, &ossl_bio_cf_in_read);
    BIO_meth_set_ctrl(m, &ossl_bio_cf_ctrl);
    BIO_meth_set_create(m, &ossl_bio_cf_create);
    BIO_meth_set_destroy(m, &ossl_bio_cf_destroy);
  }
  return m;
}

static void ossl_bio_cf_method_free(BIO_METHOD *m)
{
  if(m)
    BIO_meth_free(m);
}

#endif


/*
 * Number of bytes to read from the random number seed file. This must be
 * a finite value (because some entropy "files" like /dev/urandom have
 * an infinite length), but must be large enough to provide enough
 * entropy to properly seed OpenSSL's PRNG.
 */
#define RAND_LOAD_LENGTH 1024

#ifdef HAVE_KEYLOG_CALLBACK
static void ossl_keylog_callback(const SSL *ssl, const char *line)
{
  (void)ssl;

  Curl_tls_keylog_write_line(line);
}
#else
/*
 * ossl_log_tls12_secret is called by libcurl to make the CLIENT_RANDOMs if the
 * OpenSSL being used does not have native support for doing that.
 */
static void
ossl_log_tls12_secret(const SSL *ssl, bool *keylog_done)
{
  const SSL_SESSION *session = SSL_get_session(ssl);
  unsigned char client_random[SSL3_RANDOM_SIZE];
  unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
  int master_key_length = 0;

  if(!session || *keylog_done)
    return;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L &&    \
  !(defined(LIBRESSL_VERSION_NUMBER) &&         \
    LIBRESSL_VERSION_NUMBER < 0x20700000L)
  /* ssl->s3 is not checked in OpenSSL 1.1.0-pre6, but let's assume that
   * we have a valid SSL context if we have a non-NULL session. */
  SSL_get_client_random(ssl, client_random, SSL3_RANDOM_SIZE);
  master_key_length = (int)
    SSL_SESSION_get_master_key(session, master_key, SSL_MAX_MASTER_KEY_LENGTH);
#else
  if(ssl->s3 && session->master_key_length > 0) {
    master_key_length = session->master_key_length;
    memcpy(master_key, session->master_key, session->master_key_length);
    memcpy(client_random, ssl->s3->client_random, SSL3_RANDOM_SIZE);
  }
#endif

  /* The handshake has not progressed sufficiently yet, or this is a TLS 1.3
   * session (when curl was built with older OpenSSL headers and running with
   * newer OpenSSL runtime libraries). */
  if(master_key_length <= 0)
    return;

  *keylog_done = true;
  Curl_tls_keylog_write("CLIENT_RANDOM", client_random,
                        master_key, master_key_length);
}
#endif /* !HAVE_KEYLOG_CALLBACK */

static const char *SSL_ERROR_to_str(int err)
{
  switch(err) {
  case SSL_ERROR_NONE:
    return "SSL_ERROR_NONE";
  case SSL_ERROR_SSL:
    return "SSL_ERROR_SSL";
  case SSL_ERROR_WANT_READ:
    return "SSL_ERROR_WANT_READ";
  case SSL_ERROR_WANT_WRITE:
    return "SSL_ERROR_WANT_WRITE";
  case SSL_ERROR_WANT_X509_LOOKUP:
    return "SSL_ERROR_WANT_X509_LOOKUP";
  case SSL_ERROR_SYSCALL:
    return "SSL_ERROR_SYSCALL";
  case SSL_ERROR_ZERO_RETURN:
    return "SSL_ERROR_ZERO_RETURN";
  case SSL_ERROR_WANT_CONNECT:
    return "SSL_ERROR_WANT_CONNECT";
  case SSL_ERROR_WANT_ACCEPT:
    return "SSL_ERROR_WANT_ACCEPT";
#if defined(SSL_ERROR_WANT_ASYNC)
  case SSL_ERROR_WANT_ASYNC:
    return "SSL_ERROR_WANT_ASYNC";
#endif
#if defined(SSL_ERROR_WANT_ASYNC_JOB)
  case SSL_ERROR_WANT_ASYNC_JOB:
    return "SSL_ERROR_WANT_ASYNC_JOB";
#endif
#if defined(SSL_ERROR_WANT_EARLY)
  case SSL_ERROR_WANT_EARLY:
    return "SSL_ERROR_WANT_EARLY";
#endif
  default:
    return "SSL_ERROR unknown";
  }
}

static size_t ossl_version(char *buffer, size_t size);

/* Return error string for last OpenSSL error
 */
static char *ossl_strerror(unsigned long error, char *buf, size_t size)
{
  size_t len;
  DEBUGASSERT(size);
  *buf = '\0';

  len = ossl_version(buf, size);
  DEBUGASSERT(len < (size - 2));
  if(len < (size - 2)) {
    buf += len;
    size -= (len + 2);
    *buf++ = ':';
    *buf++ = ' ';
    *buf = '\0';
  }

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
  ERR_error_string_n((uint32_t)error, buf, size);
#else
  ERR_error_string_n(error, buf, size);
#endif

  if(!*buf) {
    const char *msg = error ? "Unknown error" : "No error";
    if(strlen(msg) < size)
      strcpy(buf, msg);
  }

  return buf;
}

static int passwd_callback(char *buf, int num, int encrypting,
                           void *global_passwd)
{
  DEBUGASSERT(0 == encrypting);

  if(!encrypting && num >= 0) {
    int klen = curlx_uztosi(strlen((char *)global_passwd));
    if(num > klen) {
      memcpy(buf, global_passwd, klen + 1);
      return klen;
    }
  }
  return 0;
}

/*
 * rand_enough() returns TRUE if we have seeded the random engine properly.
 */
static bool rand_enough(void)
{
  return (0 != RAND_status()) ? TRUE : FALSE;
}

static CURLcode ossl_seed(struct Curl_easy *data)
{
  /* This might get called before it has been added to a multi handle */
  if(data->multi && data->multi->ssl_seeded)
    return CURLE_OK;

  if(rand_enough()) {
    /* OpenSSL 1.1.0+ should return here */
    if(data->multi)
      data->multi->ssl_seeded = TRUE;
    return CURLE_OK;
  }
#ifdef HAVE_RANDOM_INIT_BY_DEFAULT
  /* with OpenSSL 1.1.0+, a failed RAND_status is a showstopper */
  failf(data, "Insufficient randomness");
  return CURLE_SSL_CONNECT_ERROR;
#else

#ifdef RANDOM_FILE
  RAND_load_file(RANDOM_FILE, RAND_LOAD_LENGTH);
  if(rand_enough())
    return CURLE_OK;
#endif

  /* fallback to a custom seeding of the PRNG using a hash based on a current
     time */
  do {
    unsigned char randb[64];
    size_t len = sizeof(randb);
    size_t i, i_max;
    for(i = 0, i_max = len / sizeof(struct curltime); i < i_max; ++i) {
      struct curltime tv = Curl_now();
      Curl_wait_ms(1);
      tv.tv_sec *= (time_t)i + 1;
      tv.tv_usec *= (int)i + 2;
      tv.tv_sec ^= ((Curl_now().tv_sec + (time_t)Curl_now().tv_usec) *
                    (time_t)(i + 3)) << 8;
      tv.tv_usec ^= (int) ((Curl_now().tv_sec + (time_t)Curl_now().tv_usec) *
                           (time_t)(i + 4)) << 16;
      memcpy(&randb[i * sizeof(struct curltime)], &tv,
             sizeof(struct curltime));
    }
    RAND_add(randb, (int)len, (double)len/2);
  } while(!rand_enough());

  {
    /* generates a default path for the random seed file */
    char fname[256];
    fname[0] = 0; /* blank it first */
    RAND_file_name(fname, sizeof(fname));
    if(fname[0]) {
      /* we got a filename to try */
      RAND_load_file(fname, RAND_LOAD_LENGTH);
      if(rand_enough())
        return CURLE_OK;
    }
  }

  infof(data, "libcurl is now using a weak random seed");
  return (rand_enough() ? CURLE_OK :
          CURLE_SSL_CONNECT_ERROR /* confusing error code */);
#endif
}

#ifndef SSL_FILETYPE_ENGINE
#define SSL_FILETYPE_ENGINE 42
#endif
#ifndef SSL_FILETYPE_PKCS12
#define SSL_FILETYPE_PKCS12 43
#endif
static int do_file_type(const char *type)
{
  if(!type || !type[0])
    return SSL_FILETYPE_PEM;
  if(strcasecompare(type, "PEM"))
    return SSL_FILETYPE_PEM;
  if(strcasecompare(type, "DER"))
    return SSL_FILETYPE_ASN1;
  if(strcasecompare(type, "ENG"))
    return SSL_FILETYPE_ENGINE;
  if(strcasecompare(type, "P12"))
    return SSL_FILETYPE_PKCS12;
  return -1;
}

#ifdef USE_OPENSSL_ENGINE
/*
 * Supply default password to the engine user interface conversation.
 * The password is passed by OpenSSL engine from ENGINE_load_private_key()
 * last argument to the ui and can be obtained by UI_get0_user_data(ui) here.
 */
static int ssl_ui_reader(UI *ui, UI_STRING *uis)
{
  const char *password;
  switch(UI_get_string_type(uis)) {
  case UIT_PROMPT:
  case UIT_VERIFY:
    password = (const char *)UI_get0_user_data(ui);
    if(password && (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD)) {
      UI_set_result(ui, uis, password);
      return 1;
    }
    FALLTHROUGH();
  default:
    break;
  }
  return (UI_method_get_reader(UI_OpenSSL()))(ui, uis);
}

/*
 * Suppress interactive request for a default password if available.
 */
static int ssl_ui_writer(UI *ui, UI_STRING *uis)
{
  switch(UI_get_string_type(uis)) {
  case UIT_PROMPT:
  case UIT_VERIFY:
    if(UI_get0_user_data(ui) &&
       (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD)) {
      return 1;
    }
    FALLTHROUGH();
  default:
    break;
  }
  return (UI_method_get_writer(UI_OpenSSL()))(ui, uis);
}

/*
 * Check if a given string is a PKCS#11 URI
 */
static bool is_pkcs11_uri(const char *string)
{
  return (string && strncasecompare(string, "pkcs11:", 7));
}

#endif

static CURLcode ossl_set_engine(struct Curl_easy *data, const char *engine);

static int
SSL_CTX_use_certificate_blob(SSL_CTX *ctx, const struct curl_blob *blob,
                             int type, const char *key_passwd)
{
  int ret = 0;
  X509 *x = NULL;
  /* the typecast of blob->len is fine since it is guaranteed to never be
     larger than CURL_MAX_INPUT_LENGTH */
  BIO *in = BIO_new_mem_buf(blob->data, (int)(blob->len));
  if(!in)
    return CURLE_OUT_OF_MEMORY;

  if(type == SSL_FILETYPE_ASN1) {
    /* j = ERR_R_ASN1_LIB; */
    x = d2i_X509_bio(in, NULL);
  }
  else if(type == SSL_FILETYPE_PEM) {
    /* ERR_R_PEM_LIB; */
    x = PEM_read_bio_X509(in, NULL,
                          passwd_callback, (void *)key_passwd);
  }
  else {
    ret = 0;
    goto end;
  }

  if(!x) {
    ret = 0;
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx, x);
end:
  X509_free(x);
  BIO_free(in);
  return ret;
}

static int
SSL_CTX_use_PrivateKey_blob(SSL_CTX *ctx, const struct curl_blob *blob,
                            int type, const char *key_passwd)
{
  int ret = 0;
  EVP_PKEY *pkey = NULL;
  BIO *in = BIO_new_mem_buf(blob->data, (int)(blob->len));
  if(!in)
    return CURLE_OUT_OF_MEMORY;

  if(type == SSL_FILETYPE_PEM)
    pkey = PEM_read_bio_PrivateKey(in, NULL, passwd_callback,
                                   (void *)key_passwd);
  else if(type == SSL_FILETYPE_ASN1)
    pkey = d2i_PrivateKey_bio(in, NULL);
  else {
    ret = 0;
    goto end;
  }
  if(!pkey) {
    ret = 0;
    goto end;
  }
  ret = SSL_CTX_use_PrivateKey(ctx, pkey);
  EVP_PKEY_free(pkey);
end:
  BIO_free(in);
  return ret;
}

static int
SSL_CTX_use_certificate_chain_blob(SSL_CTX *ctx, const struct curl_blob *blob,
                                   const char *key_passwd)
{
/* SSL_CTX_add1_chain_cert introduced in OpenSSL 1.0.2 */
#if (OPENSSL_VERSION_NUMBER >= 0x1000200fL) && /* OpenSSL 1.0.2 or later */ \
  !(defined(LIBRESSL_VERSION_NUMBER) &&                                     \
    (LIBRESSL_VERSION_NUMBER < 0x2090100fL)) /* LibreSSL 2.9.1 or later */
  int ret = 0;
  X509 *x = NULL;
  void *passwd_callback_userdata = (void *)key_passwd;
  BIO *in = BIO_new_mem_buf(blob->data, (int)(blob->len));
  if(!in)
    return CURLE_OUT_OF_MEMORY;

  ERR_clear_error();

  x = PEM_read_bio_X509_AUX(in, NULL,
                            passwd_callback, (void *)key_passwd);

  if(!x) {
    ret = 0;
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx, x);

  if(ERR_peek_error() != 0)
    ret = 0;

  if(ret) {
    X509 *ca;
    sslerr_t err;

    if(!SSL_CTX_clear_chain_certs(ctx)) {
      ret = 0;
      goto end;
    }

    while((ca = PEM_read_bio_X509(in, NULL, passwd_callback,
                                  passwd_callback_userdata))
          != NULL) {

      if(!SSL_CTX_add0_chain_cert(ctx, ca)) {
        X509_free(ca);
        ret = 0;
        goto end;
      }
    }

    err = ERR_peek_last_error();
    if((ERR_GET_LIB(err) == ERR_LIB_PEM) &&
       (ERR_GET_REASON(err) == PEM_R_NO_START_LINE))
      ERR_clear_error();
    else
      ret = 0;
  }

end:
  X509_free(x);
  BIO_free(in);
  return ret;
#else
  (void)ctx; /* unused */
  (void)blob; /* unused */
  (void)key_passwd; /* unused */
  return 0;
#endif
}

static
int cert_stuff(struct Curl_easy *data,
               SSL_CTX* ctx,
               char *cert_file,
               const struct curl_blob *cert_blob,
               const char *cert_type,
               char *key_file,
               const struct curl_blob *key_blob,
               const char *key_type,
               char *key_passwd)
{
  char error_buffer[256];
  bool check_privkey = TRUE;

  int file_type = do_file_type(cert_type);

  if(cert_file || cert_blob || (file_type == SSL_FILETYPE_ENGINE)) {
    SSL *ssl;
    X509 *x509;
    int cert_done = 0;
    int cert_use_result;

    if(key_passwd) {
      /* set the password in the callback userdata */
      SSL_CTX_set_default_passwd_cb_userdata(ctx, key_passwd);
      /* Set passwd callback: */
      SSL_CTX_set_default_passwd_cb(ctx, passwd_callback);
    }


    switch(file_type) {
    case SSL_FILETYPE_PEM:
      /* SSL_CTX_use_certificate_chain_file() only works on PEM files */
      cert_use_result = cert_blob ?
        SSL_CTX_use_certificate_chain_blob(ctx, cert_blob, key_passwd) :
        SSL_CTX_use_certificate_chain_file(ctx, cert_file);
      if(cert_use_result != 1) {
        failf(data,
              "could not load PEM client certificate from %s, " OSSL_PACKAGE
              " error %s, "
              "(no key found, wrong pass phrase, or wrong file format?)",
              (cert_blob ? "CURLOPT_SSLCERT_BLOB" : cert_file),
              ossl_strerror(ERR_get_error(), error_buffer,
                            sizeof(error_buffer)) );
        return 0;
      }
      break;

    case SSL_FILETYPE_ASN1:
      /* SSL_CTX_use_certificate_file() works with either PEM or ASN1, but
         we use the case above for PEM so this can only be performed with
         ASN1 files. */

      cert_use_result = cert_blob ?
        SSL_CTX_use_certificate_blob(ctx, cert_blob,
                                     file_type, key_passwd) :
      SSL_CTX_use_certificate_file(ctx, cert_file, file_type);
      if(cert_use_result != 1) {
        failf(data,
              "could not load ASN1 client certificate from %s, " OSSL_PACKAGE
              " error %s, "
              "(no key found, wrong pass phrase, or wrong file format?)",
              (cert_blob ? "CURLOPT_SSLCERT_BLOB" : cert_file),
              ossl_strerror(ERR_get_error(), error_buffer,
                            sizeof(error_buffer)) );
        return 0;
      }
      break;
    case SSL_FILETYPE_ENGINE:
#if defined(USE_OPENSSL_ENGINE) && defined(ENGINE_CTRL_GET_CMD_FROM_NAME)
    {
      /* Implicitly use pkcs11 engine if none was provided and the
       * cert_file is a PKCS#11 URI */
      if(!data->state.engine) {
        if(is_pkcs11_uri(cert_file)) {
          if(ossl_set_engine(data, "pkcs11") != CURLE_OK) {
            return 0;
          }
        }
      }

      if(data->state.engine) {
        const char *cmd_name = "LOAD_CERT_CTRL";
        struct {
          const char *cert_id;
          X509 *cert;
        } params;

        params.cert_id = cert_file;
        params.cert = NULL;

        /* Does the engine supports LOAD_CERT_CTRL ? */
        if(!ENGINE_ctrl(data->state.engine, ENGINE_CTRL_GET_CMD_FROM_NAME,
                        0, (void *)cmd_name, NULL)) {
          failf(data, "ssl engine does not support loading certificates");
          return 0;
        }

        /* Load the certificate from the engine */
        if(!ENGINE_ctrl_cmd(data->state.engine, cmd_name,
                            0, &params, NULL, 1)) {
          failf(data, "ssl engine cannot load client cert with id"
                " '%s' [%s]", cert_file,
                ossl_strerror(ERR_get_error(), error_buffer,
                              sizeof(error_buffer)));
          return 0;
        }

        if(!params.cert) {
          failf(data, "ssl engine did not initialized the certificate "
                "properly.");
          return 0;
        }

        if(SSL_CTX_use_certificate(ctx, params.cert) != 1) {
          failf(data, "unable to set client certificate [%s]",
                ossl_strerror(ERR_get_error(), error_buffer,
                              sizeof(error_buffer)));
          return 0;
        }
        X509_free(params.cert); /* we do not need the handle any more... */
      }
      else {
        failf(data, "crypto engine not set, cannot load certificate");
        return 0;
      }
    }
    break;
#else
    failf(data, "file type ENG for certificate not implemented");
    return 0;
#endif

    case SSL_FILETYPE_PKCS12:
    {
      BIO *cert_bio = NULL;
      PKCS12 *p12 = NULL;
      EVP_PKEY *pri;
      STACK_OF(X509) *ca = NULL;
      if(cert_blob) {
        cert_bio = BIO_new_mem_buf(cert_blob->data, (int)(cert_blob->len));
        if(!cert_bio) {
          failf(data,
                "BIO_new_mem_buf NULL, " OSSL_PACKAGE
                " error %s",
                ossl_strerror(ERR_get_error(), error_buffer,
                              sizeof(error_buffer)) );
          return 0;
        }
      }
      else {
        cert_bio = BIO_new(BIO_s_file());
        if(!cert_bio) {
          failf(data,
                "BIO_new return NULL, " OSSL_PACKAGE
                " error %s",
                ossl_strerror(ERR_get_error(), error_buffer,
                              sizeof(error_buffer)) );
          return 0;
        }

        if(BIO_read_filename(cert_bio, cert_file) <= 0) {
          failf(data, "could not open PKCS12 file '%s'", cert_file);
          BIO_free(cert_bio);
          return 0;
        }
      }

      p12 = d2i_PKCS12_bio(cert_bio, NULL);
      BIO_free(cert_bio);

      if(!p12) {
        failf(data, "error reading PKCS12 file '%s'",
              cert_blob ? "(memory blob)" : cert_file);
        return 0;
      }

      PKCS12_PBE_add();

      if(!PKCS12_parse(p12, key_passwd, &pri, &x509,
                       &ca)) {
        failf(data,
              "could not parse PKCS12 file, check password, " OSSL_PACKAGE
              " error %s",
              ossl_strerror(ERR_get_error(), error_buffer,
                            sizeof(error_buffer)) );
        PKCS12_free(p12);
        return 0;
      }

      PKCS12_free(p12);

      if(SSL_CTX_use_certificate(ctx, x509) != 1) {
        failf(data,
              "could not load PKCS12 client certificate, " OSSL_PACKAGE
              " error %s",
              ossl_strerror(ERR_get_error(), error_buffer,
                            sizeof(error_buffer)) );
        goto fail;
      }

      if(SSL_CTX_use_PrivateKey(ctx, pri) != 1) {
        failf(data, "unable to use private key from PKCS12 file '%s'",
              cert_file);
        goto fail;
      }

      if(!SSL_CTX_check_private_key (ctx)) {
        failf(data, "private key from PKCS12 file '%s' "
              "does not match certificate in same file", cert_file);
        goto fail;
      }
      /* Set Certificate Verification chain */
      if(ca) {
        while(sk_X509_num(ca)) {
          /*
           * Note that sk_X509_pop() is used below to make sure the cert is
           * removed from the stack properly before getting passed to
           * SSL_CTX_add_extra_chain_cert(), which takes ownership. Previously
           * we used sk_X509_value() instead, but then we would clean it in the
           * subsequent sk_X509_pop_free() call.
           */
          X509 *x = sk_X509_pop(ca);
          if(!SSL_CTX_add_client_CA(ctx, x)) {
            X509_free(x);
            failf(data, "cannot add certificate to client CA list");
            goto fail;
          }
          if(!SSL_CTX_add_extra_chain_cert(ctx, x)) {
            X509_free(x);
            failf(data, "cannot add certificate to certificate chain");
            goto fail;
          }
        }
      }

      cert_done = 1;
fail:
      EVP_PKEY_free(pri);
      X509_free(x509);
      sk_X509_pop_free(ca, X509_free);
      if(!cert_done)
        return 0; /* failure! */
      break;
    }
    default:
      failf(data, "not supported file type '%s' for certificate", cert_type);
      return 0;
    }

    if((!key_file) && (!key_blob)) {
      key_file = cert_file;
      key_blob = cert_blob;
    }
    else
      file_type = do_file_type(key_type);

    switch(file_type) {
    case SSL_FILETYPE_PEM:
      if(cert_done)
        break;
      FALLTHROUGH();
    case SSL_FILETYPE_ASN1:
      cert_use_result = key_blob ?
        SSL_CTX_use_PrivateKey_blob(ctx, key_blob, file_type, key_passwd) :
      SSL_CTX_use_PrivateKey_file(ctx, key_file, file_type);
      if(cert_use_result != 1) {
        failf(data, "unable to set private key file: '%s' type %s",
              key_file?key_file:"(memory blob)", key_type?key_type:"PEM");
        return 0;
      }
      break;
    case SSL_FILETYPE_ENGINE:
#ifdef USE_OPENSSL_ENGINE
    {
      EVP_PKEY *priv_key = NULL;

      /* Implicitly use pkcs11 engine if none was provided and the
       * key_file is a PKCS#11 URI */
      if(!data->state.engine) {
        if(is_pkcs11_uri(key_file)) {
          if(ossl_set_engine(data, "pkcs11") != CURLE_OK) {
            return 0;
          }
        }
      }

      if(data->state.engine) {
        UI_METHOD *ui_method =
          UI_create_method((char *)"curl user interface");
        if(!ui_method) {
          failf(data, "unable do create " OSSL_PACKAGE
                " user-interface method");
          return 0;
        }
        UI_method_set_opener(ui_method, UI_method_get_opener(UI_OpenSSL()));
        UI_method_set_closer(ui_method, UI_method_get_closer(UI_OpenSSL()));
        UI_method_set_reader(ui_method, ssl_ui_reader);
        UI_method_set_writer(ui_method, ssl_ui_writer);
        priv_key = ENGINE_load_private_key(data->state.engine, key_file,
                                           ui_method,
                                           key_passwd);
        UI_destroy_method(ui_method);
        if(!priv_key) {
          failf(data, "failed to load private key from crypto engine");
          return 0;
        }
        if(SSL_CTX_use_PrivateKey(ctx, priv_key) != 1) {
          failf(data, "unable to set private key");
          EVP_PKEY_free(priv_key);
          return 0;
        }
        EVP_PKEY_free(priv_key);  /* we do not need the handle any more... */
      }
      else {
        failf(data, "crypto engine not set, cannot load private key");
        return 0;
      }
    }
    break;
#else
    failf(data, "file type ENG for private key not supported");
    return 0;
#endif
    case SSL_FILETYPE_PKCS12:
      if(!cert_done) {
        failf(data, "file type P12 for private key not supported");
        return 0;
      }
      break;
    default:
      failf(data, "not supported file type for private key");
      return 0;
    }

    ssl = SSL_new(ctx);
    if(!ssl) {
      failf(data, "unable to create an SSL structure");
      return 0;
    }

    x509 = SSL_get_certificate(ssl);

    /* This version was provided by Evan Jordan and is supposed to not
       leak memory as the previous version: */
    if(x509) {
      EVP_PKEY *pktmp = X509_get_pubkey(x509);
      EVP_PKEY_copy_parameters(pktmp, SSL_get_privatekey(ssl));
      EVP_PKEY_free(pktmp);
    }

#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_IS_BORINGSSL) &&       \
  !defined(OPENSSL_NO_DEPRECATED_3_0)
    {
      /* If RSA is used, do not check the private key if its flags indicate
       * it does not support it. */
      EVP_PKEY *priv_key = SSL_get_privatekey(ssl);
      int pktype;
#ifdef HAVE_OPAQUE_EVP_PKEY
      pktype = EVP_PKEY_id(priv_key);
#else
      pktype = priv_key->type;
#endif
      if(pktype == EVP_PKEY_RSA) {
        RSA *rsa = EVP_PKEY_get1_RSA(priv_key);
        if(RSA_flags(rsa) & RSA_METHOD_FLAG_NO_CHECK)
          check_privkey = FALSE;
        RSA_free(rsa); /* Decrement reference count */
      }
    }
#endif

    SSL_free(ssl);

    /* If we are using DSA, we can copy the parameters from
     * the private key */

    if(check_privkey == TRUE) {
      /* Now we know that a key and cert have been set against
       * the SSL context */
      if(!SSL_CTX_check_private_key(ctx)) {
        failf(data, "Private key does not match the certificate public key");
        return 0;
      }
    }
  }
  return 1;
}

CURLcode Curl_ossl_set_client_cert(struct Curl_easy *data, SSL_CTX *ctx,
                                   char *cert_file,
                                   const struct curl_blob *cert_blob,
                                   const char *cert_type, char *key_file,
                                   const struct curl_blob *key_blob,
                                   const char *key_type, char *key_passwd)
{
  int rv = cert_stuff(data, ctx, cert_file, cert_blob, cert_type, key_file,
                      key_blob, key_type, key_passwd);
  if(rv != 1) {
    return CURLE_SSL_CERTPROBLEM;
  }

  return CURLE_OK;
}

/* returns non-zero on failure */
static int x509_name_oneline(X509_NAME *a, char *buf, size_t size)
{
  BIO *bio_out = BIO_new(BIO_s_mem());
  BUF_MEM *biomem;
  int rc;

  if(!bio_out)
    return 1; /* alloc failed! */

  rc = X509_NAME_print_ex(bio_out, a, 0, XN_FLAG_SEP_SPLUS_SPC);
  BIO_get_mem_ptr(bio_out, &biomem);

  if((size_t)biomem->length < size)
    size = biomem->length;
  else
    size--; /* do not overwrite the buffer end */

  memcpy(buf, biomem->data, size);
  buf[size] = 0;

  BIO_free(bio_out);

  return !rc;
}

/**
 * Global SSL init
 *
 * @retval 0 error initializing SSL
 * @retval 1 SSL initialized successfully
 */
static int ossl_init(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) &&  \
  (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER >= 0x2070000fL)
  const uint64_t flags =
#ifdef OPENSSL_INIT_ENGINE_ALL_BUILTIN
    /* not present in BoringSSL */
    OPENSSL_INIT_ENGINE_ALL_BUILTIN |
#endif
#ifdef CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG
    OPENSSL_INIT_NO_LOAD_CONFIG |
#else
    OPENSSL_INIT_LOAD_CONFIG |
#endif
    0;
  OPENSSL_init_ssl(flags, NULL);
#else
  OPENSSL_load_builtin_modules();

#ifdef USE_OPENSSL_ENGINE
  ENGINE_load_builtin_engines();
#endif

/* CONF_MFLAGS_DEFAULT_SECTION was introduced some time between 0.9.8b and
   0.9.8e */
#ifndef CONF_MFLAGS_DEFAULT_SECTION
#define CONF_MFLAGS_DEFAULT_SECTION 0x0
#endif

#ifndef CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG
  CONF_modules_load_file(NULL, NULL,
                         CONF_MFLAGS_DEFAULT_SECTION|
                         CONF_MFLAGS_IGNORE_MISSING_FILE);
#endif

  /* Let's get nice error messages */
  SSL_load_error_strings();

  /* Init the global ciphers and digests */
  if(!SSLeay_add_ssl_algorithms())
    return 0;

  OpenSSL_add_all_algorithms();
#endif

  Curl_tls_keylog_open();

  return 1;
}

/* Global cleanup */
static void ossl_cleanup(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) &&  \
  (!defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER >= 0x2070000fL)
  /* OpenSSL 1.1 deprecates all these cleanup functions and
     turns them into no-ops in OpenSSL 1.0 compatibility mode */
#else
  /* Free ciphers and digests lists */
  EVP_cleanup();

#ifdef USE_OPENSSL_ENGINE
  /* Free engine list */
  ENGINE_cleanup();
#endif

  /* Free OpenSSL error strings */
  ERR_free_strings();

  /* Free thread local error state, destroying hash upon zero refcount */
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
  ERR_remove_thread_state(NULL);
#else
  ERR_remove_state(0);
#endif

  /* Free all memory allocated by all configuration modules */
  CONF_modules_free();

#ifdef HAVE_SSL_COMP_FREE_COMPRESSION_METHODS
  SSL_COMP_free_compression_methods();
#endif
#endif

  Curl_tls_keylog_close();
}

/* Selects an OpenSSL crypto engine
 */
static CURLcode ossl_set_engine(struct Curl_easy *data, const char *engine)
{
#ifdef USE_OPENSSL_ENGINE
  ENGINE *e;

#if OPENSSL_VERSION_NUMBER >= 0x00909000L
  e = ENGINE_by_id(engine);
#else
  /* avoid memory leak */
  for(e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
    const char *e_id = ENGINE_get_id(e);
    if(!strcmp(engine, e_id))
      break;
  }
#endif

  if(!e) {
    failf(data, "SSL Engine '%s' not found", engine);
    return CURLE_SSL_ENGINE_NOTFOUND;
  }

  if(data->state.engine) {
    ENGINE_finish(data->state.engine);
    ENGINE_free(data->state.engine);
    data->state.engine = NULL;
  }
  if(!ENGINE_init(e)) {
    char buf[256];

    ENGINE_free(e);
    failf(data, "Failed to initialise SSL Engine '%s': %s",
          engine, ossl_strerror(ERR_get_error(), buf, sizeof(buf)));
    return CURLE_SSL_ENGINE_INITFAILED;
  }
  data->state.engine = e;
  return CURLE_OK;
#else
  (void)engine;
  failf(data, "SSL Engine not supported");
  return CURLE_SSL_ENGINE_NOTFOUND;
#endif
}

/* Sets engine as default for all SSL operations
 */
static CURLcode ossl_set_engine_default(struct Curl_easy *data)
{
#ifdef USE_OPENSSL_ENGINE
  if(data->state.engine) {
    if(ENGINE_set_default(data->state.engine, ENGINE_METHOD_ALL) > 0) {
      infof(data, "set default crypto engine '%s'",
            ENGINE_get_id(data->state.engine));
    }
    else {
      failf(data, "set default crypto engine '%s' failed",
            ENGINE_get_id(data->state.engine));
      return CURLE_SSL_ENGINE_SETFAILED;
    }
  }
#else
  (void) data;
#endif
  return CURLE_OK;
}

/* Return list of OpenSSL crypto engine names.
 */
static struct curl_slist *ossl_engines_list(struct Curl_easy *data)
{
  struct curl_slist *list = NULL;
#ifdef USE_OPENSSL_ENGINE
  struct curl_slist *beg;
  ENGINE *e;

  for(e = ENGINE_get_first(); e; e = ENGINE_get_next(e)) {
    beg = curl_slist_append(list, ENGINE_get_id(e));
    if(!beg) {
      curl_slist_free_all(list);
      return NULL;
    }
    list = beg;
  }
#endif
  (void) data;
  return list;
}

static CURLcode ossl_shutdown(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;
  CURLcode result = CURLE_OK;
  char buf[1024];
  int nread, err;
  unsigned long sslerr;
  size_t i;

  DEBUGASSERT(octx);
  if(!octx->ssl || cf->shutdown) {
    *done = TRUE;
    goto out;
  }

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  *done = FALSE;
  if(!(SSL_get_shutdown(octx->ssl) & SSL_SENT_SHUTDOWN)) {
    /* We have not started the shutdown from our side yet. Check
     * if the server already sent us one. */
    ERR_clear_error();
    for(i = 0; i < 10; ++i) {
      nread = SSL_read(octx->ssl, buf, (int)sizeof(buf));
      CURL_TRC_CF(data, cf, "SSL shutdown not sent, read -> %d", nread);
      if(nread <= 0)
        break;
    }
    err = SSL_get_error(octx->ssl, nread);
    if(!nread && err == SSL_ERROR_ZERO_RETURN) {
      bool input_pending;
      /* Yes, it did. */
      if(!send_shutdown) {
        CURL_TRC_CF(data, cf, "SSL shutdown received, not sending");
        *done = TRUE;
        goto out;
      }
      else if(!cf->next->cft->is_alive(cf->next, data, &input_pending)) {
        /* Server closed the connection after its closy notify. It
         * seems not interested to see our close notify, so do not
         * send it. We are done. */
        connssl->peer_closed = TRUE;
        CURL_TRC_CF(data, cf, "peer closed connection");
        *done = TRUE;
        goto out;
      }
    }
    if(send_shutdown && SSL_shutdown(octx->ssl) == 1) {
      CURL_TRC_CF(data, cf, "SSL shutdown finished");
      *done = TRUE;
      goto out;
    }
  }

  /* SSL should now have started the shutdown from our side. Since it
   * was not complete, we are lacking the close notify from the server. */
  for(i = 0; i < 10; ++i) {
    ERR_clear_error();
    nread = SSL_read(octx->ssl, buf, (int)sizeof(buf));
    CURL_TRC_CF(data, cf, "SSL shutdown read -> %d", nread);
    if(nread <= 0)
      break;
  }
  if(SSL_get_shutdown(octx->ssl) & SSL_RECEIVED_SHUTDOWN) {
    CURL_TRC_CF(data, cf, "SSL shutdown received, finished");
    *done = TRUE;
    goto out;
  }
  err = SSL_get_error(octx->ssl, nread);
  switch(err) {
  case SSL_ERROR_ZERO_RETURN: /* no more data */
    CURL_TRC_CF(data, cf, "SSL shutdown not received, but closed");
    *done = TRUE;
    break;
  case SSL_ERROR_NONE: /* just did not get anything */
  case SSL_ERROR_WANT_READ:
    /* SSL has send its notify and now wants to read the reply
     * from the server. We are not really interested in that. */
    CURL_TRC_CF(data, cf, "SSL shutdown sent, want receive");
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    break;
  case SSL_ERROR_WANT_WRITE:
    CURL_TRC_CF(data, cf, "SSL shutdown send blocked");
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
    break;
  default:
    /* Server seems to have closed the connection without sending us
     * a close notify. */
    sslerr = ERR_get_error();
    CURL_TRC_CF(data, cf, "SSL shutdown, ignore recv error: '%s', errno %d",
                (sslerr ?
                 ossl_strerror(sslerr, buf, sizeof(buf)) :
                 SSL_ERROR_to_str(err)),
                SOCKERRNO);
    *done = TRUE;
    result = CURLE_OK;
    break;
  }

out:
  cf->shutdown = (result || *done);
  return result;
}

static void ossl_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;

  (void)data;
  DEBUGASSERT(octx);

  if(octx->ssl) {
    SSL_free(octx->ssl);
    octx->ssl = NULL;
  }
  if(octx->ssl_ctx) {
    SSL_CTX_free(octx->ssl_ctx);
    octx->ssl_ctx = NULL;
    octx->x509_store_setup = FALSE;
  }
  if(octx->bio_method) {
    ossl_bio_cf_method_free(octx->bio_method);
    octx->bio_method = NULL;
  }
}

static void ossl_session_free(void *sessionid, size_t idsize)
{
  /* free the ID */
  (void)idsize;
  SSL_SESSION_free(sessionid);
}

/*
 * This function is called when the 'data' struct is going away. Close
 * down everything and free all resources!
 */
static void ossl_close_all(struct Curl_easy *data)
{
#ifdef USE_OPENSSL_ENGINE
  if(data->state.engine) {
    ENGINE_finish(data->state.engine);
    ENGINE_free(data->state.engine);
    data->state.engine = NULL;
  }
#else
  (void)data;
#endif
#if !defined(HAVE_ERR_REMOVE_THREAD_STATE_DEPRECATED) &&        \
  defined(HAVE_ERR_REMOVE_THREAD_STATE)
  /* OpenSSL 1.0.1 and 1.0.2 build an error queue that is stored per-thread
     so we need to clean it here in case the thread will be killed. All OpenSSL
     code should extract the error in association with the error so clearing
     this queue here should be harmless at worst. */
  ERR_remove_thread_state(NULL);
#endif
}

/* ====================================================== */

/*
 * Match subjectAltName against the hostname.
 */
static bool subj_alt_hostcheck(struct Curl_easy *data,
                               const char *match_pattern,
                               size_t matchlen,
                               const char *hostname,
                               size_t hostlen,
                               const char *dispname)
{
#ifdef CURL_DISABLE_VERBOSE_STRINGS
  (void)dispname;
  (void)data;
#endif
  if(Curl_cert_hostcheck(match_pattern, matchlen, hostname, hostlen)) {
    infof(data, " subjectAltName: host \"%s\" matched cert's \"%s\"",
          dispname, match_pattern);
    return TRUE;
  }
  return FALSE;
}

/* Quote from RFC2818 section 3.1 "Server Identity"

   If a subjectAltName extension of type dNSName is present, that MUST
   be used as the identity. Otherwise, the (most specific) Common Name
   field in the Subject field of the certificate MUST be used. Although
   the use of the Common Name is existing practice, it is deprecated and
   Certification Authorities are encouraged to use the dNSName instead.

   Matching is performed using the matching rules specified by
   [RFC2459]. If more than one identity of a given type is present in
   the certificate (e.g., more than one dNSName name, a match in any one
   of the set is considered acceptable.) Names may contain the wildcard
   character * which is considered to match any single domain name
   component or component fragment. E.g., *.a.com matches foo.a.com but
   not bar.foo.a.com. f*.com matches foo.com but not bar.com.

   In some cases, the URI is specified as an IP address rather than a
   hostname. In this case, the iPAddress subjectAltName must be present
   in the certificate and must exactly match the IP in the URI.

   This function is now used from ngtcp2 (QUIC) as well.
*/
CURLcode Curl_ossl_verifyhost(struct Curl_easy *data, struct connectdata *conn,
                              struct ssl_peer *peer, X509 *server_cert)
{
  bool matched = FALSE;
  int target; /* target type, GEN_DNS or GEN_IPADD */
  size_t addrlen = 0;
  STACK_OF(GENERAL_NAME) *altnames;
#ifdef USE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif
  CURLcode result = CURLE_OK;
  bool dNSName = FALSE; /* if a dNSName field exists in the cert */
  bool iPAddress = FALSE; /* if an iPAddress field exists in the cert */
  size_t hostlen;

  (void)conn;
  hostlen = strlen(peer->hostname);
  switch(peer->type) {
  case CURL_SSL_PEER_IPV4:
    if(!Curl_inet_pton(AF_INET, peer->hostname, &addr))
      return CURLE_PEER_FAILED_VERIFICATION;
    target = GEN_IPADD;
    addrlen = sizeof(struct in_addr);
    break;
#ifdef USE_IPV6
  case CURL_SSL_PEER_IPV6:
    if(!Curl_inet_pton(AF_INET6, peer->hostname, &addr))
      return CURLE_PEER_FAILED_VERIFICATION;
    target = GEN_IPADD;
    addrlen = sizeof(struct in6_addr);
    break;
#endif
  case CURL_SSL_PEER_DNS:
    target = GEN_DNS;
    break;
  default:
    DEBUGASSERT(0);
    failf(data, "unexpected ssl peer type: %d", peer->type);
    return CURLE_PEER_FAILED_VERIFICATION;
  }

  /* get a "list" of alternative names */
  altnames = X509_get_ext_d2i(server_cert, NID_subject_alt_name, NULL, NULL);

  if(altnames) {
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
    size_t numalts;
    size_t i;
#else
    int numalts;
    int i;
#endif
    bool dnsmatched = FALSE;
    bool ipmatched = FALSE;

    /* get amount of alternatives, RFC2459 claims there MUST be at least
       one, but we do not depend on it... */
    numalts = sk_GENERAL_NAME_num(altnames);

    /* loop through all alternatives - until a dnsmatch */
    for(i = 0; (i < numalts) && !dnsmatched; i++) {
      /* get a handle to alternative name number i */
      const GENERAL_NAME *check = sk_GENERAL_NAME_value(altnames, i);

      if(check->type == GEN_DNS)
        dNSName = TRUE;
      else if(check->type == GEN_IPADD)
        iPAddress = TRUE;

      /* only check alternatives of the same type the target is */
      if(check->type == target) {
        /* get data and length */
        const char *altptr = (char *)ASN1_STRING_get0_data(check->d.ia5);
        size_t altlen = (size_t) ASN1_STRING_length(check->d.ia5);

        switch(target) {
        case GEN_DNS: /* name/pattern comparison */
          /* The OpenSSL manpage explicitly says: "In general it cannot be
             assumed that the data returned by ASN1_STRING_data() is null
             terminated or does not contain embedded nulls." But also that
             "The actual format of the data will depend on the actual string
             type itself: for example for an IA5String the data will be ASCII"

             It has been however verified that in 0.9.6 and 0.9.7, IA5String
             is always null-terminated.
          */
          if((altlen == strlen(altptr)) &&
             /* if this is not true, there was an embedded zero in the name
                string and we cannot match it. */
             subj_alt_hostcheck(data, altptr, altlen,
                                peer->hostname, hostlen,
                                peer->dispname)) {
            dnsmatched = TRUE;
          }
          break;

        case GEN_IPADD: /* IP address comparison */
          /* compare alternative IP address if the data chunk is the same size
             our server IP address is */
          if((altlen == addrlen) && !memcmp(altptr, &addr, altlen)) {
            ipmatched = TRUE;
            infof(data,
                  " subjectAltName: host \"%s\" matched cert's IP address!",
                  peer->dispname);
          }
          break;
        }
      }
    }
    GENERAL_NAMES_free(altnames);

    if(dnsmatched || ipmatched)
      matched = TRUE;
  }

  if(matched)
    /* an alternative name matched */
    ;
  else if(dNSName || iPAddress) {
    const char *tname = (peer->type == CURL_SSL_PEER_DNS) ? "hostname" :
                        (peer->type == CURL_SSL_PEER_IPV4) ?
                        "ipv4 address" : "ipv6 address";
    infof(data, " subjectAltName does not match %s %s", tname, peer->dispname);
    failf(data, "SSL: no alternative certificate subject name matches "
          "target %s '%s'", tname, peer->dispname);
    result = CURLE_PEER_FAILED_VERIFICATION;
  }
  else {
    /* we have to look to the last occurrence of a commonName in the
       distinguished one to get the most significant one. */
    int i = -1;
    unsigned char *peer_CN = NULL;
    int peerlen = 0;

    /* The following is done because of a bug in 0.9.6b */
    X509_NAME *name = X509_get_subject_name(server_cert);
    if(name) {
      int j;
      while((j = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0)
        i = j;
    }

    /* we have the name entry and we will now convert this to a string
       that we can use for comparison. Doing this we support BMPstring,
       UTF8, etc. */

    if(i >= 0) {
      ASN1_STRING *tmp =
        X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i));

      /* In OpenSSL 0.9.7d and earlier, ASN1_STRING_to_UTF8 fails if the input
         is already UTF-8 encoded. We check for this case and copy the raw
         string manually to avoid the problem. This code can be made
         conditional in the future when OpenSSL has been fixed. */
      if(tmp) {
        if(ASN1_STRING_type(tmp) == V_ASN1_UTF8STRING) {
          peerlen = ASN1_STRING_length(tmp);
          if(peerlen >= 0) {
            peer_CN = OPENSSL_malloc(peerlen + 1);
            if(peer_CN) {
              memcpy(peer_CN, ASN1_STRING_get0_data(tmp), peerlen);
              peer_CN[peerlen] = '\0';
            }
            else
              result = CURLE_OUT_OF_MEMORY;
          }
        }
        else /* not a UTF8 name */
          peerlen = ASN1_STRING_to_UTF8(&peer_CN, tmp);

        if(peer_CN && (curlx_uztosi(strlen((char *)peer_CN)) != peerlen)) {
          /* there was a terminating zero before the end of string, this
             cannot match and we return failure! */
          failf(data, "SSL: illegal cert name field");
          result = CURLE_PEER_FAILED_VERIFICATION;
        }
      }
    }

    if(result)
      /* error already detected, pass through */
      ;
    else if(!peer_CN) {
      failf(data,
            "SSL: unable to obtain common name from peer certificate");
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else if(!Curl_cert_hostcheck((const char *)peer_CN,
                                 peerlen, peer->hostname, hostlen)) {
      failf(data, "SSL: certificate subject name '%s' does not match "
            "target hostname '%s'", peer_CN, peer->dispname);
      result = CURLE_PEER_FAILED_VERIFICATION;
    }
    else {
      infof(data, " common name: %s (matched)", peer_CN);
    }
    if(peer_CN)
      OPENSSL_free(peer_CN);
  }

  return result;
}

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
  !defined(OPENSSL_NO_OCSP)
static CURLcode verifystatus(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct ossl_ctx *octx)
{
  int i, ocsp_status;
#if defined(OPENSSL_IS_AWSLC)
  const uint8_t *status;
#else
  unsigned char *status;
#endif
  const unsigned char *p;
  CURLcode result = CURLE_OK;
  OCSP_RESPONSE *rsp = NULL;
  OCSP_BASICRESP *br = NULL;
  X509_STORE     *st = NULL;
  STACK_OF(X509) *ch = NULL;
  X509 *cert;
  OCSP_CERTID *id = NULL;
  int cert_status, crl_reason;
  ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;
  int ret;
  long len;

  (void)cf;
  DEBUGASSERT(octx);

  len = (long)SSL_get_tlsext_status_ocsp_resp(octx->ssl, &status);

  if(!status) {
    failf(data, "No OCSP response received");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }
  p = status;
  rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
  if(!rsp) {
    failf(data, "Invalid OCSP response");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  ocsp_status = OCSP_response_status(rsp);
  if(ocsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
    failf(data, "Invalid OCSP response status: %s (%d)",
          OCSP_response_status_str(ocsp_status), ocsp_status);
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  br = OCSP_response_get1_basic(rsp);
  if(!br) {
    failf(data, "Invalid OCSP response");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  ch = SSL_get_peer_cert_chain(octx->ssl);
  if(!ch) {
    failf(data, "Could not get peer certificate chain");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }
  st = SSL_CTX_get_cert_store(octx->ssl_ctx);

#if ((OPENSSL_VERSION_NUMBER <= 0x1000201fL) /* Fixed after 1.0.2a */ || \
     (defined(LIBRESSL_VERSION_NUMBER) &&                               \
      LIBRESSL_VERSION_NUMBER <= 0x2040200fL))
  /* The authorized responder cert in the OCSP response MUST be signed by the
     peer cert's issuer (see RFC6960 section 4.2.2.2). If that is a root cert,
     no problem, but if it is an intermediate cert OpenSSL has a bug where it
     expects this issuer to be present in the chain embedded in the OCSP
     response. So we add it if necessary. */

  /* First make sure the peer cert chain includes both a peer and an issuer,
     and the OCSP response contains a responder cert. */
  if(sk_X509_num(ch) >= 2 && sk_X509_num(br->certs) >= 1) {
    X509 *responder = sk_X509_value(br->certs, sk_X509_num(br->certs) - 1);

    /* Find issuer of responder cert and add it to the OCSP response chain */
    for(i = 0; i < sk_X509_num(ch); i++) {
      X509 *issuer = sk_X509_value(ch, i);
      if(X509_check_issued(issuer, responder) == X509_V_OK) {
        if(!OCSP_basic_add1_cert(br, issuer)) {
          failf(data, "Could not add issuer cert to OCSP response");
          result = CURLE_SSL_INVALIDCERTSTATUS;
          goto end;
        }
      }
    }
  }
#endif

  if(OCSP_basic_verify(br, ch, st, 0) <= 0) {
    failf(data, "OCSP response verification failed");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  /* Compute the certificate's ID */
  cert = SSL_get1_peer_certificate(octx->ssl);
  if(!cert) {
    failf(data, "Error getting peer certificate");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  for(i = 0; i < (int)sk_X509_num(ch); i++) {
    X509 *issuer = sk_X509_value(ch, (ossl_valsize_t)i);
    if(X509_check_issued(issuer, cert) == X509_V_OK) {
      id = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
      break;
    }
  }
  X509_free(cert);

  if(!id) {
    failf(data, "Error computing OCSP ID");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  /* Find the single OCSP response corresponding to the certificate ID */
  ret = OCSP_resp_find_status(br, id, &cert_status, &crl_reason, &rev,
                              &thisupd, &nextupd);
  OCSP_CERTID_free(id);
  if(ret != 1) {
    failf(data, "Could not find certificate ID in OCSP response");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  /* Validate the corresponding single OCSP response */
  if(!OCSP_check_validity(thisupd, nextupd, 300L, -1L)) {
    failf(data, "OCSP response has expired");
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

  infof(data, "SSL certificate status: %s (%d)",
        OCSP_cert_status_str(cert_status), cert_status);

  switch(cert_status) {
  case V_OCSP_CERTSTATUS_GOOD:
    break;

  case V_OCSP_CERTSTATUS_REVOKED:
    result = CURLE_SSL_INVALIDCERTSTATUS;
    failf(data, "SSL certificate revocation reason: %s (%d)",
          OCSP_crl_reason_str(crl_reason), crl_reason);
    goto end;

  case V_OCSP_CERTSTATUS_UNKNOWN:
  default:
    result = CURLE_SSL_INVALIDCERTSTATUS;
    goto end;
  }

end:
  if(br)
    OCSP_BASICRESP_free(br);
  OCSP_RESPONSE_free(rsp);

  return result;
}
#endif

#endif /* USE_OPENSSL */

/* The SSL_CTRL_SET_MSG_CALLBACK does not exist in ancient OpenSSL versions
   and thus this cannot be done there. */
#ifdef SSL_CTRL_SET_MSG_CALLBACK

static const char *ssl_msg_type(int ssl_ver, int msg)
{
#ifdef SSL2_VERSION_MAJOR
  if(ssl_ver == SSL2_VERSION_MAJOR) {
    switch(msg) {
    case SSL2_MT_ERROR:
      return "Error";
    case SSL2_MT_CLIENT_HELLO:
      return "Client hello";
    case SSL2_MT_CLIENT_MASTER_KEY:
      return "Client key";
    case SSL2_MT_CLIENT_FINISHED:
      return "Client finished";
    case SSL2_MT_SERVER_HELLO:
      return "Server hello";
    case SSL2_MT_SERVER_VERIFY:
      return "Server verify";
    case SSL2_MT_SERVER_FINISHED:
      return "Server finished";
    case SSL2_MT_REQUEST_CERTIFICATE:
      return "Request CERT";
    case SSL2_MT_CLIENT_CERTIFICATE:
      return "Client CERT";
    }
  }
  else
#endif
  if(ssl_ver == SSL3_VERSION_MAJOR) {
    switch(msg) {
    case SSL3_MT_HELLO_REQUEST:
      return "Hello request";
    case SSL3_MT_CLIENT_HELLO:
      return "Client hello";
    case SSL3_MT_SERVER_HELLO:
      return "Server hello";
#ifdef SSL3_MT_NEWSESSION_TICKET
    case SSL3_MT_NEWSESSION_TICKET:
      return "Newsession Ticket";
#endif
    case SSL3_MT_CERTIFICATE:
      return "Certificate";
    case SSL3_MT_SERVER_KEY_EXCHANGE:
      return "Server key exchange";
    case SSL3_MT_CLIENT_KEY_EXCHANGE:
      return "Client key exchange";
    case SSL3_MT_CERTIFICATE_REQUEST:
      return "Request CERT";
    case SSL3_MT_SERVER_DONE:
      return "Server finished";
    case SSL3_MT_CERTIFICATE_VERIFY:
      return "CERT verify";
    case SSL3_MT_FINISHED:
      return "Finished";
#ifdef SSL3_MT_CERTIFICATE_STATUS
    case SSL3_MT_CERTIFICATE_STATUS:
      return "Certificate Status";
#endif
#ifdef SSL3_MT_ENCRYPTED_EXTENSIONS
    case SSL3_MT_ENCRYPTED_EXTENSIONS:
      return "Encrypted Extensions";
#endif
#ifdef SSL3_MT_SUPPLEMENTAL_DATA
    case SSL3_MT_SUPPLEMENTAL_DATA:
      return "Supplemental data";
#endif
#ifdef SSL3_MT_END_OF_EARLY_DATA
    case SSL3_MT_END_OF_EARLY_DATA:
      return "End of early data";
#endif
#ifdef SSL3_MT_KEY_UPDATE
    case SSL3_MT_KEY_UPDATE:
      return "Key update";
#endif
#ifdef SSL3_MT_NEXT_PROTO
    case SSL3_MT_NEXT_PROTO:
      return "Next protocol";
#endif
#ifdef SSL3_MT_MESSAGE_HASH
    case SSL3_MT_MESSAGE_HASH:
      return "Message hash";
#endif
    }
  }
  return "Unknown";
}

static const char *tls_rt_type(int type)
{
  switch(type) {
#ifdef SSL3_RT_HEADER
  case SSL3_RT_HEADER:
    return "TLS header";
#endif
  case SSL3_RT_CHANGE_CIPHER_SPEC:
    return "TLS change cipher";
  case SSL3_RT_ALERT:
    return "TLS alert";
  case SSL3_RT_HANDSHAKE:
    return "TLS handshake";
  case SSL3_RT_APPLICATION_DATA:
    return "TLS app data";
  default:
    return "TLS Unknown";
  }
}

/*
 * Our callback from the SSL/TLS layers.
 */
static void ossl_trace(int direction, int ssl_ver, int content_type,
                       const void *buf, size_t len, SSL *ssl,
                       void *userp)
{
  const char *verstr = "???";
  struct Curl_cfilter *cf = userp;
  struct Curl_easy *data = NULL;
  char unknown[32];

  if(!cf)
    return;
  data = CF_DATA_CURRENT(cf);
  if(!data || !data->set.fdebug || (direction && direction != 1))
    return;

  switch(ssl_ver) {
#ifdef SSL2_VERSION /* removed in recent versions */
  case SSL2_VERSION:
    verstr = "SSLv2";
    break;
#endif
#ifdef SSL3_VERSION
  case SSL3_VERSION:
    verstr = "SSLv3";
    break;
#endif
  case TLS1_VERSION:
    verstr = "TLSv1.0";
    break;
#ifdef TLS1_1_VERSION
  case TLS1_1_VERSION:
    verstr = "TLSv1.1";
    break;
#endif
#ifdef TLS1_2_VERSION
  case TLS1_2_VERSION:
    verstr = "TLSv1.2";
    break;
#endif
#ifdef TLS1_3_VERSION
  case TLS1_3_VERSION:
    verstr = "TLSv1.3";
    break;
#endif
  case 0:
    break;
  default:
    msnprintf(unknown, sizeof(unknown), "(%x)", ssl_ver);
    verstr = unknown;
    break;
  }

  /* Log progress for interesting records only (like Handshake or Alert), skip
   * all raw record headers (content_type == SSL3_RT_HEADER or ssl_ver == 0).
   * For TLS 1.3, skip notification of the decrypted inner Content-Type.
   */
  if(ssl_ver
#ifdef SSL3_RT_HEADER
     && content_type != SSL3_RT_HEADER
#endif
#ifdef SSL3_RT_INNER_CONTENT_TYPE
     && content_type != SSL3_RT_INNER_CONTENT_TYPE
#endif
    ) {
    const char *msg_name, *tls_rt_name;
    char ssl_buf[1024];
    int msg_type, txt_len;

    /* the info given when the version is zero is not that useful for us */

    ssl_ver >>= 8; /* check the upper 8 bits only below */

    /* SSLv2 does not seem to have TLS record-type headers, so OpenSSL
     * always pass-up content-type as 0. But the interesting message-type
     * is at 'buf[0]'.
     */
    if(ssl_ver == SSL3_VERSION_MAJOR && content_type)
      tls_rt_name = tls_rt_type(content_type);
    else
      tls_rt_name = "";

    if(content_type == SSL3_RT_CHANGE_CIPHER_SPEC) {
      msg_type = *(char *)buf;
      msg_name = "Change cipher spec";
    }
    else if(content_type == SSL3_RT_ALERT) {
      msg_type = (((char *)buf)[0] << 8) + ((char *)buf)[1];
      msg_name = SSL_alert_desc_string_long(msg_type);
    }
    else {
      msg_type = *(char *)buf;
      msg_name = ssl_msg_type(ssl_ver, msg_type);
    }

    txt_len = msnprintf(ssl_buf, sizeof(ssl_buf),
                        "%s (%s), %s, %s (%d):\n",
                        verstr, direction?"OUT":"IN",
                        tls_rt_name, msg_name, msg_type);
    if(0 <= txt_len && (unsigned)txt_len < sizeof(ssl_buf)) {
      Curl_debug(data, CURLINFO_TEXT, ssl_buf, (size_t)txt_len);
    }
  }

  Curl_debug(data, (direction == 1) ? CURLINFO_SSL_DATA_OUT :
             CURLINFO_SSL_DATA_IN, (char *)buf, len);
  (void) ssl;
}
#endif

#ifdef USE_OPENSSL
/* ====================================================== */

/* Check for OpenSSL 1.0.2 which has ALPN support. */
#undef HAS_ALPN
#if OPENSSL_VERSION_NUMBER >= 0x10002000L       \
  && !defined(OPENSSL_NO_TLSEXT)
#  define HAS_ALPN 1
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) /* 1.1.0 */
static CURLcode
ossl_set_ssl_version_min_max(struct Curl_cfilter *cf, SSL_CTX *ctx)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  /* first, TLS min version... */
  long curl_ssl_version_min = conn_config->version;
  long curl_ssl_version_max;

  /* convert curl min SSL version option to OpenSSL constant */
#if (defined(OPENSSL_IS_BORINGSSL)  || \
     defined(OPENSSL_IS_AWSLC)      || \
     defined(LIBRESSL_VERSION_NUMBER))
  uint16_t ossl_ssl_version_min = 0;
  uint16_t ossl_ssl_version_max = 0;
#else
  long ossl_ssl_version_min = 0;
  long ossl_ssl_version_max = 0;
#endif
  switch(curl_ssl_version_min) {
  case CURL_SSLVERSION_TLSv1: /* TLS 1.x */
  case CURL_SSLVERSION_TLSv1_0:
    ossl_ssl_version_min = TLS1_VERSION;
    break;
  case CURL_SSLVERSION_TLSv1_1:
    ossl_ssl_version_min = TLS1_1_VERSION;
    break;
  case CURL_SSLVERSION_TLSv1_2:
    ossl_ssl_version_min = TLS1_2_VERSION;
    break;
  case CURL_SSLVERSION_TLSv1_3:
#ifdef TLS1_3_VERSION
    ossl_ssl_version_min = TLS1_3_VERSION;
    break;
#else
    return CURLE_NOT_BUILT_IN;
#endif
  }

  /* CURL_SSLVERSION_DEFAULT means that no option was selected.
     We do not want to pass 0 to SSL_CTX_set_min_proto_version as
     it would enable all versions down to the lowest supported by
     the library.
     So we skip this, and stay with the library default
  */
  if(curl_ssl_version_min != CURL_SSLVERSION_DEFAULT) {
    if(!SSL_CTX_set_min_proto_version(ctx, ossl_ssl_version_min)) {
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* ... then, TLS max version */
  curl_ssl_version_max = (long)conn_config->version_max;

  /* convert curl max SSL version option to OpenSSL constant */
  switch(curl_ssl_version_max) {
  case CURL_SSLVERSION_MAX_TLSv1_0:
    ossl_ssl_version_max = TLS1_VERSION;
    break;
  case CURL_SSLVERSION_MAX_TLSv1_1:
    ossl_ssl_version_max = TLS1_1_VERSION;
    break;
  case CURL_SSLVERSION_MAX_TLSv1_2:
    ossl_ssl_version_max = TLS1_2_VERSION;
    break;
#ifdef TLS1_3_VERSION
  case CURL_SSLVERSION_MAX_TLSv1_3:
    ossl_ssl_version_max = TLS1_3_VERSION;
    break;
#endif
  case CURL_SSLVERSION_MAX_NONE:  /* none selected */
  case CURL_SSLVERSION_MAX_DEFAULT:  /* max selected */
  default:
    /* SSL_CTX_set_max_proto_version states that:
       setting the maximum to 0 will enable
       protocol versions up to the highest version
       supported by the library */
    ossl_ssl_version_max = 0;
    break;
  }

  if(!SSL_CTX_set_max_proto_version(ctx, ossl_ssl_version_max)) {
    return CURLE_SSL_CONNECT_ERROR;
  }

  return CURLE_OK;
}
#endif

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
typedef uint32_t ctx_option_t;
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
typedef uint64_t ctx_option_t;
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L && \
  !defined(LIBRESSL_VERSION_NUMBER)
typedef unsigned long ctx_option_t;
#else
typedef long ctx_option_t;
#endif

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) /* 1.1.0 */
static CURLcode
ossl_set_ssl_version_min_max_legacy(ctx_option_t *ctx_options,
                                    struct Curl_cfilter *cf,
                                    struct Curl_easy *data)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  long ssl_version = conn_config->version;
  long ssl_version_max = conn_config->version_max;

  (void) data; /* In case it is unused. */

  switch(ssl_version) {
  case CURL_SSLVERSION_TLSv1_3:
#ifdef TLS1_3_VERSION
  {
    struct ssl_connect_data *connssl = cf->ctx;
    struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;
    DEBUGASSERT(octx);
    SSL_CTX_set_max_proto_version(octx->ssl_ctx, TLS1_3_VERSION);
    *ctx_options |= SSL_OP_NO_TLSv1_2;
  }
#else
  (void)ctx_options;
  failf(data, OSSL_PACKAGE " was built without TLS 1.3 support");
  return CURLE_NOT_BUILT_IN;
#endif
  FALLTHROUGH();
  case CURL_SSLVERSION_TLSv1_2:
#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
    *ctx_options |= SSL_OP_NO_TLSv1_1;
#else
    failf(data, OSSL_PACKAGE " was built without TLS 1.2 support");
    return CURLE_NOT_BUILT_IN;
#endif
    FALLTHROUGH();
  case CURL_SSLVERSION_TLSv1_1:
#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
    *ctx_options |= SSL_OP_NO_TLSv1;
#else
    failf(data, OSSL_PACKAGE " was built without TLS 1.1 support");
    return CURLE_NOT_BUILT_IN;
#endif
    FALLTHROUGH();
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1:
    break;
  }

  switch(ssl_version_max) {
  case CURL_SSLVERSION_MAX_TLSv1_0:
#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
    *ctx_options |= SSL_OP_NO_TLSv1_1;
#endif
    FALLTHROUGH();
  case CURL_SSLVERSION_MAX_TLSv1_1:
#if OPENSSL_VERSION_NUMBER >= 0x1000100FL
    *ctx_options |= SSL_OP_NO_TLSv1_2;
#endif
    FALLTHROUGH();
  case CURL_SSLVERSION_MAX_TLSv1_2:
#ifdef TLS1_3_VERSION
    *ctx_options |= SSL_OP_NO_TLSv1_3;
#endif
    break;
  case CURL_SSLVERSION_MAX_TLSv1_3:
#ifdef TLS1_3_VERSION
    break;
#else
    failf(data, OSSL_PACKAGE " was built without TLS 1.3 support");
    return CURLE_NOT_BUILT_IN;
#endif
  }
  return CURLE_OK;
}
#endif

CURLcode Curl_ossl_add_session(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const struct ssl_peer *peer,
                               SSL_SESSION *session)
{
  const struct ssl_config_data *config;
  CURLcode result = CURLE_OK;

  if(!cf || !data)
    goto out;

  config = Curl_ssl_cf_get_config(cf, data);
  if(config->primary.cache_session) {

    Curl_ssl_sessionid_lock(data);
    result = Curl_ssl_set_sessionid(cf, data, peer, session, 0,
                                    ossl_session_free);
    session = NULL; /* call has taken ownership */
    Curl_ssl_sessionid_unlock(data);
  }

out:
  if(session)
    ossl_session_free(session, 0);
  return result;
}

/* The "new session" callback must return zero if the session can be removed
 * or non-zero if the session has been put into the session cache.
 */
static int ossl_new_session_cb(SSL *ssl, SSL_SESSION *ssl_sessionid)
{
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  struct ssl_connect_data *connssl;

  cf = (struct Curl_cfilter*) SSL_get_app_data(ssl);
  connssl = cf? cf->ctx : NULL;
  data = connssl? CF_DATA_CURRENT(cf) : NULL;
  Curl_ossl_add_session(cf, data, &connssl->peer, ssl_sessionid);
  return 1;
}

static CURLcode load_cacert_from_memory(X509_STORE *store,
                                        const struct curl_blob *ca_info_blob)
{
  /* these need to be freed at the end */
  BIO *cbio = NULL;
  STACK_OF(X509_INFO) *inf = NULL;

  /* everything else is just a reference */
  int i, count = 0;
  X509_INFO *itmp = NULL;

  if(ca_info_blob->len > (size_t)INT_MAX)
    return CURLE_SSL_CACERT_BADFILE;

  cbio = BIO_new_mem_buf(ca_info_blob->data, (int)ca_info_blob->len);
  if(!cbio)
    return CURLE_OUT_OF_MEMORY;

  inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);
  if(!inf) {
    BIO_free(cbio);
    return CURLE_SSL_CACERT_BADFILE;
  }

  /* add each entry from PEM file to x509_store */
  for(i = 0; i < (int)sk_X509_INFO_num(inf); ++i) {
    itmp = sk_X509_INFO_value(inf, (ossl_valsize_t)i);
    if(itmp->x509) {
      if(X509_STORE_add_cert(store, itmp->x509)) {
        ++count;
      }
      else {
        /* set count to 0 to return an error */
        count = 0;
        break;
      }
    }
    if(itmp->crl) {
      if(X509_STORE_add_crl(store, itmp->crl)) {
        ++count;
      }
      else {
        /* set count to 0 to return an error */
        count = 0;
        break;
      }
    }
  }

  sk_X509_INFO_pop_free(inf, X509_INFO_free);
  BIO_free(cbio);

  /* if we did not end up importing anything, treat that as an error */
  return (count > 0) ? CURLE_OK : CURLE_SSL_CACERT_BADFILE;
}

#if defined(USE_WIN32_CRYPTO)
static CURLcode import_windows_cert_store(struct Curl_easy *data,
                                          const char *name,
                                          X509_STORE *store,
                                          bool *imported)
{
  CURLcode result = CURLE_OK;
  HCERTSTORE hStore;

  *imported = false;

  hStore = CertOpenSystemStoreA(0, name);
  if(hStore) {
    PCCERT_CONTEXT pContext = NULL;
    /* The array of enhanced key usage OIDs will vary per certificate and
       is declared outside of the loop so that rather than malloc/free each
       iteration we can grow it with realloc, when necessary. */
    CERT_ENHKEY_USAGE *enhkey_usage = NULL;
    DWORD enhkey_usage_size = 0;

    /* This loop makes a best effort to import all valid certificates from
       the MS root store. If a certificate cannot be imported it is
       skipped. 'result' is used to store only hard-fail conditions (such
       as out of memory) that cause an early break. */
    result = CURLE_OK;
    for(;;) {
      X509 *x509;
      FILETIME now;
      BYTE key_usage[2];
      DWORD req_size;
      const unsigned char *encoded_cert;
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
      char cert_name[256];
#endif

      pContext = CertEnumCertificatesInStore(hStore, pContext);
      if(!pContext)
        break;

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
      if(!CertGetNameStringA(pContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                             NULL, cert_name, sizeof(cert_name))) {
        strcpy(cert_name, "Unknown");
      }
      infof(data, "SSL: Checking cert \"%s\"", cert_name);
#endif
      encoded_cert = (const unsigned char *)pContext->pbCertEncoded;
      if(!encoded_cert)
        continue;

      GetSystemTimeAsFileTime(&now);
      if(CompareFileTime(&pContext->pCertInfo->NotBefore, &now) > 0 ||
         CompareFileTime(&now, &pContext->pCertInfo->NotAfter) > 0)
        continue;

      /* If key usage exists check for signing attribute */
      if(CertGetIntendedKeyUsage(pContext->dwCertEncodingType,
                                 pContext->pCertInfo,
                                 key_usage, sizeof(key_usage))) {
        if(!(key_usage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE))
          continue;
      }
      else if(GetLastError())
        continue;

      /* If enhanced key usage exists check for server auth attribute.
       *
       * Note "In a Microsoft environment, a certificate might also have
       * EKU extended properties that specify valid uses for the
       * certificate."  The call below checks both, and behavior varies
       * depending on what is found. For more details see
       * CertGetEnhancedKeyUsage doc.
       */
      if(CertGetEnhancedKeyUsage(pContext, 0, NULL, &req_size)) {
        if(req_size && req_size > enhkey_usage_size) {
          void *tmp = realloc(enhkey_usage, req_size);

          if(!tmp) {
            failf(data, "SSL: Out of memory allocating for OID list");
            result = CURLE_OUT_OF_MEMORY;
            break;
          }

          enhkey_usage = (CERT_ENHKEY_USAGE *)tmp;
          enhkey_usage_size = req_size;
        }

        if(CertGetEnhancedKeyUsage(pContext, 0, enhkey_usage, &req_size)) {
          if(!enhkey_usage->cUsageIdentifier) {
            /* "If GetLastError returns CRYPT_E_NOT_FOUND, the certificate
               is good for all uses. If it returns zero, the certificate
               has no valid uses." */
            if((HRESULT)GetLastError() != CRYPT_E_NOT_FOUND)
              continue;
          }
          else {
            DWORD i;
            bool found = false;

            for(i = 0; i < enhkey_usage->cUsageIdentifier; ++i) {
              if(!strcmp("1.3.6.1.5.5.7.3.1" /* OID server auth */,
                         enhkey_usage->rgpszUsageIdentifier[i])) {
                found = true;
                break;
              }
            }

            if(!found)
              continue;
          }
        }
        else
          continue;
      }
      else
        continue;

      x509 = d2i_X509(NULL, &encoded_cert, (long)pContext->cbCertEncoded);
      if(!x509)
        continue;

      /* Try to import the certificate. This may fail for legitimate
         reasons such as duplicate certificate, which is allowed by MS but
         not OpenSSL. */
      if(X509_STORE_add_cert(store, x509) == 1) {
#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
        infof(data, "SSL: Imported cert \"%s\"", cert_name);
#endif
        *imported = true;
      }
      X509_free(x509);
    }

    free(enhkey_usage);
    CertFreeCertificateContext(pContext);
    CertCloseStore(hStore, 0);

    if(result)
      return result;
  }

  return result;
}
#endif

static CURLcode populate_x509_store(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    X509_STORE *store)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  CURLcode result = CURLE_OK;
  X509_LOOKUP *lookup = NULL;
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ca_info_blob ? NULL : conn_config->CAfile);
  const char * const ssl_capath = conn_config->CApath;
  const char * const ssl_crlfile = ssl_config->primary.CRLfile;
  const bool verifypeer = conn_config->verifypeer;
  bool imported_native_ca = false;
  bool imported_ca_info_blob = false;

  CURL_TRC_CF(data, cf, "populate_x509_store, path=%s, blob=%d",
              ssl_cafile? ssl_cafile : "none", !!ca_info_blob);
  if(!store)
    return CURLE_OUT_OF_MEMORY;

  if(verifypeer) {
#if defined(USE_WIN32_CRYPTO)
    /* Import certificates from the Windows root certificate store if
       requested.
       https://stackoverflow.com/questions/9507184/
       https://github.com/d3x0r/SACK/blob/master/src/netlib/ssl_layer.c#L1037
       https://datatracker.ietf.org/doc/html/rfc5280 */
    if(ssl_config->native_ca_store) {
      const char *storeNames[] = {
        "ROOT",   /* Trusted Root Certification Authorities */
        "CA"      /* Intermediate Certification Authorities */
      };
      size_t i;
      for(i = 0; i < ARRAYSIZE(storeNames); ++i) {
        bool imported = false;
        result = import_windows_cert_store(data, storeNames[i], store,
                                           &imported);
        if(result)
          return result;
        if(imported) {
          infof(data, "successfully imported Windows %s store", storeNames[i]);
          imported_native_ca = true;
        }
        else
          infof(data, "error importing Windows %s store, continuing anyway",
                storeNames[i]);
      }
    }
#endif
    if(ca_info_blob) {
      result = load_cacert_from_memory(store, ca_info_blob);
      if(result) {
        failf(data, "error importing CA certificate blob");
        return result;
      }
      else {
        imported_ca_info_blob = true;
        infof(data, "successfully imported CA certificate blob");
      }
    }

    if(ssl_cafile || ssl_capath) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
      /* OpenSSL 3.0.0 has deprecated SSL_CTX_load_verify_locations */
      if(ssl_cafile && !X509_STORE_load_file(store, ssl_cafile)) {
        if(!imported_native_ca && !imported_ca_info_blob) {
          /* Fail if we insist on successfully verifying the server. */
          failf(data, "error setting certificate file: %s", ssl_cafile);
          return CURLE_SSL_CACERT_BADFILE;
        }
        else
          infof(data, "error setting certificate file, continuing anyway");
      }
      if(ssl_capath && !X509_STORE_load_path(store, ssl_capath)) {
        if(!imported_native_ca && !imported_ca_info_blob) {
          /* Fail if we insist on successfully verifying the server. */
          failf(data, "error setting certificate path: %s", ssl_capath);
          return CURLE_SSL_CACERT_BADFILE;
        }
        else
          infof(data, "error setting certificate path, continuing anyway");
      }
#else
      /* tell OpenSSL where to find CA certificates that are used to verify the
         server's certificate. */
      if(!X509_STORE_load_locations(store, ssl_cafile, ssl_capath)) {
        if(!imported_native_ca && !imported_ca_info_blob) {
          /* Fail if we insist on successfully verifying the server. */
          failf(data, "error setting certificate verify locations:"
                "  CAfile: %s CApath: %s",
                ssl_cafile ? ssl_cafile : "none",
                ssl_capath ? ssl_capath : "none");
          return CURLE_SSL_CACERT_BADFILE;
        }
        else {
          infof(data, "error setting certificate verify locations,"
                " continuing anyway");
        }
      }
#endif
      infof(data, " CAfile: %s", ssl_cafile ? ssl_cafile : "none");
      infof(data, " CApath: %s", ssl_capath ? ssl_capath : "none");
    }

#ifdef CURL_CA_FALLBACK
    if(!ssl_cafile && !ssl_capath &&
       !imported_native_ca && !imported_ca_info_blob) {
      /* verifying the peer without any CA certificates will not
         work so use OpenSSL's built-in default as fallback */
      X509_STORE_set_default_paths(store);
    }
#endif
  }

  if(ssl_crlfile) {
    /* tell OpenSSL where to find CRL file that is used to check certificate
     * revocation */
    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if(!lookup ||
       (!X509_load_crl_file(lookup, ssl_crlfile, X509_FILETYPE_PEM)) ) {
      failf(data, "error loading CRL file: %s", ssl_crlfile);
      return CURLE_SSL_CRL_BADFILE;
    }
    /* Everything is fine. */
    infof(data, "successfully loaded CRL file:");
    X509_STORE_set_flags(store,
                         X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    infof(data, "  CRLfile: %s", ssl_crlfile);
  }

  if(verifypeer) {
    /* Try building a chain using issuers in the trusted store first to avoid
       problems with server-sent legacy intermediates. Newer versions of
       OpenSSL do alternate chain checking by default but we do not know how to
       determine that in a reliable manner.
       https://web.archive.org/web/20190422050538/
       rt.openssl.org/Ticket/Display.html?id=3621
    */
#if defined(X509_V_FLAG_TRUSTED_FIRST)
    X509_STORE_set_flags(store, X509_V_FLAG_TRUSTED_FIRST);
#endif
#ifdef X509_V_FLAG_PARTIAL_CHAIN
    if(!ssl_config->no_partialchain && !ssl_crlfile) {
      /* Have intermediate certificates in the trust store be treated as
         trust-anchors, in the same way as self-signed root CA certificates
         are. This allows users to verify servers using the intermediate cert
         only, instead of needing the whole chain.

         Due to OpenSSL bug https://github.com/openssl/openssl/issues/5081 we
         cannot do partial chains with a CRL check.
      */
      X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);
    }
#endif
  }

  return result;
}

#if defined(HAVE_SSL_X509_STORE_SHARE)

/* key to use at `multi->proto_hash` */
#define MPROTO_OSSL_X509_KEY   "tls:ossl:x509:share"

struct ossl_x509_share {
  char *CAfile;         /* CAfile path used to generate X509 store */
  X509_STORE *store;    /* cached X509 store or NULL if none */
  struct curltime time; /* when the cached store was created */
};

static void oss_x509_share_free(void *key, size_t key_len, void *p)
{
  struct ossl_x509_share *share = p;
  DEBUGASSERT(key_len == (sizeof(MPROTO_OSSL_X509_KEY)-1));
  DEBUGASSERT(!memcmp(MPROTO_OSSL_X509_KEY, key, key_len));
  (void)key;
  (void)key_len;
  if(share->store) {
    X509_STORE_free(share->store);
  }
  free(share->CAfile);
  free(share);
}

static bool
cached_x509_store_expired(const struct Curl_easy *data,
                          const struct ossl_x509_share *mb)
{
  const struct ssl_general_config *cfg = &data->set.general_ssl;
  if(cfg->ca_cache_timeout < 0)
    return FALSE;
  else {
    struct curltime now = Curl_now();
    timediff_t elapsed_ms = Curl_timediff(now, mb->time);
    timediff_t timeout_ms = cfg->ca_cache_timeout * (timediff_t)1000;

    return elapsed_ms >= timeout_ms;
  }
}

static bool
cached_x509_store_different(struct Curl_cfilter *cf,
                            const struct ossl_x509_share *mb)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  if(!mb->CAfile || !conn_config->CAfile)
    return mb->CAfile != conn_config->CAfile;

  return strcmp(mb->CAfile, conn_config->CAfile);
}

static X509_STORE *get_cached_x509_store(struct Curl_cfilter *cf,
                                         const struct Curl_easy *data)
{
  struct Curl_multi *multi = data->multi;
  struct ossl_x509_share *share;
  X509_STORE *store = NULL;

  DEBUGASSERT(multi);
  share = multi? Curl_hash_pick(&multi->proto_hash,
                                (void *)MPROTO_OSSL_X509_KEY,
                                sizeof(MPROTO_OSSL_X509_KEY)-1) : NULL;
  if(share && share->store &&
     !cached_x509_store_expired(data, share) &&
     !cached_x509_store_different(cf, share)) {
    store = share->store;
  }

  return store;
}

static void set_cached_x509_store(struct Curl_cfilter *cf,
                                  const struct Curl_easy *data,
                                  X509_STORE *store)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_multi *multi = data->multi;
  struct ossl_x509_share *share;

  DEBUGASSERT(multi);
  if(!multi)
    return;
  share = Curl_hash_pick(&multi->proto_hash,
                         (void *)MPROTO_OSSL_X509_KEY,
                         sizeof(MPROTO_OSSL_X509_KEY)-1);

  if(!share) {
    share = calloc(1, sizeof(*share));
    if(!share)
      return;
    if(!Curl_hash_add2(&multi->proto_hash,
                       (void *)MPROTO_OSSL_X509_KEY,
                       sizeof(MPROTO_OSSL_X509_KEY)-1,
                       share, oss_x509_share_free)) {
      free(share);
      return;
    }
  }

  if(X509_STORE_up_ref(store)) {
    char *CAfile = NULL;

    if(conn_config->CAfile) {
      CAfile = strdup(conn_config->CAfile);
      if(!CAfile) {
        X509_STORE_free(store);
        return;
      }
    }

    if(share->store) {
      X509_STORE_free(share->store);
      free(share->CAfile);
    }

    share->time = Curl_now();
    share->store = store;
    share->CAfile = CAfile;
  }
}

CURLcode Curl_ssl_setup_x509_store(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   SSL_CTX *ssl_ctx)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  CURLcode result = CURLE_OK;
  X509_STORE *cached_store;
  bool cache_criteria_met;

  /* Consider the X509 store cacheable if it comes exclusively from a CAfile,
     or no source is provided and we are falling back to OpenSSL's built-in
     default. */
  cache_criteria_met = (data->set.general_ssl.ca_cache_timeout != 0) &&
    conn_config->verifypeer &&
    !conn_config->CApath &&
    !conn_config->ca_info_blob &&
    !ssl_config->primary.CRLfile &&
    !ssl_config->native_ca_store;

  cached_store = get_cached_x509_store(cf, data);
  if(cached_store && cache_criteria_met && X509_STORE_up_ref(cached_store)) {
    SSL_CTX_set_cert_store(ssl_ctx, cached_store);
  }
  else {
    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);

    result = populate_x509_store(cf, data, store);
    if(result == CURLE_OK && cache_criteria_met) {
      set_cached_x509_store(cf, data, store);
    }
  }

  return result;
}
#else /* HAVE_SSL_X509_STORE_SHARE */
CURLcode Curl_ssl_setup_x509_store(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   SSL_CTX *ssl_ctx)
{
  X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);

  return populate_x509_store(cf, data, store);
}
#endif /* HAVE_SSL_X509_STORE_SHARE */

CURLcode Curl_ossl_ctx_init(struct ossl_ctx *octx,
                            struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct ssl_peer *peer,
                            int transport, /* TCP or QUIC */
                            const unsigned char *alpn, size_t alpn_len,
                            Curl_ossl_ctx_setup_cb *cb_setup,
                            void *cb_user_data,
                            Curl_ossl_new_session_cb *cb_new_session,
                            void *ssl_user_data)
{
  CURLcode result = CURLE_OK;
  const char *ciphers;
  SSL_METHOD_QUAL SSL_METHOD *req_method = NULL;
  ctx_option_t ctx_options = 0;
  void *ssl_sessionid = NULL;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const long int ssl_version_min = conn_config->version;
  char * const ssl_cert = ssl_config->primary.clientcert;
  const struct curl_blob *ssl_cert_blob = ssl_config->primary.cert_blob;
  const char * const ssl_cert_type = ssl_config->cert_type;
  const bool verifypeer = conn_config->verifypeer;
  char error_buffer[256];

  /* Make funny stuff to get random input */
  result = ossl_seed(data);
  if(result)
    return result;

  ssl_config->certverifyresult = !X509_V_OK;

  switch(transport) {
  case TRNSPRT_TCP:
    /* check to see if we have been told to use an explicit SSL/TLS version */
    switch(ssl_version_min) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
    case CURL_SSLVERSION_TLSv1_0:
    case CURL_SSLVERSION_TLSv1_1:
    case CURL_SSLVERSION_TLSv1_2:
    case CURL_SSLVERSION_TLSv1_3:
      /* it will be handled later with the context options */
  #if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
      req_method = TLS_client_method();
  #else
      req_method = SSLv23_client_method();
  #endif
      break;
    case CURL_SSLVERSION_SSLv2:
      failf(data, "No SSLv2 support");
      return CURLE_NOT_BUILT_IN;
    case CURL_SSLVERSION_SSLv3:
      failf(data, "No SSLv3 support");
      return CURLE_NOT_BUILT_IN;
    default:
      failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
      return CURLE_SSL_CONNECT_ERROR;
    }
    break;
  case TRNSPRT_QUIC:
    if(conn_config->version_max &&
       (conn_config->version_max != CURL_SSLVERSION_MAX_TLSv1_3)) {
      failf(data, "QUIC needs at least TLS version 1.3");
      return CURLE_SSL_CONNECT_ERROR;
    }

#ifdef USE_OPENSSL_QUIC
    req_method = OSSL_QUIC_client_method();
#elif (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    req_method = TLS_method();
#else
    req_method = SSLv23_client_method();
#endif
    break;
  default:
    failf(data, "unsupported transport %d in SSL init", transport);
    return CURLE_SSL_CONNECT_ERROR;
  }


  DEBUGASSERT(!octx->ssl_ctx);
  octx->ssl_ctx = SSL_CTX_new(req_method);

  if(!octx->ssl_ctx) {
    failf(data, "SSL: could not create a context: %s",
          ossl_strerror(ERR_peek_error(), error_buffer, sizeof(error_buffer)));
    return CURLE_OUT_OF_MEMORY;
  }

  if(cb_setup) {
    result = cb_setup(cf, data, cb_user_data);
    if(result)
      return result;
  }

#ifdef SSL_CTRL_SET_MSG_CALLBACK
  if(data->set.fdebug && data->set.verbose) {
    /* the SSL trace callback is only used for verbose logging */
    SSL_CTX_set_msg_callback(octx->ssl_ctx, ossl_trace);
    SSL_CTX_set_msg_callback_arg(octx->ssl_ctx, cf);
  }
#endif

  /* OpenSSL contains code to work around lots of bugs and flaws in various
     SSL-implementations. SSL_CTX_set_options() is used to enabled those
     work-arounds. The manpage for this option states that SSL_OP_ALL enables
     all the work-arounds and that "It is usually safe to use SSL_OP_ALL to
     enable the bug workaround options if compatibility with somewhat broken
     implementations is desired."

     The "-no_ticket" option was introduced in OpenSSL 0.9.8j. it is a flag to
     disable "rfc4507bis session ticket support". rfc4507bis was later turned
     into the proper RFC5077: https://datatracker.ietf.org/doc/html/rfc5077

     The enabled extension concerns the session management. I wonder how often
     libcurl stops a connection and then resumes a TLS session. Also, sending
     the session data is some overhead. I suggest that you just use your
     proposed patch (which explicitly disables TICKET).

     If someone writes an application with libcurl and OpenSSL who wants to
     enable the feature, one can do this in the SSL callback.

     SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG option enabling allowed proper
     interoperability with web server Netscape Enterprise Server 2.0.1 which
     was released back in 1996.

     Due to CVE-2010-4180, option SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG has
     become ineffective as of OpenSSL 0.9.8q and 1.0.0c. In order to mitigate
     CVE-2010-4180 when using previous OpenSSL versions we no longer enable
     this option regardless of OpenSSL version and SSL_OP_ALL definition.

     OpenSSL added a work-around for a SSL 3.0/TLS 1.0 CBC vulnerability:
     https://web.archive.org/web/20240114184648/openssl.org/~bodo/tls-cbc.txt.
     In 0.9.6e they added a bit to SSL_OP_ALL that _disables_ that work-around
     despite the fact that SSL_OP_ALL is documented to do "rather harmless"
     workarounds. In order to keep the secure work-around, the
     SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS bit must not be set.
  */

  ctx_options = SSL_OP_ALL;

#ifdef SSL_OP_NO_TICKET
  ctx_options |= SSL_OP_NO_TICKET;
#endif

#ifdef SSL_OP_NO_COMPRESSION
  ctx_options |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
  /* mitigate CVE-2010-4180 */
  ctx_options &= ~(ctx_option_t)SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
  /* unless the user explicitly asks to allow the protocol vulnerability we
     use the work-around */
  if(!ssl_config->enable_beast)
    ctx_options &= ~(ctx_option_t)SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
#endif

  switch(ssl_version_min) {
  case CURL_SSLVERSION_SSLv2:
  case CURL_SSLVERSION_SSLv3:
    return CURLE_NOT_BUILT_IN;

    /* "--tlsv<x.y>" options mean TLS >= version <x.y> */
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1: /* TLS >= version 1.0 */
  case CURL_SSLVERSION_TLSv1_0: /* TLS >= version 1.0 */
  case CURL_SSLVERSION_TLSv1_1: /* TLS >= version 1.1 */
  case CURL_SSLVERSION_TLSv1_2: /* TLS >= version 1.2 */
  case CURL_SSLVERSION_TLSv1_3: /* TLS >= version 1.3 */
    /* asking for any TLS version as the minimum, means no SSL versions
       allowed */
    ctx_options |= SSL_OP_NO_SSLv2;
    ctx_options |= SSL_OP_NO_SSLv3;

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) /* 1.1.0 */
    result = ossl_set_ssl_version_min_max(cf, octx->ssl_ctx);
#else
    result = ossl_set_ssl_version_min_max_legacy(&ctx_options, cf, data);
#endif
    if(result != CURLE_OK)
      return result;
    break;

  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

  SSL_CTX_set_options(octx->ssl_ctx, ctx_options);

#ifdef HAS_ALPN
  if(alpn && alpn_len) {
    if(SSL_CTX_set_alpn_protos(octx->ssl_ctx, alpn, (int)alpn_len)) {
      failf(data, "Error setting ALPN");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
#endif

  if(ssl_cert || ssl_cert_blob || ssl_cert_type) {
    if(!result &&
       !cert_stuff(data, octx->ssl_ctx,
                   ssl_cert, ssl_cert_blob, ssl_cert_type,
                   ssl_config->key, ssl_config->key_blob,
                   ssl_config->key_type, ssl_config->key_passwd))
      result = CURLE_SSL_CERTPROBLEM;
    if(result)
      /* failf() is already done in cert_stuff() */
      return result;
  }

  ciphers = conn_config->cipher_list;
  if(!ciphers && (peer->transport != TRNSPRT_QUIC))
    ciphers = DEFAULT_CIPHER_SELECTION;
  if(ciphers) {
    if(!SSL_CTX_set_cipher_list(octx->ssl_ctx, ciphers)) {
      failf(data, "failed setting cipher list: %s", ciphers);
      return CURLE_SSL_CIPHER;
    }
    infof(data, "Cipher selection: %s", ciphers);
  }

#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
  {
    const char *ciphers13 = conn_config->cipher_list13;
    if(ciphers13) {
      if(!SSL_CTX_set_ciphersuites(octx->ssl_ctx, ciphers13)) {
        failf(data, "failed setting TLS 1.3 cipher suite: %s", ciphers13);
        return CURLE_SSL_CIPHER;
      }
      infof(data, "TLS 1.3 cipher selection: %s", ciphers13);
    }
  }
#endif

#ifdef HAVE_SSL_CTX_SET_POST_HANDSHAKE_AUTH
  /* OpenSSL 1.1.1 requires clients to opt-in for PHA */
  SSL_CTX_set_post_handshake_auth(octx->ssl_ctx, 1);
#endif

#ifdef HAVE_SSL_CTX_SET_EC_CURVES
  {
    const char *curves = conn_config->curves;
    if(curves) {
      if(!SSL_CTX_set1_curves_list(octx->ssl_ctx, curves)) {
        failf(data, "failed setting curves list: '%s'", curves);
        return CURLE_SSL_CIPHER;
      }
    }
  }
#endif

#ifdef USE_OPENSSL_SRP
  if(ssl_config->primary.username && Curl_auth_allowed_to_host(data)) {
    char * const ssl_username = ssl_config->primary.username;
    char * const ssl_password = ssl_config->primary.password;
    infof(data, "Using TLS-SRP username: %s", ssl_username);

    if(!SSL_CTX_set_srp_username(octx->ssl_ctx, ssl_username)) {
      failf(data, "Unable to set SRP username");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!SSL_CTX_set_srp_password(octx->ssl_ctx, ssl_password)) {
      failf(data, "failed setting SRP password");
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if(!conn_config->cipher_list) {
      infof(data, "Setting cipher list SRP");

      if(!SSL_CTX_set_cipher_list(octx->ssl_ctx, "SRP")) {
        failf(data, "failed setting SRP cipher list");
        return CURLE_SSL_CIPHER;
      }
    }
  }
#endif

  /* OpenSSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
  SSL_CTX_set_verify(octx->ssl_ctx,
                     verifypeer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

  /* Enable logging of secrets to the file specified in env SSLKEYLOGFILE. */
#ifdef HAVE_KEYLOG_CALLBACK
  if(Curl_tls_keylog_enabled()) {
    SSL_CTX_set_keylog_callback(octx->ssl_ctx, ossl_keylog_callback);
  }
#endif

  if(cb_new_session) {
    /* Enable the session cache because it is a prerequisite for the
     * "new session" callback. Use the "external storage" mode to prevent
     * OpenSSL from creating an internal session cache.
     */
    SSL_CTX_set_session_cache_mode(octx->ssl_ctx,
                                   SSL_SESS_CACHE_CLIENT |
                                   SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(octx->ssl_ctx, cb_new_session);
  }

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    /* When a user callback is installed to modify the SSL_CTX,
     * we need to do the full initialization before calling it.
     * See: #11800 */
    if(!octx->x509_store_setup) {
      result = Curl_ssl_setup_x509_store(cf, data, octx->ssl_ctx);
      if(result)
        return result;
      octx->x509_store_setup = TRUE;
    }
    Curl_set_in_callback(data, true);
    result = (*data->set.ssl.fsslctx)(data, octx->ssl_ctx,
                                      data->set.ssl.fsslctxp);
    Curl_set_in_callback(data, false);
    if(result) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }

  /* Let's make an SSL structure */
  if(octx->ssl)
    SSL_free(octx->ssl);
  octx->ssl = SSL_new(octx->ssl_ctx);
  if(!octx->ssl) {
    failf(data, "SSL: could not create a context (handle)");
    return CURLE_OUT_OF_MEMORY;
  }

  SSL_set_app_data(octx->ssl, ssl_user_data);

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
  !defined(OPENSSL_NO_OCSP)
  if(conn_config->verifystatus)
    SSL_set_tlsext_status_type(octx->ssl, TLSEXT_STATUSTYPE_ocsp);
#endif

#if (defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)) && \
    defined(ALLOW_RENEG)
  SSL_set_renegotiate_mode(octx->ssl, ssl_renegotiate_freely);
#endif

  SSL_set_connect_state(octx->ssl);

  octx->server_cert = 0x0;
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
  if(peer->sni) {
    if(!SSL_set_tlsext_host_name(octx->ssl, peer->sni)) {
      failf(data, "Failed set SNI");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

#ifdef USE_ECH
  if(ECH_ENABLED(data)) {
    unsigned char *ech_config = NULL;
    size_t ech_config_len = 0;
    char *outername = data->set.str[STRING_ECH_PUBLIC];
    int trying_ech_now = 0;

    if(data->set.tls_ech & CURLECH_GREASE) {
      infof(data, "ECH: will GREASE ClientHello");
# ifdef OPENSSL_IS_BORINGSSL
      SSL_set_enable_ech_grease(octx->ssl, 1);
# else
      SSL_set_options(octx->ssl, SSL_OP_ECH_GREASE);
# endif
    }
    else if(data->set.tls_ech & CURLECH_CLA_CFG) {
# ifdef OPENSSL_IS_BORINGSSL
      /* have to do base64 decode here for boring */
      const char *b64 = data->set.str[STRING_ECH_CONFIG];

      if(!b64) {
        infof(data, "ECH: ECHConfig from command line empty");
        return CURLE_SSL_CONNECT_ERROR;
      }
      ech_config_len = 2 * strlen(b64);
      result = Curl_base64_decode(b64, &ech_config, &ech_config_len);
      if(result || !ech_config) {
        infof(data, "ECH: cannot base64 decode ECHConfig from command line");
        if(data->set.tls_ech & CURLECH_HARD)
          return result;
      }
      if(SSL_set1_ech_config_list(octx->ssl, ech_config,
                                  ech_config_len) != 1) {
        infof(data, "ECH: SSL_ECH_set1_echconfig failed");
        if(data->set.tls_ech & CURLECH_HARD) {
          free(ech_config);
          return CURLE_SSL_CONNECT_ERROR;
        }
      }
      free(ech_config);
      trying_ech_now = 1;
# else
      ech_config = (unsigned char *) data->set.str[STRING_ECH_CONFIG];
      if(!ech_config) {
        infof(data, "ECH: ECHConfig from command line empty");
        return CURLE_SSL_CONNECT_ERROR;
      }
      ech_config_len = strlen(data->set.str[STRING_ECH_CONFIG]);
      if(SSL_ech_set1_echconfig(octx->ssl, ech_config, ech_config_len) != 1) {
        infof(data, "ECH: SSL_ECH_set1_echconfig failed");
        if(data->set.tls_ech & CURLECH_HARD)
          return CURLE_SSL_CONNECT_ERROR;
      }
      else
        trying_ech_now = 1;
# endif
      infof(data, "ECH: ECHConfig from command line");
    }
    else {
      struct Curl_dns_entry *dns = NULL;

      if(peer->hostname)
        dns = Curl_fetch_addr(data, peer->hostname, peer->port);
      if(!dns) {
        infof(data, "ECH: requested but no DNS info available");
        if(data->set.tls_ech & CURLECH_HARD)
          return CURLE_SSL_CONNECT_ERROR;
      }
      else {
        struct Curl_https_rrinfo *rinfo = NULL;

        rinfo = dns->hinfo;
        if(rinfo && rinfo->echconfiglist) {
          unsigned char *ecl = rinfo->echconfiglist;
          size_t elen = rinfo->echconfiglist_len;

          infof(data, "ECH: ECHConfig from DoH HTTPS RR");
# ifndef OPENSSL_IS_BORINGSSL
          if(SSL_ech_set1_echconfig(octx->ssl, ecl, elen) != 1) {
            infof(data, "ECH: SSL_ECH_set1_echconfig failed");
            if(data->set.tls_ech & CURLECH_HARD)
              return CURLE_SSL_CONNECT_ERROR;
          }
# else
          if(SSL_set1_ech_config_list(octx->ssl, ecl, elen) != 1) {
            infof(data, "ECH: SSL_set1_ech_config_list failed (boring)");
            if(data->set.tls_ech & CURLECH_HARD)
              return CURLE_SSL_CONNECT_ERROR;
          }
# endif
          else {
            trying_ech_now = 1;
            infof(data, "ECH: imported ECHConfigList of length %zu", elen);
          }
        }
        else {
          infof(data, "ECH: requested but no ECHConfig available");
          if(data->set.tls_ech & CURLECH_HARD)
            return CURLE_SSL_CONNECT_ERROR;
        }
        Curl_resolv_unlock(data, dns);
      }
    }
# ifdef OPENSSL_IS_BORINGSSL
    if(trying_ech_now && outername) {
      infof(data, "ECH: setting public_name not supported with BoringSSL");
      return CURLE_SSL_CONNECT_ERROR;
    }
# else
    if(trying_ech_now && outername) {
      infof(data, "ECH: inner: '%s', outer: '%s'",
            peer->hostname ? peer->hostname : "NULL", outername);
      result = SSL_ech_set_server_names(octx->ssl,
                                        peer->hostname, outername,
                                        0 /* do send outer */);
      if(result != 1) {
        infof(data, "ECH: rv failed to set server name(s) %d [ERROR]", result);
        return CURLE_SSL_CONNECT_ERROR;
      }
    }
# endif  /* not BORING */
    if(trying_ech_now
       && SSL_set_min_proto_version(octx->ssl, TLS1_3_VERSION) != 1) {
      infof(data, "ECH: cannot force TLSv1.3 [ERROR]");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
#endif  /* USE_ECH */

#endif

  octx->reused_session = FALSE;
  if(ssl_config->primary.cache_session && transport == TRNSPRT_TCP) {
    Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(cf, data, peer, &ssl_sessionid, NULL)) {
      /* we got a session id, use it! */
      if(!SSL_set_session(octx->ssl, ssl_sessionid)) {
        Curl_ssl_sessionid_unlock(data);
        failf(data, "SSL: SSL_set_session failed: %s",
              ossl_strerror(ERR_get_error(), error_buffer,
                            sizeof(error_buffer)));
        return CURLE_SSL_CONNECT_ERROR;
      }
      /* Informational message */
      infof(data, "SSL reusing session ID");
      octx->reused_session = TRUE;
    }
    Curl_ssl_sessionid_unlock(data);
  }

  return CURLE_OK;
}

static CURLcode ossl_connect_step1(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;
  struct alpn_proto_buf proto;
  BIO *bio;
  CURLcode result;

  DEBUGASSERT(ssl_connect_1 == connssl->connecting_state);
  DEBUGASSERT(octx);
  memset(&proto, 0, sizeof(proto));
#ifdef HAS_ALPN
  if(connssl->alpn) {
    result = Curl_alpn_to_proto_buf(&proto, connssl->alpn);
    if(result) {
      failf(data, "Error determining ALPN");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
#endif

  result = Curl_ossl_ctx_init(octx, cf, data, &connssl->peer, TRNSPRT_TCP,
                              proto.data, proto.len, NULL, NULL,
                              ossl_new_session_cb, cf);
  if(result)
    return result;

  octx->bio_method = ossl_bio_cf_method_create();
  if(!octx->bio_method)
    return CURLE_OUT_OF_MEMORY;
  bio = BIO_new(octx->bio_method);
  if(!bio)
    return CURLE_OUT_OF_MEMORY;

  BIO_set_data(bio, cf);
#ifdef HAVE_SSL_SET0_WBIO
  /* with OpenSSL v1.1.1 we get an alternative to SSL_set_bio() that works
   * without backward compat quirks. Every call takes one reference, so we
   * up it and pass. SSL* then owns it and will free.
   * We check on the function in configure, since LibreSSL and friends
   * each have their own versions to add support for this. */
  BIO_up_ref(bio);
  SSL_set0_rbio(octx->ssl, bio);
  SSL_set0_wbio(octx->ssl, bio);
#else
  SSL_set_bio(octx->ssl, bio, bio);
#endif

#ifdef HAS_ALPN
  if(connssl->alpn) {
    Curl_alpn_to_proto_str(&proto, connssl->alpn);
    infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
  }
#endif
  connssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}

#ifdef USE_ECH
/* If we have retry configs, then trace those out */
static void ossl_trace_ech_retry_configs(struct Curl_easy *data, SSL* ssl,
                                         int reason)
{
  CURLcode result = CURLE_OK;
  size_t rcl = 0;
  int rv = 1;
# ifndef OPENSSL_IS_BORINGSSL
  char *inner = NULL;
  unsigned char *rcs = NULL;
  char *outer = NULL;
# else
  const char *inner = NULL;
  const uint8_t *rcs = NULL;
  const char *outer = NULL;
  size_t out_name_len = 0;
  int servername_type = 0;
# endif

  /* nothing to trace if not doing ECH */
  if(!ECH_ENABLED(data))
    return;
# ifndef OPENSSL_IS_BORINGSSL
  rv = SSL_ech_get_retry_config(ssl, &rcs, &rcl);
# else
  SSL_get0_ech_retry_configs(ssl, &rcs, &rcl);
  rv = (int)rcl;
# endif

  if(rv && rcs) {
# define HEXSTR_MAX 800
    char *b64str = NULL;
    size_t blen = 0;

    result = Curl_base64_encode((const char *)rcs, rcl,
                                &b64str, &blen);
    if(!result && b64str)
      infof(data, "ECH: retry_configs %s", b64str);
    free(b64str);
# ifndef OPENSSL_IS_BORINGSSL
    rv = SSL_ech_get_status(ssl, &inner, &outer);
    infof(data, "ECH: retry_configs for %s from %s, %d %d",
          inner ? inner : "NULL", outer ? outer : "NULL", reason, rv);
#else
    rv = SSL_ech_accepted(ssl);
    servername_type = SSL_get_servername_type(ssl);
    inner = SSL_get_servername(ssl, servername_type);
    SSL_get0_ech_name_override(ssl, &outer, &out_name_len);
    /* TODO: get the inner from boring */
    infof(data, "ECH: retry_configs for %s from %s, %d %d",
          inner ? inner : "NULL", outer ? outer : "NULL", reason, rv);
#endif
  }
  else
    infof(data, "ECH: no retry_configs (rv = %d)", rv);
# ifndef OPENSSL_IS_BORINGSSL
  OPENSSL_free((void *)rcs);
# endif
  return;
}

#endif

static CURLcode ossl_connect_step2(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  int err;
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  DEBUGASSERT(ssl_connect_2 == connssl->connecting_state);
  DEBUGASSERT(octx);

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  ERR_clear_error();

  err = SSL_connect(octx->ssl);

  if(!octx->x509_store_setup) {
    /* After having send off the ClientHello, we prepare the x509
     * store to verify the coming certificate from the server */
    CURLcode result = Curl_ssl_setup_x509_store(cf, data, octx->ssl_ctx);
    if(result)
      return result;
    octx->x509_store_setup = TRUE;
  }

#ifndef HAVE_KEYLOG_CALLBACK
  /* If key logging is enabled, wait for the handshake to complete and then
   * proceed with logging secrets (for TLS 1.2 or older).
   */
  if(Curl_tls_keylog_enabled() && !octx->keylog_done)
    ossl_log_tls12_secret(octx->ssl, &octx->keylog_done);
#endif

  /* 1  is fine
     0  is "not successful but was shut down controlled"
     <0 is "handshake was not successful, because a fatal error occurred" */
  if(1 != err) {
    int detail = SSL_get_error(octx->ssl, err);

    if(SSL_ERROR_WANT_READ == detail) {
      connssl->io_need = CURL_SSL_IO_NEED_RECV;
      return CURLE_OK;
    }
    if(SSL_ERROR_WANT_WRITE == detail) {
      connssl->io_need = CURL_SSL_IO_NEED_SEND;
      return CURLE_OK;
    }
#ifdef SSL_ERROR_WANT_ASYNC
    if(SSL_ERROR_WANT_ASYNC == detail) {
      connssl->connecting_state = ssl_connect_2;
      return CURLE_OK;
    }
#endif
#ifdef SSL_ERROR_WANT_RETRY_VERIFY
    if(SSL_ERROR_WANT_RETRY_VERIFY == detail) {
      connssl->connecting_state = ssl_connect_2;
      return CURLE_OK;
    }
#endif
    if(octx->io_result == CURLE_AGAIN) {
      return CURLE_OK;
    }
    else {
      /* untreated error */
      sslerr_t errdetail;
      char error_buffer[256]="";
      CURLcode result;
      long lerr;
      int lib;
      int reason;

      /* the connection failed, we are not waiting for anything else. */
      connssl->connecting_state = ssl_connect_2;

      /* Get the earliest error code from the thread's error queue and remove
         the entry. */
      errdetail = ERR_get_error();

      /* Extract which lib and reason */
      lib = ERR_GET_LIB(errdetail);
      reason = ERR_GET_REASON(errdetail);

      if((lib == ERR_LIB_SSL) &&
         ((reason == SSL_R_CERTIFICATE_VERIFY_FAILED) ||
          (reason == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED))) {
        result = CURLE_PEER_FAILED_VERIFICATION;

        lerr = SSL_get_verify_result(octx->ssl);
        if(lerr != X509_V_OK) {
          ssl_config->certverifyresult = lerr;
          msnprintf(error_buffer, sizeof(error_buffer),
                    "SSL certificate problem: %s",
                    X509_verify_cert_error_string(lerr));
        }
        else
          /* strcpy() is fine here as long as the string fits within
             error_buffer */
          strcpy(error_buffer, "SSL certificate verification failed");
      }
#if defined(SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED)
      /* SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED is only available on
         OpenSSL version above v1.1.1, not LibreSSL, BoringSSL, or AWS-LC */
      else if((lib == ERR_LIB_SSL) &&
              (reason == SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED)) {
        /* If client certificate is required, communicate the
           error to client */
        result = CURLE_SSL_CLIENTCERT;
        ossl_strerror(errdetail, error_buffer, sizeof(error_buffer));
      }
#endif
#ifdef USE_ECH
      else if((lib == ERR_LIB_SSL) &&
# ifndef OPENSSL_IS_BORINGSSL
              (reason == SSL_R_ECH_REQUIRED)) {
# else
              (reason == SSL_R_ECH_REJECTED)) {
# endif

        /* trace retry_configs if we got some */
        ossl_trace_ech_retry_configs(data, octx->ssl, reason);

        result = CURLE_ECH_REQUIRED;
        ossl_strerror(errdetail, error_buffer, sizeof(error_buffer));
      }
#endif
      else {
        result = CURLE_SSL_CONNECT_ERROR;
        ossl_strerror(errdetail, error_buffer, sizeof(error_buffer));
      }

      /* detail is already set to the SSL error above */

      /* If we e.g. use SSLv2 request-method and the server does not like us
       * (RST connection, etc.), OpenSSL gives no explanation whatsoever and
       * the SO_ERROR is also lost.
       */
      if(CURLE_SSL_CONNECT_ERROR == result && errdetail == 0) {
        char extramsg[80]="";
        int sockerr = SOCKERRNO;

        if(sockerr && detail == SSL_ERROR_SYSCALL)
          Curl_strerror(sockerr, extramsg, sizeof(extramsg));
        failf(data, OSSL_PACKAGE " SSL_connect: %s in connection to %s:%d ",
              extramsg[0] ? extramsg : SSL_ERROR_to_str(detail),
              connssl->peer.hostname, connssl->peer.port);
        return result;
      }

      /* Could be a CERT problem */
      failf(data, "%s", error_buffer);

      return result;
    }
  }
  else {
    int psigtype_nid = NID_undef;
    const char *negotiated_group_name = NULL;

    /* we connected fine, we are not waiting for anything else. */
    connssl->connecting_state = ssl_connect_3;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    SSL_get_peer_signature_type_nid(octx->ssl, &psigtype_nid);
#if (OPENSSL_VERSION_NUMBER >= 0x30200000L)
    negotiated_group_name = SSL_get0_group_name(octx->ssl);
#else
    negotiated_group_name =
      OBJ_nid2sn(SSL_get_negotiated_group(octx->ssl) & 0x0000FFFF);
#endif
#endif

    /* Informational message */
    infof(data, "SSL connection using %s / %s / %s / %s",
          SSL_get_version(octx->ssl),
          SSL_get_cipher(octx->ssl),
          negotiated_group_name? negotiated_group_name : "[blank]",
          OBJ_nid2sn(psigtype_nid));

#ifdef USE_ECH
# ifndef OPENSSL_IS_BORINGSSL
    if(ECH_ENABLED(data)) {
      char *inner = NULL, *outer = NULL;
      const char *status = NULL;
      int rv;

      rv = SSL_ech_get_status(octx->ssl, &inner, &outer);
      switch(rv) {
      case SSL_ECH_STATUS_SUCCESS:
        status = "succeeded";
        break;
      case SSL_ECH_STATUS_GREASE_ECH:
        status = "sent GREASE, got retry-configs";
        break;
      case SSL_ECH_STATUS_GREASE:
        status = "sent GREASE";
        break;
      case SSL_ECH_STATUS_NOT_TRIED:
        status = "not attempted";
        break;
      case SSL_ECH_STATUS_NOT_CONFIGURED:
        status = "not configured";
        break;
      case SSL_ECH_STATUS_BACKEND:
        status = "backend (unexpected)";
        break;
      case SSL_ECH_STATUS_FAILED:
        status = "failed";
        break;
      case SSL_ECH_STATUS_BAD_CALL:
        status = "bad call (unexpected)";
        break;
      case SSL_ECH_STATUS_BAD_NAME:
        status = "bad name (unexpected)";
        break;
      default:
        status = "unexpected status";
        infof(data, "ECH: unexpected status %d",rv);
      }
      infof(data, "ECH: result: status is %s, inner is %s, outer is %s",
             (status?status:"NULL"),
             (inner?inner:"NULL"),
             (outer?outer:"NULL"));
      OPENSSL_free(inner);
      OPENSSL_free(outer);
      if(rv == SSL_ECH_STATUS_GREASE_ECH) {
        /* trace retry_configs if we got some */
        ossl_trace_ech_retry_configs(data, octx->ssl, 0);
      }
      if(rv != SSL_ECH_STATUS_SUCCESS
         && data->set.tls_ech & CURLECH_HARD) {
        infof(data, "ECH: ech-hard failed");
        return CURLE_SSL_CONNECT_ERROR;
      }
   }
   else {
      infof(data, "ECH: result: status is not attempted");
   }
# endif  /* BORING */
#endif  /* USE_ECH */

#ifdef HAS_ALPN
    /* Sets data and len to negotiated protocol, len is 0 if no protocol was
     * negotiated
     */
    if(connssl->alpn) {
      const unsigned char *neg_protocol;
      unsigned int len;
      SSL_get0_alpn_selected(octx->ssl, &neg_protocol, &len);

      return Curl_alpn_set_negotiated(cf, data, neg_protocol, len);
    }
#endif

    return CURLE_OK;
  }
}

/*
 * Heavily modified from:
 * https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#OpenSSL
 */
static CURLcode ossl_pkp_pin_peer_pubkey(struct Curl_easy *data, X509* cert,
                                         const char *pinnedpubkey)
{
  /* Scratch */
  int len1 = 0, len2 = 0;
  unsigned char *buff1 = NULL, *temp = NULL;

  /* Result is returned to caller */
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  /* if a path was not specified, do not pin */
  if(!pinnedpubkey)
    return CURLE_OK;

  if(!cert)
    return result;

  do {
    /* Begin Gyrations to get the subjectPublicKeyInfo     */
    /* Thanks to Viktor Dukhovni on the OpenSSL mailing list */

    /* https://groups.google.com/group/mailing.openssl.users/browse_thread
       /thread/d61858dae102c6c7 */
    len1 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
    if(len1 < 1)
      break; /* failed */

    buff1 = temp = malloc(len1);
    if(!buff1)
      break; /* failed */

    /* https://docs.openssl.org/master/man3/d2i_X509/ */
    len2 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &temp);

    /*
     * These checks are verifying we got back the same values as when we
     * sized the buffer. it is pretty weak since they should always be the
     * same. But it gives us something to test.
     */
    if((len1 != len2) || !temp || ((temp - buff1) != len1))
      break; /* failed */

    /* End Gyrations */

    /* The one good exit point */
    result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1);
  } while(0);

  if(buff1)
    free(buff1);

  return result;
}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) &&  \
  !(defined(LIBRESSL_VERSION_NUMBER) && \
    LIBRESSL_VERSION_NUMBER < 0x3060000fL) && \
  !defined(OPENSSL_IS_BORINGSSL) && \
  !defined(OPENSSL_IS_AWSLC) && \
  !defined(CURL_DISABLE_VERBOSE_STRINGS)
static void infof_certstack(struct Curl_easy *data, const SSL *ssl)
{
  STACK_OF(X509) *certstack;
  long verify_result;
  int num_cert_levels;
  int cert_level;

  verify_result = SSL_get_verify_result(ssl);
  if(verify_result != X509_V_OK)
    certstack = SSL_get_peer_cert_chain(ssl);
  else
    certstack = SSL_get0_verified_chain(ssl);
  num_cert_levels = sk_X509_num(certstack);

  for(cert_level = 0; cert_level < num_cert_levels; cert_level++) {
    char cert_algorithm[80] = "";
    char group_name_final[80] = "";
    const X509_ALGOR *palg_cert = NULL;
    const ASN1_OBJECT *paobj_cert = NULL;
    X509 *current_cert;
    EVP_PKEY *current_pkey;
    int key_bits;
    int key_sec_bits;
    int get_group_name;
    const char *type_name;

    current_cert = sk_X509_value(certstack, cert_level);

    X509_get0_signature(NULL, &palg_cert, current_cert);
    X509_ALGOR_get0(&paobj_cert, NULL, NULL, palg_cert);
    OBJ_obj2txt(cert_algorithm, sizeof(cert_algorithm), paobj_cert, 0);

    current_pkey = X509_get0_pubkey(current_cert);
    key_bits = EVP_PKEY_bits(current_pkey);
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
#define EVP_PKEY_get_security_bits EVP_PKEY_security_bits
#endif
    key_sec_bits = EVP_PKEY_get_security_bits(current_pkey);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    {
      char group_name[80] = "";
      get_group_name = EVP_PKEY_get_group_name(current_pkey, group_name,
                                               sizeof(group_name), NULL);
      msnprintf(group_name_final, sizeof(group_name_final), "/%s", group_name);
    }
    type_name = EVP_PKEY_get0_type_name(current_pkey);
#else
    get_group_name = 0;
    type_name = NULL;
#endif

    infof(data,
          "  Certificate level %d: "
          "Public key type %s%s (%d/%d Bits/secBits), signed using %s",
          cert_level, type_name ? type_name : "?",
          get_group_name == 0 ? "" : group_name_final,
          key_bits, key_sec_bits, cert_algorithm);
  }
}
#else
#define infof_certstack(data, ssl)
#endif

CURLcode Curl_oss_check_peer_cert(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct ossl_ctx *octx,
                                  struct ssl_peer *peer)
{
  struct connectdata *conn = cf->conn;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  CURLcode result = CURLE_OK;
  int rc;
  long lerr;
  X509 *issuer;
  BIO *fp = NULL;
  char error_buffer[256]="";
  char buffer[2048];
  const char *ptr;
  BIO *mem = BIO_new(BIO_s_mem());
  bool strict = (conn_config->verifypeer || conn_config->verifyhost);

  DEBUGASSERT(octx);

  if(!mem) {
    failf(data,
          "BIO_new return NULL, " OSSL_PACKAGE
          " error %s",
          ossl_strerror(ERR_get_error(), error_buffer,
                        sizeof(error_buffer)) );
    return CURLE_OUT_OF_MEMORY;
  }

  if(data->set.ssl.certinfo)
    /* asked to gather certificate info */
    (void)Curl_ossl_certchain(data, octx->ssl);

  octx->server_cert = SSL_get1_peer_certificate(octx->ssl);
  if(!octx->server_cert) {
    BIO_free(mem);
    if(!strict)
      return CURLE_OK;

    failf(data, "SSL: could not get peer certificate");
    return CURLE_PEER_FAILED_VERIFICATION;
  }

  infof(data, "%s certificate:",
        Curl_ssl_cf_is_proxy(cf)? "Proxy" : "Server");

  rc = x509_name_oneline(X509_get_subject_name(octx->server_cert),
                         buffer, sizeof(buffer));
  infof(data, " subject: %s", rc?"[NONE]":buffer);

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  {
    long len;
    ASN1_TIME_print(mem, X509_get0_notBefore(octx->server_cert));
    len = BIO_get_mem_data(mem, (char **) &ptr);
    infof(data, " start date: %.*s", (int)len, ptr);
    (void)BIO_reset(mem);

    ASN1_TIME_print(mem, X509_get0_notAfter(octx->server_cert));
    len = BIO_get_mem_data(mem, (char **) &ptr);
    infof(data, " expire date: %.*s", (int)len, ptr);
    (void)BIO_reset(mem);
  }
#endif

  BIO_free(mem);

  if(conn_config->verifyhost) {
    result = Curl_ossl_verifyhost(data, conn, peer, octx->server_cert);
    if(result) {
      X509_free(octx->server_cert);
      octx->server_cert = NULL;
      return result;
    }
  }

  rc = x509_name_oneline(X509_get_issuer_name(octx->server_cert),
                         buffer, sizeof(buffer));
  if(rc) {
    if(strict)
      failf(data, "SSL: could not get X509-issuer name");
    result = CURLE_PEER_FAILED_VERIFICATION;
  }
  else {
    infof(data, " issuer: %s", buffer);

    /* We could do all sorts of certificate verification stuff here before
       deallocating the certificate. */

    /* e.g. match issuer name with provided issuer certificate */
    if(conn_config->issuercert || conn_config->issuercert_blob) {
      if(conn_config->issuercert_blob) {
        fp = BIO_new_mem_buf(conn_config->issuercert_blob->data,
                             (int)conn_config->issuercert_blob->len);
        if(!fp) {
          failf(data,
                "BIO_new_mem_buf NULL, " OSSL_PACKAGE
                " error %s",
                ossl_strerror(ERR_get_error(), error_buffer,
                              sizeof(error_buffer)) );
          X509_free(octx->server_cert);
          octx->server_cert = NULL;
          return CURLE_OUT_OF_MEMORY;
        }
      }
      else {
        fp = BIO_new(BIO_s_file());
        if(!fp) {
          failf(data,
                "BIO_new return NULL, " OSSL_PACKAGE
                " error %s",
                ossl_strerror(ERR_get_error(), error_buffer,
                              sizeof(error_buffer)) );
          X509_free(octx->server_cert);
          octx->server_cert = NULL;
          return CURLE_OUT_OF_MEMORY;
        }

        if(BIO_read_filename(fp, conn_config->issuercert) <= 0) {
          if(strict)
            failf(data, "SSL: Unable to open issuer cert (%s)",
                  conn_config->issuercert);
          BIO_free(fp);
          X509_free(octx->server_cert);
          octx->server_cert = NULL;
          return CURLE_SSL_ISSUER_ERROR;
        }
      }

      issuer = PEM_read_bio_X509(fp, NULL, ZERO_NULL, NULL);
      if(!issuer) {
        if(strict)
          failf(data, "SSL: Unable to read issuer cert (%s)",
                conn_config->issuercert);
        BIO_free(fp);
        X509_free(issuer);
        X509_free(octx->server_cert);
        octx->server_cert = NULL;
        return CURLE_SSL_ISSUER_ERROR;
      }

      if(X509_check_issued(issuer, octx->server_cert) != X509_V_OK) {
        if(strict)
          failf(data, "SSL: Certificate issuer check failed (%s)",
                conn_config->issuercert);
        BIO_free(fp);
        X509_free(issuer);
        X509_free(octx->server_cert);
        octx->server_cert = NULL;
        return CURLE_SSL_ISSUER_ERROR;
      }

      infof(data, " SSL certificate issuer check ok (%s)",
            conn_config->issuercert);
      BIO_free(fp);
      X509_free(issuer);
    }

    lerr = SSL_get_verify_result(octx->ssl);
    ssl_config->certverifyresult = lerr;
    if(lerr != X509_V_OK) {
      if(conn_config->verifypeer) {
        /* We probably never reach this, because SSL_connect() will fail
           and we return earlier if verifypeer is set? */
        if(strict)
          failf(data, "SSL certificate verify result: %s (%ld)",
                X509_verify_cert_error_string(lerr), lerr);
        result = CURLE_PEER_FAILED_VERIFICATION;
      }
      else
        infof(data, " SSL certificate verify result: %s (%ld),"
              " continuing anyway.",
              X509_verify_cert_error_string(lerr), lerr);
    }
    else
      infof(data, " SSL certificate verify ok.");
  }

  infof_certstack(data, octx->ssl);

#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
  !defined(OPENSSL_NO_OCSP)
  if(conn_config->verifystatus && !octx->reused_session) {
    /* do not do this after Session ID reuse */
    result = verifystatus(cf, data, octx);
    if(result) {
      /* when verifystatus failed, remove the session id from the cache again
         if present */
      if(!Curl_ssl_cf_is_proxy(cf)) {
        void *old_ssl_sessionid = NULL;
        bool incache;
        Curl_ssl_sessionid_lock(data);
        incache = !(Curl_ssl_getsessionid(cf, data, peer,
                                          &old_ssl_sessionid, NULL));
        if(incache) {
          infof(data, "Remove session ID again from cache");
          Curl_ssl_delsessionid(data, old_ssl_sessionid);
        }
        Curl_ssl_sessionid_unlock(data);
      }

      X509_free(octx->server_cert);
      octx->server_cert = NULL;
      return result;
    }
  }
#endif

  if(!strict)
    /* when not strict, we do not bother about the verify cert problems */
    result = CURLE_OK;

#ifndef CURL_DISABLE_PROXY
  ptr = Curl_ssl_cf_is_proxy(cf)?
    data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY]:
    data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#else
  ptr = data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#endif
  if(!result && ptr) {
    result = ossl_pkp_pin_peer_pubkey(data, octx->server_cert, ptr);
    if(result)
      failf(data, "SSL: public key does not match pinned public key");
  }

  X509_free(octx->server_cert);
  octx->server_cert = NULL;

  return result;
}

static CURLcode ossl_connect_step3(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  /*
   * We check certificates to authenticate the server; otherwise we risk
   * man-in-the-middle attack; NEVERTHELESS, if we are told explicitly not to
   * verify the peer, ignore faults and failures from the server cert
   * operations.
   */

  result = Curl_oss_check_peer_cert(cf, data, octx, &connssl->peer);
  if(!result)
    connssl->connecting_state = ssl_connect_done;

  return result;
}

static CURLcode ossl_connect_common(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool nonblocking,
                                    bool *done)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Find out how much more time we are allowed */
    const timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time is already up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    result = ossl_connect_step1(cf, data);
    if(result)
      goto out;
  }

  while(ssl_connect_2 == connssl->connecting_state) {

    /* check allowed time left */
    const timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      result = CURLE_OPERATION_TIMEDOUT;
      goto out;
    }

    /* if ssl is expecting something, check if it is available. */
    if(!nonblocking && connssl->io_need) {

      curl_socket_t writefd = (connssl->io_need & CURL_SSL_IO_NEED_SEND)?
                              sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = (connssl->io_need & CURL_SSL_IO_NEED_RECV)?
                             sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
                               timeout_ms);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        result = CURLE_SSL_CONNECT_ERROR;
        goto out;
      }
      if(0 == what) {
        /* timeout */
        failf(data, "SSL connection timeout");
        result = CURLE_OPERATION_TIMEDOUT;
        goto out;
      }
      /* socket is readable or writable */
    }

    /* Run transaction, and return to the caller if it failed or if this
     * connection is done nonblocking and this loop would execute again. This
     * permits the owner of a multi handle to abort a connection attempt
     * before step2 has completed while ensuring that a client using select()
     * or epoll() will always have a valid fdset to wait on.
     */
    result = ossl_connect_step2(cf, data);
    if(result || (nonblocking && (ssl_connect_2 == connssl->connecting_state)))
      goto out;

  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    result = ossl_connect_step3(cf, data);
    if(result)
      goto out;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

out:
  return result;
}

static CURLcode ossl_connect_nonblocking(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         bool *done)
{
  return ossl_connect_common(cf, data, TRUE, done);
}

static CURLcode ossl_connect(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  CURLcode result;
  bool done = FALSE;

  result = ossl_connect_common(cf, data, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static bool ossl_data_pending(struct Curl_cfilter *cf,
                              const struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;

  (void)data;
  DEBUGASSERT(connssl && octx);
  if(octx->ssl && SSL_pending(octx->ssl))
    return TRUE;
  return FALSE;
}

static ssize_t ossl_send(struct Curl_cfilter *cf,
                         struct Curl_easy *data,
                         const void *mem,
                         size_t len,
                         CURLcode *curlcode)
{
  /* SSL_write() is said to return 'int' while write() and send() returns
     'size_t' */
  int err;
  char error_buffer[256];
  sslerr_t sslerror;
  int memlen;
  int rc;
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;

  (void)data;
  DEBUGASSERT(octx);

  ERR_clear_error();

  memlen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  rc = SSL_write(octx->ssl, mem, memlen);

  if(rc <= 0) {
    err = SSL_get_error(octx->ssl, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* The operation did not complete; the same TLS/SSL I/O function
         should be called again later. This is basically an EWOULDBLOCK
         equivalent. */
      *curlcode = CURLE_AGAIN;
      rc = -1;
      goto out;
    case SSL_ERROR_SYSCALL:
    {
      int sockerr = SOCKERRNO;

      if(octx->io_result == CURLE_AGAIN) {
        *curlcode = CURLE_AGAIN;
        rc = -1;
        goto out;
      }
      sslerror = ERR_get_error();
      if(sslerror)
        ossl_strerror(sslerror, error_buffer, sizeof(error_buffer));
      else if(sockerr)
        Curl_strerror(sockerr, error_buffer, sizeof(error_buffer));
      else
        msnprintf(error_buffer, sizeof(error_buffer), "%s",
                  SSL_ERROR_to_str(err));

      failf(data, OSSL_PACKAGE " SSL_write: %s, errno %d",
            error_buffer, sockerr);
      *curlcode = CURLE_SEND_ERROR;
      rc = -1;
      goto out;
    }
    case SSL_ERROR_SSL: {
      /*  A failure in the SSL library occurred, usually a protocol error.
          The OpenSSL error queue contains more information on the error. */
      sslerror = ERR_get_error();
      failf(data, "SSL_write() error: %s",
            ossl_strerror(sslerror, error_buffer, sizeof(error_buffer)));
      *curlcode = CURLE_SEND_ERROR;
      rc = -1;
      goto out;
    }
    default:
      /* a true error */
      failf(data, OSSL_PACKAGE " SSL_write: %s, errno %d",
            SSL_ERROR_to_str(err), SOCKERRNO);
      *curlcode = CURLE_SEND_ERROR;
      rc = -1;
      goto out;
    }
  }
  *curlcode = CURLE_OK;

out:
  return (ssize_t)rc; /* number of bytes */
}

static ssize_t ossl_recv(struct Curl_cfilter *cf,
                         struct Curl_easy *data,   /* transfer */
                         char *buf,                /* store read data here */
                         size_t buffersize,        /* max amount to read */
                         CURLcode *curlcode)
{
  char error_buffer[256];
  unsigned long sslerror;
  ssize_t nread;
  int buffsize;
  struct connectdata *conn = cf->conn;
  struct ssl_connect_data *connssl = cf->ctx;
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;

  (void)data;
  DEBUGASSERT(octx);

  ERR_clear_error();

  buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  nread = (ssize_t)SSL_read(octx->ssl, buf, buffsize);

  if(nread <= 0) {
    /* failed SSL_read */
    int err = SSL_get_error(octx->ssl, (int)nread);

    switch(err) {
    case SSL_ERROR_NONE: /* this is not an error */
      break;
    case SSL_ERROR_ZERO_RETURN: /* no more data */
      /* close_notify alert */
      if(cf->sockindex == FIRSTSOCKET)
        /* mark the connection for close if it is indeed the control
           connection */
        connclose(conn, "TLS close_notify");
      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* there is data pending, re-invoke SSL_read() */
      *curlcode = CURLE_AGAIN;
      nread = -1;
      goto out;
    default:
      /* openssl/ssl.h for SSL_ERROR_SYSCALL says "look at error stack/return
         value/errno" */
      /* https://docs.openssl.org/master/man3/ERR_get_error/ */
      if(octx->io_result == CURLE_AGAIN) {
        *curlcode = CURLE_AGAIN;
        nread = -1;
        goto out;
      }
      sslerror = ERR_get_error();
      if((nread < 0) || sslerror) {
        /* If the return code was negative or there actually is an error in the
           queue */
        int sockerr = SOCKERRNO;
        if(sslerror)
          ossl_strerror(sslerror, error_buffer, sizeof(error_buffer));
        else if(sockerr && err == SSL_ERROR_SYSCALL)
          Curl_strerror(sockerr, error_buffer, sizeof(error_buffer));
        else
          msnprintf(error_buffer, sizeof(error_buffer), "%s",
                    SSL_ERROR_to_str(err));
        failf(data, OSSL_PACKAGE " SSL_read: %s, errno %d",
              error_buffer, sockerr);
        *curlcode = CURLE_RECV_ERROR;
        nread = -1;
        goto out;
      }
      /* For debug builds be a little stricter and error on any
         SSL_ERROR_SYSCALL. For example a server may have closed the connection
         abruptly without a close_notify alert. For compatibility with older
         peers we do not do this by default. #4624

         We can use this to gauge how many users may be affected, and
         if it goes ok eventually transition to allow in dev and release with
         the newest OpenSSL: #if (OPENSSL_VERSION_NUMBER >= 0x10101000L) */
#ifdef DEBUGBUILD
      if(err == SSL_ERROR_SYSCALL) {
        int sockerr = SOCKERRNO;
        if(sockerr)
          Curl_strerror(sockerr, error_buffer, sizeof(error_buffer));
        else {
          msnprintf(error_buffer, sizeof(error_buffer),
                    "Connection closed abruptly");
        }
        failf(data, OSSL_PACKAGE " SSL_read: %s, errno %d"
              " (Fatal because this is a curl debug build)",
              error_buffer, sockerr);
        *curlcode = CURLE_RECV_ERROR;
        nread = -1;
        goto out;
      }
#endif
    }
  }

out:
  return nread;
}

static size_t ossl_version(char *buffer, size_t size)
{
#ifdef LIBRESSL_VERSION_NUMBER
#ifdef HAVE_OPENSSL_VERSION
  char *p;
  size_t count;
  const char *ver = OpenSSL_version(OPENSSL_VERSION);
  const char expected[] = OSSL_PACKAGE " "; /* ie "LibreSSL " */
  if(strncasecompare(ver, expected, sizeof(expected) - 1)) {
    ver += sizeof(expected) - 1;
  }
  count = msnprintf(buffer, size, "%s/%s", OSSL_PACKAGE, ver);
  for(p = buffer; *p; ++p) {
    if(ISBLANK(*p))
      *p = '_';
  }
  return count;
#else
  return msnprintf(buffer, size, "%s/%lx.%lx.%lx",
                   OSSL_PACKAGE,
                   (LIBRESSL_VERSION_NUMBER>>28)&0xf,
                   (LIBRESSL_VERSION_NUMBER>>20)&0xff,
                   (LIBRESSL_VERSION_NUMBER>>12)&0xff);
#endif
#elif defined(OPENSSL_IS_BORINGSSL)
#ifdef CURL_BORINGSSL_VERSION
  return msnprintf(buffer, size, "%s/%s",
                   OSSL_PACKAGE,
                   CURL_BORINGSSL_VERSION);
#else
  return msnprintf(buffer, size, OSSL_PACKAGE);
#endif
#elif defined(OPENSSL_IS_AWSLC)
  return msnprintf(buffer, size, "%s/%s",
                   OSSL_PACKAGE,
                   AWSLC_VERSION_NUMBER_STRING);
#elif defined(HAVE_OPENSSL_VERSION) && defined(OPENSSL_VERSION_STRING)
  return msnprintf(buffer, size, "%s/%s",
                   OSSL_PACKAGE, OpenSSL_version(OPENSSL_VERSION_STRING));
#else
  /* not LibreSSL, BoringSSL and not using OpenSSL_version */

  char sub[3];
  unsigned long ssleay_value;
  sub[2]='\0';
  sub[1]='\0';
  ssleay_value = OpenSSL_version_num();
  if(ssleay_value < 0x906000) {
    ssleay_value = SSLEAY_VERSION_NUMBER;
    sub[0]='\0';
  }
  else {
    if(ssleay_value&0xff0) {
      int minor_ver = (ssleay_value >> 4) & 0xff;
      if(minor_ver > 26) {
        /* handle extended version introduced for 0.9.8za */
        sub[1] = (char) ((minor_ver - 1) % 26 + 'a' + 1);
        sub[0] = 'z';
      }
      else {
        sub[0] = (char) (minor_ver + 'a' - 1);
      }
    }
    else
      sub[0]='\0';
  }

  return msnprintf(buffer, size, "%s/%lx.%lx.%lx%s"
#ifdef OPENSSL_FIPS
                   "-fips"
#endif
                   ,
                   OSSL_PACKAGE,
                   (ssleay_value>>28)&0xf,
                   (ssleay_value>>20)&0xff,
                   (ssleay_value>>12)&0xff,
                   sub);
#endif /* OPENSSL_IS_BORINGSSL */
}

/* can be called with data == NULL */
static CURLcode ossl_random(struct Curl_easy *data,
                            unsigned char *entropy, size_t length)
{
  int rc;
  if(data) {
    if(ossl_seed(data)) /* Initiate the seed if not already done */
      return CURLE_FAILED_INIT; /* could not seed for some reason */
  }
  else {
    if(!rand_enough())
      return CURLE_FAILED_INIT;
  }
  /* RAND_bytes() returns 1 on success, 0 otherwise.  */
  rc = RAND_bytes(entropy, (ossl_valsize_t)curlx_uztosi(length));
  return (rc == 1 ? CURLE_OK : CURLE_FAILED_INIT);
}

#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
static CURLcode ossl_sha256sum(const unsigned char *tmp, /* input */
                               size_t tmplen,
                               unsigned char *sha256sum /* output */,
                               size_t unused)
{
  EVP_MD_CTX *mdctx;
  unsigned int len = 0;
  (void) unused;

  mdctx = EVP_MD_CTX_create();
  if(!mdctx)
    return CURLE_OUT_OF_MEMORY;
  if(!EVP_DigestInit(mdctx, EVP_sha256())) {
    EVP_MD_CTX_destroy(mdctx);
    return CURLE_FAILED_INIT;
  }
  EVP_DigestUpdate(mdctx, tmp, tmplen);
  EVP_DigestFinal_ex(mdctx, sha256sum, &len);
  EVP_MD_CTX_destroy(mdctx);
  return CURLE_OK;
}
#endif

static bool ossl_cert_status_request(void)
{
#if (OPENSSL_VERSION_NUMBER >= 0x0090808fL) && !defined(OPENSSL_NO_TLSEXT) && \
  !defined(OPENSSL_NO_OCSP)
  return TRUE;
#else
  return FALSE;
#endif
}

static void *ossl_get_internals(struct ssl_connect_data *connssl,
                                CURLINFO info)
{
  /* Legacy: CURLINFO_TLS_SESSION must return an SSL_CTX pointer. */
  struct ossl_ctx *octx = (struct ossl_ctx *)connssl->backend;
  DEBUGASSERT(octx);
  return info == CURLINFO_TLS_SESSION ?
    (void *)octx->ssl_ctx : (void *)octx->ssl;
}

const struct Curl_ssl Curl_ssl_openssl = {
  { CURLSSLBACKEND_OPENSSL, "openssl" }, /* info */

  SSLSUPP_CA_PATH |
  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_CERTINFO |
  SSLSUPP_PINNEDPUBKEY |
  SSLSUPP_SSL_CTX |
#ifdef HAVE_SSL_CTX_SET_CIPHERSUITES
  SSLSUPP_TLS13_CIPHERSUITES |
#endif
#ifdef USE_ECH
  SSLSUPP_ECH |
#endif
  SSLSUPP_CA_CACHE |
  SSLSUPP_HTTPS_PROXY,

  sizeof(struct ossl_ctx),

  ossl_init,                /* init */
  ossl_cleanup,             /* cleanup */
  ossl_version,             /* version */
  Curl_none_check_cxn,      /* check_cxn */
  ossl_shutdown,            /* shutdown */
  ossl_data_pending,        /* data_pending */
  ossl_random,              /* random */
  ossl_cert_status_request, /* cert_status_request */
  ossl_connect,             /* connect */
  ossl_connect_nonblocking, /* connect_nonblocking */
  Curl_ssl_adjust_pollset,  /* adjust_pollset */
  ossl_get_internals,       /* get_internals */
  ossl_close,               /* close_one */
  ossl_close_all,           /* close_all */
  ossl_set_engine,          /* set_engine */
  ossl_set_engine_default,  /* set_engine_default */
  ossl_engines_list,        /* engines_list */
  Curl_none_false_start,    /* false_start */
#if (OPENSSL_VERSION_NUMBER >= 0x0090800fL) && !defined(OPENSSL_NO_SHA256)
  ossl_sha256sum,           /* sha256sum */
#else
  NULL,                     /* sha256sum */
#endif
  NULL,                     /* use of data in this connection */
  NULL,                     /* remote of data from this connection */
  ossl_recv,                /* recv decrypted data */
  ossl_send,                /* send data to encrypt */
};

#endif /* USE_OPENSSL */
