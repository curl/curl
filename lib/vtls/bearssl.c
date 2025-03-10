/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Michael Forney, <mforney@mforney.org>
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

#ifdef USE_BEARSSL

#include <bearssl.h>

#include "bearssl.h"
#include "cipher_suite.h"
#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "vtls.h"
#include "vtls_int.h"
#include "vtls_scache.h"
#include "connect.h"
#include "select.h"
#include "multiif.h"
#include "curl_printf.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

struct x509_context {
  const br_x509_class *vtable;
  br_x509_minimal_context minimal;
  br_x509_decoder_context decoder;
  bool verifyhost;
  bool verifypeer;
  int cert_num;
};

struct bearssl_ssl_backend_data {
  br_ssl_client_context ctx;
  struct x509_context x509;
  unsigned char buf[BR_SSL_BUFSIZE_BIDI];
  br_x509_trust_anchor *anchors;
  size_t anchors_len;
  const char *protocols[ALPN_ENTRIES_MAX];
  /* SSL client context is active */
  bool active;
  /* size of pending write, yet to be flushed */
  size_t pending_write;
  BIT(sent_shutdown);
};

struct cafile_parser {
  CURLcode err;
  bool in_cert;
  br_x509_decoder_context xc;
  /* array of trust anchors loaded from CAfile */
  br_x509_trust_anchor *anchors;
  size_t anchors_len;
  /* buffer for DN data */
  unsigned char dn[1024];
  size_t dn_len;
};

#define CAFILE_SOURCE_PATH 1
#define CAFILE_SOURCE_BLOB 2
struct cafile_source {
  int type;
  const char *data;
  size_t len;
};

static void append_dn(void *ctx, const void *buf, size_t len)
{
  struct cafile_parser *ca = ctx;

  if(ca->err != CURLE_OK || !ca->in_cert)
    return;
  if(sizeof(ca->dn) - ca->dn_len < len) {
    ca->err = CURLE_FAILED_INIT;
    return;
  }
  memcpy(ca->dn + ca->dn_len, buf, len);
  ca->dn_len += len;
}

static void x509_push(void *ctx, const void *buf, size_t len)
{
  struct cafile_parser *ca = ctx;

  if(ca->in_cert)
    br_x509_decoder_push(&ca->xc, buf, len);
}

static CURLcode load_cafile(struct cafile_source *source,
                            br_x509_trust_anchor **anchors,
                            size_t *anchors_len)
{
  struct cafile_parser ca;
  br_pem_decoder_context pc;
  br_x509_trust_anchor *ta;
  size_t ta_size;
  br_x509_trust_anchor *new_anchors;
  size_t new_anchors_len;
  br_x509_pkey *pkey;
  FILE *fp = 0;
  unsigned char buf[BUFSIZ];
  const unsigned char *p = NULL;
  const char *name;
  size_t n = 0, i, pushed;

  DEBUGASSERT(source->type == CAFILE_SOURCE_PATH
              || source->type == CAFILE_SOURCE_BLOB);

  if(source->type == CAFILE_SOURCE_PATH) {
    fp = fopen(source->data, "rb");
    if(!fp)
      return CURLE_SSL_CACERT_BADFILE;
  }

  if(source->type == CAFILE_SOURCE_BLOB && source->len > (size_t)INT_MAX)
    return CURLE_SSL_CACERT_BADFILE;

  ca.err = CURLE_OK;
  ca.in_cert = FALSE;
  ca.anchors = NULL;
  ca.anchors_len = 0;
  br_pem_decoder_init(&pc);
  br_pem_decoder_setdest(&pc, x509_push, &ca);
  do {
    if(source->type == CAFILE_SOURCE_PATH) {
      n = fread(buf, 1, sizeof(buf), fp);
      if(n == 0)
        break;
      p = buf;
    }
    else if(source->type == CAFILE_SOURCE_BLOB) {
      n = source->len;
      p = (const unsigned char *) source->data;
    }
    while(n) {
      pushed = br_pem_decoder_push(&pc, p, n);
      if(ca.err)
        goto fail;
      p += pushed;
      n -= pushed;

      switch(br_pem_decoder_event(&pc)) {
      case 0:
        break;
      case BR_PEM_BEGIN_OBJ:
        name = br_pem_decoder_name(&pc);
        if(strcmp(name, "CERTIFICATE") && strcmp(name, "X509 CERTIFICATE"))
          break;
        br_x509_decoder_init(&ca.xc, append_dn, &ca);
        ca.in_cert = TRUE;
        ca.dn_len = 0;
        break;
      case BR_PEM_END_OBJ:
        if(!ca.in_cert)
          break;
        ca.in_cert = FALSE;
        if(br_x509_decoder_last_error(&ca.xc)) {
          ca.err = CURLE_SSL_CACERT_BADFILE;
          goto fail;
        }
        /* add trust anchor */
        if(ca.anchors_len == SIZE_MAX / sizeof(ca.anchors[0])) {
          ca.err = CURLE_OUT_OF_MEMORY;
          goto fail;
        }
        new_anchors_len = ca.anchors_len + 1;
        new_anchors = realloc(ca.anchors,
                              new_anchors_len * sizeof(ca.anchors[0]));
        if(!new_anchors) {
          ca.err = CURLE_OUT_OF_MEMORY;
          goto fail;
        }
        ca.anchors = new_anchors;
        ca.anchors_len = new_anchors_len;
        ta = &ca.anchors[ca.anchors_len - 1];
        ta->dn.data = NULL;
        ta->flags = 0;
        if(br_x509_decoder_isCA(&ca.xc))
          ta->flags |= BR_X509_TA_CA;
        pkey = br_x509_decoder_get_pkey(&ca.xc);
        if(!pkey) {
          ca.err = CURLE_SSL_CACERT_BADFILE;
          goto fail;
        }
        ta->pkey = *pkey;

        /* calculate space needed for trust anchor data */
        ta_size = ca.dn_len;
        switch(pkey->key_type) {
        case BR_KEYTYPE_RSA:
          ta_size += pkey->key.rsa.nlen + pkey->key.rsa.elen;
          break;
        case BR_KEYTYPE_EC:
          ta_size += pkey->key.ec.qlen;
          break;
        default:
          ca.err = CURLE_FAILED_INIT;
          goto fail;
        }

        /* fill in trust anchor DN and public key data */
        ta->dn.data = malloc(ta_size);
        if(!ta->dn.data) {
          ca.err = CURLE_OUT_OF_MEMORY;
          goto fail;
        }
        memcpy(ta->dn.data, ca.dn, ca.dn_len);
        ta->dn.len = ca.dn_len;
        switch(pkey->key_type) {
        case BR_KEYTYPE_RSA:
          ta->pkey.key.rsa.n = ta->dn.data + ta->dn.len;
          memcpy(ta->pkey.key.rsa.n, pkey->key.rsa.n, pkey->key.rsa.nlen);
          ta->pkey.key.rsa.e = ta->pkey.key.rsa.n + ta->pkey.key.rsa.nlen;
          memcpy(ta->pkey.key.rsa.e, pkey->key.rsa.e, pkey->key.rsa.elen);
          break;
        case BR_KEYTYPE_EC:
          ta->pkey.key.ec.q = ta->dn.data + ta->dn.len;
          memcpy(ta->pkey.key.ec.q, pkey->key.ec.q, pkey->key.ec.qlen);
          break;
        }
        break;
      default:
        ca.err = CURLE_SSL_CACERT_BADFILE;
        goto fail;
      }
    }
  } while(source->type != CAFILE_SOURCE_BLOB);
  if(fp && ferror(fp))
    ca.err = CURLE_READ_ERROR;
  else if(ca.in_cert)
    ca.err = CURLE_SSL_CACERT_BADFILE;

fail:
  if(fp)
    fclose(fp);
  if(ca.err == CURLE_OK) {
    *anchors = ca.anchors;
    *anchors_len = ca.anchors_len;
  }
  else {
    for(i = 0; i < ca.anchors_len; ++i)
      free(ca.anchors[i].dn.data);
    free(ca.anchors);
  }

  return ca.err;
}

static void x509_start_chain(const br_x509_class **ctx,
                             const char *server_name)
{
  struct x509_context *x509 = (struct x509_context *)ctx;

  if(!x509->verifypeer) {
    x509->cert_num = 0;
    return;
  }

  if(!x509->verifyhost)
    server_name = NULL;
  x509->minimal.vtable->start_chain(&x509->minimal.vtable, server_name);
}

static void x509_start_cert(const br_x509_class **ctx, uint32_t length)
{
  struct x509_context *x509 = (struct x509_context *)ctx;

  if(!x509->verifypeer) {
    /* Only decode the first cert in the chain to obtain the public key */
    if(x509->cert_num == 0)
      br_x509_decoder_init(&x509->decoder, NULL, NULL);
    return;
  }

  x509->minimal.vtable->start_cert(&x509->minimal.vtable, length);
}

static void x509_append(const br_x509_class **ctx, const unsigned char *buf,
                        size_t len)
{
  struct x509_context *x509 = (struct x509_context *)ctx;

  if(!x509->verifypeer) {
    if(x509->cert_num == 0)
      br_x509_decoder_push(&x509->decoder, buf, len);
    return;
  }

  x509->minimal.vtable->append(&x509->minimal.vtable, buf, len);
}

static void x509_end_cert(const br_x509_class **ctx)
{
  struct x509_context *x509 = (struct x509_context *)ctx;

  if(!x509->verifypeer) {
    x509->cert_num++;
    return;
  }

  x509->minimal.vtable->end_cert(&x509->minimal.vtable);
}

static unsigned x509_end_chain(const br_x509_class **ctx)
{
  struct x509_context *x509 = (struct x509_context *)ctx;

  if(!x509->verifypeer) {
    return (unsigned)br_x509_decoder_last_error(&x509->decoder);
  }

  return x509->minimal.vtable->end_chain(&x509->minimal.vtable);
}

static const br_x509_pkey *x509_get_pkey(const br_x509_class *const *ctx,
                                         unsigned *usages)
{
  struct x509_context *x509 = (struct x509_context *)CURL_UNCONST(ctx);

  if(!x509->verifypeer) {
    /* Nothing in the chain is verified, just return the public key of the
       first certificate and allow its usage for both TLS_RSA_* and
       TLS_ECDHE_* */
    if(usages)
      *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
    return br_x509_decoder_get_pkey(&x509->decoder);
  }

  return x509->minimal.vtable->get_pkey(&x509->minimal.vtable, usages);
}

static const br_x509_class x509_vtable = {
  sizeof(struct x509_context),
  x509_start_chain,
  x509_start_cert,
  x509_append,
  x509_end_cert,
  x509_end_chain,
  x509_get_pkey
};

static CURLcode
bearssl_set_ssl_version_min_max(struct Curl_easy *data,
                                br_ssl_engine_context *ssl_eng,
                                struct ssl_primary_config *conn_config)
{
  unsigned version_min, version_max;

  switch(conn_config->version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
    version_min = BR_TLS10;
    break;
  case CURL_SSLVERSION_TLSv1_1:
    version_min = BR_TLS11;
    break;
  case CURL_SSLVERSION_TLSv1_2:
    version_min = BR_TLS12;
    break;
  case CURL_SSLVERSION_TLSv1_3:
    failf(data, "BearSSL: does not support TLS 1.3");
    return CURLE_SSL_CONNECT_ERROR;
  default:
    failf(data, "BearSSL: unsupported minimum TLS version value");
    return CURLE_SSL_CONNECT_ERROR;
  }

  switch(conn_config->version_max) {
  case CURL_SSLVERSION_MAX_DEFAULT:
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_TLSv1_3:
  case CURL_SSLVERSION_MAX_TLSv1_2:
    version_max = BR_TLS12;
    break;
  case CURL_SSLVERSION_MAX_TLSv1_1:
    version_max = BR_TLS11;
    break;
  case CURL_SSLVERSION_MAX_TLSv1_0:
    version_max = BR_TLS10;
    break;
  default:
    failf(data, "BearSSL: unsupported maximum TLS version value");
    return CURLE_SSL_CONNECT_ERROR;
  }

  br_ssl_engine_set_versions(ssl_eng, version_min, version_max);

  return CURLE_OK;
}

static const uint16_t ciphertable[] = {
  /* RFC 2246 TLS 1.0 */
  BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA,                        /* 0x000A */

  /* RFC 3268 TLS 1.0 AES */
  BR_TLS_RSA_WITH_AES_128_CBC_SHA,                         /* 0x002F */
  BR_TLS_RSA_WITH_AES_256_CBC_SHA,                         /* 0x0035 */

  /* RFC 5246 TLS 1.2 */
  BR_TLS_RSA_WITH_AES_128_CBC_SHA256,                      /* 0x003C */
  BR_TLS_RSA_WITH_AES_256_CBC_SHA256,                      /* 0x003D */

  /* RFC 5288 TLS 1.2 AES GCM */
  BR_TLS_RSA_WITH_AES_128_GCM_SHA256,                      /* 0x009C */
  BR_TLS_RSA_WITH_AES_256_GCM_SHA384,                      /* 0x009D */

  /* RFC 4492 TLS 1.0 ECC */
  BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,                 /* 0xC003 */
  BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,                  /* 0xC004 */
  BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,                  /* 0xC005 */
  BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,                /* 0xC008 */
  BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,                 /* 0xC009 */
  BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,                 /* 0xC00A */
  BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,                   /* 0xC00D */
  BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,                    /* 0xC00E */
  BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,                    /* 0xC00F */
  BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,                  /* 0xC012 */
  BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,                   /* 0xC013 */
  BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,                   /* 0xC014 */

  /* RFC 5289 TLS 1.2 ECC HMAC SHA256/384 */
  BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,              /* 0xC023 */
  BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,              /* 0xC024 */
  BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,               /* 0xC025 */
  BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,               /* 0xC026 */
  BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,                /* 0xC027 */
  BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,                /* 0xC028 */
  BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,                 /* 0xC029 */
  BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,                 /* 0xC02A */

  /* RFC 5289 TLS 1.2 GCM */
  BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,              /* 0xC02B */
  BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,              /* 0xC02C */
  BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,               /* 0xC02D */
  BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,               /* 0xC02E */
  BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                /* 0xC02F */
  BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,                /* 0xC030 */
  BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,                 /* 0xC031 */
  BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,                 /* 0xC032 */

#ifdef BR_TLS_RSA_WITH_AES_128_CCM
  /* RFC 6655 TLS 1.2 CCM
     Supported since BearSSL 0.6 */
  BR_TLS_RSA_WITH_AES_128_CCM,                             /* 0xC09C */
  BR_TLS_RSA_WITH_AES_256_CCM,                             /* 0xC09D */
  BR_TLS_RSA_WITH_AES_128_CCM_8,                           /* 0xC0A0 */
  BR_TLS_RSA_WITH_AES_256_CCM_8,                           /* 0xC0A1 */

  /* RFC 7251 TLS 1.2 ECC CCM
     Supported since BearSSL 0.6 */
  BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,                     /* 0xC0AC */
  BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,                     /* 0xC0AD */
  BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,                   /* 0xC0AE */
  BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,                   /* 0xC0AF */
#endif

  /* RFC 7905 TLS 1.2 ChaCha20-Poly1305
     Supported since BearSSL 0.2 */
  BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,          /* 0xCCA8 */
  BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,        /* 0xCCA9 */
};

#define NUM_OF_CIPHERS CURL_ARRAYSIZE(ciphertable)

static CURLcode bearssl_set_selected_ciphers(struct Curl_easy *data,
                                             br_ssl_engine_context *ssl_eng,
                                             const char *ciphers)
{
  uint16_t selected[NUM_OF_CIPHERS];
  size_t count = 0, i;
  const char *ptr, *end;

  for(ptr = ciphers; ptr[0] != '\0' && count < NUM_OF_CIPHERS; ptr = end) {
    uint16_t id = Curl_cipher_suite_walk_str(&ptr, &end);

    /* Check if cipher is supported */
    if(id) {
      for(i = 0; i < NUM_OF_CIPHERS && ciphertable[i] != id; i++);
      if(i == NUM_OF_CIPHERS)
        id = 0;
    }
    if(!id) {
      if(ptr[0] != '\0')
        infof(data, "BearSSL: unknown cipher in list: \"%.*s\"",
              (int) (end - ptr), ptr);
      continue;
    }

    /* No duplicates allowed */
    for(i = 0; i < count && selected[i] != id; i++);
    if(i < count) {
      infof(data, "BearSSL: duplicate cipher in list: \"%.*s\"",
            (int) (end - ptr), ptr);
      continue;
    }

    selected[count++] = id;
  }

  if(count == 0) {
    failf(data, "BearSSL: no supported cipher in list");
    return CURLE_SSL_CIPHER;
  }

  br_ssl_engine_set_suites(ssl_eng, selected, count);
  return CURLE_OK;
}

static CURLcode bearssl_connect_step1(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ca_info_blob ? NULL : conn_config->CAfile);
  const char *hostname = connssl->peer.hostname;
  const bool verifypeer = conn_config->verifypeer;
  const bool verifyhost = conn_config->verifyhost;
  CURLcode ret;
  int session_set = 0;

  DEBUGASSERT(backend);
  CURL_TRC_CF(data, cf, "connect_step1");

  if(verifypeer) {
    if(ca_info_blob) {
      struct cafile_source source;
      source.type = CAFILE_SOURCE_BLOB;
      source.data = ca_info_blob->data;
      source.len = ca_info_blob->len;

      CURL_TRC_CF(data, cf, "connect_step1, load ca_info_blob");
      ret = load_cafile(&source, &backend->anchors, &backend->anchors_len);
      if(ret != CURLE_OK) {
        failf(data, "error importing CA certificate blob");
        return ret;
      }
    }

    if(ssl_cafile) {
      struct cafile_source source;
      source.type = CAFILE_SOURCE_PATH;
      source.data = ssl_cafile;
      source.len = 0;

      CURL_TRC_CF(data, cf, "connect_step1, load cafile");
      ret = load_cafile(&source, &backend->anchors, &backend->anchors_len);
      if(ret != CURLE_OK) {
        failf(data, "error setting certificate verify locations."
              " CAfile: %s", ssl_cafile);
        return ret;
      }
    }
  }

  /* initialize SSL context */
  br_ssl_client_init_full(&backend->ctx, &backend->x509.minimal,
                          backend->anchors, backend->anchors_len);

  ret = bearssl_set_ssl_version_min_max(data, &backend->ctx.eng, conn_config);
  if(ret != CURLE_OK)
    return ret;

  br_ssl_engine_set_buffer(&backend->ctx.eng, backend->buf,
                           sizeof(backend->buf), 1);

  if(conn_config->cipher_list) {
    /* Override the ciphers as specified. For the default cipher list see the
       BearSSL source code of br_ssl_client_init_full() */
    CURL_TRC_CF(data, cf, "connect_step1, set ciphers");
    ret = bearssl_set_selected_ciphers(data, &backend->ctx.eng,
                                       conn_config->cipher_list);
    if(ret)
      return ret;
  }

  /* initialize X.509 context */
  backend->x509.vtable = &x509_vtable;
  backend->x509.verifypeer = verifypeer;
  backend->x509.verifyhost = verifyhost;
  br_ssl_engine_set_x509(&backend->ctx.eng, &backend->x509.vtable);

  if(ssl_config->primary.cache_session) {
    struct Curl_ssl_session *sc_session = NULL;

    ret = Curl_ssl_scache_take(cf, data, connssl->peer.scache_key,
                               &sc_session);
    if(!ret && sc_session && sc_session->sdata && sc_session->sdata_len) {
      const br_ssl_session_parameters *session;
      session = (const br_ssl_session_parameters *)sc_session->sdata;
      br_ssl_engine_set_session_parameters(&backend->ctx.eng, session);
      session_set = 1;
      infof(data, "BearSSL: reusing session ID");
      /* single use of sessions */
      Curl_ssl_scache_return(cf, data, connssl->peer.scache_key, sc_session);
    }
  }

  if(connssl->alpn) {
    struct alpn_proto_buf proto;
    size_t i;

    for(i = 0; i < connssl->alpn->count; ++i) {
      backend->protocols[i] = connssl->alpn->entries[i];
    }
    br_ssl_engine_set_protocol_names(&backend->ctx.eng, backend->protocols,
                                     connssl->alpn->count);
    Curl_alpn_to_proto_str(&proto, connssl->alpn);
    infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
  }

  if(connssl->peer.type != CURL_SSL_PEER_DNS) {
    if(verifyhost) {
      failf(data, "BearSSL: "
            "host verification of IP address is not supported");
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    hostname = NULL;
  }
  else {
    if(!connssl->peer.sni) {
      failf(data, "Failed to set SNI");
      return CURLE_SSL_CONNECT_ERROR;
    }
    hostname = connssl->peer.sni;
    CURL_TRC_CF(data, cf, "connect_step1, SNI set");
  }

  /* give application a chance to interfere with SSL set up. */
  if(data->set.ssl.fsslctx) {
    Curl_set_in_callback(data, TRUE);
    ret = (*data->set.ssl.fsslctx)(data, &backend->ctx,
                                   data->set.ssl.fsslctxp);
    Curl_set_in_callback(data, FALSE);
    if(ret) {
      failf(data, "BearSSL: error signaled by ssl ctx callback");
      return ret;
    }
  }

  if(!br_ssl_client_reset(&backend->ctx, hostname, session_set))
    return CURLE_FAILED_INIT;
  backend->active = TRUE;

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode bearssl_run_until(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  unsigned target)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  unsigned state;
  unsigned char *buf;
  size_t len;
  ssize_t ret;
  CURLcode result;
  int err;

  DEBUGASSERT(backend);

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  for(;;) {
    state = br_ssl_engine_current_state(&backend->ctx.eng);
    if(state & BR_SSL_CLOSED) {
      err = br_ssl_engine_last_error(&backend->ctx.eng);
      switch(err) {
      case BR_ERR_OK:
        /* TLS close notify */
        if(connssl->state != ssl_connection_complete) {
          failf(data, "SSL: connection closed during handshake");
          return CURLE_SSL_CONNECT_ERROR;
        }
        return CURLE_OK;
      case BR_ERR_X509_EXPIRED:
        failf(data, "SSL: X.509 verification: "
              "certificate is expired or not yet valid");
        return CURLE_PEER_FAILED_VERIFICATION;
      case BR_ERR_X509_BAD_SERVER_NAME:
        failf(data, "SSL: X.509 verification: "
              "expected server name was not found in the chain");
        return CURLE_PEER_FAILED_VERIFICATION;
      case BR_ERR_X509_NOT_TRUSTED:
        failf(data, "SSL: X.509 verification: "
              "chain could not be linked to a trust anchor");
        return CURLE_PEER_FAILED_VERIFICATION;
      default:;
      }
      failf(data, "BearSSL: connection error 0x%04x", err);
      /* X.509 errors are documented to have the range 32..63 */
      if(err >= 32 && err < 64)
        return CURLE_PEER_FAILED_VERIFICATION;
      return CURLE_SSL_CONNECT_ERROR;
    }
    if(state & target)
      return CURLE_OK;
    if(state & BR_SSL_SENDREC) {
      buf = br_ssl_engine_sendrec_buf(&backend->ctx.eng, &len);
      ret = Curl_conn_cf_send(cf->next, data, (const char *)buf, len, FALSE,
                              &result);
      CURL_TRC_CF(data, cf, "ssl_send(len=%zu) -> %zd, %d", len, ret, result);
      if(ret <= 0) {
        if(result == CURLE_AGAIN)
          connssl->io_need |= CURL_SSL_IO_NEED_SEND;
        return result;
      }
      br_ssl_engine_sendrec_ack(&backend->ctx.eng, ret);
    }
    else if(state & BR_SSL_RECVREC) {
      buf = br_ssl_engine_recvrec_buf(&backend->ctx.eng, &len);
      ret = Curl_conn_cf_recv(cf->next, data, (char *)buf, len, &result);
      CURL_TRC_CF(data, cf, "ssl_recv(len=%zu) -> %zd, %d", len, ret, result);
      if(ret == 0) {
        failf(data, "SSL: EOF without close notify");
        return CURLE_RECV_ERROR;
      }
      if(ret <= 0) {
        if(result == CURLE_AGAIN)
          connssl->io_need |= CURL_SSL_IO_NEED_RECV;
        return result;
      }
      br_ssl_engine_recvrec_ack(&backend->ctx.eng, ret);
    }
  }
}

static CURLcode bearssl_connect_step2(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  br_ssl_session_parameters session;
  char cipher_str[64];
  CURLcode ret;

  DEBUGASSERT(backend);
  CURL_TRC_CF(data, cf, "connect_step2");

  ret = bearssl_run_until(cf, data, BR_SSL_SENDAPP | BR_SSL_RECVAPP);
  if(ret == CURLE_AGAIN)
    return CURLE_OK;
  if(ret == CURLE_OK) {
    unsigned int tver;
    int subver = 0;

    if(br_ssl_engine_current_state(&backend->ctx.eng) == BR_SSL_CLOSED) {
      failf(data, "SSL: connection closed during handshake");
      return CURLE_SSL_CONNECT_ERROR;
    }
    connssl->connecting_state = ssl_connect_3;
    /* Informational message */
    tver = br_ssl_engine_get_version(&backend->ctx.eng);
    switch(tver) {
    case BR_TLS12:
      subver = 2; /* 1.2 */
      break;
    case BR_TLS11:
      subver = 1; /* 1.1 */
      break;
    case BR_TLS10: /* 1.0 */
    default: /* unknown, leave it at zero */
      break;
    }
    br_ssl_engine_get_session_parameters(&backend->ctx.eng, &session);
    Curl_cipher_suite_get_str(session.cipher_suite, cipher_str,
                              sizeof(cipher_str), TRUE);
    infof(data, "BearSSL: TLS v1.%d connection using %s", subver,
          cipher_str);
  }
  return ret;
}

static CURLcode bearssl_connect_step3(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  CURLcode ret;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);
  DEBUGASSERT(backend);
  CURL_TRC_CF(data, cf, "connect_step3");

  if(connssl->alpn) {
    const char *proto;

    proto = br_ssl_engine_get_selected_protocol(&backend->ctx.eng);
    Curl_alpn_set_negotiated(cf, data, connssl, (const unsigned char *)proto,
                             proto ? strlen(proto) : 0);
  }

  if(ssl_config->primary.cache_session) {
    struct Curl_ssl_session *sc_session;
    br_ssl_session_parameters *session;

    session = malloc(sizeof(*session));
    if(!session)
      return CURLE_OUT_OF_MEMORY;
    br_ssl_engine_get_session_parameters(&backend->ctx.eng, session);
    ret = Curl_ssl_session_create((unsigned char *)session, sizeof(*session),
                                  (int)session->version,
                                  connssl->negotiated.alpn,
                                  0, 0, &sc_session);
    if(!ret) {
      ret = Curl_ssl_scache_put(cf, data, connssl->peer.scache_key,
                                sc_session);
      /* took ownership of `sc_session` */
    }
    if(ret)
      return ret;
  }

  connssl->connecting_state = ssl_connect_done;

  return CURLE_OK;
}

static ssize_t bearssl_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                            const void *buf, size_t len, CURLcode *err)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  unsigned char *app;
  size_t applen;

  DEBUGASSERT(backend);

  for(;;) {
    *err = bearssl_run_until(cf, data, BR_SSL_SENDAPP);
    if(*err)
      return -1;
    app = br_ssl_engine_sendapp_buf(&backend->ctx.eng, &applen);
    if(!app) {
      failf(data, "SSL: connection closed during write");
      *err = CURLE_SEND_ERROR;
      return -1;
    }
    if(backend->pending_write) {
      applen = backend->pending_write;
      backend->pending_write = 0;
      return applen;
    }
    if(applen > len)
      applen = len;
    memcpy(app, buf, applen);
    br_ssl_engine_sendapp_ack(&backend->ctx.eng, applen);
    br_ssl_engine_flush(&backend->ctx.eng, 0);
    backend->pending_write = applen;
  }
}

static ssize_t bearssl_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                            char *buf, size_t len, CURLcode *err)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  unsigned char *app;
  size_t applen;

  DEBUGASSERT(backend);

  *err = bearssl_run_until(cf, data, BR_SSL_RECVAPP);
  if(*err != CURLE_OK)
    return -1;
  app = br_ssl_engine_recvapp_buf(&backend->ctx.eng, &applen);
  if(!app)
    return 0;
  if(applen > len)
    applen = len;
  memcpy(buf, app, applen);
  br_ssl_engine_recvapp_ack(&backend->ctx.eng, applen);

  return applen;
}

static CURLcode bearssl_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                bool *done)
{
  CURLcode ret;
  struct ssl_connect_data *connssl = cf->ctx;

  CURL_TRC_CF(data, cf, "connect()");
  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    CURL_TRC_CF(data, cf, "connect_common, connected");
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  if(ssl_connect_1 == connssl->connecting_state) {
    ret = bearssl_connect_step1(cf, data);
    if(ret)
      return ret;
  }

  if(ssl_connect_2 == connssl->connecting_state) {
    ret = bearssl_connect_step2(cf, data);
    if(ret)
      return ret;
  }

  if(ssl_connect_3 == connssl->connecting_state) {
    ret = bearssl_connect_step3(cf, data);
    if(ret)
      return ret;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    *done = TRUE;
  }

  return CURLE_OK;
}

static size_t bearssl_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "BearSSL");
}

static bool bearssl_data_pending(struct Curl_cfilter *cf,
                                 const struct Curl_easy *data)
{
  struct ssl_connect_data *ctx = cf->ctx;
  struct bearssl_ssl_backend_data *backend;

  (void)data;
  DEBUGASSERT(ctx && ctx->backend);
  backend = (struct bearssl_ssl_backend_data *)ctx->backend;
  return br_ssl_engine_current_state(&backend->ctx.eng) & BR_SSL_RECVAPP;
}

static CURLcode bearssl_random(struct Curl_easy *data UNUSED_PARAM,
                               unsigned char *entropy, size_t length)
{
  static br_hmac_drbg_context ctx;
  static bool seeded = FALSE;

  if(!seeded) {
    br_prng_seeder seeder;

    br_hmac_drbg_init(&ctx, &br_sha256_vtable, NULL, 0);
    seeder = br_prng_seeder_system(NULL);
    if(!seeder || !seeder(&ctx.vtable))
      return CURLE_FAILED_INIT;
    seeded = TRUE;
  }
  br_hmac_drbg_generate(&ctx, entropy, length);

  return CURLE_OK;
}

static void *bearssl_get_internals(struct ssl_connect_data *connssl,
                                   CURLINFO info UNUSED_PARAM)
{
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  DEBUGASSERT(backend);
  return &backend->ctx;
}

static CURLcode bearssl_shutdown(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  CURLcode result;

  DEBUGASSERT(backend);
  if(!backend->active || cf->shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  if(!backend->sent_shutdown) {
    (void)send_shutdown; /* unknown how to suppress our close notify */
    br_ssl_engine_close(&backend->ctx.eng);
    backend->sent_shutdown = TRUE;
  }

  result = bearssl_run_until(cf, data, BR_SSL_CLOSED);
  if(result == CURLE_OK) {
    *done = TRUE;
  }
  else if(result == CURLE_AGAIN) {
    CURL_TRC_CF(data, cf, "shutdown EAGAIN, io_need=%x", connssl->io_need);
    result = CURLE_OK;
  }
  else
    CURL_TRC_CF(data, cf, "shutdown error: %d", result);

  cf->shutdown = (result || *done);
  return result;
}

static void bearssl_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  size_t i;

  (void)data;
  DEBUGASSERT(backend);

  backend->active = FALSE;
  if(backend->anchors) {
    for(i = 0; i < backend->anchors_len; ++i)
      free(backend->anchors[i].dn.data);
    Curl_safefree(backend->anchors);
  }
}

static CURLcode bearssl_sha256sum(const unsigned char *input,
                                  size_t inputlen,
                                  unsigned char *sha256sum,
                                  size_t sha256len UNUSED_PARAM)
{
  br_sha256_context ctx;

  br_sha256_init(&ctx);
  br_sha256_update(&ctx, input, inputlen);
  br_sha256_out(&ctx, sha256sum);
  return CURLE_OK;
}

const struct Curl_ssl Curl_ssl_bearssl = {
  { CURLSSLBACKEND_BEARSSL, "bearssl" }, /* info */

  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_SSL_CTX |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST,

  sizeof(struct bearssl_ssl_backend_data),

  NULL,                            /* init */
  NULL,                            /* cleanup */
  bearssl_version,                 /* version */
  bearssl_shutdown,                /* shutdown */
  bearssl_data_pending,            /* data_pending */
  bearssl_random,                  /* random */
  NULL,                            /* cert_status_request */
  bearssl_connect,                 /* connect */
  Curl_ssl_adjust_pollset,         /* adjust_pollset */
  bearssl_get_internals,           /* get_internals */
  bearssl_close,                   /* close_one */
  NULL,                            /* close_all */
  NULL,                            /* set_engine */
  NULL,                            /* set_engine_default */
  NULL,                            /* engines_list */
  NULL,                            /* false_start */
  bearssl_sha256sum,               /* sha256sum */
  bearssl_recv,                    /* recv decrypted data */
  bearssl_send,                    /* send data to encrypt */
  NULL,                            /* get_channel_binding */
};

#endif /* USE_BEARSSL */
