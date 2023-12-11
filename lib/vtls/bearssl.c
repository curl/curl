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
#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "vtls.h"
#include "vtls_int.h"
#include "connect.h"
#include "select.h"
#include "multiif.h"
#include "curl_printf.h"
#include "strcase.h"

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
  const unsigned char *p;
  const char *name;
  size_t n, i, pushed;

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
      p = (unsigned char *) source->data;
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
    return br_x509_decoder_last_error(&x509->decoder);
  }

  return x509->minimal.vtable->end_chain(&x509->minimal.vtable);
}

static const br_x509_pkey *x509_get_pkey(const br_x509_class *const *ctx,
                                         unsigned *usages)
{
  struct x509_context *x509 = (struct x509_context *)ctx;

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

struct st_cipher {
  const char *name; /* Cipher suite IANA name. It starts with "TLS_" prefix */
  const char *alias_name; /* Alias name is the same as OpenSSL cipher name */
  uint16_t num; /* BearSSL cipher suite */
};

/* Macro to initialize st_cipher data structure */
#define CIPHER_DEF(num, alias) { #num, alias, BR_##num }

static const struct st_cipher ciphertable[] = {
  /* RFC 2246 TLS 1.0 */
  CIPHER_DEF(TLS_RSA_WITH_3DES_EDE_CBC_SHA,                        /* 0x000A */
             "DES-CBC3-SHA"),

  /* RFC 3268 TLS 1.0 AES */
  CIPHER_DEF(TLS_RSA_WITH_AES_128_CBC_SHA,                         /* 0x002F */
             "AES128-SHA"),
  CIPHER_DEF(TLS_RSA_WITH_AES_256_CBC_SHA,                         /* 0x0035 */
             "AES256-SHA"),

  /* RFC 5246 TLS 1.2 */
  CIPHER_DEF(TLS_RSA_WITH_AES_128_CBC_SHA256,                      /* 0x003C */
             "AES128-SHA256"),
  CIPHER_DEF(TLS_RSA_WITH_AES_256_CBC_SHA256,                      /* 0x003D */
             "AES256-SHA256"),

  /* RFC 5288 TLS 1.2 AES GCM */
  CIPHER_DEF(TLS_RSA_WITH_AES_128_GCM_SHA256,                      /* 0x009C */
             "AES128-GCM-SHA256"),
  CIPHER_DEF(TLS_RSA_WITH_AES_256_GCM_SHA384,                      /* 0x009D */
             "AES256-GCM-SHA384"),

  /* RFC 4492 TLS 1.0 ECC */
  CIPHER_DEF(TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,                 /* 0xC003 */
             "ECDH-ECDSA-DES-CBC3-SHA"),
  CIPHER_DEF(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,                  /* 0xC004 */
             "ECDH-ECDSA-AES128-SHA"),
  CIPHER_DEF(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,                  /* 0xC005 */
             "ECDH-ECDSA-AES256-SHA"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,                /* 0xC008 */
             "ECDHE-ECDSA-DES-CBC3-SHA"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,                 /* 0xC009 */
             "ECDHE-ECDSA-AES128-SHA"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,                 /* 0xC00A */
             "ECDHE-ECDSA-AES256-SHA"),
  CIPHER_DEF(TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,                   /* 0xC00D */
             "ECDH-RSA-DES-CBC3-SHA"),
  CIPHER_DEF(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,                    /* 0xC00E */
             "ECDH-RSA-AES128-SHA"),
  CIPHER_DEF(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,                    /* 0xC00F */
             "ECDH-RSA-AES256-SHA"),
  CIPHER_DEF(TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,                  /* 0xC012 */
             "ECDHE-RSA-DES-CBC3-SHA"),
  CIPHER_DEF(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,                   /* 0xC013 */
             "ECDHE-RSA-AES128-SHA"),
  CIPHER_DEF(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,                   /* 0xC014 */
             "ECDHE-RSA-AES256-SHA"),

  /* RFC 5289 TLS 1.2 ECC HMAC SHA256/384 */
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,              /* 0xC023 */
             "ECDHE-ECDSA-AES128-SHA256"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,              /* 0xC024 */
             "ECDHE-ECDSA-AES256-SHA384"),
  CIPHER_DEF(TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,               /* 0xC025 */
             "ECDH-ECDSA-AES128-SHA256"),
  CIPHER_DEF(TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,               /* 0xC026 */
             "ECDH-ECDSA-AES256-SHA384"),
  CIPHER_DEF(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,                /* 0xC027 */
             "ECDHE-RSA-AES128-SHA256"),
  CIPHER_DEF(TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,                /* 0xC028 */
             "ECDHE-RSA-AES256-SHA384"),
  CIPHER_DEF(TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,                 /* 0xC029 */
             "ECDH-RSA-AES128-SHA256"),
  CIPHER_DEF(TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,                 /* 0xC02A */
             "ECDH-RSA-AES256-SHA384"),

  /* RFC 5289 TLS 1.2 GCM */
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,              /* 0xC02B */
             "ECDHE-ECDSA-AES128-GCM-SHA256"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,              /* 0xC02C */
             "ECDHE-ECDSA-AES256-GCM-SHA384"),
  CIPHER_DEF(TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,               /* 0xC02D */
             "ECDH-ECDSA-AES128-GCM-SHA256"),
  CIPHER_DEF(TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,               /* 0xC02E */
             "ECDH-ECDSA-AES256-GCM-SHA384"),
  CIPHER_DEF(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,                /* 0xC02F */
             "ECDHE-RSA-AES128-GCM-SHA256"),
  CIPHER_DEF(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,                /* 0xC030 */
             "ECDHE-RSA-AES256-GCM-SHA384"),
  CIPHER_DEF(TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,                 /* 0xC031 */
             "ECDH-RSA-AES128-GCM-SHA256"),
  CIPHER_DEF(TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,                 /* 0xC032 */
             "ECDH-RSA-AES256-GCM-SHA384"),
#ifdef BR_TLS_RSA_WITH_AES_128_CCM

  /* RFC 6655 TLS 1.2 CCM
     Supported since BearSSL 0.6 */
  CIPHER_DEF(TLS_RSA_WITH_AES_128_CCM,                             /* 0xC09C */
             "AES128-CCM"),
  CIPHER_DEF(TLS_RSA_WITH_AES_256_CCM,                             /* 0xC09D */
             "AES256-CCM"),
  CIPHER_DEF(TLS_RSA_WITH_AES_128_CCM_8,                           /* 0xC0A0 */
             "AES128-CCM8"),
  CIPHER_DEF(TLS_RSA_WITH_AES_256_CCM_8,                           /* 0xC0A1 */
             "AES256-CCM8"),

  /* RFC 7251 TLS 1.2 ECC CCM
     Supported since BearSSL 0.6 */
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_128_CCM,                     /* 0xC0AC */
             "ECDHE-ECDSA-AES128-CCM"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_256_CCM,                     /* 0xC0AD */
             "ECDHE-ECDSA-AES256-CCM"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,                   /* 0xC0AE */
             "ECDHE-ECDSA-AES128-CCM8"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,                   /* 0xC0AF */
             "ECDHE-ECDSA-AES256-CCM8"),
#endif

  /* RFC 7905 TLS 1.2 ChaCha20-Poly1305
     Supported since BearSSL 0.2 */
  CIPHER_DEF(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,          /* 0xCCA8 */
             "ECDHE-RSA-CHACHA20-POLY1305"),
  CIPHER_DEF(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,        /* 0xCCA9 */
             "ECDHE-ECDSA-CHACHA20-POLY1305"),
};

#define NUM_OF_CIPHERS (sizeof(ciphertable) / sizeof(ciphertable[0]))
#define CIPHER_NAME_BUF_LEN 64

static bool is_separator(char c)
{
  /* Return whether character is a cipher list separator. */
  switch(c) {
    case ' ':
    case '\t':
    case ':':
    case ',':
    case ';':
      return true;
  }
  return false;
}

static CURLcode bearssl_set_selected_ciphers(struct Curl_easy *data,
                                             br_ssl_engine_context *ssl_eng,
                                             const char *ciphers)
{
  uint16_t selected_ciphers[NUM_OF_CIPHERS];
  size_t selected_count = 0;
  const char *cipher_start = ciphers;
  const char *cipher_end;
  size_t i, j;

  if(!cipher_start)
    return CURLE_SSL_CIPHER;

  while(true) {
    const char *cipher;
    size_t clen;

    /* Extract the next cipher name from the ciphers string */
    while(is_separator(*cipher_start))
      ++cipher_start;
    if(!*cipher_start)
      break;
    cipher_end = cipher_start;
    while(*cipher_end && !is_separator(*cipher_end))
      ++cipher_end;

    clen = cipher_end - cipher_start;
    cipher = cipher_start;

    cipher_start = cipher_end;

    /* Lookup the cipher name in the table of available ciphers. If the cipher
       name starts with "TLS_" we do the lookup by IANA name. Otherwise, we try
       to match cipher name by an (OpenSSL) alias. */
    if(strncasecompare(cipher, "TLS_", 4)) {
      for(i = 0; i < NUM_OF_CIPHERS &&
            (strlen(ciphertable[i].name) == clen) &&
            !strncasecompare(cipher, ciphertable[i].name, clen); ++i);
    }
    else {
      for(i = 0; i < NUM_OF_CIPHERS &&
            (strlen(ciphertable[i].alias_name) == clen) &&
            !strncasecompare(cipher, ciphertable[i].alias_name, clen); ++i);
    }
    if(i == NUM_OF_CIPHERS) {
      infof(data, "BearSSL: unknown cipher in list: %.*s",
            (int)clen, cipher);
      continue;
    }

    /* No duplicates allowed */
    for(j = 0; j < selected_count &&
          selected_ciphers[j] != ciphertable[i].num; j++);
    if(j < selected_count) {
      infof(data, "BearSSL: duplicate cipher in list: %.*s",
            (int)clen, cipher);
      continue;
    }

    DEBUGASSERT(selected_count < NUM_OF_CIPHERS);
    selected_ciphers[selected_count] = ciphertable[i].num;
    ++selected_count;
  }

  if(selected_count == 0) {
    failf(data, "BearSSL: no supported cipher in list");
    return CURLE_SSL_CIPHER;
  }

  br_ssl_engine_set_suites(ssl_eng, selected_ciphers, selected_count);
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
  unsigned version_min, version_max;
  int session_set = 0;

  DEBUGASSERT(backend);
  CURL_TRC_CF(data, cf, "connect_step1");

  switch(conn_config->version) {
  case CURL_SSLVERSION_SSLv2:
    failf(data, "BearSSL does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_SSLv3:
    failf(data, "BearSSL does not support SSLv3");
    return CURLE_SSL_CONNECT_ERROR;
  case CURL_SSLVERSION_TLSv1_0:
    version_min = BR_TLS10;
    version_max = BR_TLS10;
    break;
  case CURL_SSLVERSION_TLSv1_1:
    version_min = BR_TLS11;
    version_max = BR_TLS11;
    break;
  case CURL_SSLVERSION_TLSv1_2:
    version_min = BR_TLS12;
    version_max = BR_TLS12;
    break;
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    version_min = BR_TLS10;
    version_max = BR_TLS12;
    break;
  default:
    failf(data, "BearSSL: unknown CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

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
  br_ssl_engine_set_versions(&backend->ctx.eng, version_min, version_max);
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

  if(ssl_config->primary.sessionid) {
    void *session;

    CURL_TRC_CF(data, cf, "connect_step1, check session cache");
    Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(cf, data, &session, NULL)) {
      br_ssl_engine_set_session_parameters(&backend->ctx.eng, session);
      session_set = 1;
      infof(data, "BearSSL: reusing session ID");
    }
    Curl_ssl_sessionid_unlock(data);
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

  if(connssl->peer.is_ip_address) {
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
    Curl_set_in_callback(data, true);
    ret = (*data->set.ssl.fsslctx)(data, &backend->ctx,
                                   data->set.ssl.fsslctxp);
    Curl_set_in_callback(data, false);
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

static void bearssl_adjust_pollset(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct easy_pollset *ps)
{
  if(!cf->connected) {
    curl_socket_t sock = Curl_conn_cf_get_socket(cf->next, data);
    if(sock != CURL_SOCKET_BAD) {
      struct ssl_connect_data *connssl = cf->ctx;
      struct bearssl_ssl_backend_data *backend =
        (struct bearssl_ssl_backend_data *)connssl->backend;
      unsigned state = br_ssl_engine_current_state(&backend->ctx.eng);

      if(state & BR_SSL_SENDREC) {
        Curl_pollset_set_out_only(data, ps, sock);
      }
      else {
        Curl_pollset_set_in_only(data, ps, sock);
      }
    }
  }
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
      }
      /* X.509 errors are documented to have the range 32..63 */
      if(err >= 32 && err < 64)
        return CURLE_PEER_FAILED_VERIFICATION;
      return CURLE_SSL_CONNECT_ERROR;
    }
    if(state & target)
      return CURLE_OK;
    if(state & BR_SSL_SENDREC) {
      buf = br_ssl_engine_sendrec_buf(&backend->ctx.eng, &len);
      ret = Curl_conn_cf_send(cf->next, data, (char *)buf, len, &result);
      CURL_TRC_CF(data, cf, "ssl_send(len=%zu) -> %zd, %d", len, ret, result);
      if(ret <= 0) {
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
        return CURLE_READ_ERROR;
      }
      if(ret <= 0) {
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
  CURLcode ret;

  DEBUGASSERT(backend);
  CURL_TRC_CF(data, cf, "connect_step2");

  ret = bearssl_run_until(cf, data, BR_SSL_SENDAPP | BR_SSL_RECVAPP);
  if(ret == CURLE_AGAIN)
    return CURLE_OK;
  if(ret == CURLE_OK) {
    unsigned int tver;
    if(br_ssl_engine_current_state(&backend->ctx.eng) == BR_SSL_CLOSED) {
      failf(data, "SSL: connection closed during handshake");
      return CURLE_SSL_CONNECT_ERROR;
    }
    connssl->connecting_state = ssl_connect_3;
    /* Informational message */
    tver = br_ssl_engine_get_version(&backend->ctx.eng);
    if(tver == 0x0303)
      infof(data, "SSL connection using TLSv1.2");
    else if(tver == 0x0304)
      infof(data, "SSL connection using TLSv1.3");
    else
      infof(data, "SSL connection using TLS 0x%x", tver);
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
    Curl_alpn_set_negotiated(cf, data, (const unsigned char *)proto,
                             proto? strlen(proto) : 0);
  }

  if(ssl_config->primary.sessionid) {
    bool incache;
    bool added = FALSE;
    void *oldsession;
    br_ssl_session_parameters *session;

    session = malloc(sizeof(*session));
    if(!session)
      return CURLE_OUT_OF_MEMORY;
    br_ssl_engine_get_session_parameters(&backend->ctx.eng, session);
    Curl_ssl_sessionid_lock(data);
    incache = !(Curl_ssl_getsessionid(cf, data, &oldsession, NULL));
    if(incache)
      Curl_ssl_delsessionid(data, oldsession);
    ret = Curl_ssl_addsessionid(cf, data, session, 0, &added);
    Curl_ssl_sessionid_unlock(data);
    if(!added)
      free(session);
    if(ret) {
      return CURLE_OUT_OF_MEMORY;
    }
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

static CURLcode bearssl_connect_common(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool nonblocking,
                                       bool *done)
{
  CURLcode ret;
  struct ssl_connect_data *connssl = cf->ctx;
  curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
  timediff_t timeout_ms;
  int what;

  CURL_TRC_CF(data, cf, "connect_common(blocking=%d)", !nonblocking);
  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    CURL_TRC_CF(data, cf, "connect_common, connected");
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    ret = bearssl_connect_step1(cf, data);
    if(ret)
      return ret;
  }

  while(ssl_connect_2 == connssl->connecting_state ||
        ssl_connect_2_reading == connssl->connecting_state ||
        ssl_connect_2_writing == connssl->connecting_state) {
    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it's available. */
    if(ssl_connect_2_reading == connssl->connecting_state ||
       ssl_connect_2_writing == connssl->connecting_state) {

      curl_socket_t writefd = ssl_connect_2_writing ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      CURL_TRC_CF(data, cf, "connect_common, check socket");
      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
                               nonblocking?0:timeout_ms);
      CURL_TRC_CF(data, cf, "connect_common, check socket -> %d", what);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking) {
          *done = FALSE;
          return CURLE_OK;
        }
        else {
          /* timeout */
          failf(data, "SSL connection timeout");
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    /* Run transaction, and return to the caller if it failed or if this
     * connection is done nonblocking and this loop would execute again. This
     * permits the owner of a multi handle to abort a connection attempt
     * before step2 has completed while ensuring that a client using select()
     * or epoll() will always have a valid fdset to wait on.
     */
    ret = bearssl_connect_step2(cf, data);
    if(ret || (nonblocking &&
               (ssl_connect_2 == connssl->connecting_state ||
                ssl_connect_2_reading == connssl->connecting_state ||
                ssl_connect_2_writing == connssl->connecting_state)))
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
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

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

static CURLcode bearssl_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  CURLcode ret;
  bool done = FALSE;

  ret = bearssl_connect_common(cf, data, FALSE, &done);
  if(ret)
    return ret;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static CURLcode bearssl_connect_nonblocking(struct Curl_cfilter *cf,
                                            struct Curl_easy *data,
                                            bool *done)
{
  return bearssl_connect_common(cf, data, TRUE, done);
}

static void *bearssl_get_internals(struct ssl_connect_data *connssl,
                                   CURLINFO info UNUSED_PARAM)
{
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  DEBUGASSERT(backend);
  return &backend->ctx;
}

static void bearssl_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct bearssl_ssl_backend_data *backend =
    (struct bearssl_ssl_backend_data *)connssl->backend;
  size_t i;

  DEBUGASSERT(backend);

  if(backend->active) {
    backend->active = FALSE;
    br_ssl_engine_close(&backend->ctx.eng);
    (void)bearssl_run_until(cf, data, BR_SSL_CLOSED);
  }
  if(backend->anchors) {
    for(i = 0; i < backend->anchors_len; ++i)
      free(backend->anchors[i].dn.data);
    Curl_safefree(backend->anchors);
  }
}

static void bearssl_session_free(void *ptr)
{
  free(ptr);
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
  SSLSUPP_CAINFO_BLOB | SSLSUPP_SSL_CTX | SSLSUPP_HTTPS_PROXY,
  sizeof(struct bearssl_ssl_backend_data),

  Curl_none_init,                  /* init */
  Curl_none_cleanup,               /* cleanup */
  bearssl_version,                 /* version */
  Curl_none_check_cxn,             /* check_cxn */
  Curl_none_shutdown,              /* shutdown */
  bearssl_data_pending,            /* data_pending */
  bearssl_random,                  /* random */
  Curl_none_cert_status_request,   /* cert_status_request */
  bearssl_connect,                 /* connect */
  bearssl_connect_nonblocking,     /* connect_nonblocking */
  bearssl_adjust_pollset,          /* adjust_pollset */
  bearssl_get_internals,           /* get_internals */
  bearssl_close,                   /* close_one */
  Curl_none_close_all,             /* close_all */
  bearssl_session_free,            /* session_free */
  Curl_none_set_engine,            /* set_engine */
  Curl_none_set_engine_default,    /* set_engine_default */
  Curl_none_engines_list,          /* engines_list */
  Curl_none_false_start,           /* false_start */
  bearssl_sha256sum,               /* sha256sum */
  NULL,                            /* associate_connection */
  NULL,                            /* disassociate_connection */
  NULL,                            /* free_multi_ssl_backend_data */
  bearssl_recv,                    /* recv decrypted data */
  bearssl_send,                    /* send data to encrypt */
};

#endif /* USE_BEARSSL */
