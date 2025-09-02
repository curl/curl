/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) Hoi-Ho Chan, <hoiho.chan@gmail.com>
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
 * Source file for all mbedTLS-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "../curl_setup.h"

#ifdef USE_MBEDTLS

/* Define this to enable lots of debugging for mbedTLS */
/* #define MBEDTLS_DEBUG */

#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER < 0x03020000
  #error "mbedTLS 3.2.0 or later required"
#endif
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#ifdef MBEDTLS_DEBUG
#include <mbedtls/debug.h>
#endif
#include "cipher_suite.h"
#include "../urldata.h"
#include "../sendf.h"
#include "../curlx/inet_pton.h"
#include "mbedtls.h"
#include "vtls.h"
#include "vtls_int.h"
#include "vtls_scache.h"
#include "x509asn1.h"
#include "../parsedate.h"
#include "../connect.h" /* for the connect timeout */
#include "../select.h"
#include "../multiif.h"
#include "mbedtls_threadlock.h"
#include "../strdup.h"

/* The last 3 #include files should be in this order */
#include "../curl_printf.h"
#include "../curl_memory.h"
#include "../memdebug.h"

/* ALPN for http2 */
#if defined(USE_HTTP2) && defined(MBEDTLS_SSL_ALPN)
#  define HAS_ALPN_MBEDTLS
#endif

struct mbed_ssl_backend_data {
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  mbedtls_ssl_context ssl;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt clicert;
#ifdef MBEDTLS_X509_CRL_PARSE_C
  mbedtls_x509_crl crl;
#endif
  mbedtls_pk_context pk;
  mbedtls_ssl_config config;
#ifdef HAS_ALPN_MBEDTLS
  const char *protocols[3];
#endif
  int *ciphersuites;
  size_t send_blocked_len;
  BIT(initialized); /* mbedtls_ssl_context is initialized */
  BIT(sent_shutdown);
  BIT(send_blocked);
};

/* apply threading? */
#if (defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)) || defined(_WIN32)
#define HAS_THREADING_SUPPORT
#endif

#ifndef MBEDTLS_ERROR_C
#define mbedtls_strerror(a,b,c) b[0] = 0
#endif

#ifdef HAS_THREADING_SUPPORT
static mbedtls_entropy_context ts_entropy;

static int entropy_init_initialized = 0;

static void entropy_init_mutex(mbedtls_entropy_context *ctx)
{
  /* lock 0 = entropy_init_mutex() */
  Curl_mbedtlsthreadlock_lock_function(0);
  if(entropy_init_initialized == 0) {
    mbedtls_entropy_init(ctx);
    entropy_init_initialized = 1;
  }
  Curl_mbedtlsthreadlock_unlock_function(0);
}

static void entropy_cleanup_mutex(mbedtls_entropy_context *ctx)
{
  /* lock 0 = use same lock as init */
  Curl_mbedtlsthreadlock_lock_function(0);
  if(entropy_init_initialized == 1) {
    mbedtls_entropy_free(ctx);
    entropy_init_initialized = 0;
  }
  Curl_mbedtlsthreadlock_unlock_function(0);
}

static int entropy_func_mutex(void *data, unsigned char *output, size_t len)
{
  int ret;
  /* lock 1 = entropy_func_mutex() */
  Curl_mbedtlsthreadlock_lock_function(1);
  ret = mbedtls_entropy_func(data, output, len);
  Curl_mbedtlsthreadlock_unlock_function(1);

  return ret;
}

#endif /* HAS_THREADING_SUPPORT */

#ifdef MBEDTLS_DEBUG
static void mbed_debug(void *context, int level, const char *f_name,
                       int line_nb, const char *line)
{
  struct Curl_easy *data = (struct Curl_easy *)context;
  (void)level;
  (void)line_nb;
  (void)f_name;

  if(data) {
    size_t len = strlen(line);
    if(len && (line[len - 1] == '\n'))
      /* discount any trailing newline */
      len--;
    infof(data, "%.*s", (int)len, line);
  }
}
#endif

static int mbedtls_bio_cf_write(void *bio,
                                const unsigned char *buf, size_t blen)
{
  struct Curl_cfilter *cf = bio;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  size_t nwritten;
  CURLcode result;

  DEBUGASSERT(data);
  if(!data)
    return 0;

  result = Curl_conn_cf_send(cf->next, data, (const char *)buf, blen, FALSE,
                             &nwritten);
  CURL_TRC_CF(data, cf, "mbedtls_bio_cf_out_write(len=%zu) -> %d, %zu",
              blen, result, nwritten);
  if(CURLE_AGAIN == result)
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  return result ? -1 : (int)nwritten;
}

static int mbedtls_bio_cf_read(void *bio, unsigned char *buf, size_t blen)
{
  struct Curl_cfilter *cf = bio;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  size_t nread;
  CURLcode result;

  DEBUGASSERT(data);
  if(!data)
    return 0;
  /* OpenSSL catches this case, so should we. */
  if(!buf)
    return 0;

  result = Curl_conn_cf_recv(cf->next, data, (char *)buf, blen, &nread);
  CURL_TRC_CF(data, cf, "mbedtls_bio_cf_in_read(len=%zu) -> %d, %zu",
              blen, result, nread);
  if(CURLE_AGAIN == result)
    return MBEDTLS_ERR_SSL_WANT_READ;
  return result ? -1 : (int)nread;
}

/*
 *  profile
 */
static const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_fr =
{
  /* Hashes from SHA-1 and above */
  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA1) |
  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_RIPEMD160) |
  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA224) |
  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
  MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
  0xFFFFFFF, /* Any PK alg    */
  0xFFFFFFF, /* Any curve     */
  1024,      /* RSA min key len */
};

/* See https://web.archive.org/web/20200921194007/tls.mbed.org/discussions/
   generic/howto-determine-exact-buffer-len-for-mbedtls_pk_write_pubkey_der
*/
#define RSA_PUB_DER_MAX_BYTES   (38 + 2 * MBEDTLS_MPI_MAX_SIZE)
#define ECP_PUB_DER_MAX_BYTES   (30 + 2 * MBEDTLS_ECP_MAX_BYTES)

#define PUB_DER_MAX_BYTES   (RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                             RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES)

static CURLcode
mbed_set_ssl_version_min_max(struct Curl_easy *data,
                             struct mbed_ssl_backend_data *backend,
                             struct ssl_primary_config *conn_config)
{
  /* TLS 1.0 and TLS 1.1 were dropped with mbedTLS 3.0.0 (2021). So, since
   * then, and before the introduction of TLS 1.3 in 3.6.0 (2024), this
   * function basically always sets TLS 1.2 as min/max, unless given
   * unsupported option values. */

  mbedtls_ssl_protocol_version ver_min = MBEDTLS_SSL_VERSION_TLS1_2;
  mbedtls_ssl_protocol_version ver_max =
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    MBEDTLS_SSL_VERSION_TLS1_3
#else
    MBEDTLS_SSL_VERSION_TLS1_2
#endif
    ;

  switch(conn_config->version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
  case CURL_SSLVERSION_TLSv1_2:
    ver_min = MBEDTLS_SSL_VERSION_TLS1_2;
    break;
  case CURL_SSLVERSION_TLSv1_3:
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    ver_min = MBEDTLS_SSL_VERSION_TLS1_3;
    break;
#endif
  default:
    failf(data, "mbedTLS: unsupported minimum TLS version value: %x",
          conn_config->version);
    return CURLE_SSL_CONNECT_ERROR;
  }

  switch(conn_config->version_max) {
  case CURL_SSLVERSION_MAX_DEFAULT:
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_TLSv1_3:
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    ver_max = MBEDTLS_SSL_VERSION_TLS1_3;
    break;
#endif
  case CURL_SSLVERSION_MAX_TLSv1_2:
    ver_max = MBEDTLS_SSL_VERSION_TLS1_2;
    break;
  case CURL_SSLVERSION_MAX_TLSv1_1:
  case CURL_SSLVERSION_MAX_TLSv1_0:
  default:
    failf(data, "mbedTLS: unsupported maximum TLS version value");
    return CURLE_SSL_CONNECT_ERROR;
  }

  mbedtls_ssl_conf_min_tls_version(&backend->config, ver_min);
  mbedtls_ssl_conf_max_tls_version(&backend->config, ver_max);

  return CURLE_OK;
}

/* TLS_ECJPAKE_WITH_AES_128_CCM_8 (0xC0FF) is marked experimental
   in mbedTLS. The number is not reserved by IANA nor is the
   cipher suite present in other SSL implementations. Provide
   provisional support for specifying the cipher suite here. */
#ifdef MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8
static int
mbed_cipher_suite_get_str(uint16_t id, char *buf, size_t buf_size,
                          bool prefer_rfc)
{
  if(id == MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8)
    msnprintf(buf, buf_size, "%s", "TLS_ECJPAKE_WITH_AES_128_CCM_8");
  else
    return Curl_cipher_suite_get_str(id, buf, buf_size, prefer_rfc);
  return 0;
}

static uint16_t
mbed_cipher_suite_walk_str(const char **str, const char **end)
{
  uint16_t id = Curl_cipher_suite_walk_str(str, end);
  size_t len = *end - *str;

  if(!id) {
    if(curl_strnequal("TLS_ECJPAKE_WITH_AES_128_CCM_8", *str, len))
      id = MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8;
  }
  return id;
}
#else
#define mbed_cipher_suite_get_str Curl_cipher_suite_get_str
#define mbed_cipher_suite_walk_str Curl_cipher_suite_walk_str
#endif

static CURLcode
mbed_set_selected_ciphers(struct Curl_easy *data,
                          struct mbed_ssl_backend_data *backend,
                          const char *ciphers12,
                          const char *ciphers13)
{
  const char *ciphers = ciphers12;
  const int *supported;
  int *selected;
  size_t supported_len, count = 0, default13_count = 0, i, j;
  const char *ptr, *end;

  supported = mbedtls_ssl_list_ciphersuites();
  for(i = 0; supported[i] != 0; i++);
  supported_len = i;

  selected = malloc(sizeof(int) * (supported_len + 1));
  if(!selected)
    return CURLE_OUT_OF_MEMORY;

#ifndef MBEDTLS_SSL_PROTO_TLS1_3
  (void)ciphers13, (void)j;
#else
  if(!ciphers13) {
    /* Add default TLSv1.3 ciphers to selection */
    for(j = 0; j < supported_len; j++) {
      uint16_t id = (uint16_t) supported[j];
      if(strncmp(mbedtls_ssl_get_ciphersuite_name(id), "TLS1-3", 6) != 0)
        continue;

      selected[count++] = id;
    }

    default13_count = count;
  }
  else
    ciphers = ciphers13;

add_ciphers:
#endif
  for(ptr = ciphers; ptr[0] != '\0' && count < supported_len; ptr = end) {
    uint16_t id = mbed_cipher_suite_walk_str(&ptr, &end);

    /* Check if cipher is supported */
    if(id) {
      for(i = 0; i < supported_len && supported[i] != id; i++);
      if(i == supported_len)
        id = 0;
    }
    if(!id) {
      if(ptr[0] != '\0')
        infof(data, "mbedTLS: unknown cipher in list: \"%.*s\"",
              (int) (end - ptr), ptr);
      continue;
    }

    /* No duplicates allowed (so selected cannot overflow) */
    for(i = 0; i < count && selected[i] != id; i++);
    if(i < count) {
      if(i >= default13_count)
        infof(data, "mbedTLS: duplicate cipher in list: \"%.*s\"",
              (int) (end - ptr), ptr);
      continue;
    }

    selected[count++] = id;
  }

#ifdef MBEDTLS_SSL_PROTO_TLS1_3
  if(ciphers == ciphers13 && ciphers12) {
    ciphers = ciphers12;
    goto add_ciphers;
  }

  if(!ciphers12) {
    /* Add default TLSv1.2 ciphers to selection */
    for(j = 0; j < supported_len; j++) {
      uint16_t id = (uint16_t) supported[j];
      if(strncmp(mbedtls_ssl_get_ciphersuite_name(id), "TLS1-3", 6) == 0)
        continue;

      /* No duplicates allowed (so selected cannot overflow) */
      for(i = 0; i < count && selected[i] != id; i++);
      if(i < count)
        continue;

      selected[count++] = id;
    }
  }
#endif

  selected[count] = 0;

  if(count == 0) {
    free(selected);
    failf(data, "mbedTLS: no supported cipher in list");
    return CURLE_SSL_CIPHER;
  }

  /* mbedtls_ssl_conf_ciphersuites(): The ciphersuites array is not copied.
     It must remain valid for the lifetime of the SSL configuration */
  backend->ciphersuites = selected;
  mbedtls_ssl_conf_ciphersuites(&backend->config, backend->ciphersuites);
  return CURLE_OK;
}

static void
mbed_dump_cert_info(struct Curl_easy *data, const mbedtls_x509_crt *crt)
{
#if defined(CURL_DISABLE_VERBOSE_STRINGS) || defined(MBEDTLS_X509_REMOVE_INFO)
  (void)data, (void)crt;
#else
  const size_t bufsize = 16384;
  char *p, *buffer = malloc(bufsize);

  if(buffer && mbedtls_x509_crt_info(buffer, bufsize, " ", crt) > 0) {
    infof(data, "Server certificate:");
    for(p = buffer; *p; p += *p != '\0') {
      size_t s = strcspn(p, "\n");
      infof(data, "%.*s", (int) s, p);
      p += s;
    }
  }
  else
    infof(data, "Unable to dump certificate information");

  free(buffer);
#endif
}

static void
mbed_extract_certinfo(struct Curl_easy *data, const mbedtls_x509_crt *crt)
{
  CURLcode result;
  const mbedtls_x509_crt *cur;
  int i;

  for(i = 0, cur = crt; cur; ++i, cur = cur->next);
  result = Curl_ssl_init_certinfo(data, i);

  for(i = 0, cur = crt; result == CURLE_OK && cur; ++i, cur = cur->next) {
    const char *beg = (const char *) cur->raw.p;
    const char *end = beg + cur->raw.len;
    result = Curl_extract_certinfo(data, i, beg, end);
  }
}

static int mbed_verify_cb(void *ptr, mbedtls_x509_crt *crt,
                          int depth, uint32_t *flags)
{
  struct Curl_cfilter *cf = (struct Curl_cfilter *) ptr;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  if(depth == 0) {
    if(data->set.verbose)
      mbed_dump_cert_info(data, crt);
    if(data->set.ssl.certinfo)
      mbed_extract_certinfo(data, crt);
  }

  if(!conn_config->verifypeer)
    *flags = 0;
  else if(!conn_config->verifyhost)
    *flags &= ~MBEDTLS_X509_BADCERT_CN_MISMATCH;

  if(*flags) {
#ifndef MBEDTLS_X509_REMOVE_INFO
    char buf[128];
    mbedtls_x509_crt_verify_info(buf, sizeof(buf), "", *flags);
    failf(data, "mbedTLS: %s", buf);
#else
    failf(data, "mbedTLS: certificate verification error 0x%08x", *flags);
#endif
  }

  return 0;
}

static CURLcode
mbed_connect_step1(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  const struct curl_blob *ca_info_blob = conn_config->ca_info_blob;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  const char * const ssl_cafile =
    /* CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO */
    (ca_info_blob ? NULL : conn_config->CAfile);
  const bool verifypeer = conn_config->verifypeer;
  const char * const ssl_capath = conn_config->CApath;
  char * const ssl_cert = ssl_config->primary.clientcert;
  const struct curl_blob *ssl_cert_blob = ssl_config->primary.cert_blob;
  const char * const ssl_crlfile = ssl_config->primary.CRLfile;
  const char *hostname = connssl->peer.hostname;
  int ret = -1;
  char errorbuf[128];

  DEBUGASSERT(backend);
  DEBUGASSERT(!backend->initialized);

  if((conn_config->version == CURL_SSLVERSION_SSLv2) ||
     (conn_config->version == CURL_SSLVERSION_SSLv3)) {
    failf(data, "Not supported SSL version");
    return CURLE_NOT_BUILT_IN;
  }

#ifdef HAS_THREADING_SUPPORT
  mbedtls_ctr_drbg_init(&backend->ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&backend->ctr_drbg, entropy_func_mutex,
                              &ts_entropy, NULL, 0);
  if(ret) {
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "mbedtls_ctr_drbg_seed returned (-0x%04X) %s",
          -ret, errorbuf);
    return CURLE_FAILED_INIT;
  }
#else
  mbedtls_entropy_init(&backend->entropy);
  mbedtls_ctr_drbg_init(&backend->ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&backend->ctr_drbg, mbedtls_entropy_func,
                              &backend->entropy, NULL, 0);
  if(ret) {
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "mbedtls_ctr_drbg_seed returned (-0x%04X) %s",
          -ret, errorbuf);
    return CURLE_FAILED_INIT;
  }
#endif /* HAS_THREADING_SUPPORT */

  /* Load the trusted CA */
  mbedtls_x509_crt_init(&backend->cacert);

  if(ca_info_blob && verifypeer) {
    /* Unfortunately, mbedtls_x509_crt_parse() requires the data to be null
       terminated even when provided the exact length, forcing us to waste
       extra memory here. */
    unsigned char *newblob = Curl_memdup0(ca_info_blob->data,
                                          ca_info_blob->len);
    if(!newblob)
      return CURLE_OUT_OF_MEMORY;
    ret = mbedtls_x509_crt_parse(&backend->cacert, newblob,
                                 ca_info_blob->len + 1);
    free(newblob);
    if(ret < 0) {
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error importing ca cert blob - mbedTLS: (-0x%04X) %s",
            -ret, errorbuf);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  if(ssl_cafile && verifypeer) {
#ifdef MBEDTLS_FS_IO
    ret = mbedtls_x509_crt_parse_file(&backend->cacert, ssl_cafile);

    if(ret < 0) {
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading ca cert file %s - mbedTLS: (-0x%04X) %s",
            ssl_cafile, -ret, errorbuf);
      return CURLE_SSL_CACERT_BADFILE;
    }
#else
    failf(data, "mbedtls: functions that use the file system not built in");
    return CURLE_NOT_BUILT_IN;
#endif
  }

  if(ssl_capath) {
#ifdef MBEDTLS_FS_IO
    ret = mbedtls_x509_crt_parse_path(&backend->cacert, ssl_capath);

    if(ret < 0) {
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading ca cert path %s - mbedTLS: (-0x%04X) %s",
            ssl_capath, -ret, errorbuf);

      if(verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
#else
    failf(data, "mbedtls: functions that use the file system not built in");
    return CURLE_NOT_BUILT_IN;
#endif
  }

  /* Load the client certificate */
  mbedtls_x509_crt_init(&backend->clicert);

  if(ssl_cert) {
#ifdef MBEDTLS_FS_IO
    ret = mbedtls_x509_crt_parse_file(&backend->clicert, ssl_cert);

    if(ret) {
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading client cert file %s - mbedTLS: (-0x%04X) %s",
            ssl_cert, -ret, errorbuf);

      return CURLE_SSL_CERTPROBLEM;
    }
#else
    failf(data, "mbedtls: functions that use the file system not built in");
    return CURLE_NOT_BUILT_IN;
#endif
  }

  if(ssl_cert_blob) {
    /* Unfortunately, mbedtls_x509_crt_parse() requires the data to be null
       terminated even when provided the exact length, forcing us to waste
       extra memory here. */
    unsigned char *newblob = Curl_memdup0(ssl_cert_blob->data,
                                          ssl_cert_blob->len);
    if(!newblob)
      return CURLE_OUT_OF_MEMORY;
    ret = mbedtls_x509_crt_parse(&backend->clicert, newblob,
                                 ssl_cert_blob->len + 1);
    free(newblob);

    if(ret) {
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading client cert data %s - mbedTLS: (-0x%04X) %s",
            ssl_config->key, -ret, errorbuf);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the client private key */
  mbedtls_pk_init(&backend->pk);

  if(ssl_config->key || ssl_config->key_blob) {
    if(ssl_config->key) {
#ifdef MBEDTLS_FS_IO
      ret = mbedtls_pk_parse_keyfile(&backend->pk, ssl_config->key,
                                     ssl_config->key_passwd,
                                     mbedtls_ctr_drbg_random,
                                     &backend->ctr_drbg);
      if(ret == 0 && !(mbedtls_pk_can_do(&backend->pk, MBEDTLS_PK_RSA) ||
                       mbedtls_pk_can_do(&backend->pk, MBEDTLS_PK_ECKEY)))
        ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

      if(ret) {
        mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
        failf(data, "Error reading private key %s - mbedTLS: (-0x%04X) %s",
              ssl_config->key, -ret, errorbuf);
        return CURLE_SSL_CERTPROBLEM;
      }
#else
      failf(data, "mbedtls: functions that use the file system not built in");
      return CURLE_NOT_BUILT_IN;
#endif
    }
    else {
      const struct curl_blob *ssl_key_blob = ssl_config->key_blob;
      const unsigned char *key_data =
        (const unsigned char *)ssl_key_blob->data;
      const char *passwd = ssl_config->key_passwd;
      ret = mbedtls_pk_parse_key(&backend->pk, key_data, ssl_key_blob->len,
                                 (const unsigned char *)passwd,
                                 passwd ? strlen(passwd) : 0,
                                 mbedtls_ctr_drbg_random,
                                 &backend->ctr_drbg);
      if(ret == 0 && !(mbedtls_pk_can_do(&backend->pk, MBEDTLS_PK_RSA) ||
                       mbedtls_pk_can_do(&backend->pk, MBEDTLS_PK_ECKEY)))
        ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

      if(ret) {
        mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
        failf(data, "Error parsing private key - mbedTLS: (-0x%04X) %s",
              -ret, errorbuf);
        return CURLE_SSL_CERTPROBLEM;
      }
    }
  }

  /* Load the CRL */
#ifdef MBEDTLS_X509_CRL_PARSE_C
  mbedtls_x509_crl_init(&backend->crl);

  if(ssl_crlfile) {
#ifdef MBEDTLS_FS_IO
    ret = mbedtls_x509_crl_parse_file(&backend->crl, ssl_crlfile);

    if(ret) {
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading CRL file %s - mbedTLS: (-0x%04X) %s",
            ssl_crlfile, -ret, errorbuf);

      return CURLE_SSL_CRL_BADFILE;
    }
#else
    failf(data, "mbedtls: functions that use the file system not built in");
    return CURLE_NOT_BUILT_IN;
#endif
  }
#else
  if(ssl_crlfile) {
    failf(data, "mbedtls: crl support not built in");
    return CURLE_NOT_BUILT_IN;
  }
#endif

  infof(data, "mbedTLS: Connecting to %s:%d", hostname, connssl->peer.port);

  mbedtls_ssl_config_init(&backend->config);
  ret = mbedtls_ssl_config_defaults(&backend->config,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if(ret) {
    failf(data, "mbedTLS: ssl_config failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef MBEDTLS_SSL_SESSION_TICKETS
  /* New in mbedTLS 3.6.1, need to enable, default is now disabled */
  mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(&backend->config,
    MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED);
#endif

  /* Always let mbedTLS verify certificates, if verifypeer or verifyhost are
   * disabled we clear the corresponding error flags in the verify callback
   * function. That is also where we log verification errors. */
  mbedtls_ssl_conf_verify(&backend->config, mbed_verify_cb, cf);
  mbedtls_ssl_conf_authmode(&backend->config, MBEDTLS_SSL_VERIFY_REQUIRED);

  mbedtls_ssl_init(&backend->ssl);
  backend->initialized = TRUE;

  /* new profile with RSA min key len = 1024 ... */
  mbedtls_ssl_conf_cert_profile(&backend->config,
                                &mbedtls_x509_crt_profile_fr);

  ret = mbed_set_ssl_version_min_max(data, backend, conn_config);
  if(ret != CURLE_OK)
    return ret;

  mbedtls_ssl_conf_rng(&backend->config, mbedtls_ctr_drbg_random,
                       &backend->ctr_drbg);

  ret = mbedtls_ssl_setup(&backend->ssl, &backend->config);
  if(ret) {
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "ssl_setup failed - mbedTLS: (-0x%04X) %s",
          -ret, errorbuf);
    return CURLE_SSL_CONNECT_ERROR;
  }

  mbedtls_ssl_set_bio(&backend->ssl, cf,
                      mbedtls_bio_cf_write,
                      mbedtls_bio_cf_read,
                      NULL /*  rev_timeout() */);

#ifndef MBEDTLS_SSL_PROTO_TLS1_3
  if(conn_config->cipher_list) {
    CURLcode result = mbed_set_selected_ciphers(data, backend,
                                                conn_config->cipher_list,
                                                NULL);
#else
  if(conn_config->cipher_list || conn_config->cipher_list13) {
    CURLcode result = mbed_set_selected_ciphers(data, backend,
                                                conn_config->cipher_list,
                                                conn_config->cipher_list13);
#endif
    if(result != CURLE_OK) {
      failf(data, "mbedTLS: failed to set cipher suites");
      return result;
    }
  }
  else {
    mbedtls_ssl_conf_ciphersuites(&backend->config,
                                  mbedtls_ssl_list_ciphersuites());
  }


#ifdef MBEDTLS_SSL_RENEGOTIATION
  mbedtls_ssl_conf_renegotiation(&backend->config,
                                 MBEDTLS_SSL_RENEGOTIATION_ENABLED);
#endif

#ifdef MBEDTLS_SSL_SESSION_TICKETS
  mbedtls_ssl_conf_session_tickets(&backend->config,
                                   MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif

  /* Check if there is a cached ID we can/should use here! */
  if(ssl_config->primary.cache_session) {
    struct Curl_ssl_session *sc_session = NULL;
    CURLcode result;

    result = Curl_ssl_scache_take(cf, data, connssl->peer.scache_key,
                                  &sc_session);
    if(!result && sc_session && sc_session->sdata && sc_session->sdata_len) {
      mbedtls_ssl_session session;

      mbedtls_ssl_session_init(&session);
      ret = mbedtls_ssl_session_load(&session, sc_session->sdata,
                                     sc_session->sdata_len);
      if(ret) {
        failf(data, "SSL session error loading: -0x%x", -ret);
      }
      else {
        ret = mbedtls_ssl_set_session(&backend->ssl, &session);
        if(ret)
          failf(data, "SSL session error setting: -0x%x", -ret);
        else
          infof(data, "SSL reusing session ID");
      }
      mbedtls_ssl_session_free(&session);
    }
    Curl_ssl_scache_return(cf, data, connssl->peer.scache_key, sc_session);
  }

  mbedtls_ssl_conf_ca_chain(&backend->config,
                            &backend->cacert,
#ifdef MBEDTLS_X509_CRL_PARSE_C
                            &backend->crl);
#else
                            NULL);
#endif

  if(ssl_config->key || ssl_config->key_blob) {
    mbedtls_ssl_conf_own_cert(&backend->config,
                              &backend->clicert, &backend->pk);
  }

  if(mbedtls_ssl_set_hostname(&backend->ssl, connssl->peer.sni ?
                              connssl->peer.sni : connssl->peer.hostname)) {
    /* mbedtls_ssl_set_hostname() sets the name to use in CN/SAN checks and
       the name to set in the SNI extension. So even if curl connects to a
       host specified as an IP address, this function must be used. */
    failf(data, "Failed to set SNI");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef HAS_ALPN_MBEDTLS
  if(connssl->alpn) {
    struct alpn_proto_buf proto;
    size_t i;

    for(i = 0; i < connssl->alpn->count; ++i) {
      backend->protocols[i] = connssl->alpn->entries[i];
    }
    /* this function does not clone the protocols array, which is why we need
       to keep it around */
    if(mbedtls_ssl_conf_alpn_protocols(&backend->config,
                                       &backend->protocols[0])) {
      failf(data, "Failed setting ALPN protocols");
      return CURLE_SSL_CONNECT_ERROR;
    }
    Curl_alpn_to_proto_str(&proto, connssl->alpn);
    infof(data, VTLS_INFOF_ALPN_OFFER_1STR, proto.data);
  }
#endif

#ifdef MBEDTLS_DEBUG
  /* In order to make that work in mbedtls MBEDTLS_DEBUG_C must be defined. */
  mbedtls_ssl_conf_dbg(&backend->config, mbed_debug, data);
  /* - 0 No debug
   * - 1 Error
   * - 2 State change
   * - 3 Informational
   * - 4 Verbose
   */
  mbedtls_debug_set_threshold(4);
#endif

  /* give application a chance to interfere with mbedTLS set up. */
  if(data->set.ssl.fsslctx) {
    CURLcode result = (*data->set.ssl.fsslctx)(data, &backend->config,
                                               data->set.ssl.fsslctxp);
    if(result != CURLE_OK) {
      failf(data, "error signaled by ssl ctx callback");
      return result;
    }
  }

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode
mbed_connect_step2(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  int ret;
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
#ifndef CURL_DISABLE_PROXY
  const char * const pinnedpubkey = Curl_ssl_cf_is_proxy(cf) ?
    data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
    data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#else
  const char * const pinnedpubkey = data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#endif

  DEBUGASSERT(backend);

  ret = mbedtls_ssl_handshake(&backend->ssl);

  if(ret == MBEDTLS_ERR_SSL_WANT_READ) {
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
    return CURLE_OK;
  }
  else if(ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
    return CURLE_OK;
  }
  else if(ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
    failf(data, "peer certificate could not be verified");
    return CURLE_PEER_FAILED_VERIFICATION;
  }
  else if(ret) {
    char errorbuf[128];
    CURL_TRC_CF(data, cf, "TLS version %04X",
                mbedtls_ssl_get_version_number(&backend->ssl));
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "ssl_handshake returned: (-0x%04X) %s",
          -ret, errorbuf);
    return CURLE_SSL_CONNECT_ERROR;
  }

  {
    char cipher_str[64];
    uint16_t cipher_id;
    cipher_id = (uint16_t)
                mbedtls_ssl_get_ciphersuite_id_from_ssl(&backend->ssl);
    mbed_cipher_suite_get_str(cipher_id, cipher_str, sizeof(cipher_str), TRUE);
    infof(data, "mbedTLS: %s Handshake complete, cipher is %s",
          mbedtls_ssl_get_version(&backend->ssl), cipher_str);
  }

  if(pinnedpubkey) {
    int size;
    CURLcode result;
    const mbedtls_x509_crt *peercert;
    mbedtls_x509_crt *p = NULL;
    unsigned char *pubkey = NULL;

    peercert = mbedtls_ssl_get_peer_cert(&backend->ssl);
    if(!peercert || !peercert->raw.p || !peercert->raw.len) {
      failf(data, "Failed due to missing peer certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    p = calloc(1, sizeof(*p));

    if(!p)
      return CURLE_OUT_OF_MEMORY;

    pubkey = malloc(PUB_DER_MAX_BYTES);

    if(!pubkey) {
      result = CURLE_OUT_OF_MEMORY;
      goto pinnedpubkey_error;
    }

    mbedtls_x509_crt_init(p);

    /* Make a copy of our const peercert because mbedtls_pk_write_pubkey_der
       needs a non-const key, for now.
       https://github.com/Mbed-TLS/mbedtls/issues/396 */
    if(mbedtls_x509_crt_parse_der(p, peercert->raw.p, peercert->raw.len)) {
      failf(data, "Failed copying peer certificate");
      result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
      goto pinnedpubkey_error;
    }

    size = mbedtls_pk_write_pubkey_der(&p->pk, pubkey, PUB_DER_MAX_BYTES);

    if(size <= 0) {
      failf(data, "Failed copying public key from peer certificate");
      result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
      goto pinnedpubkey_error;
    }

    /* mbedtls_pk_write_pubkey_der writes data at the end of the buffer. */
    result = Curl_pin_peer_pubkey(data,
                                  pinnedpubkey,
                                  &pubkey[PUB_DER_MAX_BYTES - size], size);
pinnedpubkey_error:
    mbedtls_x509_crt_free(p);
    free(p);
    free(pubkey);
    if(result) {
      return result;
    }
  }

#ifdef HAS_ALPN_MBEDTLS
  if(connssl->alpn) {
    const char *proto = mbedtls_ssl_get_alpn_protocol(&backend->ssl);

    Curl_alpn_set_negotiated(cf, data, connssl, (const unsigned char *)proto,
                             proto ? strlen(proto) : 0);
  }
#endif

  connssl->connecting_state = ssl_connect_3;
  infof(data, "SSL connected");

  return CURLE_OK;
}

static CURLcode
mbed_new_session(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  mbedtls_ssl_session session;
  bool msession_alloced = FALSE;
  struct Curl_ssl_session *sc_session = NULL;
  unsigned char *sdata = NULL;
  size_t slen = 0;
  int ietf_tls_id;
  CURLcode result = CURLE_OK;
  int ret;

  DEBUGASSERT(backend);
  if(!ssl_config->primary.cache_session)
    return CURLE_OK;

  mbedtls_ssl_session_init(&session);
  ret = mbedtls_ssl_get_session(&backend->ssl, &session);
  msession_alloced = (ret != MBEDTLS_ERR_SSL_ALLOC_FAILED);
  if(ret) {
    failf(data, "mbedtls_ssl_get_session returned -0x%x", -ret);
    result = CURLE_SSL_CONNECT_ERROR;
    goto out;
  }

  mbedtls_ssl_session_save(&session, NULL, 0, &slen);
  if(!slen) {
    failf(data, "failed to serialize session: length is 0");
    goto out;
  }

  sdata = malloc(slen);
  if(!sdata) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  ret = mbedtls_ssl_session_save(&session, sdata, slen, &slen);
  if(ret) {
    failf(data, "failed to serialize session: -0x%x", -ret);
    goto out;
  }

  ietf_tls_id = mbedtls_ssl_get_version_number(&backend->ssl);
  result = Curl_ssl_session_create(sdata, slen,
                                   ietf_tls_id,
                                   connssl->negotiated.alpn, 0, 0,
                                   &sc_session);
  sdata = NULL;  /* call took ownership */
  if(!result)
    result = Curl_ssl_scache_put(cf, data, connssl->peer.scache_key,
                                 sc_session);

out:
  if(msession_alloced)
    mbedtls_ssl_session_free(&session);
  free(sdata);
  return result;
}

static CURLcode mbed_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *mem, size_t len,
                          size_t *pnwritten)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  CURLcode result = CURLE_OK;
  int nwritten;

  (void)data;
  *pnwritten = 0;
  DEBUGASSERT(backend);
  /* mbedtls is picky when a mbedtls_ssl_write) was previously blocked.
   * It requires to be called with the same amount of bytes again, or it
   * will lose bytes, e.g. reporting all was sent but they were not.
   * Remember the blocked length and use that when set. */
  if(backend->send_blocked) {
    DEBUGASSERT(backend->send_blocked_len <= len);
    CURL_TRC_CF(data, cf, "mbedtls_ssl_write(len=%zu) -> previously blocked "
                "on %zu bytes", len, backend->send_blocked_len);
    len = backend->send_blocked_len;
  }

  nwritten = mbedtls_ssl_write(&backend->ssl, (const unsigned char *)mem, len);

  if(nwritten >= 0) {
    *pnwritten = (size_t)nwritten;
    backend->send_blocked = FALSE;
  }
  else {
    CURL_TRC_CF(data, cf, "mbedtls_ssl_write(len=%zu) -> -0x%04X",
                len, -nwritten);
    result = ((nwritten == MBEDTLS_ERR_SSL_WANT_WRITE)
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
      || (nwritten == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
#endif
      ) ? CURLE_AGAIN : CURLE_SEND_ERROR;
    if((result == CURLE_AGAIN) && !backend->send_blocked) {
      backend->send_blocked = TRUE;
      backend->send_blocked_len = len;
    }
  }

  CURL_TRC_CF(data, cf, "mbedtls_ssl_write(len=%zu) -> %d, %zu",
              len, result, *pnwritten);
  return result;
}

static CURLcode mbedtls_shutdown(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  unsigned char buf[1024];
  CURLcode result = CURLE_OK;
  int ret;
  size_t i;

  DEBUGASSERT(backend);

  if(!backend->initialized || cf->shutdown) {
    *done = TRUE;
    return CURLE_OK;
  }

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  *done = FALSE;

  if(!backend->sent_shutdown) {
    /* do this only once */
    backend->sent_shutdown = TRUE;
    if(send_shutdown) {
      ret = mbedtls_ssl_close_notify(&backend->ssl);
      switch(ret) {
      case 0: /* we sent it, receive from the server */
        break;
      case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY: /* server also closed */
        *done = TRUE;
        goto out;
      case MBEDTLS_ERR_SSL_WANT_READ:
        connssl->io_need = CURL_SSL_IO_NEED_RECV;
        goto out;
      case MBEDTLS_ERR_SSL_WANT_WRITE:
        connssl->io_need = CURL_SSL_IO_NEED_SEND;
        goto out;
      default:
        CURL_TRC_CF(data, cf, "mbedtls_shutdown error -0x%04X", -ret);
        result = CURLE_RECV_ERROR;
        goto out;
      }
    }
  }

  /* SSL should now have started the shutdown from our side. Since it
   * was not complete, we are lacking the close notify from the server. */
  for(i = 0; i < 10; ++i) {
    ret = mbedtls_ssl_read(&backend->ssl, buf, sizeof(buf));
    /* This seems to be a bug in mbedTLS TLSv1.3 where it reports
     * WANT_READ, but has not encountered an EAGAIN. */
    if(ret == MBEDTLS_ERR_SSL_WANT_READ)
      ret = mbedtls_ssl_read(&backend->ssl, buf, sizeof(buf));
#ifdef MBEDTLS_SSL_PROTO_TLS1_3
    if(ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
      continue;
#endif
    if(ret <= 0)
      break;
  }

  if(ret > 0) {
    /* still data coming in? */
    CURL_TRC_CF(data, cf, "mbedtls_shutdown, still getting data");
  }
  else if(ret == 0 || (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)) {
    /* We got the close notify alert and are done. */
    CURL_TRC_CF(data, cf, "mbedtls_shutdown done");
    *done = TRUE;
  }
  else if(ret == MBEDTLS_ERR_SSL_WANT_READ) {
    CURL_TRC_CF(data, cf, "mbedtls_shutdown, need RECV");
    connssl->io_need = CURL_SSL_IO_NEED_RECV;
  }
  else if(ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    CURL_TRC_CF(data, cf, "mbedtls_shutdown, need SEND");
    connssl->io_need = CURL_SSL_IO_NEED_SEND;
  }
  else {
    CURL_TRC_CF(data, cf, "mbedtls_shutdown error -0x%04X", -ret);
    result = CURLE_RECV_ERROR;
  }

out:
  cf->shutdown = (result || *done);
  return result;
}

static void mbedtls_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;

  (void)data;
  DEBUGASSERT(backend);
  if(backend->initialized) {
    mbedtls_pk_free(&backend->pk);
    mbedtls_x509_crt_free(&backend->clicert);
    mbedtls_x509_crt_free(&backend->cacert);
#ifdef MBEDTLS_X509_CRL_PARSE_C
    mbedtls_x509_crl_free(&backend->crl);
#endif
    Curl_safefree(backend->ciphersuites);
    mbedtls_ssl_config_free(&backend->config);
    mbedtls_ssl_free(&backend->ssl);
    mbedtls_ctr_drbg_free(&backend->ctr_drbg);
#ifndef HAS_THREADING_SUPPORT
    mbedtls_entropy_free(&backend->entropy);
#endif /* HAS_THREADING_SUPPORT */
    backend->initialized = FALSE;
  }
}

static CURLcode mbed_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                          char *buf, size_t buffersize,
                          size_t *pnread)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  CURLcode result = CURLE_OK;
  int nread;

  (void)data;
  DEBUGASSERT(backend);
  *pnread = 0;

  nread = mbedtls_ssl_read(&backend->ssl, (unsigned char *)buf, buffersize);
  if(nread > 0)
    *pnread = (size_t)nread;
  else {
    CURL_TRC_CF(data, cf, "mbedtls_ssl_read(len=%zu) -> -0x%04X",
                buffersize, -nread);
    switch(nread) {
#ifdef MBEDTLS_SSL_SESSION_TICKETS
    case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
      mbed_new_session(cf, data);
      FALLTHROUGH();
#endif
    case MBEDTLS_ERR_SSL_WANT_READ:
      result = CURLE_AGAIN;
      break;
    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
      result = CURLE_OK;
      break;
    default: {
      char errorbuf[128];
      mbedtls_strerror(nread, errorbuf, sizeof(errorbuf));
      failf(data, "ssl_read returned: (-0x%04X) %s", -nread, errorbuf);
      result = CURLE_RECV_ERROR;
      break;
    }
    }
  }
  return result;
}

static size_t mbedtls_version(char *buffer, size_t size)
{
#ifdef MBEDTLS_VERSION_C
  /* if mbedtls_version_get_number() is available it is better */
  unsigned int version = mbedtls_version_get_number();
  return msnprintf(buffer, size, "mbedTLS/%u.%u.%u", version >> 24,
                   (version >> 16) & 0xff, (version >> 8) & 0xff);
#else
  return msnprintf(buffer, size, "mbedTLS/%s", MBEDTLS_VERSION_STRING);
#endif
}

/* 'data' might be NULL */
static CURLcode mbedtls_random(struct Curl_easy *data,
                               unsigned char *entropy, size_t length)
{
#ifdef MBEDTLS_CTR_DRBG_C
  int ret;
  mbedtls_entropy_context ctr_entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&ctr_entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  (void)data;

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                              &ctr_entropy, NULL, 0);

  if(!ret)
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, entropy, length);

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&ctr_entropy);

  return ret == 0 ? CURLE_OK : CURLE_FAILED_INIT;
#elif defined(MBEDTLS_HAVEGE_C)
  mbedtls_havege_state hs;
  mbedtls_havege_init(&hs);
  mbedtls_havege_random(&hs, entropy, length);
  mbedtls_havege_free(&hs);
  return CURLE_OK;
#else
  return CURLE_NOT_BUILT_IN;
#endif
}

static CURLcode mbedtls_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                bool *done)
{
  CURLcode retcode;
  struct ssl_connect_data *connssl = cf->ctx;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;
  connssl->io_need = CURL_SSL_IO_NEED_NONE;

  if(ssl_connect_1 == connssl->connecting_state) {
    retcode = mbed_connect_step1(cf, data);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_2 == connssl->connecting_state) {
    retcode = mbed_connect_step2(cf, data);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_3 == connssl->connecting_state) {
    /* For tls1.3 we get notified about new sessions */
    struct ssl_connect_data *ctx = cf->ctx;
    struct mbed_ssl_backend_data *backend =
      (struct mbed_ssl_backend_data *)ctx->backend;

    if(mbedtls_ssl_get_version_number(&backend->ssl) <=
       MBEDTLS_SSL_VERSION_TLS1_2) {
      retcode = mbed_new_session(cf, data);
      if(retcode)
        return retcode;
    }
    connssl->connecting_state = ssl_connect_done;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    *done = TRUE;
  }

  return CURLE_OK;
}

/*
 * return 0 error initializing SSL
 * return 1 SSL initialized successfully
 */
static int mbedtls_init(void)
{
  if(!Curl_mbedtlsthreadlock_thread_setup())
    return 0;
#ifdef HAS_THREADING_SUPPORT
  entropy_init_mutex(&ts_entropy);
#endif
#ifdef MBEDTLS_USE_PSA_CRYPTO  /* requires mbedTLS 3.6.0+ */
  {
    int ret;
#ifdef HAS_THREADING_SUPPORT
    Curl_mbedtlsthreadlock_lock_function(0);
#endif
    ret = psa_crypto_init();
#ifdef HAS_THREADING_SUPPORT
    Curl_mbedtlsthreadlock_unlock_function(0);
#endif
    if(ret != PSA_SUCCESS)
      return 0;
  }
#endif /* MBEDTLS_USE_PSA_CRYPTO */
  return 1;
}

static void mbedtls_cleanup(void)
{
#ifdef HAS_THREADING_SUPPORT
  entropy_cleanup_mutex(&ts_entropy);
#endif
  (void)Curl_mbedtlsthreadlock_thread_cleanup();
}

static bool mbedtls_data_pending(struct Curl_cfilter *cf,
                                 const struct Curl_easy *data)
{
  struct ssl_connect_data *ctx = cf->ctx;
  struct mbed_ssl_backend_data *backend;

  (void)data;
  DEBUGASSERT(ctx && ctx->backend);
  backend = (struct mbed_ssl_backend_data *)ctx->backend;
  return mbedtls_ssl_get_bytes_avail(&backend->ssl) != 0;
}

static CURLcode mbedtls_sha256sum(const unsigned char *input,
                                  size_t inputlen,
                                  unsigned char *sha256sum,
                                  size_t sha256len)
{
  (void)sha256len;
  /* returns 0 on success, otherwise failure */
  if(mbedtls_sha256(input, inputlen, sha256sum, 0) != 0)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return CURLE_OK;
}

static void *mbedtls_get_internals(struct ssl_connect_data *connssl,
                                   CURLINFO info)
{
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  (void)info;
  DEBUGASSERT(backend);
  return &backend->ssl;
}

const struct Curl_ssl Curl_ssl_mbedtls = {
  { CURLSSLBACKEND_MBEDTLS, "mbedtls" }, /* info */

  SSLSUPP_CA_PATH |
  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_CERTINFO |
  SSLSUPP_PINNEDPUBKEY |
  SSLSUPP_SSL_CTX |
#ifdef MBEDTLS_SSL_PROTO_TLS1_3  /* requires mbedTLS 3.6.0+ */
  SSLSUPP_TLS13_CIPHERSUITES |
#endif
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST,

  sizeof(struct mbed_ssl_backend_data),

  mbedtls_init,                     /* init */
  mbedtls_cleanup,                  /* cleanup */
  mbedtls_version,                  /* version */
  mbedtls_shutdown,                 /* shutdown */
  mbedtls_data_pending,             /* data_pending */
  mbedtls_random,                   /* random */
  NULL,                             /* cert_status_request */
  mbedtls_connect,                  /* connect */
  Curl_ssl_adjust_pollset,          /* adjust_pollset */
  mbedtls_get_internals,            /* get_internals */
  mbedtls_close,                    /* close_one */
  NULL,                             /* close_all */
  NULL,                             /* set_engine */
  NULL,                             /* set_engine_default */
  NULL,                             /* engines_list */
  mbedtls_sha256sum,                /* sha256sum */
  mbed_recv,                        /* recv decrypted data */
  mbed_send,                        /* send data to encrypt */
  NULL,                             /* get_channel_binding */
};

#endif /* USE_MBEDTLS */
