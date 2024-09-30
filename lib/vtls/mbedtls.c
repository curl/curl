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

#include "curl_setup.h"

#ifdef USE_MBEDTLS

/* Define this to enable lots of debugging for mbedTLS */
/* #define MBEDTLS_DEBUG */

#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER >= 0x02040000
#include <mbedtls/net_sockets.h>
#else
#include <mbedtls/net.h>
#endif
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>

#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>

#if MBEDTLS_VERSION_MAJOR >= 2
#  ifdef MBEDTLS_DEBUG
#    include <mbedtls/debug.h>
#  endif
#endif

#include "cipher_suite.h"
#include "strcase.h"
#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "mbedtls.h"
#include "vtls.h"
#include "vtls_int.h"
#include "x509asn1.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "multiif.h"
#include "mbedtls_threadlock.h"
#include "strdup.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* ALPN for http2 */
#ifdef USE_HTTP2
#  undef HAS_ALPN
#  ifdef MBEDTLS_SSL_ALPN
#    define HAS_ALPN
#  endif
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
#ifdef HAS_ALPN
  const char *protocols[3];
#endif
  int *ciphersuites;
  BIT(initialized); /* mbedtls_ssl_context is initialized */
  BIT(sent_shutdown);
};

/* apply threading? */
#if (defined(USE_THREADS_POSIX) && defined(HAVE_PTHREAD_H)) || \
    defined(_WIN32)
#define THREADING_SUPPORT
#endif

#ifndef MBEDTLS_ERROR_C
#define mbedtls_strerror(a,b,c) b[0] = 0
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && MBEDTLS_VERSION_NUMBER >= 0x03060000
#define TLS13_SUPPORT
#endif

#if defined(THREADING_SUPPORT)
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

#endif /* THREADING_SUPPORT */

#ifdef MBEDTLS_DEBUG
static void mbed_debug(void *context, int level, const char *f_name,
                       int line_nb, const char *line)
{
  struct Curl_easy *data = (struct Curl_easy *)context;
  (void) level;
  (void) line_nb;
  (void) f_name;

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
  ssize_t nwritten;
  CURLcode result;

  DEBUGASSERT(data);
  if(!data)
    return 0;

  nwritten = Curl_conn_cf_send(cf->next, data, (char *)buf, blen, FALSE,
                               &result);
  CURL_TRC_CF(data, cf, "mbedtls_bio_cf_out_write(len=%zu) -> %zd, err=%d",
              blen, nwritten, result);
  if(nwritten < 0 && CURLE_AGAIN == result) {
    nwritten = MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  return (int)nwritten;
}

static int mbedtls_bio_cf_read(void *bio, unsigned char *buf, size_t blen)
{
  struct Curl_cfilter *cf = bio;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nread;
  CURLcode result;

  DEBUGASSERT(data);
  if(!data)
    return 0;
  /* OpenSSL catches this case, so should we. */
  if(!buf)
    return 0;

  nread = Curl_conn_cf_recv(cf->next, data, (char *)buf, blen, &result);
  CURL_TRC_CF(data, cf, "mbedtls_bio_cf_in_read(len=%zu) -> %zd, err=%d",
              blen, nread, result);
  if(nread < 0 && CURLE_AGAIN == result) {
    nread = MBEDTLS_ERR_SSL_WANT_READ;
  }
  return (int)nread;
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

#if MBEDTLS_VERSION_NUMBER < 0x03020000
  int ver_min = MBEDTLS_SSL_MINOR_VERSION_3; /* TLS 1.2 */
  int ver_max = MBEDTLS_SSL_MINOR_VERSION_3; /* TLS 1.2 */
#else
  /* mbedTLS 3.2.0 (2022) introduced new methods for setting TLS version */
  mbedtls_ssl_protocol_version ver_min = MBEDTLS_SSL_VERSION_TLS1_2;
  mbedtls_ssl_protocol_version ver_max = MBEDTLS_SSL_VERSION_TLS1_2;
#endif

  switch(conn_config->version) {
  case CURL_SSLVERSION_DEFAULT:
#if MBEDTLS_VERSION_NUMBER < 0x03000000
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
    ver_min = MBEDTLS_SSL_MINOR_VERSION_1;
    break;
  case CURL_SSLVERSION_TLSv1_1:
    ver_min = MBEDTLS_SSL_MINOR_VERSION_2;
    break;
#else
  case CURL_SSLVERSION_TLSv1:
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
#endif
  case CURL_SSLVERSION_TLSv1_2:
    /* ver_min = MBEDTLS_SSL_VERSION_TLS1_2; */
    break;
  case CURL_SSLVERSION_TLSv1_3:
#ifdef TLS13_SUPPORT
    ver_min = MBEDTLS_SSL_VERSION_TLS1_3;
    break;
#endif
  default:
    failf(data, "mbedTLS: unsupported minimum TLS version value");
    return CURLE_SSL_CONNECT_ERROR;
  }

  switch(conn_config->version_max) {
  case CURL_SSLVERSION_MAX_DEFAULT:
  case CURL_SSLVERSION_MAX_NONE:
  case CURL_SSLVERSION_MAX_TLSv1_3:
#ifdef TLS13_SUPPORT
    ver_max = MBEDTLS_SSL_VERSION_TLS1_3;
    break;
#endif
  case CURL_SSLVERSION_MAX_TLSv1_2:
    /* ver_max = MBEDTLS_SSL_VERSION_TLS1_2; */
    break;
#if MBEDTLS_VERSION_NUMBER < 0x03000000
  case CURL_SSLVERSION_MAX_TLSv1_1:
    ver_max = MBEDTLS_SSL_MINOR_VERSION_2;
    break;
  case CURL_SSLVERSION_MAX_TLSv1_0:
    ver_max = MBEDTLS_SSL_MINOR_VERSION_1;
    break;
#else
  case CURL_SSLVERSION_MAX_TLSv1_1:
  case CURL_SSLVERSION_MAX_TLSv1_0:
#endif
  default:
    failf(data, "mbedTLS: unsupported maximum TLS version value");
    return CURLE_SSL_CONNECT_ERROR;
  }

#if MBEDTLS_VERSION_NUMBER < 0x03020000
  mbedtls_ssl_conf_min_version(&backend->config, MBEDTLS_SSL_MAJOR_VERSION_3,
                               ver_min);
  mbedtls_ssl_conf_max_version(&backend->config, MBEDTLS_SSL_MAJOR_VERSION_3,
                               ver_max);
#else
  mbedtls_ssl_conf_min_tls_version(&backend->config, ver_min);
  mbedtls_ssl_conf_max_tls_version(&backend->config, ver_max);
#endif

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
    if(strncasecompare("TLS_ECJPAKE_WITH_AES_128_CCM_8", *str, len))
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

#ifndef TLS13_SUPPORT
  (void) ciphers13, (void) j;
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

#ifdef TLS13_SUPPORT
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
#if defined(CURL_DISABLE_VERBOSE_STRINGS) || \
    (MBEDTLS_VERSION_NUMBER >= 0x03000000 && defined(MBEDTLS_X509_REMOVE_INFO))
  (void) data, (void) crt;
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
#if MBEDTLS_VERSION_NUMBER < 0x03000000 || !defined(MBEDTLS_X509_REMOVE_INFO)
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

#ifdef TLS13_SUPPORT
  ret = psa_crypto_init();
  if(ret != PSA_SUCCESS) {
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "mbedTLS psa_crypto_init returned (-0x%04X) %s",
          -ret, errorbuf);
    return CURLE_SSL_CONNECT_ERROR;
  }
#endif /* TLS13_SUPPORT */

#ifdef THREADING_SUPPORT
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
#endif /* THREADING_SUPPORT */

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
    failf(data, "mbedtls: functions that use the filesystem not built in");
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
    failf(data, "mbedtls: functions that use the filesystem not built in");
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
    failf(data, "mbedtls: functions that use the filesystem not built in");
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
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
      ret = mbedtls_pk_parse_keyfile(&backend->pk, ssl_config->key,
                                     ssl_config->key_passwd,
                                     mbedtls_ctr_drbg_random,
                                     &backend->ctr_drbg);
#else
      ret = mbedtls_pk_parse_keyfile(&backend->pk, ssl_config->key,
                                     ssl_config->key_passwd);
#endif

      if(ret) {
        mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
        failf(data, "Error reading private key %s - mbedTLS: (-0x%04X) %s",
              ssl_config->key, -ret, errorbuf);
        return CURLE_SSL_CERTPROBLEM;
      }
#else
      failf(data, "mbedtls: functions that use the filesystem not built in");
      return CURLE_NOT_BUILT_IN;
#endif
    }
    else {
      const struct curl_blob *ssl_key_blob = ssl_config->key_blob;
      const unsigned char *key_data =
        (const unsigned char *)ssl_key_blob->data;
      const char *passwd = ssl_config->key_passwd;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
      ret = mbedtls_pk_parse_key(&backend->pk, key_data, ssl_key_blob->len,
                                 (const unsigned char *)passwd,
                                 passwd ? strlen(passwd) : 0,
                                 mbedtls_ctr_drbg_random,
                                 &backend->ctr_drbg);
#else
      ret = mbedtls_pk_parse_key(&backend->pk, key_data, ssl_key_blob->len,
                                 (const unsigned char *)passwd,
                                 passwd ? strlen(passwd) : 0);
#endif

      if(ret) {
        mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
        failf(data, "Error parsing private key - mbedTLS: (-0x%04X) %s",
              -ret, errorbuf);
        return CURLE_SSL_CERTPROBLEM;
      }
    }

    if(ret == 0 && !(mbedtls_pk_can_do(&backend->pk, MBEDTLS_PK_RSA) ||
                     mbedtls_pk_can_do(&backend->pk, MBEDTLS_PK_ECKEY)))
      ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;
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
    failf(data, "mbedtls: functions that use the filesystem not built in");
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

#ifndef TLS13_SUPPORT
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


#if defined(MBEDTLS_SSL_RENEGOTIATION)
  mbedtls_ssl_conf_renegotiation(&backend->config,
                                 MBEDTLS_SSL_RENEGOTIATION_ENABLED);
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
  mbedtls_ssl_conf_session_tickets(&backend->config,
                                   MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif

  /* Check if there is a cached ID we can/should use here! */
  if(ssl_config->primary.cache_session) {
    void *old_session = NULL;

    Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(cf, data, &connssl->peer, &old_session, NULL)) {
      ret = mbedtls_ssl_set_session(&backend->ssl, old_session);
      if(ret) {
        Curl_ssl_sessionid_unlock(data);
        failf(data, "mbedtls_ssl_set_session returned -0x%x", -ret);
        return CURLE_SSL_CONNECT_ERROR;
      }
      infof(data, "mbedTLS reusing session");
    }
    Curl_ssl_sessionid_unlock(data);
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

#ifdef HAS_ALPN
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
#if MBEDTLS_VERSION_NUMBER >= 0x03020000
    CURL_TRC_CF(data, cf, "TLS version %04X",
                mbedtls_ssl_get_version_number(&backend->ssl));
#endif
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "ssl_handshake returned: (-0x%04X) %s",
          -ret, errorbuf);
    return CURLE_SSL_CONNECT_ERROR;
  }

#if MBEDTLS_VERSION_NUMBER >= 0x03020000
  {
    char cipher_str[64];
    uint16_t cipher_id;
    cipher_id = (uint16_t)
                mbedtls_ssl_get_ciphersuite_id_from_ssl(&backend->ssl);
    mbed_cipher_suite_get_str(cipher_id, cipher_str, sizeof(cipher_str), true);
    infof(data, "mbedTLS: %s Handshake complete, cipher is %s",
          mbedtls_ssl_get_version(&backend->ssl), cipher_str);
  }
#else
  infof(data, "mbedTLS: %s Handshake complete",
        mbedtls_ssl_get_version(&backend->ssl));
#endif

  if(pinnedpubkey) {
    int size;
    CURLcode result;
    const mbedtls_x509_crt *peercert;
    mbedtls_x509_crt *p = NULL;
    unsigned char *pubkey = NULL;

    peercert = mbedtls_ssl_get_peer_cert(&backend->ssl);
#if MBEDTLS_VERSION_NUMBER == 0x03000000
    if(!peercert || !peercert->MBEDTLS_PRIVATE(raw).MBEDTLS_PRIVATE(p) ||
       !peercert->MBEDTLS_PRIVATE(raw).MBEDTLS_PRIVATE(len)) {
#else
    if(!peercert || !peercert->raw.p || !peercert->raw.len) {
#endif
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
       https://github.com/ARMmbed/mbedtls/issues/396 */
#if MBEDTLS_VERSION_NUMBER == 0x03000000
    if(mbedtls_x509_crt_parse_der(p,
                        peercert->MBEDTLS_PRIVATE(raw).MBEDTLS_PRIVATE(p),
                        peercert->MBEDTLS_PRIVATE(raw).MBEDTLS_PRIVATE(len))) {
#else
    if(mbedtls_x509_crt_parse_der(p, peercert->raw.p, peercert->raw.len)) {
#endif
      failf(data, "Failed copying peer certificate");
      result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
      goto pinnedpubkey_error;
    }

#if MBEDTLS_VERSION_NUMBER == 0x03000000
    size = mbedtls_pk_write_pubkey_der(&p->MBEDTLS_PRIVATE(pk), pubkey,
                                       PUB_DER_MAX_BYTES);
#else
    size = mbedtls_pk_write_pubkey_der(&p->pk, pubkey, PUB_DER_MAX_BYTES);
#endif

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

#ifdef HAS_ALPN
  if(connssl->alpn) {
    const char *proto = mbedtls_ssl_get_alpn_protocol(&backend->ssl);

    Curl_alpn_set_negotiated(cf, data, (const unsigned char *)proto,
                             proto ? strlen(proto) : 0);
  }
#endif

  connssl->connecting_state = ssl_connect_3;
  infof(data, "SSL connected");

  return CURLE_OK;
}

static void mbedtls_session_free(void *sessionid, size_t idsize)
{
  (void)idsize;
  mbedtls_ssl_session_free(sessionid);
  free(sessionid);
}

static CURLcode
mbed_connect_step3(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  CURLcode retcode = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);
  DEBUGASSERT(backend);

  if(ssl_config->primary.cache_session) {
    int ret;
    mbedtls_ssl_session *our_ssl_sessionid;

    our_ssl_sessionid = malloc(sizeof(mbedtls_ssl_session));
    if(!our_ssl_sessionid)
      return CURLE_OUT_OF_MEMORY;

    mbedtls_ssl_session_init(our_ssl_sessionid);

    ret = mbedtls_ssl_get_session(&backend->ssl, our_ssl_sessionid);
    if(ret) {
      if(ret != MBEDTLS_ERR_SSL_ALLOC_FAILED)
        mbedtls_ssl_session_free(our_ssl_sessionid);
      free(our_ssl_sessionid);
      failf(data, "mbedtls_ssl_get_session returned -0x%x", -ret);
      return CURLE_SSL_CONNECT_ERROR;
    }

    /* If there is already a matching session in the cache, delete it */
    Curl_ssl_sessionid_lock(data);
    retcode = Curl_ssl_set_sessionid(cf, data, &connssl->peer,
                                     our_ssl_sessionid, 0,
                                     mbedtls_session_free);
    Curl_ssl_sessionid_unlock(data);
    if(retcode)
      return retcode;
  }

  connssl->connecting_state = ssl_connect_done;

  return CURLE_OK;
}

static ssize_t mbed_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                         const void *mem, size_t len,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  int ret = -1;

  (void)data;
  DEBUGASSERT(backend);
  ret = mbedtls_ssl_write(&backend->ssl, (unsigned char *)mem, len);

  if(ret < 0) {
    CURL_TRC_CF(data, cf, "mbedtls_ssl_write(len=%zu) -> -0x%04X",
                len, -ret);
    *curlcode = ((ret == MBEDTLS_ERR_SSL_WANT_WRITE)
#ifdef TLS13_SUPPORT
      || (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
#endif
      ) ? CURLE_AGAIN : CURLE_SEND_ERROR;
    ret = -1;
  }

  return ret;
}

static void mbedtls_close_all(struct Curl_easy *data)
{
  (void)data;
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
#ifdef TLS13_SUPPORT
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
#ifndef THREADING_SUPPORT
    mbedtls_entropy_free(&backend->entropy);
#endif /* THREADING_SUPPORT */
    backend->initialized = FALSE;
  }
}

static ssize_t mbed_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                         char *buf, size_t buffersize,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct mbed_ssl_backend_data *backend =
    (struct mbed_ssl_backend_data *)connssl->backend;
  int ret = -1;
  ssize_t len = -1;

  (void)data;
  DEBUGASSERT(backend);

  ret = mbedtls_ssl_read(&backend->ssl, (unsigned char *)buf,
                         buffersize);
  if(ret <= 0) {
    CURL_TRC_CF(data, cf, "mbedtls_ssl_read(len=%zu) -> -0x%04X",
                buffersize, -ret);
    if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
      return 0;
    *curlcode = ((ret == MBEDTLS_ERR_SSL_WANT_READ)
#ifdef TLS13_SUPPORT
              || (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
#endif
    ) ? CURLE_AGAIN : CURLE_RECV_ERROR;
    if(*curlcode != CURLE_AGAIN) {
      char errorbuf[128];
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "ssl_read returned: (-0x%04X) %s", -ret, errorbuf);
    }
    return -1;
  }

  len = ret;

  return len;
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

static CURLcode mbedtls_random(struct Curl_easy *data,
                               unsigned char *entropy, size_t length)
{
#if defined(MBEDTLS_CTR_DRBG_C)
  int ret = -1;
  char errorbuf[128];
  mbedtls_entropy_context ctr_entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&ctr_entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                              &ctr_entropy, NULL, 0);

  if(ret) {
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "mbedtls_ctr_drbg_seed returned (-0x%04X) %s",
          -ret, errorbuf);
  }
  else {
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, entropy, length);

    if(ret) {
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "mbedtls_ctr_drbg_random returned (-0x%04X) %s",
            -ret, errorbuf);
    }
  }

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

static CURLcode
mbed_connect_common(struct Curl_cfilter *cf, struct Curl_easy *data,
                    bool nonblocking,
                    bool *done)
{
  CURLcode retcode;
  struct ssl_connect_data *connssl = cf->ctx;
  curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);
  timediff_t timeout_ms;
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Find out how much more time we are allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    retcode = mbed_connect_step1(cf, data);
    if(retcode)
      return retcode;
  }

  while(ssl_connect_2 == connssl->connecting_state) {

    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it is available. */
    if(connssl->io_need) {
      curl_socket_t writefd = (connssl->io_need & CURL_SSL_IO_NEED_SEND) ?
        sockfd : CURL_SOCKET_BAD;
      curl_socket_t readfd = (connssl->io_need & CURL_SSL_IO_NEED_RECV) ?
        sockfd : CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
                               nonblocking ? 0 : timeout_ms);
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

    /* Run transaction, and return to the caller if it failed or if
     * this connection is part of a multi handle and this loop would
     * execute again. This permits the owner of a multi handle to
     * abort a connection attempt before step2 has completed while
     * ensuring that a client using select() or epoll() will always
     * have a valid fdset to wait on.
     */
    connssl->io_need = CURL_SSL_IO_NEED_NONE;
    retcode = mbed_connect_step2(cf, data);
    if(retcode ||
       (nonblocking && (ssl_connect_2 == connssl->connecting_state)))
      return retcode;

  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    retcode = mbed_connect_step3(cf, data);
    if(retcode)
      return retcode;
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

static CURLcode mbedtls_connect_nonblocking(struct Curl_cfilter *cf,
                                            struct Curl_easy *data,
                                            bool *done)
{
  return mbed_connect_common(cf, data, TRUE, done);
}


static CURLcode mbedtls_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  CURLcode retcode;
  bool done = FALSE;

  retcode = mbed_connect_common(cf, data, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

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
#ifdef THREADING_SUPPORT
  entropy_init_mutex(&ts_entropy);
#endif
  return 1;
}

static void mbedtls_cleanup(void)
{
#ifdef THREADING_SUPPORT
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
                                  size_t sha256len UNUSED_PARAM)
{
  /* TODO: explain this for different mbedtls 2.x vs 3 version */
  (void)sha256len;
#if MBEDTLS_VERSION_NUMBER < 0x02070000
  mbedtls_sha256(input, inputlen, sha256sum, 0);
#else
  /* returns 0 on success, otherwise failure */
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
  if(mbedtls_sha256(input, inputlen, sha256sum, 0) != 0)
#else
  if(mbedtls_sha256_ret(input, inputlen, sha256sum, 0) != 0)
#endif
    return CURLE_BAD_FUNCTION_ARGUMENT;
#endif
  return CURLE_OK;
}

static void *mbedtls_get_internals(struct ssl_connect_data *connssl,
                                   CURLINFO info UNUSED_PARAM)
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
#ifdef TLS13_SUPPORT
  SSLSUPP_TLS13_CIPHERSUITES |
#endif
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CIPHER_LIST,

  sizeof(struct mbed_ssl_backend_data),

  mbedtls_init,                     /* init */
  mbedtls_cleanup,                  /* cleanup */
  mbedtls_version,                  /* version */
  Curl_none_check_cxn,              /* check_cxn */
  mbedtls_shutdown,                 /* shutdown */
  mbedtls_data_pending,             /* data_pending */
  mbedtls_random,                   /* random */
  Curl_none_cert_status_request,    /* cert_status_request */
  mbedtls_connect,                  /* connect */
  mbedtls_connect_nonblocking,      /* connect_nonblocking */
  Curl_ssl_adjust_pollset,          /* adjust_pollset */
  mbedtls_get_internals,            /* get_internals */
  mbedtls_close,                    /* close_one */
  mbedtls_close_all,                /* close_all */
  Curl_none_set_engine,             /* set_engine */
  Curl_none_set_engine_default,     /* set_engine_default */
  Curl_none_engines_list,           /* engines_list */
  Curl_none_false_start,            /* false_start */
  mbedtls_sha256sum,                /* sha256sum */
  NULL,                             /* associate_connection */
  NULL,                             /* disassociate_connection */
  mbed_recv,                        /* recv decrypted data */
  mbed_send,                        /* send data to encrypt */
  NULL,                             /* get_channel_binding */
};

#endif /* USE_MBEDTLS */
