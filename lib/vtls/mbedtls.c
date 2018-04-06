/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010 - 2011, Hoi-Ho Chan, <hoiho.chan@gmail.com>
 * Copyright (C) 2012 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
 * Source file for all mbedTLS-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "curl_setup.h"

#ifdef USE_MBEDTLS

#include <mbedtls/version.h>
#if MBEDTLS_VERSION_NUMBER >= 0x02040000
#include <mbedtls/net_sockets.h>
#else
#include <mbedtls/net.h>
#endif
#include <mbedtls/ssl.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>

#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "mbedtls.h"
#include "vtls.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "polarssl_threadlock.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

struct ssl_backend_data {
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
  mbedtls_ssl_context ssl;
  int server_fd;
  mbedtls_x509_crt cacert;
  mbedtls_x509_crt clicert;
  mbedtls_x509_crl crl;
  mbedtls_pk_context pk;
  mbedtls_ssl_config config;
  const char *protocols[3];
};

#define BACKEND connssl->backend

/* apply threading? */
#if defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)
#define THREADING_SUPPORT
#endif

#if defined(THREADING_SUPPORT)
static mbedtls_entropy_context ts_entropy;

static int entropy_init_initialized = 0;

/* start of entropy_init_mutex() */
static void entropy_init_mutex(mbedtls_entropy_context *ctx)
{
  /* lock 0 = entropy_init_mutex() */
  Curl_polarsslthreadlock_lock_function(0);
  if(entropy_init_initialized == 0) {
    mbedtls_entropy_init(ctx);
    entropy_init_initialized = 1;
  }
  Curl_polarsslthreadlock_unlock_function(0);
}
/* end of entropy_init_mutex() */

/* start of entropy_func_mutex() */
static int entropy_func_mutex(void *data, unsigned char *output, size_t len)
{
  int ret;
  /* lock 1 = entropy_func_mutex() */
  Curl_polarsslthreadlock_lock_function(1);
  ret = mbedtls_entropy_func(data, output, len);
  Curl_polarsslthreadlock_unlock_function(1);

  return ret;
}
/* end of entropy_func_mutex() */

#endif /* THREADING_SUPPORT */

/* Define this to enable lots of debugging for mbedTLS */
#undef MBEDTLS_DEBUG

#ifdef MBEDTLS_DEBUG
static void mbed_debug(void *context, int level, const char *f_name,
                       int line_nb, const char *line)
{
  struct Curl_easy *data = NULL;

  if(!context)
    return;

  data = (struct Curl_easy *)context;

  infof(data, "%s", line);
  (void) level;
}
#else
#endif

/* ALPN for http2? */
#ifdef USE_NGHTTP2
#  undef HAS_ALPN
#  ifdef MBEDTLS_SSL_ALPN
#    define HAS_ALPN
#  endif
#endif


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

/* See https://tls.mbed.org/discussions/generic/
   howto-determine-exact-buffer-len-for-mbedtls_pk_write_pubkey_der
*/
#define RSA_PUB_DER_MAX_BYTES   (38 + 2 * MBEDTLS_MPI_MAX_SIZE)
#define ECP_PUB_DER_MAX_BYTES   (30 + 2 * MBEDTLS_ECP_MAX_BYTES)

#define PUB_DER_MAX_BYTES   (RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                             RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES)

static Curl_recv mbed_recv;
static Curl_send mbed_send;

static CURLcode mbedtls_version_from_curl(int *mbedver, long version)
{
  switch(version) {
    case CURL_SSLVERSION_TLSv1_0:
      *mbedver = MBEDTLS_SSL_MINOR_VERSION_1;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_1:
      *mbedver = MBEDTLS_SSL_MINOR_VERSION_2;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_2:
      *mbedver = MBEDTLS_SSL_MINOR_VERSION_3;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_3:
      break;
  }
  return CURLE_SSL_CONNECT_ERROR;
}

static CURLcode
set_ssl_version_min_max(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  int mbedtls_ver_min = MBEDTLS_SSL_MINOR_VERSION_1;
  int mbedtls_ver_max = MBEDTLS_SSL_MINOR_VERSION_1;
  long ssl_version = SSL_CONN_CONFIG(version);
  long ssl_version_max = SSL_CONN_CONFIG(version_max);
  CURLcode result = CURLE_OK;

  switch(ssl_version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      ssl_version = CURL_SSLVERSION_TLSv1_0;
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }

  switch(ssl_version_max) {
    case CURL_SSLVERSION_MAX_NONE:
      ssl_version_max = ssl_version << 16;
      break;
    case CURL_SSLVERSION_MAX_DEFAULT:
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }

  result = mbedtls_version_from_curl(&mbedtls_ver_min, ssl_version);
  if(result) {
    failf(data, "unsupported min version passed via CURLOPT_SSLVERSION");
    return result;
  }
  result = mbedtls_version_from_curl(&mbedtls_ver_max, ssl_version_max >> 16);
  if(result) {
    failf(data, "unsupported max version passed via CURLOPT_SSLVERSION");
    return result;
  }

  mbedtls_ssl_conf_min_version(&BACKEND->config, MBEDTLS_SSL_MAJOR_VERSION_3,
                               mbedtls_ver_min);
  mbedtls_ssl_conf_max_version(&BACKEND->config, MBEDTLS_SSL_MAJOR_VERSION_3,
                               mbedtls_ver_max);

  return result;
}

static CURLcode
mbed_connect_step1(struct connectdata *conn,
                   int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  const char * const ssl_cafile = SSL_CONN_CONFIG(CAfile);
  const bool verifypeer = SSL_CONN_CONFIG(verifypeer);
  const char * const ssl_capath = SSL_CONN_CONFIG(CApath);
  char * const ssl_cert = SSL_SET_OPTION(cert);
  const char * const ssl_crlfile = SSL_SET_OPTION(CRLfile);
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;
  const long int port = SSL_IS_PROXY() ? conn->port : conn->remote_port;
  int ret = -1;
  char errorbuf[128];
  errorbuf[0] = 0;

  /* mbedTLS only supports SSLv3 and TLSv1 */
  if(SSL_CONN_CONFIG(version) == CURL_SSLVERSION_SSLv2) {
    failf(data, "mbedTLS does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef THREADING_SUPPORT
  entropy_init_mutex(&ts_entropy);
  mbedtls_ctr_drbg_init(&BACKEND->ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&BACKEND->ctr_drbg, entropy_func_mutex,
                              &ts_entropy, NULL, 0);
  if(ret) {
#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
    failf(data, "Failed - mbedTLS: ctr_drbg_init returned (-0x%04X) %s\n",
          -ret, errorbuf);
  }
#else
  mbedtls_entropy_init(&BACKEND->entropy);
  mbedtls_ctr_drbg_init(&BACKEND->ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&BACKEND->ctr_drbg, mbedtls_entropy_func,
                              &BACKEND->entropy, NULL, 0);
  if(ret) {
#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
    failf(data, "Failed - mbedTLS: ctr_drbg_init returned (-0x%04X) %s\n",
          -ret, errorbuf);
  }
#endif /* THREADING_SUPPORT */

  /* Load the trusted CA */
  mbedtls_x509_crt_init(&BACKEND->cacert);

  if(ssl_cafile) {
    ret = mbedtls_x509_crt_parse_file(&BACKEND->cacert, ssl_cafile);

    if(ret<0) {
#ifdef MBEDTLS_ERROR_C
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
      failf(data, "Error reading ca cert file %s - mbedTLS: (-0x%04X) %s",
            ssl_cafile, -ret, errorbuf);

      if(verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  if(ssl_capath) {
    ret = mbedtls_x509_crt_parse_path(&BACKEND->cacert, ssl_capath);

    if(ret<0) {
#ifdef MBEDTLS_ERROR_C
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
      failf(data, "Error reading ca cert path %s - mbedTLS: (-0x%04X) %s",
            ssl_capath, -ret, errorbuf);

      if(verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  /* Load the client certificate */
  mbedtls_x509_crt_init(&BACKEND->clicert);

  if(ssl_cert) {
    ret = mbedtls_x509_crt_parse_file(&BACKEND->clicert, ssl_cert);

    if(ret) {
#ifdef MBEDTLS_ERROR_C
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
      failf(data, "Error reading client cert file %s - mbedTLS: (-0x%04X) %s",
            ssl_cert, -ret, errorbuf);

      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the client private key */
  mbedtls_pk_init(&BACKEND->pk);

  if(SSL_SET_OPTION(key)) {
    ret = mbedtls_pk_parse_keyfile(&BACKEND->pk, SSL_SET_OPTION(key),
                                   SSL_SET_OPTION(key_passwd));
    if(ret == 0 && !mbedtls_pk_can_do(&BACKEND->pk, MBEDTLS_PK_RSA))
      ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;

    if(ret) {
#ifdef MBEDTLS_ERROR_C
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
      failf(data, "Error reading private key %s - mbedTLS: (-0x%04X) %s",
            SSL_SET_OPTION(key), -ret, errorbuf);

      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the CRL */
  mbedtls_x509_crl_init(&BACKEND->crl);

  if(ssl_crlfile) {
    ret = mbedtls_x509_crl_parse_file(&BACKEND->crl, ssl_crlfile);

    if(ret) {
#ifdef MBEDTLS_ERROR_C
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
      failf(data, "Error reading CRL file %s - mbedTLS: (-0x%04X) %s",
            ssl_crlfile, -ret, errorbuf);

      return CURLE_SSL_CRL_BADFILE;
    }
  }

  infof(data, "mbedTLS: Connecting to %s:%d\n", hostname, port);

  mbedtls_ssl_config_init(&BACKEND->config);

  mbedtls_ssl_init(&BACKEND->ssl);
  if(mbedtls_ssl_setup(&BACKEND->ssl, &BACKEND->config)) {
    failf(data, "mbedTLS: ssl_init failed");
    return CURLE_SSL_CONNECT_ERROR;
  }
  ret = mbedtls_ssl_config_defaults(&BACKEND->config,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if(ret) {
    failf(data, "mbedTLS: ssl_config failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* new profile with RSA min key len = 1024 ... */
  mbedtls_ssl_conf_cert_profile(&BACKEND->config,
                                &mbedtls_x509_crt_profile_fr);

  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    mbedtls_ssl_conf_min_version(&BACKEND->config, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_1);
    infof(data, "mbedTLS: Set min SSL version to TLS 1.0\n");
    break;
  case CURL_SSLVERSION_SSLv3:
    mbedtls_ssl_conf_min_version(&BACKEND->config, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_0);
    mbedtls_ssl_conf_max_version(&BACKEND->config, MBEDTLS_SSL_MAJOR_VERSION_3,
                                 MBEDTLS_SSL_MINOR_VERSION_0);
    infof(data, "mbedTLS: Set SSL version to SSLv3\n");
    break;
  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
  case CURL_SSLVERSION_TLSv1_2:
  case CURL_SSLVERSION_TLSv1_3:
    {
      CURLcode result = set_ssl_version_min_max(conn, sockindex);
      if(result != CURLE_OK)
        return result;
      break;
    }
  default:
    failf(data, "Unrecognized parameter passed via CURLOPT_SSLVERSION");
    return CURLE_SSL_CONNECT_ERROR;
  }

  mbedtls_ssl_conf_authmode(&BACKEND->config, MBEDTLS_SSL_VERIFY_OPTIONAL);

  mbedtls_ssl_conf_rng(&BACKEND->config, mbedtls_ctr_drbg_random,
                       &BACKEND->ctr_drbg);
  mbedtls_ssl_set_bio(&BACKEND->ssl, &conn->sock[sockindex],
                      mbedtls_net_send,
                      mbedtls_net_recv,
                      NULL /*  rev_timeout() */);

  mbedtls_ssl_conf_ciphersuites(&BACKEND->config,
                                mbedtls_ssl_list_ciphersuites());

#if defined(MBEDTLS_SSL_RENEGOTIATION)
  mbedtls_ssl_conf_renegotiation(&BACKEND->config,
                                 MBEDTLS_SSL_RENEGOTIATION_ENABLED);
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
  mbedtls_ssl_conf_session_tickets(&BACKEND->config,
                                   MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif

  /* Check if there's a cached ID we can/should use here! */
  if(SSL_SET_OPTION(primary.sessionid)) {
    void *old_session = NULL;

    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, &old_session, NULL, sockindex)) {
      ret = mbedtls_ssl_set_session(&BACKEND->ssl, old_session);
      if(ret) {
        Curl_ssl_sessionid_unlock(conn);
        failf(data, "mbedtls_ssl_set_session returned -0x%x", -ret);
        return CURLE_SSL_CONNECT_ERROR;
      }
      infof(data, "mbedTLS re-using session\n");
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  mbedtls_ssl_conf_ca_chain(&BACKEND->config,
                            &BACKEND->cacert,
                            &BACKEND->crl);

  if(SSL_SET_OPTION(key)) {
    mbedtls_ssl_conf_own_cert(&BACKEND->config,
                              &BACKEND->clicert, &BACKEND->pk);
  }
  if(mbedtls_ssl_set_hostname(&BACKEND->ssl, hostname)) {
    /* mbedtls_ssl_set_hostname() sets the name to use in CN/SAN checks *and*
       the name to set in the SNI extension. So even if curl connects to a
       host specified as an IP address, this function must be used. */
    failf(data, "couldn't set hostname in mbedTLS");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef HAS_ALPN
  if(conn->bits.tls_enable_alpn) {
    const char **p = &BACKEND->protocols[0];
#ifdef USE_NGHTTP2
    if(data->set.httpversion >= CURL_HTTP_VERSION_2)
      *p++ = NGHTTP2_PROTO_VERSION_ID;
#endif
    *p++ = ALPN_HTTP_1_1;
    *p = NULL;
    /* this function doesn't clone the protocols array, which is why we need
       to keep it around */
    if(mbedtls_ssl_conf_alpn_protocols(&BACKEND->config,
                                       &BACKEND->protocols[0])) {
      failf(data, "Failed setting ALPN protocols");
      return CURLE_SSL_CONNECT_ERROR;
    }
    for(p = &BACKEND->protocols[0]; *p; ++p)
      infof(data, "ALPN, offering %s\n", *p);
  }
#endif

#ifdef MBEDTLS_DEBUG
  /* In order to make that work in mbedtls MBEDTLS_DEBUG_C must be defined. */
  mbedtls_ssl_conf_dbg(&BACKEND->config, mbed_debug, data);
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
    ret = (*data->set.ssl.fsslctx)(data, &BACKEND->config,
                                   data->set.ssl.fsslctxp);
    if(ret) {
      failf(data, "error signaled by ssl ctx callback");
      return ret;
    }
  }

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode
mbed_connect_step2(struct connectdata *conn,
                   int sockindex)
{
  int ret;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  const mbedtls_x509_crt *peercert;
  const char * const pinnedpubkey = SSL_IS_PROXY() ?
        data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
        data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG];

#ifdef HAS_ALPN
  const char *next_protocol;
#endif

  char errorbuf[128];
  errorbuf[0] = 0;

  conn->recv[sockindex] = mbed_recv;
  conn->send[sockindex] = mbed_send;

  ret = mbedtls_ssl_handshake(&BACKEND->ssl);

  if(ret == MBEDTLS_ERR_SSL_WANT_READ) {
    connssl->connecting_state = ssl_connect_2_reading;
    return CURLE_OK;
  }
  else if(ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    connssl->connecting_state = ssl_connect_2_writing;
    return CURLE_OK;
  }
  else if(ret) {
#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
    failf(data, "ssl_handshake returned - mbedTLS: (-0x%04X) %s",
          -ret, errorbuf);
    return CURLE_SSL_CONNECT_ERROR;
  }

  infof(data, "mbedTLS: Handshake complete, cipher is %s\n",
        mbedtls_ssl_get_ciphersuite(&BACKEND->ssl)
    );

  ret = mbedtls_ssl_get_verify_result(&BACKEND->ssl);

  if(ret && SSL_CONN_CONFIG(verifypeer)) {
    if(ret & MBEDTLS_X509_BADCERT_EXPIRED)
      failf(data, "Cert verify failed: BADCERT_EXPIRED");

    if(ret & MBEDTLS_X509_BADCERT_REVOKED) {
      failf(data, "Cert verify failed: BADCERT_REVOKED");
      return CURLE_SSL_CACERT;
    }

    if(ret & MBEDTLS_X509_BADCERT_CN_MISMATCH)
      failf(data, "Cert verify failed: BADCERT_CN_MISMATCH");

    if(ret & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
      failf(data, "Cert verify failed: BADCERT_NOT_TRUSTED");

    return CURLE_PEER_FAILED_VERIFICATION;
  }

  peercert = mbedtls_ssl_get_peer_cert(&BACKEND->ssl);

  if(peercert && data->set.verbose) {
    const size_t bufsize = 16384;
    char *buffer = malloc(bufsize);

    if(!buffer)
      return CURLE_OUT_OF_MEMORY;

    if(mbedtls_x509_crt_info(buffer, bufsize, "* ", peercert) > 0)
      infof(data, "Dumping cert info:\n%s\n", buffer);
    else
      infof(data, "Unable to dump certificate information.\n");

    free(buffer);
  }

  if(pinnedpubkey) {
    int size;
    CURLcode result;
    mbedtls_x509_crt *p;
    unsigned char pubkey[PUB_DER_MAX_BYTES];

    if(!peercert || !peercert->raw.p || !peercert->raw.len) {
      failf(data, "Failed due to missing peer certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    p = calloc(1, sizeof(*p));

    if(!p)
      return CURLE_OUT_OF_MEMORY;

    mbedtls_x509_crt_init(p);

    /* Make a copy of our const peercert because mbedtls_pk_write_pubkey_der
       needs a non-const key, for now.
       https://github.com/ARMmbed/mbedtls/issues/396 */
    if(mbedtls_x509_crt_parse_der(p, peercert->raw.p, peercert->raw.len)) {
      failf(data, "Failed copying peer certificate");
      mbedtls_x509_crt_free(p);
      free(p);
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    size = mbedtls_pk_write_pubkey_der(&p->pk, pubkey, PUB_DER_MAX_BYTES);

    if(size <= 0) {
      failf(data, "Failed copying public key from peer certificate");
      mbedtls_x509_crt_free(p);
      free(p);
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    /* mbedtls_pk_write_pubkey_der writes data at the end of the buffer. */
    result = Curl_pin_peer_pubkey(data,
                                  pinnedpubkey,
                                  &pubkey[PUB_DER_MAX_BYTES - size], size);
    if(result) {
      mbedtls_x509_crt_free(p);
      free(p);
      return result;
    }

    mbedtls_x509_crt_free(p);
    free(p);
  }

#ifdef HAS_ALPN
  if(conn->bits.tls_enable_alpn) {
    next_protocol = mbedtls_ssl_get_alpn_protocol(&BACKEND->ssl);

    if(next_protocol) {
      infof(data, "ALPN, server accepted to use %s\n", next_protocol);
#ifdef USE_NGHTTP2
      if(!strncmp(next_protocol, NGHTTP2_PROTO_VERSION_ID,
                  NGHTTP2_PROTO_VERSION_ID_LEN) &&
         !next_protocol[NGHTTP2_PROTO_VERSION_ID_LEN]) {
        conn->negnpn = CURL_HTTP_VERSION_2;
      }
      else
#endif
        if(!strncmp(next_protocol, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH) &&
           !next_protocol[ALPN_HTTP_1_1_LENGTH]) {
          conn->negnpn = CURL_HTTP_VERSION_1_1;
        }
    }
    else {
      infof(data, "ALPN, server did not agree to a protocol\n");
    }
  }
#endif

  connssl->connecting_state = ssl_connect_3;
  infof(data, "SSL connected\n");

  return CURLE_OK;
}

static CURLcode
mbed_connect_step3(struct connectdata *conn,
                   int sockindex)
{
  CURLcode retcode = CURLE_OK;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  if(SSL_SET_OPTION(primary.sessionid)) {
    int ret;
    mbedtls_ssl_session *our_ssl_sessionid;
    void *old_ssl_sessionid = NULL;

    our_ssl_sessionid = malloc(sizeof(mbedtls_ssl_session));
    if(!our_ssl_sessionid)
      return CURLE_OUT_OF_MEMORY;

    mbedtls_ssl_session_init(our_ssl_sessionid);

    ret = mbedtls_ssl_get_session(&BACKEND->ssl, our_ssl_sessionid);
    if(ret) {
      free(our_ssl_sessionid);
      failf(data, "mbedtls_ssl_get_session returned -0x%x", -ret);
      return CURLE_SSL_CONNECT_ERROR;
    }

    /* If there's already a matching session in the cache, delete it */
    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL, sockindex))
      Curl_ssl_delsessionid(conn, old_ssl_sessionid);

    retcode = Curl_ssl_addsessionid(conn, our_ssl_sessionid, 0, sockindex);
    Curl_ssl_sessionid_unlock(conn);
    if(retcode) {
      free(our_ssl_sessionid);
      failf(data, "failed to store ssl session");
      return retcode;
    }
  }

  connssl->connecting_state = ssl_connect_done;

  return CURLE_OK;
}

static ssize_t mbed_send(struct connectdata *conn, int sockindex,
                         const void *mem, size_t len,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  int ret = -1;

  ret = mbedtls_ssl_write(&BACKEND->ssl,
                          (unsigned char *)mem, len);

  if(ret < 0) {
    *curlcode = (ret == MBEDTLS_ERR_SSL_WANT_WRITE) ?
      CURLE_AGAIN : CURLE_SEND_ERROR;
    ret = -1;
  }

  return ret;
}

static void Curl_mbedtls_close_all(struct Curl_easy *data)
{
  (void)data;
}

static void Curl_mbedtls_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  mbedtls_pk_free(&BACKEND->pk);
  mbedtls_x509_crt_free(&BACKEND->clicert);
  mbedtls_x509_crt_free(&BACKEND->cacert);
  mbedtls_x509_crl_free(&BACKEND->crl);
  mbedtls_ssl_config_free(&BACKEND->config);
  mbedtls_ssl_free(&BACKEND->ssl);
  mbedtls_ctr_drbg_free(&BACKEND->ctr_drbg);
#ifndef THREADING_SUPPORT
  mbedtls_entropy_free(&BACKEND->entropy);
#endif /* THREADING_SUPPORT */
}

static ssize_t mbed_recv(struct connectdata *conn, int num,
                         char *buf, size_t buffersize,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = &conn->ssl[num];
  int ret = -1;
  ssize_t len = -1;

  memset(buf, 0, buffersize);
  ret = mbedtls_ssl_read(&BACKEND->ssl, (unsigned char *)buf,
                         buffersize);

  if(ret <= 0) {
    if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
      return 0;

    *curlcode = (ret == MBEDTLS_ERR_SSL_WANT_READ) ?
      CURLE_AGAIN : CURLE_RECV_ERROR;
    return -1;
  }

  len = ret;

  return len;
}

static void Curl_mbedtls_session_free(void *ptr)
{
  mbedtls_ssl_session_free(ptr);
  free(ptr);
}

static size_t Curl_mbedtls_version(char *buffer, size_t size)
{
  unsigned int version = mbedtls_version_get_number();
  return snprintf(buffer, size, "mbedTLS/%d.%d.%d", version>>24,
                  (version>>16)&0xff, (version>>8)&0xff);
}

static CURLcode Curl_mbedtls_random(struct Curl_easy *data,
                                    unsigned char *entropy, size_t length)
{
#if defined(MBEDTLS_CTR_DRBG_C)
  int ret = -1;
  char errorbuf[128];
  mbedtls_entropy_context ctr_entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&ctr_entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  errorbuf[0] = 0;

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                              &ctr_entropy, NULL, 0);

  if(ret) {
#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
    failf(data, "Failed - mbedTLS: ctr_drbg_seed returned (-0x%04X) %s\n",
          -ret, errorbuf);
  }
  else {
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, entropy, length);

    if(ret) {
#ifdef MBEDTLS_ERROR_C
      mbedtls_strerror(ret, errorbuf, sizeof(errorbuf));
#endif /* MBEDTLS_ERROR_C */
      failf(data, "mbedTLS: ctr_drbg_init returned (-0x%04X) %s\n",
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
mbed_connect_common(struct connectdata *conn,
                    int sockindex,
                    bool nonblocking,
                    bool *done)
{
  CURLcode retcode;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1 == connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    retcode = mbed_connect_step1(conn, sockindex);
    if(retcode)
      return retcode;
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
    if(connssl->connecting_state == ssl_connect_2_reading
       || connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

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
    retcode = mbed_connect_step2(conn, sockindex);
    if(retcode || (nonblocking &&
                   (ssl_connect_2 == connssl->connecting_state ||
                    ssl_connect_2_reading == connssl->connecting_state ||
                    ssl_connect_2_writing == connssl->connecting_state)))
      return retcode;

  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    retcode = mbed_connect_step3(conn, sockindex);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = mbed_recv;
    conn->send[sockindex] = mbed_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

static CURLcode Curl_mbedtls_connect_nonblocking(struct connectdata *conn,
                                                 int sockindex, bool *done)
{
  return mbed_connect_common(conn, sockindex, TRUE, done);
}


static CURLcode Curl_mbedtls_connect(struct connectdata *conn, int sockindex)
{
  CURLcode retcode;
  bool done = FALSE;

  retcode = mbed_connect_common(conn, sockindex, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

/*
 * return 0 error initializing SSL
 * return 1 SSL initialized successfully
 */
static int Curl_mbedtls_init(void)
{
  return Curl_polarsslthreadlock_thread_setup();
}

static void Curl_mbedtls_cleanup(void)
{
  (void)Curl_polarsslthreadlock_thread_cleanup();
}

static bool Curl_mbedtls_data_pending(const struct connectdata *conn,
                                      int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  return mbedtls_ssl_get_bytes_avail(&BACKEND->ssl) != 0;
}

static void Curl_mbedtls_sha256sum(const unsigned char *input,
                                    size_t inputlen,
                                    unsigned char *sha256sum,
                                    size_t sha256len UNUSED_PARAM)
{
  (void)sha256len;
  mbedtls_sha256(input, inputlen, sha256sum, 0);
}

static void *Curl_mbedtls_get_internals(struct ssl_connect_data *connssl,
                                        CURLINFO info UNUSED_PARAM)
{
  (void)info;
  return &BACKEND->ssl;
}

const struct Curl_ssl Curl_ssl_mbedtls = {
  { CURLSSLBACKEND_MBEDTLS, "mbedtls" }, /* info */

  1, /* have_ca_path */
  0, /* have_certinfo */
  1, /* have_pinnedpubkey */
  1, /* have_ssl_ctx */
  0, /* support_https_proxy */

  sizeof(struct ssl_backend_data),

  Curl_mbedtls_init,                /* init */
  Curl_mbedtls_cleanup,             /* cleanup */
  Curl_mbedtls_version,             /* version */
  Curl_none_check_cxn,              /* check_cxn */
  Curl_none_shutdown,               /* shutdown */
  Curl_mbedtls_data_pending,        /* data_pending */
  Curl_mbedtls_random,              /* random */
  Curl_none_cert_status_request,    /* cert_status_request */
  Curl_mbedtls_connect,             /* connect */
  Curl_mbedtls_connect_nonblocking, /* connect_nonblocking */
  Curl_mbedtls_get_internals,       /* get_internals */
  Curl_mbedtls_close,               /* close_one */
  Curl_mbedtls_close_all,           /* close_all */
  Curl_mbedtls_session_free,        /* session_free */
  Curl_none_set_engine,             /* set_engine */
  Curl_none_set_engine_default,     /* set_engine_default */
  Curl_none_engines_list,           /* engines_list */
  Curl_none_false_start,            /* false_start */
  Curl_none_md5sum,                 /* md5sum */
  Curl_mbedtls_sha256sum            /* sha256sum */
};

#endif /* USE_MBEDTLS */
