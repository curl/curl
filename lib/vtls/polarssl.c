/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 * Copyright (C) 2010 - 2011, Hoi-Ho Chan, <hoiho.chan@gmail.com>
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
 * Source file for all PolarSSL-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "curl_setup.h"

#ifdef USE_POLARSSL
#include <polarssl/net.h>
#include <polarssl/ssl.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>
#include <polarssl/version.h>
#include <polarssl/sha256.h>

#if POLARSSL_VERSION_NUMBER < 0x01030000
#error too old PolarSSL
#endif

#include <polarssl/error.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "polarssl.h"
#include "vtls.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "strcase.h"
#include "polarssl_threadlock.h"
#include "multiif.h"
#include "curl_printf.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* See https://tls.mbed.org/discussions/generic/
   howto-determine-exact-buffer-len-for-mbedtls_pk_write_pubkey_der
*/
#define RSA_PUB_DER_MAX_BYTES   (38 + 2 * POLARSSL_MPI_MAX_SIZE)
#define ECP_PUB_DER_MAX_BYTES   (30 + 2 * POLARSSL_ECP_MAX_BYTES)

#define PUB_DER_MAX_BYTES   (RSA_PUB_DER_MAX_BYTES > ECP_PUB_DER_MAX_BYTES ? \
                             RSA_PUB_DER_MAX_BYTES : ECP_PUB_DER_MAX_BYTES)

struct ssl_backend_data {
  ctr_drbg_context ctr_drbg;
  entropy_context entropy;
  ssl_context ssl;
  int server_fd;
  x509_crt cacert;
  x509_crt clicert;
  x509_crl crl;
  rsa_context rsa;
};

#define BACKEND connssl->backend

/* apply threading? */
#if defined(USE_THREADS_POSIX) || defined(USE_THREADS_WIN32)
#define THREADING_SUPPORT
#endif

#ifndef POLARSSL_ERROR_C
#define error_strerror(x,y,z)
#endif /* POLARSSL_ERROR_C */


#if defined(THREADING_SUPPORT)
static entropy_context entropy;

static int  entropy_init_initialized  = 0;

/* start of entropy_init_mutex() */
static void entropy_init_mutex(entropy_context *ctx)
{
  /* lock 0 = entropy_init_mutex() */
  Curl_polarsslthreadlock_lock_function(0);
  if(entropy_init_initialized == 0) {
    entropy_init(ctx);
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
  ret = entropy_func(data, output, len);
  Curl_polarsslthreadlock_unlock_function(1);

  return ret;
}
/* end of entropy_func_mutex() */

#endif /* THREADING_SUPPORT */

/* Define this to enable lots of debugging for PolarSSL */
#undef POLARSSL_DEBUG

#ifdef POLARSSL_DEBUG
static void polarssl_debug(void *context, int level, const char *line)
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
#ifdef POLARSSL_SSL_ALPN
#  define HAS_ALPN
#endif

static Curl_recv polarssl_recv;
static Curl_send polarssl_send;

static CURLcode polarssl_version_from_curl(int *polarver, long ssl_version)
{
  switch(ssl_version) {
    case CURL_SSLVERSION_TLSv1_0:
      *polarver = SSL_MINOR_VERSION_1;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_1:
      *polarver = SSL_MINOR_VERSION_2;
      return CURLE_OK;
    case CURL_SSLVERSION_TLSv1_2:
      *polarver = SSL_MINOR_VERSION_3;
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
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  long ssl_version = SSL_CONN_CONFIG(version);
  long ssl_version_max = SSL_CONN_CONFIG(version_max);
  int ssl_min_ver = SSL_MINOR_VERSION_1;
  int ssl_max_ver = SSL_MINOR_VERSION_1;
  CURLcode result = CURLE_OK;

  switch(ssl_version) {
    case CURL_SSLVERSION_DEFAULT:
    case CURL_SSLVERSION_TLSv1:
      ssl_version = CURL_SSLVERSION_TLSv1_0;
      break;
  }

  switch(ssl_version_max) {
    case CURL_SSLVERSION_MAX_NONE:
    case CURL_SSLVERSION_MAX_DEFAULT:
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
      break;
  }

  result = polarssl_version_from_curl(&ssl_min_ver, ssl_version);
  if(result) {
    failf(data, "unsupported min version passed via CURLOPT_SSLVERSION");
    return result;
  }
  result = polarssl_version_from_curl(&ssl_max_ver, ssl_version_max >> 16);
  if(result) {
    failf(data, "unsupported max version passed via CURLOPT_SSLVERSION");
    return result;
  }

  ssl_set_min_version(&BACKEND->ssl, SSL_MAJOR_VERSION_3, ssl_min_ver);
  ssl_set_max_version(&BACKEND->ssl, SSL_MAJOR_VERSION_3, ssl_max_ver);

  return result;
}

static CURLcode
polarssl_connect_step1(struct connectdata *conn,
                       int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  const char *capath = SSL_CONN_CONFIG(CApath);
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;
  const long int port = SSL_IS_PROXY() ? conn->port : conn->remote_port;
  int ret = -1;
  char errorbuf[128];
  errorbuf[0] = 0;

  /* PolarSSL only supports SSLv3 and TLSv1 */
  if(SSL_CONN_CONFIG(version) == CURL_SSLVERSION_SSLv2) {
    failf(data, "PolarSSL does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef THREADING_SUPPORT
  entropy_init_mutex(&entropy);

  if((ret = ctr_drbg_init(&BACKEND->ctr_drbg, entropy_func_mutex, &entropy,
                          NULL, 0)) != 0) {
    error_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "Failed - PolarSSL: ctr_drbg_init returned (-0x%04X) %s\n",
          -ret, errorbuf);
  }
#else
  entropy_init(&BACKEND->entropy);

  if((ret = ctr_drbg_init(&BACKEND->ctr_drbg, entropy_func, &BACKEND->entropy,
                          NULL, 0)) != 0) {
    error_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "Failed - PolarSSL: ctr_drbg_init returned (-0x%04X) %s\n",
          -ret, errorbuf);
  }
#endif /* THREADING_SUPPORT */

  /* Load the trusted CA */
  memset(&BACKEND->cacert, 0, sizeof(x509_crt));

  if(SSL_CONN_CONFIG(CAfile)) {
    ret = x509_crt_parse_file(&BACKEND->cacert,
                              SSL_CONN_CONFIG(CAfile));

    if(ret<0) {
      error_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading ca cert file %s - PolarSSL: (-0x%04X) %s",
            SSL_CONN_CONFIG(CAfile), -ret, errorbuf);

      if(SSL_CONN_CONFIG(verifypeer))
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  if(capath) {
    ret = x509_crt_parse_path(&BACKEND->cacert, capath);

    if(ret<0) {
      error_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading ca cert path %s - PolarSSL: (-0x%04X) %s",
            capath, -ret, errorbuf);

      if(SSL_CONN_CONFIG(verifypeer))
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  /* Load the client certificate */
  memset(&BACKEND->clicert, 0, sizeof(x509_crt));

  if(SSL_SET_OPTION(cert)) {
    ret = x509_crt_parse_file(&BACKEND->clicert,
                              SSL_SET_OPTION(cert));

    if(ret) {
      error_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading client cert file %s - PolarSSL: (-0x%04X) %s",
            SSL_SET_OPTION(cert), -ret, errorbuf);

      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the client private key */
  if(SSL_SET_OPTION(key)) {
    pk_context pk;
    pk_init(&pk);
    ret = pk_parse_keyfile(&pk, SSL_SET_OPTION(key),
                           SSL_SET_OPTION(key_passwd));
    if(ret == 0 && !pk_can_do(&pk, POLARSSL_PK_RSA))
      ret = POLARSSL_ERR_PK_TYPE_MISMATCH;
    if(ret == 0)
      rsa_copy(&BACKEND->rsa, pk_rsa(pk));
    else
      rsa_free(&BACKEND->rsa);
    pk_free(&pk);

    if(ret) {
      error_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading private key %s - PolarSSL: (-0x%04X) %s",
            SSL_SET_OPTION(key), -ret, errorbuf);

      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the CRL */
  memset(&BACKEND->crl, 0, sizeof(x509_crl));

  if(SSL_SET_OPTION(CRLfile)) {
    ret = x509_crl_parse_file(&BACKEND->crl,
                              SSL_SET_OPTION(CRLfile));

    if(ret) {
      error_strerror(ret, errorbuf, sizeof(errorbuf));
      failf(data, "Error reading CRL file %s - PolarSSL: (-0x%04X) %s",
            SSL_SET_OPTION(CRLfile), -ret, errorbuf);

      return CURLE_SSL_CRL_BADFILE;
    }
  }

  infof(data, "PolarSSL: Connecting to %s:%d\n", hostname, port);

  if(ssl_init(&BACKEND->ssl)) {
    failf(data, "PolarSSL: ssl_init failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    ssl_set_min_version(&BACKEND->ssl, SSL_MAJOR_VERSION_3,
                        SSL_MINOR_VERSION_1);
    break;
  case CURL_SSLVERSION_SSLv3:
    ssl_set_min_version(&BACKEND->ssl, SSL_MAJOR_VERSION_3,
                        SSL_MINOR_VERSION_0);
    ssl_set_max_version(&BACKEND->ssl, SSL_MAJOR_VERSION_3,
                        SSL_MINOR_VERSION_0);
    infof(data, "PolarSSL: Forced min. SSL Version to be SSLv3\n");
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

  ssl_set_endpoint(&BACKEND->ssl, SSL_IS_CLIENT);
  ssl_set_authmode(&BACKEND->ssl, SSL_VERIFY_OPTIONAL);

  ssl_set_rng(&BACKEND->ssl, ctr_drbg_random,
              &BACKEND->ctr_drbg);
  ssl_set_bio(&BACKEND->ssl,
              net_recv, &conn->sock[sockindex],
              net_send, &conn->sock[sockindex]);

  ssl_set_ciphersuites(&BACKEND->ssl, ssl_list_ciphersuites());

  /* Check if there's a cached ID we can/should use here! */
  if(SSL_SET_OPTION(primary.sessionid)) {
    void *old_session = NULL;

    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, &old_session, NULL, sockindex)) {
      ret = ssl_set_session(&BACKEND->ssl, old_session);
      if(ret) {
        Curl_ssl_sessionid_unlock(conn);
        failf(data, "ssl_set_session returned -0x%x", -ret);
        return CURLE_SSL_CONNECT_ERROR;
      }
      infof(data, "PolarSSL re-using session\n");
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  ssl_set_ca_chain(&BACKEND->ssl,
                   &BACKEND->cacert,
                   &BACKEND->crl,
                   hostname);

  ssl_set_own_cert_rsa(&BACKEND->ssl,
                       &BACKEND->clicert, &BACKEND->rsa);

  if(ssl_set_hostname(&BACKEND->ssl, hostname)) {
    /* ssl_set_hostname() sets the name to use in CN/SAN checks *and* the name
       to set in the SNI extension. So even if curl connects to a host
       specified as an IP address, this function must be used. */
    failf(data, "couldn't set hostname in PolarSSL");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef HAS_ALPN
  if(conn->bits.tls_enable_alpn) {
    static const char *protocols[3];
    int cur = 0;

#ifdef USE_NGHTTP2
    if(data->set.httpversion >= CURL_HTTP_VERSION_2) {
      protocols[cur++] = NGHTTP2_PROTO_VERSION_ID;
      infof(data, "ALPN, offering %s\n", NGHTTP2_PROTO_VERSION_ID);
    }
#endif

    protocols[cur++] = ALPN_HTTP_1_1;
    infof(data, "ALPN, offering %s\n", ALPN_HTTP_1_1);

    protocols[cur] = NULL;

    ssl_set_alpn_protocols(&BACKEND->ssl, protocols);
  }
#endif

#ifdef POLARSSL_DEBUG
  ssl_set_dbg(&BACKEND->ssl, polarssl_debug, data);
#endif

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode
polarssl_connect_step2(struct connectdata *conn,
                       int sockindex)
{
  int ret;
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  char buffer[1024];
  const char * const pinnedpubkey = SSL_IS_PROXY() ?
            data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY] :
            data->set.str[STRING_SSL_PINNEDPUBLICKEY_ORIG];


  char errorbuf[128];
  errorbuf[0] = 0;

  conn->recv[sockindex] = polarssl_recv;
  conn->send[sockindex] = polarssl_send;

  ret = ssl_handshake(&BACKEND->ssl);

  switch(ret) {
  case 0:
    break;

  case POLARSSL_ERR_NET_WANT_READ:
    connssl->connecting_state = ssl_connect_2_reading;
    return CURLE_OK;

  case POLARSSL_ERR_NET_WANT_WRITE:
    connssl->connecting_state = ssl_connect_2_writing;
    return CURLE_OK;

  default:
    error_strerror(ret, errorbuf, sizeof(errorbuf));
    failf(data, "ssl_handshake returned - PolarSSL: (-0x%04X) %s",
          -ret, errorbuf);
    return CURLE_SSL_CONNECT_ERROR;
  }

  infof(data, "PolarSSL: Handshake complete, cipher is %s\n",
        ssl_get_ciphersuite(&BACKEND->ssl) );

  ret = ssl_get_verify_result(&BACKEND->ssl);

  if(ret && SSL_CONN_CONFIG(verifypeer)) {
    if(ret & BADCERT_EXPIRED)
      failf(data, "Cert verify failed: BADCERT_EXPIRED");

    if(ret & BADCERT_REVOKED) {
      failf(data, "Cert verify failed: BADCERT_REVOKED");
      return CURLE_PEER_FAILED_VERIFICATION;
    }

    if(ret & BADCERT_CN_MISMATCH)
      failf(data, "Cert verify failed: BADCERT_CN_MISMATCH");

    if(ret & BADCERT_NOT_TRUSTED)
      failf(data, "Cert verify failed: BADCERT_NOT_TRUSTED");

    return CURLE_PEER_FAILED_VERIFICATION;
  }

  if(ssl_get_peer_cert(&(BACKEND->ssl))) {
    /* If the session was resumed, there will be no peer certs */
    memset(buffer, 0, sizeof(buffer));

    if(x509_crt_info(buffer, sizeof(buffer), (char *)"* ",
                     ssl_get_peer_cert(&(BACKEND->ssl))) != -1)
      infof(data, "Dumping cert info:\n%s\n", buffer);
  }

  /* adapted from mbedtls.c */
  if(pinnedpubkey) {
    int size;
    CURLcode result;
    x509_crt *p;
    unsigned char pubkey[PUB_DER_MAX_BYTES];
    const x509_crt *peercert;

    peercert = ssl_get_peer_cert(&BACKEND->ssl);

    if(!peercert || !peercert->raw.p || !peercert->raw.len) {
      failf(data, "Failed due to missing peer certificate");
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    p = calloc(1, sizeof(*p));

    if(!p)
      return CURLE_OUT_OF_MEMORY;

    x509_crt_init(p);

    /* Make a copy of our const peercert because pk_write_pubkey_der
       needs a non-const key, for now.
       https://github.com/ARMmbed/mbedtls/issues/396 */
    if(x509_crt_parse_der(p, peercert->raw.p, peercert->raw.len)) {
      failf(data, "Failed copying peer certificate");
      x509_crt_free(p);
      free(p);
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    size = pk_write_pubkey_der(&p->pk, pubkey, PUB_DER_MAX_BYTES);

    if(size <= 0) {
      failf(data, "Failed copying public key from peer certificate");
      x509_crt_free(p);
      free(p);
      return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }

    /* pk_write_pubkey_der writes data at the end of the buffer. */
    result = Curl_pin_peer_pubkey(data,
                                  pinnedpubkey,
                                  &pubkey[PUB_DER_MAX_BYTES - size], size);
    if(result) {
      x509_crt_free(p);
      free(p);
      return result;
    }

    x509_crt_free(p);
    free(p);
  }

#ifdef HAS_ALPN
  if(conn->bits.tls_enable_alpn) {
    const char *next_protocol = ssl_get_alpn_protocol(&BACKEND->ssl);

    if(next_protocol != NULL) {
      infof(data, "ALPN, server accepted to use %s\n", next_protocol);

#ifdef USE_NGHTTP2
      if(!strncmp(next_protocol, NGHTTP2_PROTO_VERSION_ID,
                  NGHTTP2_PROTO_VERSION_ID_LEN)) {
        conn->negnpn = CURL_HTTP_VERSION_2;
      }
      else
#endif
        if(!strncmp(next_protocol, ALPN_HTTP_1_1, ALPN_HTTP_1_1_LENGTH)) {
          conn->negnpn = CURL_HTTP_VERSION_1_1;
        }
    }
    else
      infof(data, "ALPN, server did not agree to a protocol\n");
    Curl_multiuse_state(conn, conn->negnpn == CURL_HTTP_VERSION_2 ?
                        BUNDLE_MULTIPLEX : BUNDLE_NO_MULTIUSE);
  }
#endif

  connssl->connecting_state = ssl_connect_3;
  infof(data, "SSL connected\n");

  return CURLE_OK;
}

static CURLcode
polarssl_connect_step3(struct connectdata *conn,
                       int sockindex)
{
  CURLcode retcode = CURLE_OK;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  if(SSL_SET_OPTION(primary.sessionid)) {
    int ret;
    ssl_session *our_ssl_sessionid;
    void *old_ssl_sessionid = NULL;

    our_ssl_sessionid = calloc(1, sizeof(ssl_session));
    if(!our_ssl_sessionid)
      return CURLE_OUT_OF_MEMORY;

    ret = ssl_get_session(&BACKEND->ssl, our_ssl_sessionid);
    if(ret) {
      failf(data, "ssl_get_session returned -0x%x", -ret);
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

static ssize_t polarssl_send(struct connectdata *conn,
                             int sockindex,
                             const void *mem,
                             size_t len,
                             CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  int ret = -1;

  ret = ssl_write(&BACKEND->ssl,
                  (unsigned char *)mem, len);

  if(ret < 0) {
    *curlcode = (ret == POLARSSL_ERR_NET_WANT_WRITE) ?
      CURLE_AGAIN : CURLE_SEND_ERROR;
    ret = -1;
  }

  return ret;
}

static void Curl_polarssl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  rsa_free(&BACKEND->rsa);
  x509_crt_free(&BACKEND->clicert);
  x509_crt_free(&BACKEND->cacert);
  x509_crl_free(&BACKEND->crl);
  ssl_free(&BACKEND->ssl);
}

static ssize_t polarssl_recv(struct connectdata *conn,
                             int num,
                             char *buf,
                             size_t buffersize,
                             CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = &conn->ssl[num];
  int ret = -1;
  ssize_t len = -1;

  memset(buf, 0, buffersize);
  ret = ssl_read(&BACKEND->ssl, (unsigned char *)buf, buffersize);

  if(ret <= 0) {
    if(ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
      return 0;

    *curlcode = (ret == POLARSSL_ERR_NET_WANT_READ) ?
      CURLE_AGAIN : CURLE_RECV_ERROR;
    return -1;
  }

  len = ret;

  return len;
}

static void Curl_polarssl_session_free(void *ptr)
{
  ssl_session_free(ptr);
  free(ptr);
}

/* 1.3.10 was the first rebranded version. All new releases (in 1.3 branch and
   higher) will be mbed TLS branded.. */

static size_t Curl_polarssl_version(char *buffer, size_t size)
{
  unsigned int version = version_get_number();
  return msnprintf(buffer, size, "%s/%d.%d.%d",
                   version >= 0x01030A00?"mbedTLS":"PolarSSL",
                   version>>24, (version>>16)&0xff, (version>>8)&0xff);
}

static CURLcode
polarssl_connect_common(struct connectdata *conn,
                        int sockindex,
                        bool nonblocking,
                        bool *done)
{
  CURLcode result;
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

    result = polarssl_connect_step1(conn, sockindex);
    if(result)
      return result;
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
    if(connssl->connecting_state == ssl_connect_2_reading ||
       connssl->connecting_state == ssl_connect_2_writing) {

      curl_socket_t writefd = ssl_connect_2_writing ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading ==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
                               nonblocking?0:timeout_ms);
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
    result = polarssl_connect_step2(conn, sockindex);
    if(result || (nonblocking &&
                  (ssl_connect_2 == connssl->connecting_state ||
                   ssl_connect_2_reading == connssl->connecting_state ||
                   ssl_connect_2_writing == connssl->connecting_state)))
      return result;

  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    result = polarssl_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = polarssl_recv;
    conn->send[sockindex] = polarssl_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}

static CURLcode Curl_polarssl_connect_nonblocking(struct connectdata *conn,
                                                  int sockindex, bool *done)
{
  return polarssl_connect_common(conn, sockindex, TRUE, done);
}


static CURLcode Curl_polarssl_connect(struct connectdata *conn, int sockindex)
{
  CURLcode result;
  bool done = FALSE;

  result = polarssl_connect_common(conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

/*
 * return 0 error initializing SSL
 * return 1 SSL initialized successfully
 */
static int Curl_polarssl_init(void)
{
  return Curl_polarsslthreadlock_thread_setup();
}

static void Curl_polarssl_cleanup(void)
{
  (void)Curl_polarsslthreadlock_thread_cleanup();
}

static bool Curl_polarssl_data_pending(const struct connectdata *conn,
                                       int sockindex)
{
  const struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  return ssl_get_bytes_avail(&BACKEND->ssl) != 0;
}

static CURLcode Curl_polarssl_sha256sum(const unsigned char *input,
                                    size_t inputlen,
                                    unsigned char *sha256sum,
                                    size_t sha256len UNUSED_PARAM)
{
  (void)sha256len;
  sha256(input, inputlen, sha256sum, 0);
  return CURLE_OK;
}

static void *Curl_polarssl_get_internals(struct ssl_connect_data *connssl,
                                         CURLINFO info UNUSED_PARAM)
{
  (void)info;
  return &BACKEND->ssl;
}

const struct Curl_ssl Curl_ssl_polarssl = {
  { CURLSSLBACKEND_POLARSSL, "polarssl" }, /* info */

  SSLSUPP_CA_PATH |
  SSLSUPP_PINNEDPUBKEY,

  sizeof(struct ssl_backend_data),

  Curl_polarssl_init,                /* init */
  Curl_polarssl_cleanup,             /* cleanup */
  Curl_polarssl_version,             /* version */
  Curl_none_check_cxn,               /* check_cxn */
  Curl_none_shutdown,                /* shutdown */
  Curl_polarssl_data_pending,        /* data_pending */
  /* This might cause libcurl to use a weeker random! */
  Curl_none_random,                  /* random */
  Curl_none_cert_status_request,     /* cert_status_request */
  Curl_polarssl_connect,             /* connect */
  Curl_polarssl_connect_nonblocking, /* connect_nonblocking */
  Curl_polarssl_get_internals,       /* get_internals */
  Curl_polarssl_close,               /* close_one */
  Curl_none_close_all,               /* close_all */
  Curl_polarssl_session_free,        /* session_free */
  Curl_none_set_engine,              /* set_engine */
  Curl_none_set_engine_default,      /* set_engine_default */
  Curl_none_engines_list,            /* engines_list */
  Curl_none_false_start,             /* false_start */
  Curl_none_md5sum,                  /* md5sum */
  Curl_polarssl_sha256sum            /* sha256sum */
};

#endif /* USE_POLARSSL */
