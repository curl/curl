/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, 2011, Hoi-Ho Chan, <hoiho.chan@gmail.com>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
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
 * but sslgen.c should ever call or use these functions.
 *
 */

#include "setup.h"
#ifdef USE_POLARSSL

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <polarssl/net.h>
#include <polarssl/ssl.h>
#include <polarssl/havege.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "polarssl.h"
#include "sslgen.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "rawstr.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Define this to enable lots of debugging for PolarSSL */
#undef POLARSSL_DEBUG

#ifdef POLARSSL_DEBUG
static void polarssl_debug(void *context, int level, char *line)
{
  struct SessionHandle *data = NULL;

  if(!context)
    return;

  data = (struct SessionHandle *)context;

  infof(data, "%s", line);
}
#else
#endif

static Curl_recv polarssl_recv;
static Curl_send polarssl_send;

/*
 * This function loads all the client/CA certificates and CRLs. Setup the TLS
 * layer and do all necessary magic.
 */
CURLcode
Curl_polarssl_connect(struct connectdata *conn,
                      int sockindex)
{
  struct SessionHandle *data = conn->data;
  bool sni = TRUE; /* default is SNI enabled */
  int ret = -1;
#ifdef ENABLE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif
  void *old_session = NULL;
  size_t old_session_size = 0;
  char buffer[1024];

  if(conn->ssl[sockindex].state == ssl_connection_complete)
    return CURLE_OK;

  /* PolarSSL only supports SSLv3 and TLSv1 */
  if(data->set.ssl.version == CURL_SSLVERSION_SSLv2) {
    failf(data, "PolarSSL does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  } else if(data->set.ssl.version == CURL_SSLVERSION_SSLv3) {
    sni = FALSE; /* SSLv3 has no SNI */
  }

  havege_init(&conn->ssl[sockindex].hs);

  /* Load the trusted CA */
  memset(&conn->ssl[sockindex].cacert, 0, sizeof(x509_cert));

  if(data->set.str[STRING_SSL_CAFILE]) {
    ret = x509parse_crtfile(&conn->ssl[sockindex].cacert,
                            data->set.str[STRING_SSL_CAFILE]);

    if(ret) {
      failf(data, "Error reading ca cert file %s: -0x%04X",
            data->set.str[STRING_SSL_CAFILE], -ret);

      if(data->set.ssl.verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  /* Load the client certificate */
  memset(&conn->ssl[sockindex].clicert, 0, sizeof(x509_cert));

  if(data->set.str[STRING_CERT]) {
    ret = x509parse_crtfile(&conn->ssl[sockindex].clicert,
                            data->set.str[STRING_CERT]);

    if(ret) {
      failf(data, "Error reading client cert file %s: -0x%04X",
            data->set.str[STRING_CERT], -ret);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the client private key */
  if(data->set.str[STRING_KEY]) {
    ret = x509parse_keyfile(&conn->ssl[sockindex].rsa,
                            data->set.str[STRING_KEY],
                            data->set.str[STRING_KEY_PASSWD]);

    if(ret) {
      failf(data, "Error reading private key %s: -0x%04X",
            data->set.str[STRING_KEY], -ret);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the CRL */
  memset(&conn->ssl[sockindex].crl, 0, sizeof(x509_crl));

  if(data->set.str[STRING_SSL_CRLFILE]) {
    ret = x509parse_crlfile(&conn->ssl[sockindex].crl,
                            data->set.str[STRING_SSL_CRLFILE]);

    if(ret) {
      failf(data, "Error reading CRL file %s: -0x%04X",
            data->set.str[STRING_SSL_CRLFILE], -ret);
      return CURLE_SSL_CRL_BADFILE;
    }
  }

  infof(data, "PolarSSL: Connected to %s:%d\n",
        conn->host.name, conn->remote_port);

  havege_init(&conn->ssl[sockindex].hs);

  if(ssl_init(&conn->ssl[sockindex].ssl)) {
    failf(data, "PolarSSL: ssl_init failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  ssl_set_endpoint(&conn->ssl[sockindex].ssl, SSL_IS_CLIENT);
  ssl_set_authmode(&conn->ssl[sockindex].ssl, SSL_VERIFY_OPTIONAL);

  ssl_set_rng(&conn->ssl[sockindex].ssl, havege_rand,
              &conn->ssl[sockindex].hs);
  ssl_set_bio(&conn->ssl[sockindex].ssl,
              net_recv, &conn->sock[sockindex],
              net_send, &conn->sock[sockindex]);

  ssl_set_ciphers(&conn->ssl[sockindex].ssl, ssl_default_ciphers);

  if(!Curl_ssl_getsessionid(conn, &old_session, &old_session_size)) {
    memcpy(&conn->ssl[sockindex].ssn, old_session, old_session_size);
    infof(data, "PolarSSL re-using session\n");
  }

  ssl_set_session(&conn->ssl[sockindex].ssl, 1, 600,
                  &conn->ssl[sockindex].ssn);

  ssl_set_ca_chain(&conn->ssl[sockindex].ssl,
                   &conn->ssl[sockindex].cacert,
                   &conn->ssl[sockindex].crl,
                   conn->host.name);

  ssl_set_own_cert(&conn->ssl[sockindex].ssl,
                   &conn->ssl[sockindex].clicert, &conn->ssl[sockindex].rsa);

  if(!Curl_inet_pton(AF_INET, conn->host.name, &addr) &&
#ifdef ENABLE_IPV6
     !Curl_inet_pton(AF_INET6, conn->host.name, &addr) &&
#endif
     sni && ssl_set_hostname(&conn->ssl[sockindex].ssl, conn->host.name)) {
     infof(data, "WARNING: failed to configure "
                 "server name indication (SNI) TLS extension\n");
  }

  infof(data, "PolarSSL: performing SSL/TLS handshake...\n");

#ifdef POLARSSL_DEBUG
  ssl_set_dbg(&conn->ssl[sockindex].ssl, polarssl_debug, data);
#endif

  for(;;) {
    if (!(ret = ssl_handshake(&conn->ssl[sockindex].ssl))) {
      break;
    } else if(ret != POLARSSL_ERR_NET_TRY_AGAIN) {
      failf(data, "ssl_handshake returned -0x%04X", -ret);
      return CURLE_SSL_CONNECT_ERROR;
    } else {
      /* wait for data from server... */
      long timeout_ms = Curl_timeleft(data, NULL, TRUE);

      if(timeout_ms < 0) {
        failf(data, "SSL connection timeout");
        return CURLE_OPERATION_TIMEDOUT;
      }

      switch(Curl_socket_ready(conn->sock[sockindex],
                        CURL_SOCKET_BAD, timeout_ms)) {
      case 0:
        failf(data, "SSL handshake timeout");
        return CURLE_OPERATION_TIMEDOUT;
        break;
      case CURL_CSELECT_IN:
        continue;
        break;
      default:
        return CURLE_SSL_CONNECT_ERROR;
        break;
      }
    }
  }

  infof(data, "PolarSSL: Handshake complete, cipher is %s\n",
        ssl_get_cipher(&conn->ssl[sockindex].ssl));

  ret = ssl_get_verify_result(&conn->ssl[sockindex].ssl);

  if(ret && data->set.ssl.verifypeer) {
    if(ret & BADCERT_EXPIRED)
      failf(data, "Cert verify failed: BADCERT_EXPIRED\n");

    if(ret & BADCERT_REVOKED)
      failf(data, "Cert verify failed: BADCERT_REVOKED");

    if(ret & BADCERT_CN_MISMATCH)
      failf(data, "Cert verify failed: BADCERT_CN_MISMATCH");

    if(ret & BADCERT_NOT_TRUSTED)
      failf(data, "Cert verify failed: BADCERT_NOT_TRUSTED");

    return CURLE_SSL_CACERT;
  }

  if(conn->ssl[sockindex].ssl.peer_cert) {
    /* If the session was resumed, there will be no peer certs */
    memset(buffer, 0, sizeof(buffer));

    if(x509parse_cert_info(buffer, sizeof(buffer), (char *)"* ",
                           conn->ssl[sockindex].ssl.peer_cert) != -1)
      infof(data, "Dumping cert info:\n%s\n", buffer);
  }

  conn->ssl[sockindex].state = ssl_connection_complete;
  conn->recv[sockindex] = polarssl_recv;
  conn->send[sockindex] = polarssl_send;

  /* Save the current session data for possible re-use */
  {
    void *new_session = malloc(sizeof(conn->ssl[sockindex].ssn));

    if(new_session) {
      memcpy(new_session, &conn->ssl[sockindex].ssn,
             sizeof(conn->ssl[sockindex].ssn));

      if(old_session)
        Curl_ssl_delsessionid(conn, old_session);

      return Curl_ssl_addsessionid(conn, new_session,
                                   sizeof(conn->ssl[sockindex].ssn));
    }
  }

  return CURLE_OK;
}

static ssize_t polarssl_send(struct connectdata *conn,
                             int sockindex,
                             const void *mem,
                             size_t len,
                             CURLcode *curlcode)
{
  int ret = -1;

  ret = ssl_write(&conn->ssl[sockindex].ssl,
                  (unsigned char *)mem, len);

  if(ret < 0) {
    *curlcode = (ret == POLARSSL_ERR_NET_TRY_AGAIN) ?
      CURLE_AGAIN : CURLE_SEND_ERROR;
    ret = -1;
  }

  return ret;
}

void Curl_polarssl_close_all(struct SessionHandle *data)
{
  (void)data;
}

void Curl_polarssl_close(struct connectdata *conn, int sockindex)
{
  rsa_free(&conn->ssl[sockindex].rsa);
  x509_free(&conn->ssl[sockindex].clicert);
  x509_free(&conn->ssl[sockindex].cacert);
  x509_crl_free(&conn->ssl[sockindex].crl);
  ssl_free(&conn->ssl[sockindex].ssl);
}

static ssize_t polarssl_recv(struct connectdata *conn,
                             int num,
                             char *buf,
                             size_t buffersize,
                             CURLcode *curlcode)
{
  int ret = -1;
  ssize_t len = -1;

  memset(buf, 0, buffersize);
  ret = ssl_read(&conn->ssl[num].ssl, (unsigned char *)buf, buffersize);

  if(ret <= 0) {
    *curlcode = (ret == POLARSSL_ERR_NET_TRY_AGAIN) ?
      CURLE_AGAIN : CURLE_RECV_ERROR;
    return -1;
  }

  len = ret;

  return len;
}

void Curl_polarssl_session_free(void *ptr)
{
  free(ptr);
}

size_t Curl_polarssl_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "PolarSSL");
}

#endif
