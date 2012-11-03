/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, 2011, Hoi-Ho Chan, <hoiho.chan@gmail.com>
 * Copyright (C) 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <polarssl/net.h>
#include <polarssl/ssl.h>
#include <polarssl/havege.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>
#include <polarssl/version.h>

#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>

#if POLARSSL_VERSION_NUMBER<0x01000000
/*
  Earlier versions of polarssl had no WANT_READ or WANT_WRITE, only TRY_AGAIN
*/
#define POLARSSL_ERR_NET_WANT_READ  POLARSSL_ERR_NET_TRY_AGAIN
#define POLARSSL_ERR_NET_WANT_WRITE POLARSSL_ERR_NET_TRY_AGAIN
#endif

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

/* version dependent differences */
#if POLARSSL_VERSION_NUMBER < 0x01010000
/* the old way */
#define HAVEGE_RANDOM havege_rand
#else
/* from 1.1.0 */
#define HAVEGE_RANDOM havege_random
#endif

/* Define this to enable lots of debugging for PolarSSL */
#undef POLARSSL_DEBUG

#ifdef POLARSSL_DEBUG
static void polarssl_debug(void *context, int level, char *line)
{
  struct SessionHandle *data = NULL;

  if(!context)
    return;

  data = (struct SessionHandle *)context;

  infof(data, "%s\n", line);
}
#else
#endif

static Curl_recv polarssl_recv;
static Curl_send polarssl_send;


static CURLcode
polarssl_connect_step1(struct connectdata *conn,
                     int sockindex)
{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];

  bool sni = TRUE; /* default is SNI enabled */
  int ret = -1;
#ifdef ENABLE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif
  void *old_session = NULL;
  size_t old_session_size = 0;

  /* PolarSSL only supports SSLv3 and TLSv1 */
  if(data->set.ssl.version == CURL_SSLVERSION_SSLv2) {
    failf(data, "PolarSSL does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }
  else if(data->set.ssl.version == CURL_SSLVERSION_SSLv3)
    sni = FALSE; /* SSLv3 has no SNI */

  havege_init(&connssl->hs);

  /* Load the trusted CA */
  memset(&connssl->cacert, 0, sizeof(x509_cert));

  if(data->set.str[STRING_SSL_CAFILE]) {
    ret = x509parse_crtfile(&connssl->cacert,
                            data->set.str[STRING_SSL_CAFILE]);

    if(ret<0) {
      failf(data, "Error reading ca cert file %s: -0x%04X",
            data->set.str[STRING_SSL_CAFILE], ret);

      if(data->set.ssl.verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
  }

  /* Load the client certificate */
  memset(&connssl->clicert, 0, sizeof(x509_cert));

  if(data->set.str[STRING_CERT]) {
    ret = x509parse_crtfile(&connssl->clicert,
                            data->set.str[STRING_CERT]);

    if(ret) {
      failf(data, "Error reading client cert file %s: -0x%04X",
            data->set.str[STRING_CERT], -ret);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the client private key */
  if(data->set.str[STRING_KEY]) {
    ret = x509parse_keyfile(&connssl->rsa,
                            data->set.str[STRING_KEY],
                            data->set.str[STRING_KEY_PASSWD]);

    if(ret) {
      failf(data, "Error reading private key %s: -0x%04X",
            data->set.str[STRING_KEY], -ret);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load the CRL */
  memset(&connssl->crl, 0, sizeof(x509_crl));

  if(data->set.str[STRING_SSL_CRLFILE]) {
    ret = x509parse_crlfile(&connssl->crl,
                            data->set.str[STRING_SSL_CRLFILE]);

    if(ret) {
      failf(data, "Error reading CRL file %s: -0x%04X",
            data->set.str[STRING_SSL_CRLFILE], -ret);
      return CURLE_SSL_CRL_BADFILE;
    }
  }

  infof(data, "PolarSSL: Connecting to %s:%d\n",
        conn->host.name, conn->remote_port);

  if(ssl_init(&connssl->ssl)) {
    failf(data, "PolarSSL: ssl_init failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  ssl_set_endpoint(&connssl->ssl, SSL_IS_CLIENT);
  ssl_set_authmode(&connssl->ssl, SSL_VERIFY_OPTIONAL);

  ssl_set_rng(&connssl->ssl, HAVEGE_RANDOM,
              &connssl->hs);
  ssl_set_bio(&connssl->ssl,
              net_recv, &conn->sock[sockindex],
              net_send, &conn->sock[sockindex]);


#if POLARSSL_VERSION_NUMBER<0x01000000
  ssl_set_ciphers(&connssl->ssl, ssl_default_ciphers);
#else
  ssl_set_ciphersuites(&connssl->ssl, ssl_default_ciphersuites);
#endif
  if(!Curl_ssl_getsessionid(conn, &old_session, &old_session_size)) {
    memcpy(&connssl->ssn, old_session, old_session_size);
    infof(data, "PolarSSL re-using session\n");
  }

/* PolarSSL SVN revision r1316 to r1317, matching <1.2.0 is to cover Ubuntu's
   1.1.4 version and the like */
#if POLARSSL_VERSION_NUMBER<0x01020000
  ssl_set_session(&connssl->ssl, 1, 600,
                  &connssl->ssn);
#else
  ssl_set_session(&connssl->ssl,
                  &connssl->ssn);
#endif

  ssl_set_ca_chain(&connssl->ssl,
                   &connssl->cacert,
                   &connssl->crl,
                   conn->host.name);

  ssl_set_own_cert(&connssl->ssl,
                   &connssl->clicert, &connssl->rsa);

  if(!Curl_inet_pton(AF_INET, conn->host.name, &addr) &&
#ifdef ENABLE_IPV6
     !Curl_inet_pton(AF_INET6, conn->host.name, &addr) &&
#endif
     sni && ssl_set_hostname(&connssl->ssl, conn->host.name)) {
     infof(data, "WARNING: failed to configure "
                 "server name indication (SNI) TLS extension\n");
  }

#ifdef POLARSSL_DEBUG
  ssl_set_dbg(&connssl->ssl, polarssl_debug, data);
#endif

  connssl->connecting_state = ssl_connect_2;

  return CURLE_OK;
}

static CURLcode
polarssl_connect_step2(struct connectdata *conn,
                     int sockindex)
{
  int ret;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data* connssl = &conn->ssl[sockindex];
  char buffer[1024];

  conn->recv[sockindex] = polarssl_recv;
  conn->send[sockindex] = polarssl_send;

  for(;;) {
    if(!(ret = ssl_handshake(&connssl->ssl)))
      break;
    else if(ret != POLARSSL_ERR_NET_WANT_READ &&
            ret != POLARSSL_ERR_NET_WANT_WRITE) {
      failf(data, "ssl_handshake returned -0x%04X", -ret);
      return CURLE_SSL_CONNECT_ERROR;
    }
    else {
      if(ret == POLARSSL_ERR_NET_WANT_READ) {
        connssl->connecting_state = ssl_connect_2_reading;
        return CURLE_OK;
      }
      if(ret == POLARSSL_ERR_NET_WANT_WRITE) {
        connssl->connecting_state = ssl_connect_2_writing;
        return CURLE_OK;
      }
      failf(data, "SSL_connect failed with error %d.", ret);
      return CURLE_SSL_CONNECT_ERROR;

    }
  }

  infof(data, "PolarSSL: Handshake complete, cipher is %s\n",
#if POLARSSL_VERSION_NUMBER<0x01000000
        ssl_get_cipher(&conn->ssl[sockindex].ssl)
#elif POLARSSL_VERSION_NUMBER >= 0x01010000
        ssl_get_ciphersuite(&conn->ssl[sockindex].ssl)
#else
        ssl_get_ciphersuite_name(&conn->ssl[sockindex].ssl)
#endif
    );

  ret = ssl_get_verify_result(&conn->ssl[sockindex].ssl);

  if(ret && data->set.ssl.verifypeer) {
    if(ret & BADCERT_EXPIRED)
      failf(data, "Cert verify failed: BADCERT_EXPIRED");

    if(ret & BADCERT_REVOKED) {
      failf(data, "Cert verify failed: BADCERT_REVOKED");
      return CURLE_SSL_CACERT;
    }

    if(ret & BADCERT_CN_MISMATCH)
      failf(data, "Cert verify failed: BADCERT_CN_MISMATCH");

    if(ret & BADCERT_NOT_TRUSTED)
      failf(data, "Cert verify failed: BADCERT_NOT_TRUSTED");

    return CURLE_PEER_FAILED_VERIFICATION;
  }

/* PolarSSL SVN revision r1316 to r1317, matching <1.2.0 is to cover Ubuntu's
   1.1.4 version and the like */
#if POLARSSL_VERSION_NUMBER<0x01020000
  if(conn->ssl[sockindex].ssl.peer_cert) {
#else
  if(ssl_get_peer_cert(&(connssl->ssl))) {
#endif
    /* If the session was resumed, there will be no peer certs */
    memset(buffer, 0, sizeof(buffer));

/* PolarSSL SVN revision r1316 to r1317, matching <1.2.0 is to cover Ubuntu's
   1.1.4 version and the like */
#if POLARSSL_VERSION_NUMBER<0x01020000
    if(x509parse_cert_info(buffer, sizeof(buffer), (char *)"* ",
                           conn->ssl[sockindex].ssl.peer_cert) != -1)
#else
    if(x509parse_cert_info(buffer, sizeof(buffer), (char *)"* ",
                           ssl_get_peer_cert(&(connssl->ssl))) != -1)
#endif
      infof(data, "Dumping cert info:\n%s\n", buffer);
  }

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
  struct SessionHandle *data = conn->data;
  void *old_ssl_sessionid = NULL;
  ssl_session *our_ssl_sessionid = &conn->ssl[sockindex].ssn ;
  int incache;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  /* Save the current session data for possible re-use */
  incache = !(Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL));
  if(incache) {
    if(old_ssl_sessionid != our_ssl_sessionid) {
      infof(data, "old SSL session ID is stale, removing\n");
      Curl_ssl_delsessionid(conn, old_ssl_sessionid);
      incache = FALSE;
    }
  }
  if(!incache) {
    void *new_session = malloc(sizeof(ssl_session));

    if(new_session) {
      memcpy(new_session, our_ssl_sessionid,
             sizeof(ssl_session));

      retcode = Curl_ssl_addsessionid(conn, new_session,
                                   sizeof(ssl_session));
    }
    else {
      retcode = CURLE_OUT_OF_MEMORY;
    }

    if(retcode) {
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
  int ret = -1;

  ret = ssl_write(&conn->ssl[sockindex].ssl,
                  (unsigned char *)mem, len);

  if(ret < 0) {
    *curlcode = (ret == POLARSSL_ERR_NET_WANT_WRITE) ?
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
    if(ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
      return 0;

    *curlcode = (ret == POLARSSL_ERR_NET_WANT_READ) ?
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
  unsigned int version = version_get_number();
  return snprintf(buffer, size, "PolarSSL/%d.%d.%d", version>>24,
                  (version>>16)&0xff, (version>>8)&0xff);
}

static CURLcode
polarssl_connect_common(struct connectdata *conn,
                        int sockindex,
                        bool nonblocking,
                        bool *done)
{
  CURLcode retcode;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
  int what;

  /* check if the connection has already been established */
  if(ssl_connection_complete == connssl->state) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(ssl_connect_1==connssl->connecting_state) {
    /* Find out how much more time we're allowed */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }
    retcode = polarssl_connect_step1(conn, sockindex);
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

      curl_socket_t writefd = ssl_connect_2_writing==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = ssl_connect_2_reading==
        connssl->connecting_state?sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_ready(readfd, writefd, nonblocking?0:timeout_ms);
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
    retcode = polarssl_connect_step2(conn, sockindex);
    if(retcode || (nonblocking &&
                   (ssl_connect_2 == connssl->connecting_state ||
                    ssl_connect_2_reading == connssl->connecting_state ||
                    ssl_connect_2_writing == connssl->connecting_state)))
      return retcode;

  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3==connssl->connecting_state) {
    retcode = polarssl_connect_step3(conn, sockindex);
    if(retcode)
      return retcode;
  }

  if(ssl_connect_done==connssl->connecting_state) {
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

CURLcode
Curl_polarssl_connect_nonblocking(struct connectdata *conn,
                                int sockindex,
                                bool *done)
{
  return polarssl_connect_common(conn, sockindex, TRUE, done);
}


CURLcode
Curl_polarssl_connect(struct connectdata *conn,
                    int sockindex)
{
  CURLcode retcode;
  bool done = FALSE;

  retcode = polarssl_connect_common(conn, sockindex, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

#endif
