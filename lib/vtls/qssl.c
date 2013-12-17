/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2013, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef USE_QSOSSL

#include <qsossl.h>

#ifdef HAVE_LIMITS_H
#  include <limits.h>
#endif

#include <curl/curl.h>
#include "urldata.h"
#include "sendf.h"
#include "qssl.h"
#include "sslgen.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "x509asn1.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"


int Curl_qsossl_init(void)

{
  /* Nothing to do here. We must have connection data to initialize ssl, so
   * defer.
   */

  return 1;
}


void Curl_qsossl_cleanup(void)

{
  /* Nothing to do. */
}


static CURLcode Curl_qsossl_init_session(struct SessionHandle * data)

{
  int rc;
  char * certname;
  SSLInit initstr;
  SSLInitApp initappstr;

  /* Initialize the job for SSL according to the current parameters.
   * QsoSSL offers two ways to do it: SSL_Init_Application() that uses an
   *  application identifier to select certificates in the main certificate
   *  store, and SSL_Init() that uses named keyring files and a password.
   * It is not possible to have different keyrings for the CAs and the
   *  local certificate. We thus use the certificate name to identify the
   *  keyring if given, else the CA file name.
   * If the key file name is given, it is taken as the password for the
   *  keyring in certificate file.
   * We first try to SSL_Init_Application(), then SSL_Init() if it failed.
   */

  certname = data->set.str[STRING_CERT];

  if(!certname) {
    certname = data->set.str[STRING_SSL_CAFILE];

    if(!certname)
      return CURLE_OK;          /* Use previous setup. */
    }

  memset((char *) &initappstr, 0, sizeof initappstr);
  initappstr.applicationID = certname;
  initappstr.applicationIDLen = strlen(certname);
  initappstr.protocol = SSL_VERSION_CURRENT;    /* TLSV1 compat. SSLV[23]. */
  initappstr.sessionType = SSL_REGISTERED_AS_CLIENT;
  rc = SSL_Init_Application(&initappstr);

  if(rc == SSL_ERROR_NOT_REGISTERED) {
    initstr.keyringFileName = certname;
    initstr.keyringPassword = data->set.str[STRING_KEY];
    initstr.cipherSuiteList = NULL;    /* Use default. */
    initstr.cipherSuiteListLen = 0;
    rc = SSL_Init(&initstr);
    }

  switch (rc) {

  case 0:                             /* No error. */
    break;

  case SSL_ERROR_IO:
    failf(data, "SSL_Init() I/O error: %s", strerror(errno));
    return CURLE_SSL_CONNECT_ERROR;

  case SSL_ERROR_BAD_CIPHER_SUITE:
    return CURLE_SSL_CIPHER;

  case SSL_ERROR_KEYPASSWORD_EXPIRED:
  case SSL_ERROR_NOT_REGISTERED:
    return CURLE_SSL_CONNECT_ERROR;

  case SSL_ERROR_NO_KEYRING:
    return CURLE_SSL_CACERT;

  case SSL_ERROR_CERT_EXPIRED:
    return CURLE_SSL_CERTPROBLEM;

  default:
    failf(data, "SSL_Init(): %s", SSL_Strerror(rc, NULL));
    return CURLE_SSL_CONNECT_ERROR;
  }

  return CURLE_OK;
}


static CURLcode Curl_qsossl_create(struct connectdata * conn, int sockindex)

{
  SSLHandle * h;
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];

  h = SSL_Create(conn->sock[sockindex], SSL_ENCRYPT);

  if(!h) {
    failf(conn->data, "SSL_Create() I/O error: %s", strerror(errno));
    return CURLE_SSL_CONNECT_ERROR;
  }

  connssl->handle = h;
  return CURLE_OK;
}


static int Curl_qsossl_trap_cert(SSLHandle * h)

{
  return 1;       /* Accept certificate. */
}


static CURLcode Curl_qsossl_handshake(struct connectdata * conn, int sockindex)

{
  int rc;
  struct SessionHandle * data = conn->data;
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  SSLHandle * h = connssl->handle;
  long timeout_ms;

  h->exitPgm = data->set.ssl.verifypeer? NULL: Curl_qsossl_trap_cert;

  /* figure out how long time we should wait at maximum */
  timeout_ms = Curl_timeleft(data, NULL, TRUE);

  if(timeout_ms < 0) {
    /* time-out, bail out, go home */
    failf(data, "Connection time-out");
    return CURLE_OPERATION_TIMEDOUT;
  }

  /* SSL_Handshake() timeout resolution is second, so round up. */
  h->timeout = (timeout_ms + 1000 - 1) / 1000;

  /* Set-up protocol. */

  switch (data->set.ssl.version) {

  default:
  case CURL_SSLVERSION_DEFAULT:
    h->protocol = SSL_VERSION_CURRENT;          /* TLSV1 compat. SSLV[23]. */
    break;

  case CURL_SSLVERSION_TLSv1:
    h->protocol = TLS_VERSION_1;
    break;

  case CURL_SSLVERSION_SSLv2:
    h->protocol = SSL_VERSION_2;
    break;

  case CURL_SSLVERSION_SSLv3:
    h->protocol = SSL_VERSION_3;
    break;

  case CURL_SSLVERSION_TLSv1_0:
  case CURL_SSLVERSION_TLSv1_1:
  case CURL_SSLVERSION_TLSv1_2:
    failf(data, "TLS minor version cannot be set");
    return CURLE_SSL_CONNECT_ERROR;
  }

  h->peerCert = NULL;
  h->peerCertLen = 0;
  rc = SSL_Handshake(h, SSL_HANDSHAKE_AS_CLIENT);

  switch (rc) {

  case 0:                             /* No error. */
    break;

  case SSL_ERROR_BAD_CERTIFICATE:
  case SSL_ERROR_BAD_CERT_SIG:
  case SSL_ERROR_NOT_TRUSTED_ROOT:
    return CURLE_PEER_FAILED_VERIFICATION;

  case SSL_ERROR_BAD_CIPHER_SUITE:
  case SSL_ERROR_NO_CIPHERS:
    return CURLE_SSL_CIPHER;

  case SSL_ERROR_CERTIFICATE_REJECTED:
  case SSL_ERROR_CERT_EXPIRED:
  case SSL_ERROR_NO_CERTIFICATE:
    return CURLE_SSL_CERTPROBLEM;

  case SSL_ERROR_IO:
    failf(data, "SSL_Handshake() I/O error: %s", strerror(errno));
    return CURLE_SSL_CONNECT_ERROR;

  default:
    failf(data, "SSL_Handshake(): %s", SSL_Strerror(rc, NULL));
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* Verify host. */
  rc = Curl_verifyhost(conn, h->peerCert, h->peerCert + h->peerCertLen);
  if(rc != CURLE_OK)
    return rc;

  /* Gather certificate info. */
  if(data->set.ssl.certinfo) {
    if(Curl_ssl_init_certinfo(data, 1))
      return CURLE_OUT_OF_MEMORY;
    if(h->peerCert) {
      rc = Curl_extract_certinfo(conn, 0, h->peerCert,
                                 h->peerCert + h->peerCertLen);
      if(rc != CURLE_OK)
        return rc;
    }
  }

  return CURLE_OK;
}


static Curl_recv qsossl_recv;
static Curl_send qsossl_send;

CURLcode Curl_qsossl_connect(struct connectdata * conn, int sockindex)

{
  struct SessionHandle * data = conn->data;
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  int rc;

  rc = Curl_qsossl_init_session(data);

  if(rc == CURLE_OK) {
    rc = Curl_qsossl_create(conn, sockindex);

    if(rc == CURLE_OK) {
      rc = Curl_qsossl_handshake(conn, sockindex);
      if(rc != CURLE_OK)
        SSL_Destroy(connssl->handle);
    }
  }

  if(rc == CURLE_OK) {
    conn->recv[sockindex] = qsossl_recv;
    conn->send[sockindex] = qsossl_send;
    connssl->state = ssl_connection_complete;
  }
  else {
    connssl->handle = NULL;
    connssl->use = FALSE;
    connssl->state = ssl_connection_none;
  }

  return rc;
}


static int Curl_qsossl_close_one(struct ssl_connect_data * conn,
                                 struct SessionHandle * data)

{
  int rc;

  if(!conn->handle)
    return 0;

  rc = SSL_Destroy(conn->handle);

  if(rc) {
    if(rc == SSL_ERROR_IO) {
      failf(data, "SSL_Destroy() I/O error: %s", strerror(errno));
      return -1;
    }

    /* An SSL error. */
    failf(data, "SSL_Destroy() returned error %s", SSL_Strerror(rc, NULL));
    return -1;
  }

  conn->handle = NULL;
  return 0;
}


void Curl_qsossl_close(struct connectdata *conn, int sockindex)

{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->use)
    (void) Curl_qsossl_close_one(connssl, data);
}


int Curl_qsossl_close_all(struct SessionHandle * data)

{
  /* Unimplemented. */
  (void) data;
  return 0;
}


int Curl_qsossl_shutdown(struct connectdata * conn, int sockindex)

{
  struct ssl_connect_data * connssl = &conn->ssl[sockindex];
  struct SessionHandle *data = conn->data;
  ssize_t nread;
  int what;
  int rc;
  char buf[120];

  if(!connssl->handle)
    return 0;

  if(data->set.ftp_ccc != CURLFTPSSL_CCC_ACTIVE)
    return 0;

  if(Curl_qsossl_close_one(connssl, data))
    return -1;

  rc = 0;

  what = Curl_socket_ready(conn->sock[sockindex],
                           CURL_SOCKET_BAD, SSL_SHUTDOWN_TIMEOUT);

  for(;;) {
    if(what < 0) {
      /* anything that gets here is fatally bad */
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      rc = -1;
      break;
    }

    if(!what) {                                /* timeout */
      failf(data, "SSL shutdown timeout");
      break;
    }

    /* Something to read, let's do it and hope that it is the close
       notify alert from the server. No way to SSL_Read now, so use read(). */

    nread = read(conn->sock[sockindex], buf, sizeof(buf));

    if(nread < 0) {
      failf(data, "read: %s", strerror(errno));
      rc = -1;
    }

    if(nread <= 0)
      break;

    what = Curl_socket_ready(conn->sock[sockindex], CURL_SOCKET_BAD, 0);
  }

  return rc;
}


static ssize_t qsossl_send(struct connectdata * conn, int sockindex,
                           const void * mem, size_t len, CURLcode * curlcode)

{
  /* SSL_Write() is said to return 'int' while write() and send() returns
     'size_t' */
  int rc;

  rc = SSL_Write(conn->ssl[sockindex].handle, (void *) mem, (int) len);

  if(rc < 0) {
    switch(rc) {

    case SSL_ERROR_BAD_STATE:
      /* The operation did not complete; the same SSL I/O function
         should be called again later. This is basically an EWOULDBLOCK
         equivalent. */
      *curlcode = CURLE_AGAIN;
      return -1;

    case SSL_ERROR_IO:
      switch (errno) {
      case EWOULDBLOCK:
      case EINTR:
        *curlcode = CURLE_AGAIN;
        return -1;
        }

      failf(conn->data, "SSL_Write() I/O error: %s", strerror(errno));
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }

    /* An SSL error. */
    failf(conn->data, "SSL_Write() returned error %s",
          SSL_Strerror(rc, NULL));
    *curlcode = CURLE_SEND_ERROR;
    return -1;
  }

  return (ssize_t) rc; /* number of bytes */
}


static ssize_t qsossl_recv(struct connectdata * conn, int num, char * buf,
                           size_t buffersize, CURLcode * curlcode)

{
  char error_buffer[120]; /* OpenSSL documents that this must be at
                             least 120 bytes long. */
  unsigned long sslerror;
  int buffsize;
  int nread;

  buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  nread = SSL_Read(conn->ssl[num].handle, buf, buffsize);

  if(nread < 0) {
    /* failed SSL_read */

    switch (nread) {

    case SSL_ERROR_BAD_STATE:
      /* there's data pending, re-invoke SSL_Read(). */
      *curlcode = CURLE_AGAIN;
      return -1;

    case SSL_ERROR_IO:
      switch (errno) {
      case EWOULDBLOCK:
        *curlcode = CURLE_AGAIN;
        return -1;
        }

      failf(conn->data, "SSL_Read() I/O error: %s", strerror(errno));
      *curlcode = CURLE_RECV_ERROR;
      return -1;

    default:
      failf(conn->data, "SSL read error: %s", SSL_Strerror(nread, NULL));
      *curlcode = CURLE_RECV_ERROR;
      return -1;
    }
  }
  return (ssize_t) nread;
}


size_t Curl_qsossl_version(char * buffer, size_t size)

{
  strncpy(buffer, "IBM OS/400 SSL", size);
  return strlen(buffer);
}


int Curl_qsossl_check_cxn(struct connectdata * cxn)

{
  int err;
  int errlen;

  /* The only thing that can be tested here is at the socket level. */

  if(!cxn->ssl[FIRSTSOCKET].handle)
    return 0; /* connection has been closed */

  err = 0;
  errlen = sizeof err;

  if(getsockopt(cxn->sock[FIRSTSOCKET], SOL_SOCKET, SO_ERROR,
                 (unsigned char *) &err, &errlen) ||
      errlen != sizeof err || err)
    return 0; /* connection has been closed */

  return -1;  /* connection status unknown */
}

#endif /* USE_QSOSSL */
