/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * Source file for all CyaSSL-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 */

#include "curl_setup.h"

#ifdef USE_CYASSL

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "cyassl.h"
#include "vtls.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "rawstr.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>
#include "curl_memory.h"

#include <cyassl/ssl.h>
#ifdef HAVE_CYASSL_ERROR_SSL_H
#include <cyassl/error-ssl.h>
#else
#include <cyassl/error.h>
#endif
#include <cyassl/ctaocrypt/random.h>

/* The last #include file should be: */
#include "memdebug.h"

static Curl_recv cyassl_recv;
static Curl_send cyassl_send;


static int do_file_type(const char *type)
{
  if(!type || !type[0])
    return SSL_FILETYPE_PEM;
  if(Curl_raw_equal(type, "PEM"))
    return SSL_FILETYPE_PEM;
  if(Curl_raw_equal(type, "DER"))
    return SSL_FILETYPE_ASN1;
  return -1;
}

/*
 * This function loads all the client/CA certificates and CRLs. Setup the TLS
 * layer and do all necessary magic.
 */
static CURLcode
cyassl_connect_step1(struct connectdata *conn,
                     int sockindex)
{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data* conssl = &conn->ssl[sockindex];
  SSL_METHOD* req_method = NULL;
  void* ssl_sessionid = NULL;
  curl_socket_t sockfd = conn->sock[sockindex];

  if(conssl->state == ssl_connection_complete)
    return CURLE_OK;

  /* CyaSSL doesn't support SSLv2 */
  if(data->set.ssl.version == CURL_SSLVERSION_SSLv2) {
    failf(data, "CyaSSL does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* check to see if we've been told to use an explicit SSL/TLS version */
  switch(data->set.ssl.version) {
  default:
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    infof(data, "CyaSSL cannot be configured to use TLS 1.0-1.2, "
          "TLS 1.0 is used exclusively\n");
    req_method = TLSv1_client_method();
    break;
  case CURL_SSLVERSION_TLSv1_0:
    req_method = TLSv1_client_method();
    break;
  case CURL_SSLVERSION_TLSv1_1:
    req_method = TLSv1_1_client_method();
    break;
  case CURL_SSLVERSION_TLSv1_2:
    req_method = TLSv1_2_client_method();
    break;
  case CURL_SSLVERSION_SSLv3:
    req_method = SSLv3_client_method();
    break;
  }

  if(!req_method) {
    failf(data, "SSL: couldn't create a method!");
    return CURLE_OUT_OF_MEMORY;
  }

  if(conssl->ctx)
    SSL_CTX_free(conssl->ctx);
  conssl->ctx = SSL_CTX_new(req_method);

  if(!conssl->ctx) {
    failf(data, "SSL: couldn't create a context!");
    return CURLE_OUT_OF_MEMORY;
  }

#ifndef NO_FILESYSTEM
  /* load trusted cacert */
  if(data->set.str[STRING_SSL_CAFILE]) {
    if(!SSL_CTX_load_verify_locations(conssl->ctx,
                                      data->set.str[STRING_SSL_CAFILE],
                                      data->set.str[STRING_SSL_CAPATH])) {
      if(data->set.ssl.verifypeer) {
        /* Fail if we insist on successfully verifying the server. */
        failf(data,"error setting certificate verify locations:\n"
              "  CAfile: %s\n  CApath: %s",
              data->set.str[STRING_SSL_CAFILE]?
              data->set.str[STRING_SSL_CAFILE]: "none",
              data->set.str[STRING_SSL_CAPATH]?
              data->set.str[STRING_SSL_CAPATH] : "none");
        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        /* Just continue with a warning if no strict certificate
           verification is required. */
        infof(data, "error setting certificate verify locations,"
              " continuing anyway:\n");
      }
    }
    else {
      /* Everything is fine. */
      infof(data, "successfully set certificate verify locations:\n");
    }
    infof(data,
          "  CAfile: %s\n"
          "  CApath: %s\n",
          data->set.str[STRING_SSL_CAFILE] ? data->set.str[STRING_SSL_CAFILE]:
          "none",
          data->set.str[STRING_SSL_CAPATH] ? data->set.str[STRING_SSL_CAPATH]:
          "none");
  }

  /* Load the client certificate, and private key */
  if(data->set.str[STRING_CERT] && data->set.str[STRING_KEY]) {
    int file_type = do_file_type(data->set.str[STRING_CERT_TYPE]);

    if(SSL_CTX_use_certificate_file(conssl->ctx, data->set.str[STRING_CERT],
                                     file_type) != 1) {
      failf(data, "unable to use client certificate (no key or wrong pass"
            " phrase?)");
      return CURLE_SSL_CONNECT_ERROR;
    }

    file_type = do_file_type(data->set.str[STRING_KEY_TYPE]);
    if(SSL_CTX_use_PrivateKey_file(conssl->ctx, data->set.str[STRING_KEY],
                                    file_type) != 1) {
      failf(data, "unable to set private key");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
#else
  if(CyaSSL_no_filesystem_verify(conssl->ctx)!= SSL_SUCCESS) {
    return CURLE_SSL_CONNECT_ERROR;
  }
#endif /* NO_FILESYSTEM */

  /* SSL always tries to verify the peer, this only says whether it should
   * fail to connect if the verification fails, or if it should continue
   * anyway. In the latter case the result of the verification is checked with
   * SSL_get_verify_result() below. */
  SSL_CTX_set_verify(conssl->ctx,
                     data->set.ssl.verifypeer?SSL_VERIFY_PEER:SSL_VERIFY_NONE,
                     NULL);

  /* Let's make an SSL structure */
  if(conssl->handle)
    SSL_free(conssl->handle);
  conssl->handle = SSL_new(conssl->ctx);
  if(!conssl->handle) {
    failf(data, "SSL: couldn't create a context (handle)!");
    return CURLE_OUT_OF_MEMORY;
  }

  /* Check if there's a cached ID we can/should use here! */
  if(!Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL)) {
    /* we got a session id, use it! */
    if(!SSL_set_session(conssl->handle, ssl_sessionid)) {
      failf(data, "SSL: SSL_set_session failed: %s",
            ERR_error_string(SSL_get_error(conssl->handle, 0),NULL));
      return CURLE_SSL_CONNECT_ERROR;
    }
    /* Informational message */
    infof (data, "SSL re-using session ID\n");
  }

  /* pass the raw socket into the SSL layer */
  if(!SSL_set_fd(conssl->handle, (int)sockfd)) {
    failf(data, "SSL: SSL_set_fd failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  conssl->connecting_state = ssl_connect_2;
  return CURLE_OK;
}


static CURLcode
cyassl_connect_step2(struct connectdata *conn,
                     int sockindex)
{
  int ret = -1;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data* conssl = &conn->ssl[sockindex];

  infof(data, "CyaSSL: Connecting to %s:%d\n",
        conn->host.name, conn->remote_port);

  conn->recv[sockindex] = cyassl_recv;
  conn->send[sockindex] = cyassl_send;

  /* Enable RFC2818 checks */
  if(data->set.ssl.verifyhost) {
    ret = CyaSSL_check_domain_name(conssl->handle, conn->host.name);
    if(ret == SSL_FAILURE)
      return CURLE_OUT_OF_MEMORY;
  }

  ret = SSL_connect(conssl->handle);
  if(ret != 1) {
    char error_buffer[80];
    int  detail = SSL_get_error(conssl->handle, ret);

    if(SSL_ERROR_WANT_READ == detail) {
      conssl->connecting_state = ssl_connect_2_reading;
      return CURLE_OK;
    }
    else if(SSL_ERROR_WANT_WRITE == detail) {
      conssl->connecting_state = ssl_connect_2_writing;
      return CURLE_OK;
    }
    /* There is no easy way to override only the CN matching.
     * This will enable the override of both mismatching SubjectAltNames
     * as also mismatching CN fields */
    else if(DOMAIN_NAME_MISMATCH == detail) {
#if 1
      failf(data, "\tsubject alt name(s) or common name do not match \"%s\"\n",
            conn->host.dispname);
      return CURLE_PEER_FAILED_VERIFICATION;
#else
      /* When the CyaSSL_check_domain_name() is used and you desire to continue
       * on a DOMAIN_NAME_MISMATCH, i.e. 'data->set.ssl.verifyhost == 0',
       * CyaSSL version 2.4.0 will fail with an INCOMPLETE_DATA error. The only
       * way to do this is currently to switch the CyaSSL_check_domain_name()
       * in and out based on the 'data->set.ssl.verifyhost' value. */
      if(data->set.ssl.verifyhost) {
        failf(data,
              "\tsubject alt name(s) or common name do not match \"%s\"\n",
              conn->host.dispname);
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else {
        infof(data,
              "\tsubject alt name(s) and/or common name do not match \"%s\"\n",
              conn->host.dispname);
        return CURLE_OK;
      }
#endif
    }
#if LIBCYASSL_VERSION_HEX >= 0x02007000 /* 2.7.0 */
    else if(ASN_NO_SIGNER_E == detail) {
      if(data->set.ssl.verifypeer) {
        failf(data, "\tCA signer not available for verification\n");
        return CURLE_SSL_CACERT_BADFILE;
      }
      else {
        /* Just continue with a warning if no strict certificate
           verification is required. */
        infof(data, "CA signer not available for verification, "
                    "continuing anyway\n");
      }
    }
#endif
    else {
      failf(data, "SSL_connect failed with error %d: %s", detail,
          ERR_error_string(detail, error_buffer));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  conssl->connecting_state = ssl_connect_3;
  infof(data, "SSL connected\n");

  return CURLE_OK;
}


static CURLcode
cyassl_connect_step3(struct connectdata *conn,
                     int sockindex)
{
  CURLcode result = CURLE_OK;
  void *old_ssl_sessionid=NULL;
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  bool incache;
  SSL_SESSION *our_ssl_sessionid;

  DEBUGASSERT(ssl_connect_3 == connssl->connecting_state);

  our_ssl_sessionid = SSL_get_session(connssl->handle);

  incache = !(Curl_ssl_getsessionid(conn, &old_ssl_sessionid, NULL));
  if(incache) {
    if(old_ssl_sessionid != our_ssl_sessionid) {
      infof(data, "old SSL session ID is stale, removing\n");
      Curl_ssl_delsessionid(conn, old_ssl_sessionid);
      incache = FALSE;
    }
  }

  if(!incache) {
    result = Curl_ssl_addsessionid(conn, our_ssl_sessionid,
                                   0 /* unknown size */);
    if(result) {
      failf(data, "failed to store ssl session");
      return result;
    }
  }

  connssl->connecting_state = ssl_connect_done;

  return result;
}


static ssize_t cyassl_send(struct connectdata *conn,
                           int sockindex,
                           const void *mem,
                           size_t len,
                           CURLcode *curlcode)
{
  char error_buffer[80];
  int  memlen = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
  int  rc     = SSL_write(conn->ssl[sockindex].handle, mem, memlen);

  if(rc < 0) {
    int err = SSL_get_error(conn->ssl[sockindex].handle, rc);

    switch(err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* there's data pending, re-invoke SSL_write() */
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(conn->data, "SSL write: %s, errno %d",
            ERR_error_string(err, error_buffer),
            SOCKERRNO);
      *curlcode = CURLE_SEND_ERROR;
      return -1;
    }
  }
  return rc;
}

void Curl_cyassl_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *conssl = &conn->ssl[sockindex];

  if(conssl->handle) {
    (void)SSL_shutdown(conssl->handle);
    SSL_free (conssl->handle);
    conssl->handle = NULL;
  }
  if(conssl->ctx) {
    SSL_CTX_free (conssl->ctx);
    conssl->ctx = NULL;
  }
}

static ssize_t cyassl_recv(struct connectdata *conn,
                           int num,
                           char *buf,
                           size_t buffersize,
                           CURLcode *curlcode)
{
  char error_buffer[80];
  int  buffsize = (buffersize > (size_t)INT_MAX) ? INT_MAX : (int)buffersize;
  int  nread    = SSL_read(conn->ssl[num].handle, buf, buffsize);

  if(nread < 0) {
    int err = SSL_get_error(conn->ssl[num].handle, nread);

    switch(err) {
    case SSL_ERROR_ZERO_RETURN: /* no more data */
      break;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      /* there's data pending, re-invoke SSL_read() */
      *curlcode = CURLE_AGAIN;
      return -1;
    default:
      failf(conn->data, "SSL read: %s, errno %d",
            ERR_error_string(err, error_buffer),
            SOCKERRNO);
      *curlcode = CURLE_RECV_ERROR;
      return -1;
    }
  }
  return nread;
}


void Curl_cyassl_session_free(void *ptr)
{
  (void)ptr;
  /* CyaSSL reuses sessions on own, no free */
}


size_t Curl_cyassl_version(char *buffer, size_t size)
{
#ifdef CYASSL_VERSION
  return snprintf(buffer, size, "CyaSSL/%s", CYASSL_VERSION);
#else
  return snprintf(buffer, size, "CyaSSL/%s", "<1.8.8");
#endif
}


int Curl_cyassl_init(void)
{
  if(CyaSSL_Init() == 0)
    return 1;

  return -1;
}


bool Curl_cyassl_data_pending(const struct connectdata* conn, int connindex)
{
  if(conn->ssl[connindex].handle)   /* SSL is in use */
    return (0 != SSL_pending(conn->ssl[connindex].handle)) ? TRUE : FALSE;
  else
    return FALSE;
}


/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
int Curl_cyassl_shutdown(struct connectdata *conn, int sockindex)
{
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  if(connssl->handle) {
    SSL_free (connssl->handle);
    connssl->handle = NULL;
  }
  return retval;
}


static CURLcode
cyassl_connect_common(struct connectdata *conn,
                      int sockindex,
                      bool nonblocking,
                      bool *done)
{
  CURLcode result;
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

    result = cyassl_connect_step1(conn, sockindex);
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
    result = cyassl_connect_step2(conn, sockindex);
    if(result || (nonblocking &&
                  (ssl_connect_2 == connssl->connecting_state ||
                   ssl_connect_2_reading == connssl->connecting_state ||
                   ssl_connect_2_writing == connssl->connecting_state)))
      return result;
  } /* repeat step2 until all transactions are done. */

  if(ssl_connect_3 == connssl->connecting_state) {
    result = cyassl_connect_step3(conn, sockindex);
    if(result)
      return result;
  }

  if(ssl_connect_done == connssl->connecting_state) {
    connssl->state = ssl_connection_complete;
    conn->recv[sockindex] = cyassl_recv;
    conn->send[sockindex] = cyassl_send;
    *done = TRUE;
  }
  else
    *done = FALSE;

  /* Reset our connect state machine */
  connssl->connecting_state = ssl_connect_1;

  return CURLE_OK;
}


CURLcode
Curl_cyassl_connect_nonblocking(struct connectdata *conn,
                                int sockindex,
                                bool *done)
{
  return cyassl_connect_common(conn, sockindex, TRUE, done);
}


CURLcode
Curl_cyassl_connect(struct connectdata *conn,
                    int sockindex)
{
  CURLcode result;
  bool done = FALSE;

  result = cyassl_connect_common(conn, sockindex, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

int Curl_cyassl_random(struct SessionHandle *data,
                       unsigned char *entropy,
                       size_t length)
{
  RNG rng;
  (void)data;
  if(InitRng(&rng))
    return 1;
  if(RNG_GenerateBlock(&rng, entropy, length))
    return 1;
  return 0;
}

#endif
