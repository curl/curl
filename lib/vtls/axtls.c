/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, DirecTV, Contact: Eric Hu, <ehu@directv.com>.
 * Copyright (C) 2010 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * Source file for all axTLS-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 */

#include "curl_setup.h"

#ifdef USE_AXTLS

#error axTLS support has been disabled in curl due to doubts about quality,
#error user dedication and a lack of use/testing. We urge users to consider
#error using a more established TLS backend instead.

#include <axTLS/config.h>
#include <axTLS/ssl.h>
#include "axtls.h"

#include "sendf.h"
#include "inet_pton.h"
#include "vtls.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "curl_printf.h"
#include "hostcheck.h"
#include <unistd.h>

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

struct ssl_backend_data {
  SSL_CTX* ssl_ctx;
  SSL*     ssl;
};

#define BACKEND connssl->backend

static CURLcode map_error_to_curl(int axtls_err)
{
  switch(axtls_err) {
  case SSL_ERROR_NOT_SUPPORTED:
  case SSL_ERROR_INVALID_VERSION:
  case -70:                       /* protocol version alert from server */
    return CURLE_UNSUPPORTED_PROTOCOL;
    break;
  case SSL_ERROR_NO_CIPHER:
    return CURLE_SSL_CIPHER;
    break;
  case SSL_ERROR_BAD_CERTIFICATE: /* this may be bad server cert too */
  case SSL_ERROR_NO_CERT_DEFINED:
  case -42:                       /* bad certificate alert from server */
  case -43:                       /* unsupported cert alert from server */
  case -44:                       /* cert revoked alert from server */
  case -45:                       /* cert expired alert from server */
  case -46:                       /* cert unknown alert from server */
    return CURLE_SSL_CERTPROBLEM;
    break;
  case SSL_X509_ERROR(X509_NOT_OK):
  case SSL_X509_ERROR(X509_VFY_ERROR_NO_TRUSTED_CERT):
  case SSL_X509_ERROR(X509_VFY_ERROR_BAD_SIGNATURE):
  case SSL_X509_ERROR(X509_VFY_ERROR_NOT_YET_VALID):
  case SSL_X509_ERROR(X509_VFY_ERROR_EXPIRED):
  case SSL_X509_ERROR(X509_VFY_ERROR_SELF_SIGNED):
  case SSL_X509_ERROR(X509_VFY_ERROR_INVALID_CHAIN):
  case SSL_X509_ERROR(X509_VFY_ERROR_UNSUPPORTED_DIGEST):
  case SSL_X509_ERROR(X509_INVALID_PRIV_KEY):
    return CURLE_PEER_FAILED_VERIFICATION;
    break;
  case -48:                       /* unknown ca alert from server */
    return CURLE_SSL_CACERT;
    break;
  case -49:                       /* access denied alert from server */
    return CURLE_REMOTE_ACCESS_DENIED;
    break;
  case SSL_ERROR_CONN_LOST:
  case SSL_ERROR_SOCK_SETUP_FAILURE:
  case SSL_ERROR_INVALID_HANDSHAKE:
  case SSL_ERROR_INVALID_PROT_MSG:
  case SSL_ERROR_INVALID_HMAC:
  case SSL_ERROR_INVALID_SESSION:
  case SSL_ERROR_INVALID_KEY:     /* it's too bad this doesn't map better */
  case SSL_ERROR_FINISHED_INVALID:
  case SSL_ERROR_NO_CLIENT_RENOG:
  default:
    return CURLE_SSL_CONNECT_ERROR;
    break;
  }
}

static Curl_recv axtls_recv;
static Curl_send axtls_send;

static void free_ssl_structs(struct ssl_connect_data *connssl)
{
  if(BACKEND->ssl) {
    ssl_free(BACKEND->ssl);
    BACKEND->ssl = NULL;
  }
  if(BACKEND->ssl_ctx) {
    ssl_ctx_free(BACKEND->ssl_ctx);
    BACKEND->ssl_ctx = NULL;
  }
}

/*
 * For both blocking and non-blocking connects, this function sets up the
 * ssl context and state.  This function is called after the TCP connect
 * has completed.
 */
static CURLcode connect_prep(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;
  SSL_CTX *ssl_ctx;
  SSL *ssl = NULL;
  int cert_types[] = {SSL_OBJ_X509_CERT, SSL_OBJ_PKCS12, 0};
  int key_types[] = {SSL_OBJ_RSA_KEY, SSL_OBJ_PKCS8, SSL_OBJ_PKCS12, 0};
  int i, ssl_fcn_return;

  /* Assuming users will not compile in custom key/cert to axTLS.
  *  Also, even for blocking connects, use axTLS non-blocking feature.
  */
  uint32_t client_option = SSL_NO_DEFAULT_KEY |
    SSL_SERVER_VERIFY_LATER |
    SSL_CONNECT_IN_PARTS;

  if(connssl->state == ssl_connection_complete)
    /* to make us tolerant against being called more than once for the
       same connection */
    return CURLE_OK;

  if(SSL_CONN_CONFIG(version_max) != CURL_SSLVERSION_MAX_NONE) {
    failf(data, "axtls does not support CURL_SSLVERSION_MAX");
    return CURLE_SSL_CONNECT_ERROR;
  }


  /* axTLS only supports TLSv1 */
  /* check to see if we've been told to use an explicit SSL/TLS version */
  switch(SSL_CONN_CONFIG(version)) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    break;
  default:
    failf(data, "axTLS only supports TLS 1.0 and 1.1, "
          "and it cannot be specified which one to use");
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef  AXTLSDEBUG
  client_option |= SSL_DISPLAY_STATES | SSL_DISPLAY_RSA | SSL_DISPLAY_CERTS;
#endif /* AXTLSDEBUG */

  /* Allocate an SSL_CTX struct */
  ssl_ctx = ssl_ctx_new(client_option, SSL_DEFAULT_CLNT_SESS);
  if(ssl_ctx == NULL) {
    failf(data, "unable to create client SSL context");
    return CURLE_SSL_CONNECT_ERROR;
  }

  BACKEND->ssl_ctx = ssl_ctx;
  BACKEND->ssl = NULL;

  /* Load the trusted CA cert bundle file */
  if(SSL_CONN_CONFIG(CAfile)) {
    if(ssl_obj_load(ssl_ctx, SSL_OBJ_X509_CACERT,
                    SSL_CONN_CONFIG(CAfile), NULL) != SSL_OK) {
      infof(data, "error reading ca cert file %s \n",
            SSL_CONN_CONFIG(CAfile));
      if(SSL_CONN_CONFIG(verifypeer)) {
        return CURLE_SSL_CACERT_BADFILE;
      }
    }
    else
      infof(data, "found certificates in %s\n", SSL_CONN_CONFIG(CAfile));
  }

  /* gtls.c tasks we're skipping for now:
   * 1) certificate revocation list checking
   * 2) dns name assignment to host
   * 3) set protocol priority.  axTLS is TLSv1 only, so can probably ignore
   * 4) set certificate priority.  axTLS ignores type and sends certs in
   *  order added.  can probably ignore this.
   */

  /* Load client certificate */
  if(SSL_SET_OPTION(cert)) {
    i = 0;
    /* Instead of trying to analyze cert type here, let axTLS try them all. */
    while(cert_types[i] != 0) {
      ssl_fcn_return = ssl_obj_load(ssl_ctx, cert_types[i],
                                    SSL_SET_OPTION(cert), NULL);
      if(ssl_fcn_return == SSL_OK) {
        infof(data, "successfully read cert file %s \n",
              SSL_SET_OPTION(cert));
        break;
      }
      i++;
    }
    /* Tried all cert types, none worked. */
    if(cert_types[i] == 0) {
      failf(data, "%s is not x509 or pkcs12 format",
            SSL_SET_OPTION(cert));
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load client key.
     If a pkcs12 file successfully loaded a cert, then there's nothing to do
     because the key has already been loaded. */
  if(SSL_SET_OPTION(key) && cert_types[i] != SSL_OBJ_PKCS12) {
    i = 0;
    /* Instead of trying to analyze key type here, let axTLS try them all. */
    while(key_types[i] != 0) {
      ssl_fcn_return = ssl_obj_load(ssl_ctx, key_types[i],
                                    SSL_SET_OPTION(key), NULL);
      if(ssl_fcn_return == SSL_OK) {
        infof(data, "successfully read key file %s \n",
              SSL_SET_OPTION(key));
        break;
      }
      i++;
    }
    /* Tried all key types, none worked. */
    if(key_types[i] == 0) {
      failf(data, "Failure: %s is not a supported key file",
            SSL_SET_OPTION(key));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* gtls.c does more here that is being left out for now
   * 1) set session credentials.  can probably ignore since axtls puts this
   *    info in the ssl_ctx struct
   * 2) setting up callbacks.  these seem gnutls specific
   */

  if(SSL_SET_OPTION(primary.sessionid)) {
    const uint8_t *ssl_sessionid;
    size_t ssl_idsize;

    /* In axTLS, handshaking happens inside ssl_client_new. */
    Curl_ssl_sessionid_lock(conn);
    if(!Curl_ssl_getsessionid(conn, (void **) &ssl_sessionid, &ssl_idsize,
                              sockindex)) {
      /* we got a session id, use it! */
      infof(data, "SSL re-using session ID\n");
      ssl = ssl_client_new(ssl_ctx, conn->sock[sockindex],
                           ssl_sessionid, (uint8_t)ssl_idsize, NULL);
    }
    Curl_ssl_sessionid_unlock(conn);
  }

  if(!ssl)
    ssl = ssl_client_new(ssl_ctx, conn->sock[sockindex], NULL, 0, NULL);

  BACKEND->ssl = ssl;
  return CURLE_OK;
}

static void Curl_axtls_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  infof(conn->data, "  Curl_axtls_close\n");

    /* line from openssl.c: (void)SSL_shutdown(BACKEND->ssl);
       axTLS compat layer does nothing for SSL_shutdown */

    /* The following line is from openssl.c.  There seems to be no axTLS
       equivalent.  ssl_free and ssl_ctx_free close things.
       SSL_set_connect_state(connssl->handle); */

  free_ssl_structs(connssl);
}

/*
 * For both blocking and non-blocking connects, this function finalizes the
 * SSL connection.
 */
static CURLcode connect_finish(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  SSL *ssl = BACKEND->ssl;
  const char *peer_CN;
  uint32_t dns_altname_index;
  const char *dns_altname;
  int8_t found_subject_alt_names = 0;
  int8_t found_subject_alt_name_matching_conn = 0;
  const char * const hostname = SSL_IS_PROXY() ? conn->http_proxy.host.name :
    conn->host.name;
  const char * const dispname = SSL_IS_PROXY() ?
    conn->http_proxy.host.dispname : conn->host.dispname;

  /* Here, gtls.c gets the peer certificates and fails out depending on
   * settings in "data."  axTLS api doesn't have get cert chain fcn, so omit?
   */

  /* Verify server's certificate */
  if(SSL_CONN_CONFIG(verifypeer)) {
    if(ssl_verify_cert(ssl) != SSL_OK) {
      Curl_axtls_close(conn, sockindex);
      failf(data, "server cert verify failed");
      return CURLE_PEER_FAILED_VERIFICATION;
    }
  }
  else
    infof(data, "\t server certificate verification SKIPPED\n");

  /* Here, gtls.c does issuer verification. axTLS has no straightforward
   * equivalent, so omitting for now.*/

  /* Here, gtls.c does the following
   * 1) x509 hostname checking per RFC2818.  axTLS doesn't support this, but
   *    it seems useful. This is now implemented, by Oscar Koeroo
   * 2) checks cert validity based on time.  axTLS does this in ssl_verify_cert
   * 3) displays a bunch of cert information.  axTLS doesn't support most of
   *    this, but a couple fields are available.
   */

  /* There is no (DNS) Altnames count in the version 1.4.8 API. There is a
     risk of an inifite loop */
  for(dns_altname_index = 0; ; dns_altname_index++) {
    dns_altname = ssl_get_cert_subject_alt_dnsname(ssl, dns_altname_index);
    if(dns_altname == NULL) {
      break;
    }
    found_subject_alt_names = 1;

    infof(data, "\tComparing subject alt name DNS with hostname: %s <-> %s\n",
          dns_altname, hostname);
    if(Curl_cert_hostcheck(dns_altname, hostname)) {
      found_subject_alt_name_matching_conn = 1;
      break;
    }
  }

  /* RFC2818 checks */
  if(found_subject_alt_names && !found_subject_alt_name_matching_conn) {
    if(SSL_CONN_CONFIG(verifyhost)) {
      /* Break connection ! */
      Curl_axtls_close(conn, sockindex);
      failf(data, "\tsubjectAltName(s) do not match %s\n", dispname);
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    else
      infof(data, "\tsubjectAltName(s) do not match %s\n", dispname);
  }
  else if(found_subject_alt_names == 0) {
    /* Per RFC2818, when no Subject Alt Names were available, examine the peer
       CN as a legacy fallback */
    peer_CN = ssl_get_cert_dn(ssl, SSL_X509_CERT_COMMON_NAME);
    if(peer_CN == NULL) {
      if(SSL_CONN_CONFIG(verifyhost)) {
        Curl_axtls_close(conn, sockindex);
        failf(data, "unable to obtain common name from peer certificate");
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else
        infof(data, "unable to obtain common name from peer certificate");
    }
    else {
      if(!Curl_cert_hostcheck((const char *)peer_CN, hostname)) {
        if(SSL_CONN_CONFIG(verifyhost)) {
          /* Break connection ! */
          Curl_axtls_close(conn, sockindex);
          failf(data, "\tcommon name \"%s\" does not match \"%s\"\n",
                peer_CN, dispname);
          return CURLE_PEER_FAILED_VERIFICATION;
        }
        else
          infof(data, "\tcommon name \"%s\" does not match \"%s\"\n",
                peer_CN, dispname);
      }
    }
  }

  /* General housekeeping */
  connssl->state = ssl_connection_complete;
  conn->recv[sockindex] = axtls_recv;
  conn->send[sockindex] = axtls_send;

  /* Put our freshly minted SSL session in cache */
  if(SSL_SET_OPTION(primary.sessionid)) {
    const uint8_t *ssl_sessionid = ssl_get_session_id(ssl);
    size_t ssl_idsize = ssl_get_session_id_size(ssl);
    Curl_ssl_sessionid_lock(conn);
    if(Curl_ssl_addsessionid(conn, (void *) ssl_sessionid, ssl_idsize,
                             sockindex) != CURLE_OK)
      infof(data, "failed to add session to cache\n");
    Curl_ssl_sessionid_unlock(conn);
  }

  return CURLE_OK;
}

/*
 * Use axTLS's non-blocking connection feature to open an SSL connection.
 * This is called after a TCP connection is already established.
 */
static CURLcode Curl_axtls_connect_nonblocking(struct connectdata *conn,
                                               int sockindex, bool *done)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  CURLcode conn_step;
  int ssl_fcn_return;
  int i;

 *done = FALSE;
  /* connectdata is calloc'd and connecting_state is only changed in this
     function, so this is safe, as the state is effectively initialized. */
  if(connssl->connecting_state == ssl_connect_1) {
    conn_step = connect_prep(conn, sockindex);
    if(conn_step != CURLE_OK) {
      Curl_axtls_close(conn, sockindex);
      return conn_step;
    }
    connssl->connecting_state = ssl_connect_2;
  }

  if(connssl->connecting_state == ssl_connect_2) {
    /* Check to make sure handshake was ok. */
    if(ssl_handshake_status(BACKEND->ssl) != SSL_OK) {
      /* Loop to perform more work in between sleeps. This is work around the
         fact that axtls does not expose any knowledge about when work needs
         to be performed. This can save ~25% of time on SSL handshakes. */
      for(i = 0; i<5; i++) {
        ssl_fcn_return = ssl_read(BACKEND->ssl, NULL);
        if(ssl_fcn_return < 0) {
          Curl_axtls_close(conn, sockindex);
          ssl_display_error(ssl_fcn_return); /* goes to stdout. */
          return map_error_to_curl(ssl_fcn_return);
        }
        return CURLE_OK;
      }
    }
    infof(conn->data, "handshake completed successfully\n");
    connssl->connecting_state = ssl_connect_3;
  }

  if(connssl->connecting_state == ssl_connect_3) {
    conn_step = connect_finish(conn, sockindex);
    if(conn_step != CURLE_OK) {
      Curl_axtls_close(conn, sockindex);
      return conn_step;
    }

    /* Reset connect state */
    connssl->connecting_state = ssl_connect_1;

    *done = TRUE;
    return CURLE_OK;
  }

  /* Unrecognized state.  Things are very bad. */
  connssl->state  = ssl_connection_none;
  connssl->connecting_state = ssl_connect_1;
  /* Return value perhaps not strictly correct, but distinguishes the issue.*/
  return CURLE_BAD_FUNCTION_ARGUMENT;
}


/*
 * This function is called after the TCP connect has completed. Setup the TLS
 * layer and do all necessary magic for a blocking connect.
 */
static CURLcode Curl_axtls_connect(struct connectdata *conn, int sockindex)
{
  struct Curl_easy *data = conn->data;
  CURLcode conn_step = connect_prep(conn, sockindex);
  int ssl_fcn_return;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  SSL *ssl = BACKEND->ssl;
  long timeout_ms;

  if(conn_step != CURLE_OK) {
    Curl_axtls_close(conn, sockindex);
    return conn_step;
  }

  /* Check to make sure handshake was ok. */
  while(ssl_handshake_status(ssl) != SSL_OK) {
    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, TRUE);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    ssl_fcn_return = ssl_read(ssl, NULL);
    if(ssl_fcn_return < 0) {
      Curl_axtls_close(conn, sockindex);
      ssl_display_error(ssl_fcn_return); /* goes to stdout. */
      return map_error_to_curl(ssl_fcn_return);
    }
    /* TODO: avoid polling */
    Curl_wait_ms(10);
  }
  infof(conn->data, "handshake completed successfully\n");

  conn_step = connect_finish(conn, sockindex);
  if(conn_step != CURLE_OK) {
    Curl_axtls_close(conn, sockindex);
    return conn_step;
  }

  return CURLE_OK;
}

/* return number of sent (non-SSL) bytes */
static ssize_t axtls_send(struct connectdata *conn,
                          int sockindex,
                          const void *mem,
                          size_t len,
                          CURLcode *err)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  /* ssl_write() returns 'int' while write() and send() returns 'size_t' */
  int rc = ssl_write(BACKEND->ssl, mem, (int)len);

  infof(conn->data, "  axtls_send\n");

  if(rc < 0) {
    *err = map_error_to_curl(rc);
    rc = -1; /* generic error code for send failure */
  }

  *err = CURLE_OK;
  return rc;
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
static int Curl_axtls_shutdown(struct connectdata *conn, int sockindex)
{
  /* Outline taken from openssl.c since functions are in axTLS compat layer.
     axTLS's error set is much smaller, so a lot of error-handling was removed.
   */
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct Curl_easy *data = conn->data;
  uint8_t *buf;
  ssize_t nread;

  infof(conn->data, "  Curl_axtls_shutdown\n");

  /* This has only been tested on the proftpd server, and the mod_tls code
     sends a close notify alert without waiting for a close notify alert in
     response. Thus we wait for a close notify alert from the server, but
     we do not send one. Let's hope other servers do the same... */

  /* axTLS compat layer does nothing for SSL_shutdown, so we do nothing too
  if(data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE)
      (void)SSL_shutdown(BACKEND->ssl);
  */

  if(BACKEND->ssl) {
    int what = SOCKET_READABLE(conn->sock[sockindex], SSL_SHUTDOWN_TIMEOUT);
    if(what > 0) {
      /* Something to read, let's do it and hope that it is the close
         notify alert from the server.  buf is managed internally by
         axTLS and will be released upon calling ssl_free via
         free_ssl_structs. */
      nread = (ssize_t)ssl_read(BACKEND->ssl, &buf);

      if(nread < SSL_OK) {
        failf(data, "close notify alert not received during shutdown");
        retval = -1;
      }
    }
    else if(0 == what) {
      /* timeout */
      failf(data, "SSL shutdown timeout");
    }
    else {
      /* anything that gets here is fatally bad */
      failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
      retval = -1;
    }

    free_ssl_structs(connssl);
  }
  return retval;
}

static ssize_t axtls_recv(struct connectdata *conn, /* connection data */
                          int num,                  /* socketindex */
                          char *buf,                /* store read data here */
                          size_t buffersize,        /* max amount to read */
                          CURLcode *err)
{
  struct ssl_connect_data *connssl = &conn->ssl[num];
  ssize_t ret = 0;
  uint8_t *read_buf;

  infof(conn->data, "  axtls_recv\n");

  *err = CURLE_OK;
  if(connssl) {
    ret = ssl_read(BACKEND->ssl, &read_buf);
    if(ret > SSL_OK) {
      /* ssl_read returns SSL_OK if there is more data to read, so if it is
         larger, then all data has been read already.  */
      memcpy(buf, read_buf,
             (size_t)ret > buffersize ? buffersize : (size_t)ret);
    }
    else if(ret == SSL_OK) {
      /* more data to be read, signal caller to call again */
      *err = CURLE_AGAIN;
      ret = -1;
    }
    else if(ret == -3) {
      /* With patched axTLS, SSL_CLOSE_NOTIFY=-3.  Hard-coding until axTLS
         team approves proposed fix. */
      Curl_axtls_close(conn, num);
    }
    else {
      failf(conn->data, "axTLS recv error (%d)", ret);
      *err = map_error_to_curl((int) ret);
      ret = -1;
    }
  }

  return ret;
}

/*
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
static int Curl_axtls_check_cxn(struct connectdata *conn)
{
  /* openssl.c line:
     rc = SSL_peek(conn->ssl[FIRSTSOCKET].backend->ssl, (void*)&buf, 1);
     axTLS compat layer always returns the last argument, so connection is
     always alive? */

  infof(conn->data, "  Curl_axtls_check_cxn\n");
   return 1; /* connection still in place */
}

static void Curl_axtls_session_free(void *ptr)
{
  (void)ptr;
  /* free the ID */
  /* both openssl.c and gtls.c do something here, but axTLS's OpenSSL
     compatibility layer does nothing, so we do nothing too. */
}

static size_t Curl_axtls_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "axTLS/%s", ssl_version());
}

static CURLcode Curl_axtls_random(struct Curl_easy *data,
                                  unsigned char *entropy, size_t length)
{
  static bool ssl_seeded = FALSE;
  (void)data;
  if(!ssl_seeded) {
    ssl_seeded = TRUE;
    /* Initialize the seed if not already done. This call is not exactly thread
     * safe (and neither is the ssl_seeded check), but the worst effect of a
     * race condition is that some global resources will leak. */
    RNG_initialize();
  }
  get_random((int)length, entropy);
  return CURLE_OK;
}

static void *Curl_axtls_get_internals(struct ssl_connect_data *connssl,
                                      CURLINFO info UNUSED_PARAM)
{
  (void)info;
  return BACKEND->ssl;
}

const struct Curl_ssl Curl_ssl_axtls = {
  { CURLSSLBACKEND_AXTLS, "axtls" }, /* info */
  0, /* no fancy stuff */
  sizeof(struct ssl_backend_data),

  /*
   * axTLS has no global init.  Everything is done through SSL and SSL_CTX
   * structs stored in connectdata structure.
   */
  Curl_none_init,                 /* init */
  /* axTLS has no global cleanup. */
  Curl_none_cleanup,              /* cleanup */
  Curl_axtls_version,             /* version */
  Curl_axtls_check_cxn,           /* check_cxn */
  Curl_axtls_shutdown,            /* shutdown */
  Curl_none_data_pending,         /* data_pending */
  Curl_axtls_random,              /* random */
  Curl_none_cert_status_request,  /* cert_status_request */
  Curl_axtls_connect,             /* connect */
  Curl_axtls_connect_nonblocking, /* connect_nonblocking */
  Curl_axtls_get_internals,       /* get_internals */
  Curl_axtls_close,               /* close_one */
  Curl_none_close_all,            /* close_all */
  Curl_axtls_session_free,        /* session_free */
  Curl_none_set_engine,           /* set_engine */
  Curl_none_set_engine_default,   /* set_engine_default */
  Curl_none_engines_list,         /* engines_list */
  Curl_none_false_start,          /* false_start */
  Curl_none_md5sum,               /* md5sum */
  NULL                            /* sha256sum */
};

#endif /* USE_AXTLS */
