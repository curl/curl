/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, DirecTV
 * contact: Eric Hu <ehu@directv.com>
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
 * Source file for all axTLS-specific code for the TLS/SSL layer. No code
 * but sslgen.c should ever call or use these functions.
 */

#include "setup.h"

#ifdef USE_AXTLS
#include <axTLS/ssl.h>
#include "axtls.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "sendf.h"
#include "inet_pton.h"
#include "sslgen.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"
#include "hostcheck.h"


/* SSL_read is opied from axTLS compat layer */
static int SSL_read(SSL *ssl, void *buf, int num)
{
  uint8_t *read_buf;
  int ret;

  while((ret = ssl_read(ssl, &read_buf)) == SSL_OK);

  if(ret > SSL_OK) {
    memcpy(buf, read_buf, ret > num ? num : ret);
  }

  return ret;
}

/* Global axTLS init, called from Curl_ssl_init() */
int Curl_axtls_init(void)
{
/* axTLS has no global init.  Everything is done through SSL and SSL_CTX
 * structs stored in connectdata structure.  Perhaps can move to axtls.h.
 */
  return 1;
}

int Curl_axtls_cleanup(void)
{
  /* axTLS has no global cleanup.  Perhaps can move this to axtls.h. */
  return 1;
}

static CURLcode map_error_to_curl(int axtls_err)
{
  switch (axtls_err) {
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

/*
 * This function is called after the TCP connect has completed. Setup the TLS
 * layer and do all necessary magic.
 */
CURLcode
Curl_axtls_connect(struct connectdata *conn,
                  int sockindex)

{
  struct SessionHandle *data = conn->data;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  int cert_types[] = {SSL_OBJ_X509_CERT, SSL_OBJ_PKCS12, 0};
  int key_types[] = {SSL_OBJ_RSA_KEY, SSL_OBJ_PKCS8, SSL_OBJ_PKCS12, 0};
  int i, ssl_fcn_return;
  const uint8_t *ssl_sessionid;
  size_t ssl_idsize;
  const char *peer_CN;
  uint32_t dns_altname_index;
  const char *dns_altname;
  int8_t found_subject_alt_names = 0;
  int8_t found_subject_alt_name_matching_conn = 0;

  /* Assuming users will not compile in custom key/cert to axTLS */
  uint32_t client_option = SSL_NO_DEFAULT_KEY|SSL_SERVER_VERIFY_LATER;

  if(conn->ssl[sockindex].state == ssl_connection_complete)
    /* to make us tolerant against being called more than once for the
       same connection */
    return CURLE_OK;

  /* axTLS only supports TLSv1 */
  /* check to see if we've been told to use an explicit SSL/TLS version */
  switch(data->set.ssl.version) {
  case CURL_SSLVERSION_DEFAULT:
  case CURL_SSLVERSION_TLSv1:
    break;
  default:
    failf(data, "axTLS only supports TLSv1");
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

  /* Load the trusted CA cert bundle file */
  if(data->set.ssl.CAfile) {
    if(ssl_obj_load(ssl_ctx, SSL_OBJ_X509_CACERT, data->set.ssl.CAfile, NULL)
       != SSL_OK) {
      infof(data, "error reading ca cert file %s \n",
            data->set.ssl.CAfile);
      if(data->set.ssl.verifypeer) {
        Curl_axtls_close(conn, sockindex);
        return CURLE_SSL_CACERT_BADFILE;
      }
    }
    else
      infof(data, "found certificates in %s\n", data->set.ssl.CAfile);
  }

  /* gtls.c tasks we're skipping for now:
   * 1) certificate revocation list checking
   * 2) dns name assignment to host
   * 3) set protocol priority.  axTLS is TLSv1 only, so can probably ignore
   * 4) set certificate priority.  axTLS ignores type and sends certs in
   *  order added.  can probably ignore this.
   */

  /* Load client certificate */
  if(data->set.str[STRING_CERT]) {
    i=0;
    /* Instead of trying to analyze cert type here, let axTLS try them all. */
    while(cert_types[i] != 0) {
      ssl_fcn_return = ssl_obj_load(ssl_ctx, cert_types[i],
                                    data->set.str[STRING_CERT], NULL);
      if(ssl_fcn_return == SSL_OK) {
        infof(data, "successfully read cert file %s \n",
              data->set.str[STRING_CERT]);
        break;
      }
      i++;
    }
    /* Tried all cert types, none worked. */
    if(cert_types[i] == 0) {
      failf(data, "%s is not x509 or pkcs12 format",
            data->set.str[STRING_CERT]);
      Curl_axtls_close(conn, sockindex);
      return CURLE_SSL_CERTPROBLEM;
    }
  }

  /* Load client key.
     If a pkcs12 file successfully loaded a cert, then there's nothing to do
     because the key has already been loaded. */
  if(data->set.str[STRING_KEY] && cert_types[i] != SSL_OBJ_PKCS12) {
    i=0;
    /* Instead of trying to analyze key type here, let axTLS try them all. */
    while(key_types[i] != 0) {
      ssl_fcn_return = ssl_obj_load(ssl_ctx, key_types[i],
                                    data->set.str[STRING_KEY], NULL);
      if(ssl_fcn_return == SSL_OK) {
        infof(data, "successfully read key file %s \n",
              data->set.str[STRING_KEY]);
        break;
      }
      i++;
    }
    /* Tried all key types, none worked. */
    if(key_types[i] == 0) {
      failf(data, "Failure: %s is not a supported key file",
            data->set.str[STRING_KEY]);
      Curl_axtls_close(conn, sockindex);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* gtls.c does more here that is being left out for now
   * 1) set session credentials.  can probably ignore since axtls puts this
   *    info in the ssl_ctx struct
   * 2) setting up callbacks.  these seem gnutls specific
   */

  /* In axTLS, handshaking happens inside ssl_client_new. */
  if(!Curl_ssl_getsessionid(conn, (void **) &ssl_sessionid, &ssl_idsize)) {
    /* we got a session id, use it! */
    infof (data, "SSL re-using session ID\n");
    ssl = ssl_client_new(ssl_ctx, conn->sock[sockindex],
                         ssl_sessionid, (uint8_t)ssl_idsize);
  }
  else
    ssl = ssl_client_new(ssl_ctx, conn->sock[sockindex], NULL, 0);

  /* Check to make sure handshake was ok. */
  ssl_fcn_return = ssl_handshake_status(ssl);
  if(ssl_fcn_return != SSL_OK) {
    Curl_axtls_close(conn, sockindex);
    ssl_display_error(ssl_fcn_return); /* goes to stdout. */
    return map_error_to_curl(ssl_fcn_return);
  }
  infof (data, "handshake completed successfully\n");

  /* Here, gtls.c gets the peer certificates and fails out depending on
   * settings in "data."  axTLS api doesn't have get cert chain fcn, so omit?
   */

  /* Verify server's certificate */
  if(data->set.ssl.verifypeer) {
    if(ssl_verify_cert(ssl) != SSL_OK) {
      Curl_axtls_close(conn, sockindex);
      failf(data, "server cert verify failed");
      return CURLE_SSL_CONNECT_ERROR;
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
          dns_altname, conn->host.name);
    if(Curl_cert_hostcheck(dns_altname, conn->host.name)) {
      found_subject_alt_name_matching_conn = 1;
      break;
    }
  }

  /* RFC2818 checks */
  if(found_subject_alt_names && !found_subject_alt_name_matching_conn) {
    /* Break connection ! */
    Curl_axtls_close(conn, sockindex);
    failf(data, "\tsubjectAltName(s) do not match %s\n", conn->host.dispname);
    return CURLE_PEER_FAILED_VERIFICATION;
  }
  else if(found_subject_alt_names == 0) {
    /* Per RFC2818, when no Subject Alt Names were available, examine the peer
       CN as a legacy fallback */
    peer_CN = ssl_get_cert_dn(ssl, SSL_X509_CERT_COMMON_NAME);
    if(peer_CN == NULL) {
      /* Similar behaviour to the OpenSSL interface */
      Curl_axtls_close(conn, sockindex);
      failf(data, "unable to obtain common name from peer certificate");
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    else {
      if(!Curl_cert_hostcheck((const char *)peer_CN, conn->host.name)) {
        if(data->set.ssl.verifyhost) {
          /* Break connection ! */
          Curl_axtls_close(conn, sockindex);
          failf(data, "\tcommon name \"%s\" does not match \"%s\"\n",
                peer_CN, conn->host.dispname);
          return CURLE_PEER_FAILED_VERIFICATION;
        }
        else
          infof(data, "\tcommon name \"%s\" does not match \"%s\"\n",
                peer_CN, conn->host.dispname);
      }
    }
  }

  /* General housekeeping */
  conn->ssl[sockindex].state = ssl_connection_complete;
  conn->ssl[sockindex].ssl = ssl;
  conn->ssl[sockindex].ssl_ctx = ssl_ctx;
  conn->recv[sockindex] = axtls_recv;
  conn->send[sockindex] = axtls_send;

  /* Put our freshly minted SSL session in cache */
  ssl_idsize = ssl_get_session_id_size(ssl);
  ssl_sessionid = ssl_get_session_id(ssl);
  if(Curl_ssl_addsessionid(conn, (void *) ssl_sessionid, ssl_idsize)
     != CURLE_OK)
    infof (data, "failed to add session to cache\n");

  return CURLE_OK;
}


/* return number of sent (non-SSL) bytes */
static ssize_t axtls_send(struct connectdata *conn,
                          int sockindex,
                          const void *mem,
                          size_t len,
                          CURLcode *err)
{
  /* ssl_write() returns 'int' while write() and send() returns 'size_t' */
  int rc = ssl_write(conn->ssl[sockindex].ssl, mem, (int)len);

  infof(conn->data, "  axtls_send\n");

  if(rc < 0 ) {
    *err = map_error_to_curl(rc);
    rc = -1; /* generic error code for send failure */
  }

  *err = CURLE_OK;
  return rc;
}

void Curl_axtls_close_all(struct SessionHandle *data)
{
  (void)data;
  infof(data, "  Curl_axtls_close_all\n");
}

void Curl_axtls_close(struct connectdata *conn, int sockindex)
{
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  infof(conn->data, "  Curl_axtls_close\n");
  if(connssl->ssl) {
    /* line from ssluse.c: (void)SSL_shutdown(connssl->ssl);
       axTLS compat layer does nothing for SSL_shutdown */

    /* The following line is from ssluse.c.  There seems to be no axTLS
       equivalent.  ssl_free and ssl_ctx_free close things.
       SSL_set_connect_state(connssl->handle); */

    ssl_free (connssl->ssl);
    connssl->ssl = NULL;
  }
  if(connssl->ssl_ctx) {
    ssl_ctx_free (connssl->ssl_ctx);
    connssl->ssl_ctx = NULL;
  }
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
int Curl_axtls_shutdown(struct connectdata *conn, int sockindex)
{
  /* Outline taken from ssluse.c since functions are in axTLS compat layer.
     axTLS's error set is much smaller, so a lot of error-handling was removed.
   */
  int retval = 0;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  struct SessionHandle *data = conn->data;
  char buf[120]; /* We will use this for the OpenSSL error buffer, so it has
                    to be at least 120 bytes long. */
  ssize_t nread;

  infof(conn->data, "  Curl_axtls_shutdown\n");

  /* This has only been tested on the proftpd server, and the mod_tls code
     sends a close notify alert without waiting for a close notify alert in
     response. Thus we wait for a close notify alert from the server, but
     we do not send one. Let's hope other servers do the same... */

  /* axTLS compat layer does nothing for SSL_shutdown, so we do nothing too
  if(data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE)
      (void)SSL_shutdown(connssl->ssl);
  */

  if(connssl->ssl) {
    int what = Curl_socket_ready(conn->sock[sockindex],
                                 CURL_SOCKET_BAD, SSL_SHUTDOWN_TIMEOUT);
    if(what > 0) {
      /* Something to read, let's do it and hope that it is the close
         notify alert from the server */
      nread = (ssize_t)SSL_read(conn->ssl[sockindex].ssl, buf,
                                sizeof(buf));

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

    ssl_free (connssl->ssl);
    connssl->ssl = NULL;
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

  infof(conn->data, "  axtls_recv\n");

  if(connssl) {
    ret = (ssize_t)SSL_read(conn->ssl[num].ssl, buf, (int)buffersize);

    /* axTLS isn't terribly generous about error reporting */
    /* With patched axTLS, SSL_CLOSE_NOTIFY=-3.  Hard-coding until axTLS
       team approves proposed fix. */
    if(ret == -3 ) {
      Curl_axtls_close(conn, num);
    }
    else if(ret < 0) {
      failf(conn->data, "axTLS recv error (%d)", (int)ret);
      *err = map_error_to_curl(ret);
      return -1;
    }
  }

  *err = CURLE_OK;
  return ret;
}

/*
 * Return codes:
 *     1 means the connection is still in place
 *     0 means the connection has been closed
 *    -1 means the connection status is unknown
 */
int Curl_axtls_check_cxn(struct connectdata *conn)
{
  /* ssluse.c line: rc = SSL_peek(conn->ssl[FIRSTSOCKET].ssl, (void*)&buf, 1);
     axTLS compat layer always returns the last argument, so connection is
     always alive? */

  infof(conn->data, "  Curl_axtls_check_cxn\n");
   return 1; /* connection still in place */
}

void Curl_axtls_session_free(void *ptr)
{
  (void)ptr;
  /* free the ID */
  /* both ssluse.c and gtls.c do something here, but axTLS's OpenSSL
     compatibility layer does nothing, so we do nothing too. */
}

size_t Curl_axtls_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, "axTLS/%s", ssl_version());
}

#endif /* USE_AXTLS */
