/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2007, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/

/*
 * Source file for all GnuTLS-specific code for the TLS/SSL layer. No code
 * but sslgen.c should ever call or use these functions.
 *
 * Note: don't use the GnuTLS' *_t variable type names in this source code,
 * since they were not present in 1.0.X.
 */

#include "setup.h"
#ifdef USE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "gtls.h"
#include "sslgen.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>
#include "memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/* Enable GnuTLS debugging by defining GTLSDEBUG */
/*#define GTLSDEBUG */

#ifdef GTLSDEBUG
static void tls_log_func(int level, const char *str)
{
    fprintf(stderr, "|<%d>| %s", level, str);
}
#endif

/*
 * Custom push and pull callback functions used by GNU TLS to read and write
 * to the socket.  These functions are simple wrappers to send() and recv()
 * (although here using the sread/swrite macros as defined by setup_once.h).
 * We use custom functions rather than the GNU TLS defaults because it allows
 * us to get specific about the fourth "flags" argument, and to use arbitrary
 * private data with gnutls_transport_set_ptr if we wish.
 */
static ssize_t Curl_gtls_push(void *s, const void *buf, size_t len)
{
  return swrite(s, buf, len);
}

static ssize_t Curl_gtls_pull(void *s, void *buf, size_t len)
{
  return sread(s, buf, len);
}

/* Global GnuTLS init, called from Curl_ssl_init() */
int Curl_gtls_init(void)
{
  gnutls_global_init();
#ifdef GTLSDEBUG
  gnutls_global_set_log_function(tls_log_func);
  gnutls_global_set_log_level(2);
#endif
  return 1;
}

int Curl_gtls_cleanup(void)
{
  gnutls_global_deinit();
  return 1;
}

static void showtime(struct SessionHandle *data,
                     const char *text,
                     time_t stamp)
{
  struct tm *tm;
#ifdef HAVE_GMTIME_R
  struct tm buffer;
  tm = (struct tm *)gmtime_r(&stamp, &buffer);
#else
  tm = gmtime(&stamp);
#endif
  snprintf(data->state.buffer,
           BUFSIZE,
           "\t %s: %s, %02d %s %4d %02d:%02d:%02d GMT\n",
           text,
           Curl_wkday[tm->tm_wday?tm->tm_wday-1:6],
           tm->tm_mday,
           Curl_month[tm->tm_mon],
           tm->tm_year + 1900,
           tm->tm_hour,
           tm->tm_min,
           tm->tm_sec);
  infof(data, "%s", data->state.buffer);
}

/* this function does a BLOCKING SSL/TLS (re-)handshake */
static CURLcode handshake(struct connectdata *conn,
                          gnutls_session session,
                          int sockindex,
                          bool duringconnect)
{
  struct SessionHandle *data = conn->data;
  int rc;

  do {
    rc = gnutls_handshake(session);

    if((rc == GNUTLS_E_AGAIN) || (rc == GNUTLS_E_INTERRUPTED)) {
      long timeout_ms = DEFAULT_CONNECT_TIMEOUT;
      long has_passed;

      if(duringconnect && data->set.connecttimeout)
        timeout_ms = data->set.connecttimeout*1000;

      if(data->set.timeout) {
        /* get the strictest timeout of the ones converted to milliseconds */
        if((data->set.timeout*1000) < timeout_ms)
          timeout_ms = data->set.timeout*1000;
      }

      /* Evaluate in milliseconds how much time that has passed */
      has_passed = Curl_tvdiff(Curl_tvnow(), data->progress.t_startsingle);

      /* subtract the passed time */
      timeout_ms -= has_passed;

      if(timeout_ms < 0) {
        /* a precaution, no need to continue if time already is up */
        failf(data, "SSL connection timeout");
        return CURLE_OPERATION_TIMEOUTED;
      }

      rc = Curl_select(conn->sock[sockindex],
                       conn->sock[sockindex], (int)timeout_ms);
      if(rc > 0)
        /* reabable or writable, go loop*/
        continue;
      else if(0 == rc) {
        /* timeout */
        failf(data, "SSL connection timeout");
        return CURLE_OPERATION_TIMEDOUT;
      }
      else {
        /* anything that gets here is fatally bad */
        failf(data, "select on SSL socket, errno: %d", Curl_sockerrno());
        return CURLE_SSL_CONNECT_ERROR;
      }
    }
    else
      break;
  } while(1);

  if (rc < 0) {
    failf(data, "gnutls_handshake() failed: %s", gnutls_strerror(rc));
    return CURLE_SSL_CONNECT_ERROR;
  }

  return CURLE_OK;
}

static gnutls_x509_crt_fmt do_file_type(const char *type)
{
  if(!type || !type[0])
    return GNUTLS_X509_FMT_PEM;
  if(curl_strequal(type, "PEM"))
    return GNUTLS_X509_FMT_PEM;
  if(curl_strequal(type, "DER"))
    return GNUTLS_X509_FMT_DER;
  return -1;
}


/*
 * This function is called after the TCP connect has completed. Setup the TLS
 * layer and do all necessary magic.
 */
CURLcode
Curl_gtls_connect(struct connectdata *conn,
                  int sockindex)

{
  const int cert_type_priority[] = { GNUTLS_CRT_X509, 0 };
  struct SessionHandle *data = conn->data;
  gnutls_session session;
  int rc;
  unsigned int cert_list_size;
  const gnutls_datum *chainp;
  unsigned int verify_status;
  gnutls_x509_crt x509_cert;
  char certbuf[256]; /* big enough? */
  size_t size;
  unsigned int algo;
  unsigned int bits;
  time_t clock;
  const char *ptr;
  void *ssl_sessionid;
  size_t ssl_idsize;

  /* GnuTLS only supports TLSv1 (and SSLv3?) */
  if(data->set.ssl.version == CURL_SSLVERSION_SSLv2) {
    failf(data, "GnuTLS does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* allocate a cred struct */
  rc = gnutls_certificate_allocate_credentials(&conn->ssl[sockindex].cred);
  if(rc < 0) {
    failf(data, "gnutls_cert_all_cred() failed: %s", gnutls_strerror(rc));
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(data->set.ssl.CAfile) {
    /* set the trusted CA cert bundle file */
    gnutls_certificate_set_verify_flags(conn->ssl[sockindex].cred,
                                        GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

    rc = gnutls_certificate_set_x509_trust_file(conn->ssl[sockindex].cred,
                                                data->set.ssl.CAfile,
                                                GNUTLS_X509_FMT_PEM);
    if(rc < 0) {
      infof(data, "error reading ca cert file %s (%s)\n",
            data->set.ssl.CAfile, gnutls_strerror(rc));
      if (data->set.ssl.verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
    else
      infof(data, "found %d certificates in %s\n",
            rc, data->set.ssl.CAfile);
  }

  /* Initialize TLS session as a client */
  rc = gnutls_init(&conn->ssl[sockindex].session, GNUTLS_CLIENT);
  if(rc) {
    failf(data, "gnutls_init() failed: %d", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* convenient assign */
  session = conn->ssl[sockindex].session;

  /* Use default priorities */
  rc = gnutls_set_default_priority(session);
  if(rc < 0)
    return CURLE_SSL_CONNECT_ERROR;

  /* Sets the priority on the certificate types supported by gnutls. Priority
     is higher for types specified before others. After specifying the types
     you want, you must append a 0. */
  rc = gnutls_certificate_type_set_priority(session, cert_type_priority);
  if(rc < 0)
    return CURLE_SSL_CONNECT_ERROR;

  if(data->set.cert) {
    if( gnutls_certificate_set_x509_key_file(
          conn->ssl[sockindex].cred, data->set.cert,
          data->set.key != 0 ? data->set.key : data->set.cert,
          do_file_type(data->set.cert_type) ) ) {
      failf(data, "error reading X.509 key or certificate file");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* put the credentials to the current session */
  rc = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
                              conn->ssl[sockindex].cred);

  /* set the connection handle (file descriptor for the socket) */
  gnutls_transport_set_ptr(session,
                           (gnutls_transport_ptr)conn->sock[sockindex]);

  /* register callback functions to send and receive data. */
  gnutls_transport_set_push_function(session, Curl_gtls_push);
  gnutls_transport_set_pull_function(session, Curl_gtls_pull);

  /* lowat must be set to zero when using custom push and pull functions. */
  gnutls_transport_set_lowat(session, 0);

  /* This might be a reconnect, so we check for a session ID in the cache
     to speed up things */

  if(!Curl_ssl_getsessionid(conn, &ssl_sessionid, &ssl_idsize)) {
    /* we got a session id, use it! */
    gnutls_session_set_data(session, ssl_sessionid, ssl_idsize);

    /* Informational message */
    infof (data, "SSL re-using session ID\n");
  }

  rc = handshake(conn, session, sockindex, TRUE);
  if(rc)
    /* handshake() sets its own error message with failf() */
    return rc;

  /* This function will return the peer's raw certificate (chain) as sent by
     the peer. These certificates are in raw format (DER encoded for
     X.509). In case of a X.509 then a certificate list may be present. The
     first certificate in the list is the peer's certificate, following the
     issuer's certificate, then the issuer's issuer etc. */

  chainp = gnutls_certificate_get_peers(session, &cert_list_size);
  if(!chainp) {
    if(data->set.ssl.verifyhost) {
      failf(data, "failed to get server cert");
      return CURLE_SSL_PEER_CERTIFICATE;
    }
    infof(data, "\t common name: WARNING couldn't obtain\n");
  }

  /* This function will try to verify the peer's certificate and return its
     status (trusted, invalid etc.). The value of status should be one or more
     of the gnutls_certificate_status_t enumerated elements bitwise or'd. To
     avoid denial of service attacks some default upper limits regarding the
     certificate key size and chain size are set. To override them use
     gnutls_certificate_set_verify_limits(). */

  rc = gnutls_certificate_verify_peers2(session, &verify_status);
  if (rc < 0) {
    failf(data, "server cert verify failed: %d", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* verify_status is a bitmask of gnutls_certificate_status bits */
  if(verify_status & GNUTLS_CERT_INVALID) {
    if (data->set.ssl.verifypeer) {
      failf(data, "server certificate verification failed. CAfile: %s",
            data->set.ssl.CAfile?data->set.ssl.CAfile:"none");
      return CURLE_SSL_CACERT;
    }
    else
      infof(data, "\t server certificate verification FAILED\n");
  }
  else
      infof(data, "\t server certificate verification OK\n");

  /* initialize an X.509 certificate structure. */
  gnutls_x509_crt_init(&x509_cert);

  /* convert the given DER or PEM encoded Certificate to the native
     gnutls_x509_crt_t format */
  gnutls_x509_crt_import(x509_cert, chainp, GNUTLS_X509_FMT_DER);

  size=sizeof(certbuf);
  rc = gnutls_x509_crt_get_dn_by_oid(x509_cert, GNUTLS_OID_X520_COMMON_NAME,
                                     0, /* the first and only one */
                                     FALSE,
                                     certbuf,
                                     &size);
  if(rc) {
    infof(data, "error fetching CN from cert:%s\n",
          gnutls_strerror(rc));
  }

  /* This function will check if the given certificate's subject matches the
     given hostname. This is a basic implementation of the matching described
     in RFC2818 (HTTPS), which takes into account wildcards, and the subject
     alternative name PKIX extension. Returns non zero on success, and zero on
     failure. */
  rc = gnutls_x509_crt_check_hostname(x509_cert, conn->host.name);

  if(!rc) {
    if (data->set.ssl.verifyhost > 1) {
      failf(data, "SSL: certificate subject name (%s) does not match "
            "target host name '%s'", certbuf, conn->host.dispname);
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_SSL_PEER_CERTIFICATE;
    }
    else
      infof(data, "\t common name: %s (does not match '%s')\n",
            certbuf, conn->host.dispname);
  }
  else
    infof(data, "\t common name: %s (matched)\n", certbuf);

  /* Show:

  - ciphers used
  - subject
  - start date
  - expire date
  - common name
  - issuer

  */

  /* public key algorithm's parameters */
  algo = gnutls_x509_crt_get_pk_algorithm(x509_cert, &bits);
  infof(data, "\t certificate public key: %s\n",
        gnutls_pk_algorithm_get_name(algo));

  /* version of the X.509 certificate. */
  infof(data, "\t certificate version: #%d\n",
        gnutls_x509_crt_get_version(x509_cert));


  size = sizeof(certbuf);
  gnutls_x509_crt_get_dn(x509_cert, certbuf, &size);
  infof(data, "\t subject: %s\n", certbuf);

  clock = gnutls_x509_crt_get_activation_time(x509_cert);
  showtime(data, "start date", clock);

  clock = gnutls_x509_crt_get_expiration_time(x509_cert);
  showtime(data, "expire date", clock);

  size = sizeof(certbuf);
  gnutls_x509_crt_get_issuer_dn(x509_cert, certbuf, &size);
  infof(data, "\t issuer: %s\n", certbuf);

  gnutls_x509_crt_deinit(x509_cert);

  /* compression algorithm (if any) */
  ptr = gnutls_compression_get_name(gnutls_compression_get(session));
  /* the *_get_name() says "NULL" if GNUTLS_COMP_NULL is returned */
  infof(data, "\t compression: %s\n", ptr);

  /* the name of the cipher used. ie 3DES. */
  ptr = gnutls_cipher_get_name(gnutls_cipher_get(session));
  infof(data, "\t cipher: %s\n", ptr);

  /* the MAC algorithms name. ie SHA1 */
  ptr = gnutls_mac_get_name(gnutls_mac_get(session));
  infof(data, "\t MAC: %s\n", ptr);

  if(!ssl_sessionid) {
    /* this session was not previously in the cache, add it now */

    /* get the session ID data size */
    gnutls_session_get_data(session, NULL, &ssl_idsize);
    ssl_sessionid = malloc(ssl_idsize); /* get a buffer for it */

    if(ssl_sessionid) {
      /* extract session ID to the allocated buffer */
      gnutls_session_get_data(session, ssl_sessionid, &ssl_idsize);

      /* store this session id */
      return Curl_ssl_addsessionid(conn, ssl_sessionid, ssl_idsize);
    }
  }

  return CURLE_OK;
}


/* return number of sent (non-SSL) bytes */
ssize_t Curl_gtls_send(struct connectdata *conn,
                   int sockindex,
                   void *mem,
                   size_t len)
{
  ssize_t rc = gnutls_record_send(conn->ssl[sockindex].session, mem, len);

  if(rc < 0 ) {
    if(rc == GNUTLS_E_AGAIN)
      return 0; /* EWOULDBLOCK equivalent */
    rc = -1; /* generic error code for send failure */
  }

  return rc;
}

void Curl_gtls_close_all(struct SessionHandle *data)
{
  /* FIX: make the OpenSSL code more generic and use parts of it here */
  (void)data;
}

static void close_one(struct connectdata *conn,
                      int index)
{
  if(conn->ssl[index].session) {
    gnutls_bye(conn->ssl[index].session, GNUTLS_SHUT_RDWR);
    gnutls_deinit(conn->ssl[index].session);
  }
  gnutls_certificate_free_credentials(conn->ssl[index].cred);
}

void Curl_gtls_close(struct connectdata *conn)
{
  if(conn->ssl[0].use)
    close_one(conn, 0);
  if(conn->ssl[1].use)
    close_one(conn, 1);
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
int Curl_gtls_shutdown(struct connectdata *conn, int sockindex)
{
  int result;
  int retval = 0;
  struct SessionHandle *data = conn->data;
  int done = 0;
  ssize_t nread;
  char buf[120];

  /* This has only been tested on the proftpd server, and the mod_tls code
     sends a close notify alert without waiting for a close notify alert in
     response. Thus we wait for a close notify alert from the server, but
     we do not send one. Let's hope other servers do the same... */

  if(conn->ssl[sockindex].session) {
    while(!done) {
      int what = Curl_select(conn->sock[sockindex],
                             CURL_SOCKET_BAD, SSL_SHUTDOWN_TIMEOUT);
      if(what > 0) {
        /* Something to read, let's do it and hope that it is the close
           notify alert from the server */
        result = gnutls_record_recv(conn->ssl[sockindex].session,
                                    buf, sizeof(buf));
        switch(result) {
        case 0:
          /* This is the expected response. There was no data but only
             the close notify alert */
          done = 1;
          break;
        case GNUTLS_E_AGAIN:
        case GNUTLS_E_INTERRUPTED:
          infof(data, "GNUTLS_E_AGAIN || GNUTLS_E_INTERRUPTED\n");
          break;
        default:
          retval = -1;
          done = 1;
          break;
        }
      }
      else if(0 == what) {
        /* timeout */
        failf(data, "SSL shutdown timeout");
        done = 1;
        break;
      }
      else {
        /* anything that gets here is fatally bad */
        failf(data, "select on SSL socket, errno: %d", Curl_sockerrno());
        retval = -1;
        done = 1;
      }
    }
    gnutls_deinit(conn->ssl[sockindex].session);
  }
  gnutls_certificate_free_credentials(conn->ssl[sockindex].cred);

  conn->ssl[sockindex].session = NULL;
  conn->ssl[sockindex].use = FALSE;

  return retval;
}

/*
 * If the read would block we return -1 and set 'wouldblock' to TRUE.
 * Otherwise we return the amount of data read. Other errors should return -1
 * and set 'wouldblock' to FALSE.
 */
ssize_t Curl_gtls_recv(struct connectdata *conn, /* connection data */
                       int num,                  /* socketindex */
                       char *buf,                /* store read data here */
                       size_t buffersize,        /* max amount to read */
                       bool *wouldblock)
{
  ssize_t ret;

  ret = gnutls_record_recv(conn->ssl[num].session, buf, buffersize);
  if((ret == GNUTLS_E_AGAIN) || (ret == GNUTLS_E_INTERRUPTED)) {
    *wouldblock = TRUE;
    return -1;
  }

  if(ret == GNUTLS_E_REHANDSHAKE) {
    /* BLOCKING call, this is bad but a work-around for now. Fixing this "the
       proper way" takes a whole lot of work. */
    CURLcode rc = handshake(conn, conn->ssl[num].session, num, FALSE);
    if(rc)
      /* handshake() writes error message on its own */
      return rc;
    *wouldblock = TRUE; /* then return as if this was a wouldblock */
    return -1;
  }

  *wouldblock = FALSE;
  if (!ret) {
    failf(conn->data, "Peer closed the TLS connection");
    return -1;
  }

  if (ret < 0) {
    failf(conn->data, "GnuTLS recv error (%d): %s",
          (int)ret, gnutls_strerror(ret));
    return -1;
  }

  return ret;
}

void Curl_gtls_session_free(void *ptr)
{
  free(ptr);
}

size_t Curl_gtls_version(char *buffer, size_t size)
{
  return snprintf(buffer, size, " GnuTLS/%s", gnutls_check_version(NULL));
}

#endif /* USE_GNUTLS */
