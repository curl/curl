/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifndef USE_GNUTLS_NETTLE
#include <gcrypt.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "gtls.h"
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

/*
 Some hackish cast macros based on:
 http://library.gnome.org/devel/glib/unstable/glib-Type-Conversion-Macros.html
*/
#ifndef GNUTLS_POINTER_TO_INT_CAST
#define GNUTLS_POINTER_TO_INT_CAST(p) ((int) (long) (p))
#endif
#ifndef GNUTLS_INT_TO_POINTER_CAST
#define GNUTLS_INT_TO_POINTER_CAST(i) ((void*) (long) (i))
#endif

/* Enable GnuTLS debugging by defining GTLSDEBUG */
/*#define GTLSDEBUG */

#ifdef GTLSDEBUG
static void tls_log_func(int level, const char *str)
{
    fprintf(stderr, "|<%d>| %s", level, str);
}
#endif
static bool gtls_inited = FALSE;

#if defined(GNUTLS_VERSION_NUMBER)
#  if (GNUTLS_VERSION_NUMBER >= 0x020c00)
#    undef gnutls_transport_set_lowat
#    define gnutls_transport_set_lowat(A,B) Curl_nop_stmt
#    define USE_GNUTLS_PRIORITY_SET_DIRECT 1
#  endif
#  if (GNUTLS_VERSION_NUMBER >= 0x020c03)
#    define GNUTLS_MAPS_WINSOCK_ERRORS 1
#  endif
#endif

/*
 * Custom push and pull callback functions used by GNU TLS to read and write
 * to the socket.  These functions are simple wrappers to send() and recv()
 * (although here using the sread/swrite macros as defined by setup_once.h).
 * We use custom functions rather than the GNU TLS defaults because it allows
 * us to get specific about the fourth "flags" argument, and to use arbitrary
 * private data with gnutls_transport_set_ptr if we wish.
 *
 * When these custom push and pull callbacks fail, GNU TLS checks its own
 * session-specific error variable, and when not set also its own global
 * errno variable, in order to take appropriate action. GNU TLS does not
 * require that the transport is actually a socket. This implies that for
 * Windows builds these callbacks should ideally set the session-specific
 * error variable using function gnutls_transport_set_errno or as a last
 * resort global errno variable using gnutls_transport_set_global_errno,
 * with a transport agnostic error value. This implies that some winsock
 * error translation must take place in these callbacks.
 *
 * Paragraph above applies to GNU TLS versions older than 2.12.3, since
 * this version GNU TLS does its own internal winsock error translation
 * using system_errno() function.
 */

#if defined(USE_WINSOCK) && !defined(GNUTLS_MAPS_WINSOCK_ERRORS)
#  define gtls_EINTR  4
#  define gtls_EIO    5
#  define gtls_EAGAIN 11
static int gtls_mapped_sockerrno(void)
{
  switch(SOCKERRNO) {
  case WSAEWOULDBLOCK:
    return gtls_EAGAIN;
  case WSAEINTR:
    return gtls_EINTR;
  default:
    break;
  }
  return gtls_EIO;
}
#endif

static ssize_t Curl_gtls_push(void *s, const void *buf, size_t len)
{
  ssize_t ret = swrite(GNUTLS_POINTER_TO_INT_CAST(s), buf, len);
#if defined(USE_WINSOCK) && !defined(GNUTLS_MAPS_WINSOCK_ERRORS)
  if(ret < 0)
    gnutls_transport_set_global_errno(gtls_mapped_sockerrno());
#endif
  return ret;
}

static ssize_t Curl_gtls_pull(void *s, void *buf, size_t len)
{
  ssize_t ret = sread(GNUTLS_POINTER_TO_INT_CAST(s), buf, len);
#if defined(USE_WINSOCK) && !defined(GNUTLS_MAPS_WINSOCK_ERRORS)
  if(ret < 0)
    gnutls_transport_set_global_errno(gtls_mapped_sockerrno());
#endif
  return ret;
}

/* Curl_gtls_init()
 *
 * Global GnuTLS init, called from Curl_ssl_init(). This calls functions that
 * are not thread-safe and thus this function itself is not thread-safe and
 * must only be called from within curl_global_init() to keep the thread
 * situation under control!
 */
int Curl_gtls_init(void)
{
  int ret = 1;
  if(!gtls_inited) {
    ret = gnutls_global_init()?0:1;
#ifdef GTLSDEBUG
    gnutls_global_set_log_function(tls_log_func);
    gnutls_global_set_log_level(2);
#endif
    gtls_inited = TRUE;
  }
  return ret;
}

int Curl_gtls_cleanup(void)
{
  if(gtls_inited) {
    gnutls_global_deinit();
    gtls_inited = FALSE;
  }
  return 1;
}

static void showtime(struct SessionHandle *data,
                     const char *text,
                     time_t stamp)
{
  struct tm buffer;
  const struct tm *tm = &buffer;
  CURLcode result = Curl_gmtime(stamp, &buffer);
  if(result)
    return;

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
  infof(data, "%s\n", data->state.buffer);
}

static gnutls_datum load_file (const char *file)
{
  FILE *f;
  gnutls_datum loaded_file = { NULL, 0 };
  long filelen;
  void *ptr;

  if(!(f = fopen(file, "r")))
    return loaded_file;
  if(fseek(f, 0, SEEK_END) != 0
     || (filelen = ftell(f)) < 0
     || fseek(f, 0, SEEK_SET) != 0
     || !(ptr = malloc((size_t)filelen)))
    goto out;
  if(fread(ptr, 1, (size_t)filelen, f) < (size_t)filelen) {
    free(ptr);
    goto out;
  }

  loaded_file.data = ptr;
  loaded_file.size = (unsigned int)filelen;
out:
  fclose(f);
  return loaded_file;
}

static void unload_file(gnutls_datum data) {
  free(data.data);
}


/* this function does a SSL/TLS (re-)handshake */
static CURLcode handshake(struct connectdata *conn,
                          int sockindex,
                          bool duringconnect,
                          bool nonblocking)
{
  struct SessionHandle *data = conn->data;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];
  gnutls_session session = conn->ssl[sockindex].session;
  curl_socket_t sockfd = conn->sock[sockindex];
  long timeout_ms;
  int rc;
  int what;

  for(;;) {
    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, duringconnect);

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

      what = Curl_socket_ready(readfd, writefd,
                               nonblocking?0:
                               timeout_ms?timeout_ms:1000);
      if(what < 0) {
        /* fatal error */
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        return CURLE_SSL_CONNECT_ERROR;
      }
      else if(0 == what) {
        if(nonblocking)
          return CURLE_OK;
        else if(timeout_ms) {
          /* timeout */
          failf(data, "SSL connection timeout at %ld", timeout_ms);
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    rc = gnutls_handshake(session);

    if((rc == GNUTLS_E_AGAIN) || (rc == GNUTLS_E_INTERRUPTED)) {
      connssl->connecting_state =
        gnutls_record_get_direction(session)?
        ssl_connect_2_writing:ssl_connect_2_reading;
      if(nonblocking)
        return CURLE_OK;
    }
    else if(rc < 0) {
      failf(data, "gnutls_handshake() failed: %s", gnutls_strerror(rc));
      return CURLE_SSL_CONNECT_ERROR;
    }
    else {
      /* Reset our connect state machine */
      connssl->connecting_state = ssl_connect_1;
      return CURLE_OK;
    }
  }
}

static gnutls_x509_crt_fmt do_file_type(const char *type)
{
  if(!type || !type[0])
    return GNUTLS_X509_FMT_PEM;
  if(Curl_raw_equal(type, "PEM"))
    return GNUTLS_X509_FMT_PEM;
  if(Curl_raw_equal(type, "DER"))
    return GNUTLS_X509_FMT_DER;
  return -1;
}

static CURLcode
gtls_connect_step1(struct connectdata *conn,
                   int sockindex)
{
#ifndef USE_GNUTLS_PRIORITY_SET_DIRECT
  static const int cert_type_priority[] = { GNUTLS_CRT_X509, 0 };
#endif
  struct SessionHandle *data = conn->data;
  gnutls_session session;
  int rc;
  void *ssl_sessionid;
  size_t ssl_idsize;
  bool sni = TRUE; /* default is SNI enabled */
#ifdef ENABLE_IPV6
  struct in6_addr addr;
#else
  struct in_addr addr;
#endif

  if(conn->ssl[sockindex].state == ssl_connection_complete)
    /* to make us tolerant against being called more than once for the
       same connection */
    return CURLE_OK;

  if(!gtls_inited)
    Curl_gtls_init();

  /* GnuTLS only supports SSLv3 and TLSv1 */
  if(data->set.ssl.version == CURL_SSLVERSION_SSLv2) {
    failf(data, "GnuTLS does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }
  else if(data->set.ssl.version == CURL_SSLVERSION_SSLv3)
    sni = FALSE; /* SSLv3 has no SNI */

  /* allocate a cred struct */
  rc = gnutls_certificate_allocate_credentials(&conn->ssl[sockindex].cred);
  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "gnutls_cert_all_cred() failed: %s", gnutls_strerror(rc));
    return CURLE_SSL_CONNECT_ERROR;
  }

#ifdef USE_TLS_SRP
  if(data->set.ssl.authtype == CURL_TLSAUTH_SRP) {
    infof(data, "Using TLS-SRP username: %s\n", data->set.ssl.username);

    rc = gnutls_srp_allocate_client_credentials(
           &conn->ssl[sockindex].srp_client_cred);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_srp_allocate_client_cred() failed: %s",
            gnutls_strerror(rc));
      return CURLE_OUT_OF_MEMORY;
    }

    rc = gnutls_srp_set_client_credentials(conn->ssl[sockindex].
                                           srp_client_cred,
                                           data->set.ssl.username,
                                           data->set.ssl.password);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_srp_set_client_cred() failed: %s",
            gnutls_strerror(rc));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }
#endif

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
      if(data->set.ssl.verifypeer)
        return CURLE_SSL_CACERT_BADFILE;
    }
    else
      infof(data, "found %d certificates in %s\n",
            rc, data->set.ssl.CAfile);
  }

  if(data->set.ssl.CRLfile) {
    /* set the CRL list file */
    rc = gnutls_certificate_set_x509_crl_file(conn->ssl[sockindex].cred,
                                              data->set.ssl.CRLfile,
                                              GNUTLS_X509_FMT_PEM);
    if(rc < 0) {
      failf(data, "error reading crl file %s (%s)\n",
            data->set.ssl.CRLfile, gnutls_strerror(rc));
      return CURLE_SSL_CRL_BADFILE;
    }
    else
      infof(data, "found %d CRL in %s\n",
            rc, data->set.ssl.CRLfile);
  }

  /* Initialize TLS session as a client */
  rc = gnutls_init(&conn->ssl[sockindex].session, GNUTLS_CLIENT);
  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "gnutls_init() failed: %d", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }

  /* convenient assign */
  session = conn->ssl[sockindex].session;

  if((0 == Curl_inet_pton(AF_INET, conn->host.name, &addr)) &&
#ifdef ENABLE_IPV6
     (0 == Curl_inet_pton(AF_INET6, conn->host.name, &addr)) &&
#endif
     sni &&
     (gnutls_server_name_set(session, GNUTLS_NAME_DNS, conn->host.name,
                             strlen(conn->host.name)) < 0))
    infof(data, "WARNING: failed to configure server name indication (SNI) "
          "TLS extension\n");

  /* Use default priorities */
  rc = gnutls_set_default_priority(session);
  if(rc != GNUTLS_E_SUCCESS)
    return CURLE_SSL_CONNECT_ERROR;

  if(data->set.ssl.version == CURL_SSLVERSION_SSLv3) {
#ifndef USE_GNUTLS_PRIORITY_SET_DIRECT
    static const int protocol_priority[] = { GNUTLS_SSL3, 0 };
    rc = gnutls_protocol_set_priority(session, protocol_priority);
#else
    const char *err;
    /* the combination of the cipher ARCFOUR with SSL 3.0 and TLS 1.0 is not
       vulnerable to attacks such as the BEAST, why this code now explicitly
       asks for that
    */
    rc = gnutls_priority_set_direct(session,
                                    "NORMAL:-VERS-TLS-ALL:+VERS-SSL3.0:"
                                    "-CIPHER-ALL:+ARCFOUR-128",
                                    &err);
#endif
    if(rc != GNUTLS_E_SUCCESS)
      return CURLE_SSL_CONNECT_ERROR;
  }

#ifndef USE_GNUTLS_PRIORITY_SET_DIRECT
  /* Sets the priority on the certificate types supported by gnutls. Priority
     is higher for types specified before others. After specifying the types
     you want, you must append a 0. */
  rc = gnutls_certificate_type_set_priority(session, cert_type_priority);
  if(rc != GNUTLS_E_SUCCESS)
    return CURLE_SSL_CONNECT_ERROR;
#endif

  if(data->set.str[STRING_CERT]) {
    if(gnutls_certificate_set_x509_key_file(
         conn->ssl[sockindex].cred,
         data->set.str[STRING_CERT],
         data->set.str[STRING_KEY] ?
         data->set.str[STRING_KEY] : data->set.str[STRING_CERT],
         do_file_type(data->set.str[STRING_CERT_TYPE]) ) !=
       GNUTLS_E_SUCCESS) {
      failf(data, "error reading X.509 key or certificate file");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

#ifdef USE_TLS_SRP
  /* put the credentials to the current session */
  if(data->set.ssl.authtype == CURL_TLSAUTH_SRP) {
    rc = gnutls_credentials_set(session, GNUTLS_CRD_SRP,
                                conn->ssl[sockindex].srp_client_cred);
    if(rc != GNUTLS_E_SUCCESS)
      failf(data, "gnutls_credentials_set() failed: %s", gnutls_strerror(rc));
  }
  else
#endif
    rc = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
                                conn->ssl[sockindex].cred);

  /* set the connection handle (file descriptor for the socket) */
  gnutls_transport_set_ptr(session,
                           GNUTLS_INT_TO_POINTER_CAST(conn->sock[sockindex]));

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

  return CURLE_OK;
}

static Curl_recv gtls_recv;
static Curl_send gtls_send;

static CURLcode
gtls_connect_step3(struct connectdata *conn,
                   int sockindex)
{
  unsigned int cert_list_size;
  const gnutls_datum *chainp;
  unsigned int verify_status;
  gnutls_x509_crt x509_cert,x509_issuer;
  gnutls_datum issuerp;
  char certbuf[256]; /* big enough? */
  size_t size;
  unsigned int algo;
  unsigned int bits;
  time_t certclock;
  const char *ptr;
  struct SessionHandle *data = conn->data;
  gnutls_session session = conn->ssl[sockindex].session;
  int rc;
  int incache;
  void *ssl_sessionid;
  CURLcode result = CURLE_OK;

  /* This function will return the peer's raw certificate (chain) as sent by
     the peer. These certificates are in raw format (DER encoded for
     X.509). In case of a X.509 then a certificate list may be present. The
     first certificate in the list is the peer's certificate, following the
     issuer's certificate, then the issuer's issuer etc. */

  chainp = gnutls_certificate_get_peers(session, &cert_list_size);
  if(!chainp) {
    if(data->set.ssl.verifypeer ||
       data->set.ssl.verifyhost ||
       data->set.ssl.issuercert) {
#ifdef USE_TLS_SRP
      if(data->set.ssl.authtype == CURL_TLSAUTH_SRP
         && data->set.ssl.username != NULL
         && !data->set.ssl.verifypeer
         && gnutls_cipher_get(session)) {
        /* no peer cert, but auth is ok if we have SRP user and cipher and no
           peer verify */
      }
      else {
#endif
        failf(data, "failed to get server cert");
        return CURLE_PEER_FAILED_VERIFICATION;
#ifdef USE_TLS_SRP
      }
#endif
    }
    infof(data, "\t common name: WARNING couldn't obtain\n");
  }

  if(data->set.ssl.verifypeer) {
    /* This function will try to verify the peer's certificate and return its
       status (trusted, invalid etc.). The value of status should be one or
       more of the gnutls_certificate_status_t enumerated elements bitwise
       or'd. To avoid denial of service attacks some default upper limits
       regarding the certificate key size and chain size are set. To override
       them use gnutls_certificate_set_verify_limits(). */

    rc = gnutls_certificate_verify_peers2(session, &verify_status);
    if(rc < 0) {
      failf(data, "server cert verify failed: %d", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }

    /* verify_status is a bitmask of gnutls_certificate_status bits */
    if(verify_status & GNUTLS_CERT_INVALID) {
      if(data->set.ssl.verifypeer) {
        failf(data, "server certificate verification failed. CAfile: %s "
              "CRLfile: %s", data->set.ssl.CAfile?data->set.ssl.CAfile:"none",
              data->set.ssl.CRLfile?data->set.ssl.CRLfile:"none");
        return CURLE_SSL_CACERT;
      }
      else
        infof(data, "\t server certificate verification FAILED\n");
    }
    else
      infof(data, "\t server certificate verification OK\n");
  }
  else {
    infof(data, "\t server certificate verification SKIPPED\n");
    goto after_server_cert_verification;
  }

  /* initialize an X.509 certificate structure. */
  gnutls_x509_crt_init(&x509_cert);

  /* convert the given DER or PEM encoded Certificate to the native
     gnutls_x509_crt_t format */
  gnutls_x509_crt_import(x509_cert, chainp, GNUTLS_X509_FMT_DER);

  if(data->set.ssl.issuercert) {
    gnutls_x509_crt_init(&x509_issuer);
    issuerp = load_file(data->set.ssl.issuercert);
    gnutls_x509_crt_import(x509_issuer, &issuerp, GNUTLS_X509_FMT_PEM);
    rc = gnutls_x509_crt_check_issuer(x509_cert,x509_issuer);
    unload_file(issuerp);
    if(rc <= 0) {
      failf(data, "server certificate issuer check failed (IssuerCert: %s)",
            data->set.ssl.issuercert?data->set.ssl.issuercert:"none");
      return CURLE_SSL_ISSUER_ERROR;
    }
    infof(data,"\t server certificate issuer check OK (Issuer Cert: %s)\n",
          data->set.ssl.issuercert?data->set.ssl.issuercert:"none");
  }

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
    if(data->set.ssl.verifyhost > 1) {
      failf(data, "SSL: certificate subject name (%s) does not match "
            "target host name '%s'", certbuf, conn->host.dispname);
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    else
      infof(data, "\t common name: %s (does not match '%s')\n",
            certbuf, conn->host.dispname);
  }
  else
    infof(data, "\t common name: %s (matched)\n", certbuf);

  /* Check for time-based validity */
  certclock = gnutls_x509_crt_get_expiration_time(x509_cert);

  if(certclock == (time_t)-1) {
    failf(data, "server cert expiration date verify failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(certclock < time(NULL)) {
    if(data->set.ssl.verifypeer) {
      failf(data, "server certificate expiration date has passed.");
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    else
      infof(data, "\t server certificate expiration date FAILED\n");
  }
  else
    infof(data, "\t server certificate expiration date OK\n");

  certclock = gnutls_x509_crt_get_activation_time(x509_cert);

  if(certclock == (time_t)-1) {
    failf(data, "server cert activation date verify failed");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(certclock > time(NULL)) {
    if(data->set.ssl.verifypeer) {
      failf(data, "server certificate not activated yet.");
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    else
      infof(data, "\t server certificate activation date FAILED\n");
  }
  else
    infof(data, "\t server certificate activation date OK\n");

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

  certclock = gnutls_x509_crt_get_activation_time(x509_cert);
  showtime(data, "start date", certclock);

  certclock = gnutls_x509_crt_get_expiration_time(x509_cert);
  showtime(data, "expire date", certclock);

  size = sizeof(certbuf);
  gnutls_x509_crt_get_issuer_dn(x509_cert, certbuf, &size);
  infof(data, "\t issuer: %s\n", certbuf);

  gnutls_x509_crt_deinit(x509_cert);

after_server_cert_verification:

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

  conn->ssl[sockindex].state = ssl_connection_complete;
  conn->recv[sockindex] = gtls_recv;
  conn->send[sockindex] = gtls_send;

  {
    /* we always unconditionally get the session id here, as even if we
       already got it from the cache and asked to use it in the connection, it
       might've been rejected and then a new one is in use now and we need to
       detect that. */
    void *connect_sessionid;
    size_t connect_idsize;

    /* get the session ID data size */
    gnutls_session_get_data(session, NULL, &connect_idsize);
    connect_sessionid = malloc(connect_idsize); /* get a buffer for it */

    if(connect_sessionid) {
      /* extract session ID to the allocated buffer */
      gnutls_session_get_data(session, connect_sessionid, &connect_idsize);

      incache = !(Curl_ssl_getsessionid(conn, &ssl_sessionid, NULL));
      if(incache) {
        /* there was one before in the cache, so instead of risking that the
           previous one was rejected, we just kill that and store the new */
        Curl_ssl_delsessionid(conn, ssl_sessionid);
      }

      /* store this session id */
      result = Curl_ssl_addsessionid(conn, connect_sessionid, connect_idsize);
      if(result) {
        free(connect_sessionid);
        result = CURLE_OUT_OF_MEMORY;
      }
    }
    else
      result = CURLE_OUT_OF_MEMORY;
  }

  return result;
}


/*
 * This function is called after the TCP connect has completed. Setup the TLS
 * layer and do all necessary magic.
 */
/* We use connssl->connecting_state to keep track of the connection status;
   there are three states: 'ssl_connect_1' (not started yet or complete),
   'ssl_connect_2_reading' (waiting for data from server), and
   'ssl_connect_2_writing' (waiting to be able to write).
 */
static CURLcode
gtls_connect_common(struct connectdata *conn,
                    int sockindex,
                    bool nonblocking,
                    bool *done)
{
  int rc;
  struct ssl_connect_data *connssl = &conn->ssl[sockindex];

  /* Initiate the connection, if not already done */
  if(ssl_connect_1==connssl->connecting_state) {
    rc = gtls_connect_step1 (conn, sockindex);
    if(rc)
      return rc;
  }

  rc = handshake(conn, sockindex, TRUE, nonblocking);
  if(rc)
    /* handshake() sets its own error message with failf() */
    return rc;

  /* Finish connecting once the handshake is done */
  if(ssl_connect_1==connssl->connecting_state) {
    rc = gtls_connect_step3(conn, sockindex);
    if(rc)
      return rc;
  }

  *done = ssl_connect_1==connssl->connecting_state;

  return CURLE_OK;
}

CURLcode
Curl_gtls_connect_nonblocking(struct connectdata *conn,
                              int sockindex,
                              bool *done)
{
  return gtls_connect_common(conn, sockindex, TRUE, done);
}

CURLcode
Curl_gtls_connect(struct connectdata *conn,
                  int sockindex)

{
  CURLcode retcode;
  bool done = FALSE;

  retcode = gtls_connect_common(conn, sockindex, FALSE, &done);
  if(retcode)
    return retcode;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static ssize_t gtls_send(struct connectdata *conn,
                         int sockindex,
                         const void *mem,
                         size_t len,
                         CURLcode *curlcode)
{
  ssize_t rc = gnutls_record_send(conn->ssl[sockindex].session, mem, len);

  if(rc < 0 ) {
    *curlcode = (rc == GNUTLS_E_AGAIN)
      ? CURLE_AGAIN
      : CURLE_SEND_ERROR;

    rc = -1;
  }

  return rc;
}

void Curl_gtls_close_all(struct SessionHandle *data)
{
  /* FIX: make the OpenSSL code more generic and use parts of it here */
  (void)data;
}

static void close_one(struct connectdata *conn,
                      int idx)
{
  if(conn->ssl[idx].session) {
    gnutls_bye(conn->ssl[idx].session, GNUTLS_SHUT_RDWR);
    gnutls_deinit(conn->ssl[idx].session);
    conn->ssl[idx].session = NULL;
  }
  if(conn->ssl[idx].cred) {
    gnutls_certificate_free_credentials(conn->ssl[idx].cred);
    conn->ssl[idx].cred = NULL;
  }
#ifdef USE_TLS_SRP
  if(conn->ssl[idx].srp_client_cred) {
    gnutls_srp_free_client_credentials(conn->ssl[idx].srp_client_cred);
    conn->ssl[idx].srp_client_cred = NULL;
  }
#endif
}

void Curl_gtls_close(struct connectdata *conn, int sockindex)
{
  close_one(conn, sockindex);
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
int Curl_gtls_shutdown(struct connectdata *conn, int sockindex)
{
  ssize_t result;
  int retval = 0;
  struct SessionHandle *data = conn->data;
  int done = 0;
  char buf[120];

  /* This has only been tested on the proftpd server, and the mod_tls code
     sends a close notify alert without waiting for a close notify alert in
     response. Thus we wait for a close notify alert from the server, but
     we do not send one. Let's hope other servers do the same... */

  if(data->set.ftp_ccc == CURLFTPSSL_CCC_ACTIVE)
      gnutls_bye(conn->ssl[sockindex].session, GNUTLS_SHUT_WR);

  if(conn->ssl[sockindex].session) {
    while(!done) {
      int what = Curl_socket_ready(conn->sock[sockindex],
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
        failf(data, "select/poll on SSL socket, errno: %d", SOCKERRNO);
        retval = -1;
        done = 1;
      }
    }
    gnutls_deinit(conn->ssl[sockindex].session);
  }
  gnutls_certificate_free_credentials(conn->ssl[sockindex].cred);

#ifdef USE_TLS_SRP
  if(data->set.ssl.authtype == CURL_TLSAUTH_SRP
     && data->set.ssl.username != NULL)
    gnutls_srp_free_client_credentials(conn->ssl[sockindex].srp_client_cred);
#endif

  conn->ssl[sockindex].cred = NULL;
  conn->ssl[sockindex].session = NULL;

  return retval;
}

static ssize_t gtls_recv(struct connectdata *conn, /* connection data */
                         int num,                  /* socketindex */
                         char *buf,                /* store read data here */
                         size_t buffersize,        /* max amount to read */
                         CURLcode *curlcode)
{
  ssize_t ret;

  ret = gnutls_record_recv(conn->ssl[num].session, buf, buffersize);
  if((ret == GNUTLS_E_AGAIN) || (ret == GNUTLS_E_INTERRUPTED)) {
    *curlcode = CURLE_AGAIN;
    return -1;
  }

  if(ret == GNUTLS_E_REHANDSHAKE) {
    /* BLOCKING call, this is bad but a work-around for now. Fixing this "the
       proper way" takes a whole lot of work. */
    CURLcode rc = handshake(conn, num, FALSE, FALSE);
    if(rc)
      /* handshake() writes error message on its own */
      *curlcode = rc;
    else
      *curlcode = CURLE_AGAIN; /* then return as if this was a wouldblock */
    return -1;
  }

  if(ret < 0) {
    failf(conn->data, "GnuTLS recv error (%d): %s",
          (int)ret, gnutls_strerror((int)ret));
    *curlcode = CURLE_RECV_ERROR;
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
  return snprintf(buffer, size, "GnuTLS/%s", gnutls_check_version(NULL));
}

int Curl_gtls_seed(struct SessionHandle *data)
{
  /* we have the "SSL is seeded" boolean static to prevent multiple
     time-consuming seedings in vain */
  static bool ssl_seeded = FALSE;

  /* Quickly add a bit of entropy */
#ifndef USE_GNUTLS_NETTLE
  gcry_fast_random_poll();
#endif

  if(!ssl_seeded || data->set.str[STRING_SSL_RANDOM_FILE] ||
     data->set.str[STRING_SSL_EGDSOCKET]) {

    /* TODO: to a good job seeding the RNG
       This may involve the gcry_control function and these options:
       GCRYCTL_SET_RANDOM_SEED_FILE
       GCRYCTL_SET_RNDEGD_SOCKET
    */
    ssl_seeded = TRUE;
  }
  return 0;
}

#endif /* USE_GNUTLS */
