/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

/*
 * Source file for all GnuTLS-specific code for the TLS/SSL layer. No code
 * but vtls.c should ever call or use these functions.
 *
 * Note: do not use the GnuTLS' *_t variable type names in this source code,
 * since they were not present in 1.0.X.
 */

#include "curl_setup.h"

#ifdef USE_GNUTLS

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#include <nettle/sha2.h>

#include "urldata.h"
#include "sendf.h"
#include "inet_pton.h"
#include "keylog.h"
#include "gtls.h"
#include "vtls.h"
#include "vtls_int.h"
#include "vauth/vauth.h"
#include "parsedate.h"
#include "connect.h" /* for the connect timeout */
#include "select.h"
#include "strcase.h"
#include "warnless.h"
#include "x509asn1.h"
#include "multiif.h"
#include "curl_printf.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#define QUIC_PRIORITY \
  "NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:" \
  "+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:" \
  "+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
  "%DISABLE_TLS13_COMPAT_MODE"

/* Enable GnuTLS debugging by defining GTLSDEBUG */
/*#define GTLSDEBUG */

#ifdef GTLSDEBUG
static void tls_log_func(int level, const char *str)
{
    fprintf(stderr, "|<%d>| %s", level, str);
}
#endif
static bool gtls_inited = FALSE;

#if !defined(GNUTLS_VERSION_NUMBER) || (GNUTLS_VERSION_NUMBER < 0x03010a)
#error "too old GnuTLS version"
#endif

# include <gnutls/ocsp.h>

struct gtls_ssl_backend_data {
  struct gtls_ctx gtls;
};

static ssize_t gtls_push(void *s, const void *buf, size_t blen)
{
  struct Curl_cfilter *cf = s;
  struct ssl_connect_data *connssl = cf->ctx;
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nwritten;
  CURLcode result;

  DEBUGASSERT(data);
  nwritten = Curl_conn_cf_send(cf->next, data, buf, blen, &result);
  CURL_TRC_CF(data, cf, "gtls_push(len=%zu) -> %zd, err=%d",
              blen, nwritten, result);
  backend->gtls.io_result = result;
  if(nwritten < 0) {
    gnutls_transport_set_errno(backend->gtls.session,
                               (CURLE_AGAIN == result)? EAGAIN : EINVAL);
    nwritten = -1;
  }
  return nwritten;
}

static ssize_t gtls_pull(void *s, void *buf, size_t blen)
{
  struct Curl_cfilter *cf = s;
  struct ssl_connect_data *connssl = cf->ctx;
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  ssize_t nread;
  CURLcode result;

  DEBUGASSERT(data);
  if(!backend->gtls.shared_creds->trust_setup) {
    result = Curl_gtls_client_trust_setup(cf, data, &backend->gtls);
    if(result) {
      gnutls_transport_set_errno(backend->gtls.session, EINVAL);
      backend->gtls.io_result = result;
      return -1;
    }
  }

  nread = Curl_conn_cf_recv(cf->next, data, buf, blen, &result);
  CURL_TRC_CF(data, cf, "glts_pull(len=%zu) -> %zd, err=%d",
              blen, nread, result);
  backend->gtls.io_result = result;
  if(nread < 0) {
    gnutls_transport_set_errno(backend->gtls.session,
                               (CURLE_AGAIN == result)? EAGAIN : EINVAL);
    nread = -1;
  }
  else if(nread == 0)
    connssl->peer_closed = TRUE;
  return nread;
}

/* gtls_init()
 *
 * Global GnuTLS init, called from Curl_ssl_init(). This calls functions that
 * are not thread-safe and thus this function itself is not thread-safe and
 * must only be called from within curl_global_init() to keep the thread
 * situation under control!
 */
static int gtls_init(void)
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

static void gtls_cleanup(void)
{
  if(gtls_inited) {
    gnutls_global_deinit();
    gtls_inited = FALSE;
  }
}

#ifndef CURL_DISABLE_VERBOSE_STRINGS
static void showtime(struct Curl_easy *data,
                     const char *text,
                     time_t stamp)
{
  struct tm buffer;
  const struct tm *tm = &buffer;
  char str[96];
  CURLcode result = Curl_gmtime(stamp, &buffer);
  if(result)
    return;

  msnprintf(str,
            sizeof(str),
            "  %s: %s, %02d %s %4d %02d:%02d:%02d GMT",
            text,
            Curl_wkday[tm->tm_wday?tm->tm_wday-1:6],
            tm->tm_mday,
            Curl_month[tm->tm_mon],
            tm->tm_year + 1900,
            tm->tm_hour,
            tm->tm_min,
            tm->tm_sec);
  infof(data, "%s", str);
}
#endif

static gnutls_datum_t load_file(const char *file)
{
  FILE *f;
  gnutls_datum_t loaded_file = { NULL, 0 };
  long filelen;
  void *ptr;

  f = fopen(file, "rb");
  if(!f)
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

static void unload_file(gnutls_datum_t data)
{
  free(data.data);
}


/* this function does a SSL/TLS (re-)handshake */
static CURLcode handshake(struct Curl_cfilter *cf,
                          struct Curl_easy *data,
                          bool duringconnect,
                          bool nonblocking)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;
  gnutls_session_t session;
  curl_socket_t sockfd = Curl_conn_cf_get_socket(cf, data);

  DEBUGASSERT(backend);
  session = backend->gtls.session;
  connssl->connecting_state = ssl_connect_2;

  for(;;) {
    timediff_t timeout_ms;
    int rc;

    /* check allowed time left */
    timeout_ms = Curl_timeleft(data, NULL, duringconnect);

    if(timeout_ms < 0) {
      /* no need to continue if time already is up */
      failf(data, "SSL connection timeout");
      return CURLE_OPERATION_TIMEDOUT;
    }

    /* if ssl is expecting something, check if it is available. */
    if(connssl->io_need) {
      int what;
      curl_socket_t writefd = (connssl->io_need & CURL_SSL_IO_NEED_SEND)?
                              sockfd:CURL_SOCKET_BAD;
      curl_socket_t readfd = (connssl->io_need & CURL_SSL_IO_NEED_RECV)?
                             sockfd:CURL_SOCKET_BAD;

      what = Curl_socket_check(readfd, CURL_SOCKET_BAD, writefd,
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
          failf(data, "SSL connection timeout at %ld", (long)timeout_ms);
          return CURLE_OPERATION_TIMEDOUT;
        }
      }
      /* socket is readable or writable */
    }

    connssl->io_need = CURL_SSL_IO_NEED_NONE;
    backend->gtls.io_result = CURLE_OK;
    rc = gnutls_handshake(session);

    if(!backend->gtls.shared_creds->trust_setup) {
      /* After having send off the ClientHello, we prepare the trust
       * store to verify the coming certificate from the server */
      CURLcode result = Curl_gtls_client_trust_setup(cf, data, &backend->gtls);
      if(result)
        return result;
    }

    if((rc == GNUTLS_E_AGAIN) || (rc == GNUTLS_E_INTERRUPTED)) {
      connssl->io_need =
        gnutls_record_get_direction(session)?
        CURL_SSL_IO_NEED_SEND:CURL_SSL_IO_NEED_RECV;
      continue;
    }
    else if((rc < 0) && !gnutls_error_is_fatal(rc)) {
      const char *strerr = NULL;

      if(rc == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        gnutls_alert_description_t alert = gnutls_alert_get(session);
        strerr = gnutls_alert_get_name(alert);
      }

      if(!strerr)
        strerr = gnutls_strerror(rc);

      infof(data, "gnutls_handshake() warning: %s", strerr);
      continue;
    }
    else if((rc < 0) && backend->gtls.io_result) {
      return backend->gtls.io_result;
    }
    else if(rc < 0) {
      const char *strerr = NULL;

      if(rc == GNUTLS_E_FATAL_ALERT_RECEIVED) {
        gnutls_alert_description_t alert = gnutls_alert_get(session);
        strerr = gnutls_alert_get_name(alert);
      }

      if(!strerr)
        strerr = gnutls_strerror(rc);

      failf(data, "gnutls_handshake() failed: %s", strerr);
      return CURLE_SSL_CONNECT_ERROR;
    }

    /* Reset our connect state machine */
    connssl->connecting_state = ssl_connect_1;
    return CURLE_OK;
  }
}

static gnutls_x509_crt_fmt_t do_file_type(const char *type)
{
  if(!type || !type[0])
    return GNUTLS_X509_FMT_PEM;
  if(strcasecompare(type, "PEM"))
    return GNUTLS_X509_FMT_PEM;
  if(strcasecompare(type, "DER"))
    return GNUTLS_X509_FMT_DER;
  return GNUTLS_X509_FMT_PEM; /* default to PEM */
}

#define GNUTLS_CIPHERS "NORMAL:-ARCFOUR-128:-CTYPE-ALL:+CTYPE-X509"
/* If GnuTLS was compiled without support for SRP it will error out if SRP is
   requested in the priority string, so treat it specially
 */
#define GNUTLS_SRP "+SRP"

static CURLcode
set_ssl_version_min_max(struct Curl_easy *data,
                        struct ssl_peer *peer,
                        struct ssl_primary_config *conn_config,
                        const char **prioritylist,
                        const char *tls13support)
{
  long ssl_version = conn_config->version;
  long ssl_version_max = conn_config->version_max;

  if((ssl_version == CURL_SSLVERSION_DEFAULT) ||
     (ssl_version == CURL_SSLVERSION_TLSv1))
    ssl_version = CURL_SSLVERSION_TLSv1_0;
  if(ssl_version_max == CURL_SSLVERSION_MAX_NONE)
    ssl_version_max = CURL_SSLVERSION_MAX_DEFAULT;

  if(peer->transport == TRNSPRT_QUIC) {
    if((ssl_version_max != CURL_SSLVERSION_MAX_DEFAULT) &&
       (ssl_version_max < CURL_SSLVERSION_MAX_TLSv1_3)) {
      failf(data, "QUIC needs at least TLS version 1.3");
      return CURLE_SSL_CONNECT_ERROR;
     }
    *prioritylist = QUIC_PRIORITY;
    return CURLE_OK;
  }

  if(!tls13support) {
    /* If the running GnuTLS does not support TLS 1.3, we must not specify a
       prioritylist involving that since it will make GnuTLS return an en
       error back at us */
    if((ssl_version_max == CURL_SSLVERSION_MAX_TLSv1_3) ||
       (ssl_version_max == CURL_SSLVERSION_MAX_DEFAULT)) {
      ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_2;
    }
  }
  else if(ssl_version_max == CURL_SSLVERSION_MAX_DEFAULT) {
    ssl_version_max = CURL_SSLVERSION_MAX_TLSv1_3;
  }

  switch(ssl_version | ssl_version_max) {
  case CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_TLSv1_0:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.0";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_TLSv1_1:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.1:+VERS-TLS1.0";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_TLSv1_2:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.2:+VERS-TLS1.1:+VERS-TLS1.0";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_1 | CURL_SSLVERSION_MAX_TLSv1_1:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.1";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_1 | CURL_SSLVERSION_MAX_TLSv1_2:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.2:+VERS-TLS1.1";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_2:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.2";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_3 | CURL_SSLVERSION_MAX_TLSv1_3:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.3";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_TLSv1_3:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_1 | CURL_SSLVERSION_MAX_TLSv1_3:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.3:+VERS-TLS1.2:+VERS-TLS1.1";
    return CURLE_OK;
  case CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_TLSv1_3:
    *prioritylist = GNUTLS_CIPHERS ":-VERS-SSL3.0:-VERS-TLS-ALL:"
      "+VERS-TLS1.3:+VERS-TLS1.2";
    return CURLE_OK;
  }

  failf(data, "GnuTLS: cannot set ssl protocol");
  return CURLE_SSL_CONNECT_ERROR;
}

CURLcode Curl_gtls_shared_creds_create(struct Curl_easy *data,
                                       struct gtls_shared_creds **pcreds)
{
  struct gtls_shared_creds *shared;
  int rc;

  *pcreds = NULL;
  shared = calloc(1, sizeof(*shared));
  if(!shared)
    return CURLE_OUT_OF_MEMORY;

  rc = gnutls_certificate_allocate_credentials(&shared->creds);
  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "gnutls_cert_all_cred() failed: %s", gnutls_strerror(rc));
    free(shared);
    return CURLE_SSL_CONNECT_ERROR;
  }

  shared->refcount = 1;
  shared->time = Curl_now();
  *pcreds = shared;
  return CURLE_OK;
}

CURLcode Curl_gtls_shared_creds_up_ref(struct gtls_shared_creds *creds)
{
  DEBUGASSERT(creds);
  if(creds->refcount < SIZE_T_MAX) {
    ++creds->refcount;
    return CURLE_OK;
  }
  return CURLE_BAD_FUNCTION_ARGUMENT;
}

void Curl_gtls_shared_creds_free(struct gtls_shared_creds **pcreds)
{
  struct gtls_shared_creds *shared = *pcreds;
  *pcreds = NULL;
  if(shared) {
    --shared->refcount;
    if(!shared->refcount) {
      gnutls_certificate_free_credentials(shared->creds);
      free(shared->CAfile);
      free(shared);
    }
  }
}

static CURLcode gtls_populate_creds(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    gnutls_certificate_credentials_t creds)
{
  struct ssl_primary_config *config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  int rc;

  if(config->verifypeer) {
    bool imported_native_ca = false;

    if(ssl_config->native_ca_store) {
      rc = gnutls_certificate_set_x509_system_trust(creds);
      if(rc < 0)
        infof(data, "error reading native ca store (%s), continuing anyway",
              gnutls_strerror(rc));
      else {
        infof(data, "found %d certificates in native ca store", rc);
        if(rc > 0)
          imported_native_ca = true;
      }
    }

    if(config->CAfile) {
      /* set the trusted CA cert bundle file */
      gnutls_certificate_set_verify_flags(creds,
                                          GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);

      rc = gnutls_certificate_set_x509_trust_file(creds,
                                                  config->CAfile,
                                                  GNUTLS_X509_FMT_PEM);
      if(rc < 0) {
        infof(data, "error reading ca cert file %s (%s)%s",
              config->CAfile, gnutls_strerror(rc),
              (imported_native_ca ? ", continuing anyway" : ""));
        if(!imported_native_ca) {
          ssl_config->certverifyresult = rc;
          return CURLE_SSL_CACERT_BADFILE;
        }
      }
      else
        infof(data, "found %d certificates in %s", rc, config->CAfile);
    }

    if(config->CApath) {
      /* set the trusted CA cert directory */
      rc = gnutls_certificate_set_x509_trust_dir(creds, config->CApath,
                                                 GNUTLS_X509_FMT_PEM);
      if(rc < 0) {
        infof(data, "error reading ca cert file %s (%s)%s",
              config->CApath, gnutls_strerror(rc),
              (imported_native_ca ? ", continuing anyway" : ""));
        if(!imported_native_ca) {
          ssl_config->certverifyresult = rc;
          return CURLE_SSL_CACERT_BADFILE;
        }
      }
      else
        infof(data, "found %d certificates in %s", rc, config->CApath);
    }
  }

  if(config->CRLfile) {
    /* set the CRL list file */
    rc = gnutls_certificate_set_x509_crl_file(creds, config->CRLfile,
                                              GNUTLS_X509_FMT_PEM);
    if(rc < 0) {
      failf(data, "error reading crl file %s (%s)",
            config->CRLfile, gnutls_strerror(rc));
      return CURLE_SSL_CRL_BADFILE;
    }
    else
      infof(data, "found %d CRL in %s", rc, config->CRLfile);
  }

  return CURLE_OK;
}

/* key to use at `multi->proto_hash` */
#define MPROTO_GTLS_X509_KEY   "tls:gtls:x509:share"

static bool gtls_shared_creds_expired(const struct Curl_easy *data,
                                      const struct gtls_shared_creds *sc)
{
  const struct ssl_general_config *cfg = &data->set.general_ssl;
  struct curltime now = Curl_now();
  timediff_t elapsed_ms = Curl_timediff(now, sc->time);
  timediff_t timeout_ms = cfg->ca_cache_timeout * (timediff_t)1000;

  if(timeout_ms < 0)
    return false;

  return elapsed_ms >= timeout_ms;
}

static bool gtls_shared_creds_different(struct Curl_cfilter *cf,
                                        const struct gtls_shared_creds *sc)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  if(!sc->CAfile || !conn_config->CAfile)
    return sc->CAfile != conn_config->CAfile;

  return strcmp(sc->CAfile, conn_config->CAfile);
}

static struct gtls_shared_creds*
gtls_get_cached_creds(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct gtls_shared_creds *shared_creds;

  if(data->multi) {
    shared_creds = Curl_hash_pick(&data->multi->proto_hash,
                                  (void *)MPROTO_GTLS_X509_KEY,
                                  sizeof(MPROTO_GTLS_X509_KEY)-1);
     if(shared_creds && shared_creds->creds &&
        !gtls_shared_creds_expired(data, shared_creds) &&
        !gtls_shared_creds_different(cf, shared_creds)) {
       return shared_creds;
     }
  }
  return NULL;
}

static void gtls_shared_creds_hash_free(void *key, size_t key_len, void *p)
{
  struct gtls_shared_creds *sc = p;
  DEBUGASSERT(key_len == (sizeof(MPROTO_GTLS_X509_KEY)-1));
  DEBUGASSERT(!memcmp(MPROTO_GTLS_X509_KEY, key, key_len));
  (void)key;
  (void)key_len;
  Curl_gtls_shared_creds_free(&sc); /* down reference */
}

static void gtls_set_cached_creds(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct gtls_shared_creds *sc)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);

  DEBUGASSERT(sc);
  DEBUGASSERT(sc->creds);
  DEBUGASSERT(!sc->CAfile);
  DEBUGASSERT(sc->refcount == 1);
  if(!data->multi)
    return;

  if(conn_config->CAfile) {
    sc->CAfile = strdup(conn_config->CAfile);
    if(!sc->CAfile)
      return;
  }

  if(Curl_gtls_shared_creds_up_ref(sc))
    return;

  if(!Curl_hash_add2(&data->multi->proto_hash,
                    (void *)MPROTO_GTLS_X509_KEY,
                    sizeof(MPROTO_GTLS_X509_KEY)-1,
                    sc, gtls_shared_creds_hash_free)) {
    Curl_gtls_shared_creds_free(&sc); /* down reference again */
    return;
  }
}

CURLcode Curl_gtls_client_trust_setup(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      struct gtls_ctx *gtls)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct gtls_shared_creds *cached_creds = NULL;
  bool cache_criteria_met;
  CURLcode result;
  int rc;


  /* Consider the X509 store cacheable if it comes exclusively from a CAfile,
     or no source is provided and we are falling back to OpenSSL's built-in
     default. */
  cache_criteria_met = (data->set.general_ssl.ca_cache_timeout != 0) &&
    conn_config->verifypeer &&
    !conn_config->CApath &&
    !conn_config->ca_info_blob &&
    !ssl_config->primary.CRLfile &&
    !ssl_config->native_ca_store &&
    !conn_config->clientcert; /* GnuTLS adds client cert to its credentials! */

  if(cache_criteria_met)
    cached_creds = gtls_get_cached_creds(cf, data);

  if(cached_creds && !Curl_gtls_shared_creds_up_ref(cached_creds)) {
    CURL_TRC_CF(data, cf, "using shared trust anchors and CRLs");
    Curl_gtls_shared_creds_free(&gtls->shared_creds);
    gtls->shared_creds = cached_creds;
    rc = gnutls_credentials_set(gtls->session, GNUTLS_CRD_CERTIFICATE,
                                gtls->shared_creds->creds);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_credentials_set() failed: %s", gnutls_strerror(rc));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else {
    CURL_TRC_CF(data, cf, "loading trust anchors and CRLs");
    result = gtls_populate_creds(cf, data, gtls->shared_creds->creds);
    if(result)
      return result;
    gtls->shared_creds->trust_setup = TRUE;
    if(cache_criteria_met)
      gtls_set_cached_creds(cf, data, gtls->shared_creds);
  }
  return CURLE_OK;
}

static void gtls_sessionid_free(void *sessionid, size_t idsize)
{
  (void)idsize;
  free(sessionid);
}

static CURLcode gtls_update_session_id(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       gnutls_session_t session)
{
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode result = CURLE_OK;

  if(ssl_config->primary.cache_session) {
    /* we always unconditionally get the session id here, as even if we
       already got it from the cache and asked to use it in the connection, it
       might've been rejected and then a new one is in use now and we need to
       detect that. */
    void *connect_sessionid;
    size_t connect_idsize = 0;

    /* get the session ID data size */
    gnutls_session_get_data(session, NULL, &connect_idsize);
    connect_sessionid = malloc(connect_idsize); /* get a buffer for it */
    if(!connect_sessionid) {
      return CURLE_OUT_OF_MEMORY;
    }
    else {
      /* extract session ID to the allocated buffer */
      gnutls_session_get_data(session, connect_sessionid, &connect_idsize);

      CURL_TRC_CF(data, cf, "get session id (len=%zu) and store in cache",
                  connect_idsize);
      Curl_ssl_sessionid_lock(data);
      /* store this session id, takes ownership */
      result = Curl_ssl_set_sessionid(cf, data, &connssl->peer,
                                      connect_sessionid, connect_idsize,
                                      gtls_sessionid_free);
      Curl_ssl_sessionid_unlock(data);
    }
  }
  return result;
}

static int gtls_handshake_cb(gnutls_session_t session, unsigned int htype,
                             unsigned when, unsigned int incoming,
                             const gnutls_datum_t *msg)
{
  struct Curl_cfilter *cf = gnutls_session_get_ptr(session);

  (void)msg;
  (void)incoming;
  if(when) { /* after message has been processed */
    struct Curl_easy *data = CF_DATA_CURRENT(cf);
    if(data) {
      CURL_TRC_CF(data, cf, "handshake: %s message type %d",
                  incoming? "incoming" : "outgoing", htype);
      switch(htype) {
      case GNUTLS_HANDSHAKE_NEW_SESSION_TICKET: {
        gtls_update_session_id(cf, data, session);
        break;
      }
      default:
        break;
      }
    }
  }
  return 0;
}

static CURLcode gtls_client_init(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct ssl_peer *peer,
                                 struct gtls_ctx *gtls)
{
  struct ssl_primary_config *config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
  unsigned int init_flags;
  int rc;
  bool sni = TRUE; /* default is SNI enabled */
  const char *prioritylist;
  const char *err = NULL;
  const char *tls13support;
  CURLcode result;

  if(!gtls_inited)
    gtls_init();

  if(config->version == CURL_SSLVERSION_SSLv2) {
    failf(data, "GnuTLS does not support SSLv2");
    return CURLE_SSL_CONNECT_ERROR;
  }
  else if(config->version == CURL_SSLVERSION_SSLv3)
    sni = FALSE; /* SSLv3 has no SNI */

  /* allocate a shared creds struct */
  result = Curl_gtls_shared_creds_create(data, &gtls->shared_creds);
  if(result)
    return result;

#ifdef USE_GNUTLS_SRP
  if(config->username && Curl_auth_allowed_to_host(data)) {
    infof(data, "Using TLS-SRP username: %s", config->username);

    rc = gnutls_srp_allocate_client_credentials(&gtls->srp_client_cred);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_srp_allocate_client_cred() failed: %s",
            gnutls_strerror(rc));
      return CURLE_OUT_OF_MEMORY;
    }

    rc = gnutls_srp_set_client_credentials(gtls->srp_client_cred,
                                           config->username,
                                           config->password);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_srp_set_client_cred() failed: %s",
            gnutls_strerror(rc));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }
#endif

  ssl_config->certverifyresult = 0;

  /* Initialize TLS session as a client */
  init_flags = GNUTLS_CLIENT;

#if defined(GNUTLS_FORCE_CLIENT_CERT)
  init_flags |= GNUTLS_FORCE_CLIENT_CERT;
#endif

#if defined(GNUTLS_NO_TICKETS)
  /* Disable TLS session tickets */
  init_flags |= GNUTLS_NO_TICKETS;
#endif

  rc = gnutls_init(&gtls->session, init_flags);
  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "gnutls_init() failed: %d", rc);
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(sni && peer->sni) {
    if(gnutls_server_name_set(gtls->session, GNUTLS_NAME_DNS,
                              peer->sni, strlen(peer->sni)) < 0) {
      failf(data, "Failed to set SNI");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* Use default priorities */
  rc = gnutls_set_default_priority(gtls->session);
  if(rc != GNUTLS_E_SUCCESS)
    return CURLE_SSL_CONNECT_ERROR;

  /* "In GnuTLS 3.6.5, TLS 1.3 is enabled by default" */
  tls13support = gnutls_check_version("3.6.5");

  /* Ensure +SRP comes at the *end* of all relevant strings so that it can be
   * removed if a runtime error indicates that SRP is not supported by this
   * GnuTLS version */

  if(config->version == CURL_SSLVERSION_SSLv2 ||
     config->version == CURL_SSLVERSION_SSLv3) {
    failf(data, "GnuTLS does not support SSLv2 or SSLv3");
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(config->version == CURL_SSLVERSION_TLSv1_3) {
    if(!tls13support) {
      failf(data, "This GnuTLS installation does not support TLS 1.3");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* At this point we know we have a supported TLS version, so set it */
  result = set_ssl_version_min_max(data, peer,
                                   config, &prioritylist, tls13support);
  if(result)
    return result;

#ifdef USE_GNUTLS_SRP
  /* Only add SRP to the cipher list if SRP is requested. Otherwise
   * GnuTLS will disable TLS 1.3 support. */
  if(config->username) {
    char *prioritysrp = aprintf("%s:" GNUTLS_SRP, prioritylist);
    if(!prioritysrp)
      return CURLE_OUT_OF_MEMORY;
    rc = gnutls_priority_set_direct(gtls->session, prioritysrp, &err);
    free(prioritysrp);

    if((rc == GNUTLS_E_INVALID_REQUEST) && err) {
      infof(data, "This GnuTLS does not support SRP");
    }
  }
  else {
#endif
    infof(data, "GnuTLS ciphers: %s", prioritylist);
    rc = gnutls_priority_set_direct(gtls->session, prioritylist, &err);
#ifdef USE_GNUTLS_SRP
  }
#endif

  if(rc != GNUTLS_E_SUCCESS) {
    failf(data, "Error %d setting GnuTLS cipher list starting with %s",
          rc, err);
    return CURLE_SSL_CONNECT_ERROR;
  }

  if(config->clientcert) {
    if(!gtls->shared_creds->trust_setup) {
      result = Curl_gtls_client_trust_setup(cf, data, gtls);
      if(result)
        return result;
    }
    if(ssl_config->key_passwd) {
      const unsigned int supported_key_encryption_algorithms =
        GNUTLS_PKCS_USE_PKCS12_3DES | GNUTLS_PKCS_USE_PKCS12_ARCFOUR |
        GNUTLS_PKCS_USE_PKCS12_RC2_40 | GNUTLS_PKCS_USE_PBES2_3DES |
        GNUTLS_PKCS_USE_PBES2_AES_128 | GNUTLS_PKCS_USE_PBES2_AES_192 |
        GNUTLS_PKCS_USE_PBES2_AES_256;
      rc = gnutls_certificate_set_x509_key_file2(
           gtls->shared_creds->creds,
           config->clientcert,
           ssl_config->key ? ssl_config->key : config->clientcert,
           do_file_type(ssl_config->cert_type),
           ssl_config->key_passwd,
           supported_key_encryption_algorithms);
      if(rc != GNUTLS_E_SUCCESS) {
        failf(data,
              "error reading X.509 potentially-encrypted key file: %s",
              gnutls_strerror(rc));
        return CURLE_SSL_CONNECT_ERROR;
      }
    }
    else {
      if(gnutls_certificate_set_x509_key_file(
           gtls->shared_creds->creds,
           config->clientcert,
           ssl_config->key ? ssl_config->key : config->clientcert,
           do_file_type(ssl_config->cert_type) ) !=
         GNUTLS_E_SUCCESS) {
        failf(data, "error reading X.509 key or certificate file");
        return CURLE_SSL_CONNECT_ERROR;
      }
    }
  }

#ifdef USE_GNUTLS_SRP
  /* put the credentials to the current session */
  if(config->username) {
    rc = gnutls_credentials_set(gtls->session, GNUTLS_CRD_SRP,
                                gtls->srp_client_cred);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_credentials_set() failed: %s", gnutls_strerror(rc));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }
  else
#endif
  {
    rc = gnutls_credentials_set(gtls->session, GNUTLS_CRD_CERTIFICATE,
                                gtls->shared_creds->creds);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_credentials_set() failed: %s", gnutls_strerror(rc));
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  if(config->verifystatus) {
    rc = gnutls_ocsp_status_request_enable_client(gtls->session,
                                                  NULL, 0, NULL);
    if(rc != GNUTLS_E_SUCCESS) {
      failf(data, "gnutls_ocsp_status_request_enable_client() failed: %d", rc);
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  return CURLE_OK;
}

static int keylog_callback(gnutls_session_t session, const char *label,
                           const gnutls_datum_t *secret)
{
  gnutls_datum_t crandom;
  gnutls_datum_t srandom;

  gnutls_session_get_random(session, &crandom, &srandom);
  if(crandom.size != 32) {
    return -1;
  }

  Curl_tls_keylog_write(label, crandom.data, secret->data, secret->size);
  return 0;
}

CURLcode Curl_gtls_ctx_init(struct gtls_ctx *gctx,
                            struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct ssl_peer *peer,
                            const unsigned char *alpn, size_t alpn_len,
                            Curl_gtls_ctx_setup_cb *cb_setup,
                            void *cb_user_data,
                            void *ssl_user_data)
{
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  CURLcode result;

  DEBUGASSERT(gctx);

  result = gtls_client_init(cf, data, peer, gctx);
  if(result)
    return result;

  gnutls_session_set_ptr(gctx->session, ssl_user_data);

  if(cb_setup) {
    result = cb_setup(cf, data, cb_user_data);
    if(result)
      return result;
  }

  /* Open the file if a TLS or QUIC backend has not done this before. */
  Curl_tls_keylog_open();
  if(Curl_tls_keylog_enabled()) {
    gnutls_session_set_keylog_function(gctx->session, keylog_callback);
  }

  /* convert the ALPN string from our arguments to a list of strings
   * that gnutls wants and will convert internally back to this very
   * string for sending to the server. nice. */
  if(alpn && alpn_len) {
    gnutls_datum_t alpns[5];
    size_t i, alen = alpn_len;
    unsigned char *s = (unsigned char *)alpn;
    unsigned char slen;
    for(i = 0; (i < ARRAYSIZE(alpns)) && alen; ++i) {
      slen = s[0];
      if(slen >= alen)
        return CURLE_FAILED_INIT;
      alpns[i].data = s + 1;
      alpns[i].size = slen;
      s += slen + 1;
      alen -= (size_t)slen + 1;
    }
    if(alen) /* not all alpn chars used, wrong format or too many */
        return CURLE_FAILED_INIT;
    if(i && gnutls_alpn_set_protocols(gctx->session,
                                      alpns, (unsigned int)i,
                                      GNUTLS_ALPN_MANDATORY)) {
      failf(data, "failed setting ALPN");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  /* This might be a reconnect, so we check for a session ID in the cache
     to speed up things */
  if(conn_config->cache_session) {
    void *ssl_sessionid;
    size_t ssl_idsize;

    Curl_ssl_sessionid_lock(data);
    if(!Curl_ssl_getsessionid(cf, data, peer, &ssl_sessionid, &ssl_idsize)) {
      /* we got a session id, use it! */
      int rc;

      rc = gnutls_session_set_data(gctx->session, ssl_sessionid, ssl_idsize);
      if(rc < 0)
        infof(data, "SSL failed to set session ID");
      else
        infof(data, "SSL reusing session ID (size=%zu)", ssl_idsize);
    }
    Curl_ssl_sessionid_unlock(data);
  }
  return CURLE_OK;
}

static CURLcode
gtls_connect_step1(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;
  struct alpn_proto_buf proto;
  CURLcode result;

  DEBUGASSERT(backend);
  DEBUGASSERT(ssl_connect_1 == connssl->connecting_state);

  if(connssl->state == ssl_connection_complete)
    /* to make us tolerant against being called more than once for the
       same connection */
    return CURLE_OK;

  memset(&proto, 0, sizeof(proto));
  if(connssl->alpn) {
    result = Curl_alpn_to_proto_buf(&proto, connssl->alpn);
    if(result) {
      failf(data, "Error determining ALPN");
      return CURLE_SSL_CONNECT_ERROR;
    }
  }

  result = Curl_gtls_ctx_init(&backend->gtls, cf, data, &connssl->peer,
                              proto.data, proto.len, NULL, NULL, cf);
  if(result)
    return result;

  gnutls_handshake_set_hook_function(backend->gtls.session,
                                     GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_POST,
                                     gtls_handshake_cb);

  /* register callback functions and handle to send and receive data. */
  gnutls_transport_set_ptr(backend->gtls.session, cf);
  gnutls_transport_set_push_function(backend->gtls.session, gtls_push);
  gnutls_transport_set_pull_function(backend->gtls.session, gtls_pull);

  return CURLE_OK;
}

static CURLcode pkp_pin_peer_pubkey(struct Curl_easy *data,
                                    gnutls_x509_crt_t cert,
                                    const char *pinnedpubkey)
{
  /* Scratch */
  size_t len1 = 0, len2 = 0;
  unsigned char *buff1 = NULL;

  gnutls_pubkey_t key = NULL;

  /* Result is returned to caller */
  CURLcode result = CURLE_SSL_PINNEDPUBKEYNOTMATCH;

  /* if a path was not specified, do not pin */
  if(!pinnedpubkey)
    return CURLE_OK;

  if(!cert)
    return result;

  do {
    int ret;

    /* Begin Gyrations to get the public key     */
    gnutls_pubkey_init(&key);

    ret = gnutls_pubkey_import_x509(key, cert, 0);
    if(ret < 0)
      break; /* failed */

    ret = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, NULL, &len1);
    if(ret != GNUTLS_E_SHORT_MEMORY_BUFFER || len1 == 0)
      break; /* failed */

    buff1 = malloc(len1);
    if(!buff1)
      break; /* failed */

    len2 = len1;

    ret = gnutls_pubkey_export(key, GNUTLS_X509_FMT_DER, buff1, &len2);
    if(ret < 0 || len1 != len2)
      break; /* failed */

    /* End Gyrations */

    /* The one good exit point */
    result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1);
  } while(0);

  if(key)
    gnutls_pubkey_deinit(key);

  Curl_safefree(buff1);

  return result;
}

CURLcode
Curl_gtls_verifyserver(struct Curl_easy *data,
                       gnutls_session_t session,
                       struct ssl_primary_config *config,
                       struct ssl_config_data *ssl_config,
                       struct ssl_peer *peer,
                       const char *pinned_key)
{
  unsigned int cert_list_size;
  const gnutls_datum_t *chainp;
  unsigned int verify_status = 0;
  gnutls_x509_crt_t x509_cert, x509_issuer;
  gnutls_datum_t issuerp;
  gnutls_datum_t certfields;
  char certname[65] = ""; /* limited to 64 chars by ASN.1 */
  size_t size;
  time_t certclock;
  int rc;
  CURLcode result = CURLE_OK;
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  const char *ptr;
  int algo;
  unsigned int bits;
  gnutls_protocol_t version = gnutls_protocol_get_version(session);
#endif
  long * const certverifyresult = &ssl_config->certverifyresult;

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  /* the name of the cipher suite used, e.g. ECDHE_RSA_AES_256_GCM_SHA384. */
  ptr = gnutls_cipher_suite_get_name(gnutls_kx_get(session),
                                     gnutls_cipher_get(session),
                                     gnutls_mac_get(session));

  infof(data, "SSL connection using %s / %s",
        gnutls_protocol_get_name(version), ptr);
#endif

  /* This function will return the peer's raw certificate (chain) as sent by
     the peer. These certificates are in raw format (DER encoded for
     X.509). In case of a X.509 then a certificate list may be present. The
     first certificate in the list is the peer's certificate, following the
     issuer's certificate, then the issuer's issuer etc. */

  chainp = gnutls_certificate_get_peers(session, &cert_list_size);
  if(!chainp) {
    if(config->verifypeer ||
       config->verifyhost ||
       config->issuercert) {
#ifdef USE_GNUTLS_SRP
      if(ssl_config->primary.username && !config->verifypeer &&
         gnutls_cipher_get(session)) {
        /* no peer cert, but auth is ok if we have SRP user and cipher and no
           peer verify */
      }
      else {
#endif
        failf(data, "failed to get server cert");
        *certverifyresult = GNUTLS_E_NO_CERTIFICATE_FOUND;
        return CURLE_PEER_FAILED_VERIFICATION;
#ifdef USE_GNUTLS_SRP
      }
#endif
    }
    infof(data, " common name: WARNING could not obtain");
  }

  if(data->set.ssl.certinfo && chainp) {
    unsigned int i;

    result = Curl_ssl_init_certinfo(data, (int)cert_list_size);
    if(result)
      return result;

    for(i = 0; i < cert_list_size; i++) {
      const char *beg = (const char *) chainp[i].data;
      const char *end = beg + chainp[i].size;

      result = Curl_extract_certinfo(data, (int)i, beg, end);
      if(result)
        return result;
    }
  }

  if(config->verifypeer) {
    /* This function will try to verify the peer's certificate and return its
       status (trusted, invalid etc.). The value of status should be one or
       more of the gnutls_certificate_status_t enumerated elements bitwise
       or'd. To avoid denial of service attacks some default upper limits
       regarding the certificate key size and chain size are set. To override
       them use gnutls_certificate_set_verify_limits(). */

    rc = gnutls_certificate_verify_peers2(session, &verify_status);
    if(rc < 0) {
      failf(data, "server cert verify failed: %d", rc);
      *certverifyresult = rc;
      return CURLE_SSL_CONNECT_ERROR;
    }

    *certverifyresult = verify_status;

    /* verify_status is a bitmask of gnutls_certificate_status bits */
    if(verify_status & GNUTLS_CERT_INVALID) {
      if(config->verifypeer) {
        failf(data, "server certificate verification failed. CAfile: %s "
              "CRLfile: %s", config->CAfile ? config->CAfile:
              "none",
              ssl_config->primary.CRLfile ?
              ssl_config->primary.CRLfile : "none");
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else
        infof(data, "  server certificate verification FAILED");
    }
    else
      infof(data, "  server certificate verification OK");
  }
  else
    infof(data, "  server certificate verification SKIPPED");

  if(config->verifystatus) {
    if(gnutls_ocsp_status_request_is_checked(session, 0) == 0) {
      gnutls_datum_t status_request;
      gnutls_ocsp_resp_t ocsp_resp;

      gnutls_ocsp_cert_status_t status;
      gnutls_x509_crl_reason_t reason;

      rc = gnutls_ocsp_status_request_get(session, &status_request);

      infof(data, " server certificate status verification FAILED");

      if(rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
        failf(data, "No OCSP response received");
        return CURLE_SSL_INVALIDCERTSTATUS;
      }

      if(rc < 0) {
        failf(data, "Invalid OCSP response received");
        return CURLE_SSL_INVALIDCERTSTATUS;
      }

      gnutls_ocsp_resp_init(&ocsp_resp);

      rc = gnutls_ocsp_resp_import(ocsp_resp, &status_request);
      if(rc < 0) {
        failf(data, "Invalid OCSP response received");
        return CURLE_SSL_INVALIDCERTSTATUS;
      }

      (void)gnutls_ocsp_resp_get_single(ocsp_resp, 0, NULL, NULL, NULL, NULL,
                                        &status, NULL, NULL, NULL, &reason);

      switch(status) {
      case GNUTLS_OCSP_CERT_GOOD:
        break;

      case GNUTLS_OCSP_CERT_REVOKED: {
        const char *crl_reason;

        switch(reason) {
          default:
          case GNUTLS_X509_CRLREASON_UNSPECIFIED:
            crl_reason = "unspecified reason";
            break;

          case GNUTLS_X509_CRLREASON_KEYCOMPROMISE:
            crl_reason = "private key compromised";
            break;

          case GNUTLS_X509_CRLREASON_CACOMPROMISE:
            crl_reason = "CA compromised";
            break;

          case GNUTLS_X509_CRLREASON_AFFILIATIONCHANGED:
            crl_reason = "affiliation has changed";
            break;

          case GNUTLS_X509_CRLREASON_SUPERSEDED:
            crl_reason = "certificate superseded";
            break;

          case GNUTLS_X509_CRLREASON_CESSATIONOFOPERATION:
            crl_reason = "operation has ceased";
            break;

          case GNUTLS_X509_CRLREASON_CERTIFICATEHOLD:
            crl_reason = "certificate is on hold";
            break;

          case GNUTLS_X509_CRLREASON_REMOVEFROMCRL:
            crl_reason = "will be removed from delta CRL";
            break;

          case GNUTLS_X509_CRLREASON_PRIVILEGEWITHDRAWN:
            crl_reason = "privilege withdrawn";
            break;

          case GNUTLS_X509_CRLREASON_AACOMPROMISE:
            crl_reason = "AA compromised";
            break;
        }

        failf(data, "Server certificate was revoked: %s", crl_reason);
        break;
      }

      default:
      case GNUTLS_OCSP_CERT_UNKNOWN:
        failf(data, "Server certificate status is unknown");
        break;
      }

      gnutls_ocsp_resp_deinit(ocsp_resp);

      return CURLE_SSL_INVALIDCERTSTATUS;
    }
    else
      infof(data, "  server certificate status verification OK");
  }
  else
    infof(data, "  server certificate status verification SKIPPED");

  /* initialize an X.509 certificate structure. */
  gnutls_x509_crt_init(&x509_cert);

  if(chainp)
    /* convert the given DER or PEM encoded Certificate to the native
       gnutls_x509_crt_t format */
    gnutls_x509_crt_import(x509_cert, chainp, GNUTLS_X509_FMT_DER);

  if(config->issuercert) {
    gnutls_x509_crt_init(&x509_issuer);
    issuerp = load_file(config->issuercert);
    gnutls_x509_crt_import(x509_issuer, &issuerp, GNUTLS_X509_FMT_PEM);
    rc = (int)gnutls_x509_crt_check_issuer(x509_cert, x509_issuer);
    gnutls_x509_crt_deinit(x509_issuer);
    unload_file(issuerp);
    if(rc <= 0) {
      failf(data, "server certificate issuer check failed (IssuerCert: %s)",
            config->issuercert?config->issuercert:"none");
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_SSL_ISSUER_ERROR;
    }
    infof(data, "  server certificate issuer check OK (Issuer Cert: %s)",
          config->issuercert?config->issuercert:"none");
  }

  size = sizeof(certname);
  rc = gnutls_x509_crt_get_dn_by_oid(x509_cert, GNUTLS_OID_X520_COMMON_NAME,
                                     0, /* the first and only one */
                                     FALSE,
                                     certname,
                                     &size);
  if(rc) {
    infof(data, "error fetching CN from cert:%s",
          gnutls_strerror(rc));
  }

  /* This function will check if the given certificate's subject matches the
     given hostname. This is a basic implementation of the matching described
     in RFC2818 (HTTPS), which takes into account wildcards, and the subject
     alternative name PKIX extension. Returns non zero on success, and zero on
     failure. */

  /* This function does not handle trailing dots, so if we have an SNI name
     use that and fallback to the hostname only if there is no SNI (like for
     IP addresses) */
  rc = (int)gnutls_x509_crt_check_hostname(x509_cert,
                                           peer->sni ? peer->sni :
                                           peer->hostname);
#if GNUTLS_VERSION_NUMBER < 0x030306
  /* Before 3.3.6, gnutls_x509_crt_check_hostname() did not check IP
     addresses. */
  if(!rc) {
#ifdef USE_IPV6
    #define use_addr in6_addr
#else
    #define use_addr in_addr
#endif
    unsigned char addrbuf[sizeof(struct use_addr)];
    size_t addrlen = 0;

    if(Curl_inet_pton(AF_INET, peer->hostname, addrbuf) > 0)
      addrlen = 4;
#ifdef USE_IPV6
    else if(Curl_inet_pton(AF_INET6, peer->hostname, addrbuf) > 0)
      addrlen = 16;
#endif

    if(addrlen) {
      unsigned char certaddr[sizeof(struct use_addr)];
      int i;

      for(i = 0; ; i++) {
        size_t certaddrlen = sizeof(certaddr);
        int ret = gnutls_x509_crt_get_subject_alt_name(x509_cert, i, certaddr,
                                                       &certaddrlen, NULL);
        /* If this happens, it was not an IP address. */
        if(ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
          continue;
        if(ret < 0)
          break;
        if(ret != GNUTLS_SAN_IPADDRESS)
          continue;
        if(certaddrlen == addrlen && !memcmp(addrbuf, certaddr, addrlen)) {
          rc = 1;
          break;
        }
      }
    }
  }
#endif
  if(!rc) {
    if(config->verifyhost) {
      failf(data, "SSL: certificate subject name (%s) does not match "
            "target hostname '%s'", certname, peer->dispname);
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_PEER_FAILED_VERIFICATION;
    }
    else
      infof(data, "  common name: %s (does not match '%s')",
            certname, peer->dispname);
  }
  else
    infof(data, "  common name: %s (matched)", certname);

  /* Check for time-based validity */
  certclock = gnutls_x509_crt_get_expiration_time(x509_cert);

  if(certclock == (time_t)-1) {
    if(config->verifypeer) {
      failf(data, "server cert expiration date verify failed");
      *certverifyresult = GNUTLS_CERT_EXPIRED;
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_SSL_CONNECT_ERROR;
    }
    else
      infof(data, "  server certificate expiration date verify FAILED");
  }
  else {
    if(certclock < time(NULL)) {
      if(config->verifypeer) {
        failf(data, "server certificate expiration date has passed.");
        *certverifyresult = GNUTLS_CERT_EXPIRED;
        gnutls_x509_crt_deinit(x509_cert);
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else
        infof(data, "  server certificate expiration date FAILED");
    }
    else
      infof(data, "  server certificate expiration date OK");
  }

  certclock = gnutls_x509_crt_get_activation_time(x509_cert);

  if(certclock == (time_t)-1) {
    if(config->verifypeer) {
      failf(data, "server cert activation date verify failed");
      *certverifyresult = GNUTLS_CERT_NOT_ACTIVATED;
      gnutls_x509_crt_deinit(x509_cert);
      return CURLE_SSL_CONNECT_ERROR;
    }
    else
      infof(data, "  server certificate activation date verify FAILED");
  }
  else {
    if(certclock > time(NULL)) {
      if(config->verifypeer) {
        failf(data, "server certificate not activated yet.");
        *certverifyresult = GNUTLS_CERT_NOT_ACTIVATED;
        gnutls_x509_crt_deinit(x509_cert);
        return CURLE_PEER_FAILED_VERIFICATION;
      }
      else
        infof(data, "  server certificate activation date FAILED");
    }
    else
      infof(data, "  server certificate activation date OK");
  }

  if(pinned_key) {
    result = pkp_pin_peer_pubkey(data, x509_cert, pinned_key);
    if(result != CURLE_OK) {
      failf(data, "SSL: public key does not match pinned public key");
      gnutls_x509_crt_deinit(x509_cert);
      return result;
    }
  }

  /* Show:

  - subject
  - start date
  - expire date
  - common name
  - issuer

  */

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  /* public key algorithm's parameters */
  algo = gnutls_x509_crt_get_pk_algorithm(x509_cert, &bits);
  infof(data, "  certificate public key: %s",
        gnutls_pk_algorithm_get_name((gnutls_pk_algorithm_t)algo));

  /* version of the X.509 certificate. */
  infof(data, "  certificate version: #%d",
        gnutls_x509_crt_get_version(x509_cert));


  rc = gnutls_x509_crt_get_dn2(x509_cert, &certfields);
  if(rc)
    infof(data, "Failed to get certificate name");
  else {
    infof(data, "  subject: %s", certfields.data);

    certclock = gnutls_x509_crt_get_activation_time(x509_cert);
    showtime(data, "start date", certclock);

    certclock = gnutls_x509_crt_get_expiration_time(x509_cert);
    showtime(data, "expire date", certclock);

    gnutls_free(certfields.data);
  }

  rc = gnutls_x509_crt_get_issuer_dn2(x509_cert, &certfields);
  if(rc)
    infof(data, "Failed to get certificate issuer");
  else {
    infof(data, "  issuer: %s", certfields.data);

    gnutls_free(certfields.data);
  }
#endif

  gnutls_x509_crt_deinit(x509_cert);

  return result;
}

static CURLcode gtls_verifyserver(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  gnutls_session_t session)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct ssl_primary_config *conn_config = Curl_ssl_cf_get_primary_config(cf);
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
#ifndef CURL_DISABLE_PROXY
  const char *pinned_key = Curl_ssl_cf_is_proxy(cf)?
    data->set.str[STRING_SSL_PINNEDPUBLICKEY_PROXY]:
    data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#else
  const char *pinned_key = data->set.str[STRING_SSL_PINNEDPUBLICKEY];
#endif
  CURLcode result;

  result = Curl_gtls_verifyserver(data, session, conn_config, ssl_config,
                                  &connssl->peer, pinned_key);
  if(result)
    goto out;

  if(connssl->alpn) {
    gnutls_datum_t proto;
    int rc;

    rc = gnutls_alpn_get_selected_protocol(session, &proto);
    if(rc == 0)
      Curl_alpn_set_negotiated(cf, data, proto.data, proto.size);
    else
      Curl_alpn_set_negotiated(cf, data, NULL, 0);
  }

  /* Only on TLSv1.2 or lower do we have the session id now. For
   * TLSv1.3 we get it via a SESSION_TICKET message that arrives later. */
  if(gnutls_protocol_get_version(session) < GNUTLS_TLS1_3)
    result = gtls_update_session_id(cf, data, session);

out:
  return result;
}

/*
 * This function is called after the TCP connect has completed. Setup the TLS
 * layer and do all necessary magic.
 */
/* We use connssl->connecting_state to keep track of the connection status;
   there are three states: 'ssl_connect_1' (not started yet or complete),
   'ssl_connect_2' (doing handshake with the server), and
   'ssl_connect_3' (verifying and getting stats).
 */
static CURLcode
gtls_connect_common(struct Curl_cfilter *cf,
                    struct Curl_easy *data,
                    bool nonblocking,
                    bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  CURLcode rc;
  CURLcode result = CURLE_OK;

  /* Initiate the connection, if not already done */
  if(ssl_connect_1 == connssl->connecting_state) {
    rc = gtls_connect_step1(cf, data);
    if(rc) {
      result = rc;
      goto out;
    }
  }

  rc = handshake(cf, data, TRUE, nonblocking);
  if(rc) {
    /* handshake() sets its own error message with failf() */
    result = rc;
    goto out;
  }

  /* Finish connecting once the handshake is done */
  if(ssl_connect_1 == connssl->connecting_state) {
    struct gtls_ssl_backend_data *backend =
      (struct gtls_ssl_backend_data *)connssl->backend;
    gnutls_session_t session;
    DEBUGASSERT(backend);
    session = backend->gtls.session;
    rc = gtls_verifyserver(cf, data, session);
    if(rc) {
      result = rc;
      goto out;
    }
    connssl->state = ssl_connection_complete;
  }

out:
  *done = ssl_connect_1 == connssl->connecting_state;

  return result;
}

static CURLcode gtls_connect_nonblocking(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         bool *done)
{
  return gtls_connect_common(cf, data, TRUE, done);
}

static CURLcode gtls_connect(struct Curl_cfilter *cf,
                             struct Curl_easy *data)
{
  CURLcode result;
  bool done = FALSE;

  result = gtls_connect_common(cf, data, FALSE, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static bool gtls_data_pending(struct Curl_cfilter *cf,
                              const struct Curl_easy *data)
{
  struct ssl_connect_data *ctx = cf->ctx;
  struct gtls_ssl_backend_data *backend;

  (void)data;
  DEBUGASSERT(ctx && ctx->backend);
  backend = (struct gtls_ssl_backend_data *)ctx->backend;
  if(backend->gtls.session &&
     0 != gnutls_record_check_pending(backend->gtls.session))
    return TRUE;
  return FALSE;
}

static ssize_t gtls_send(struct Curl_cfilter *cf,
                         struct Curl_easy *data,
                         const void *mem,
                         size_t len,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;
  ssize_t rc;

  (void)data;
  DEBUGASSERT(backend);
  backend->gtls.io_result = CURLE_OK;
  rc = gnutls_record_send(backend->gtls.session, mem, len);

  if(rc < 0) {
    *curlcode = (rc == GNUTLS_E_AGAIN)?
      CURLE_AGAIN :
      (backend->gtls.io_result? backend->gtls.io_result : CURLE_SEND_ERROR);

    rc = -1;
  }

  return rc;
}

/*
 * This function is called to shut down the SSL layer but keep the
 * socket open (CCC - Clear Command Channel)
 */
static CURLcode gtls_shutdown(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool send_shutdown, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;
  char buf[1024];
  CURLcode result = CURLE_OK;
  ssize_t nread;
  size_t i;

  DEBUGASSERT(backend);
  if(!backend->gtls.session || cf->shutdown) {
    *done = TRUE;
    goto out;
  }

  connssl->io_need = CURL_SSL_IO_NEED_NONE;
  *done = FALSE;

  if(!backend->gtls.sent_shutdown) {
    /* do this only once */
    backend->gtls.sent_shutdown = TRUE;
    if(send_shutdown) {
      int ret = gnutls_bye(backend->gtls.session, GNUTLS_SHUT_RDWR);
      if((ret == GNUTLS_E_AGAIN) || (ret == GNUTLS_E_INTERRUPTED)) {
        CURL_TRC_CF(data, cf, "SSL shutdown, gnutls_bye EAGAIN");
        connssl->io_need = gnutls_record_get_direction(backend->gtls.session)?
          CURL_SSL_IO_NEED_SEND : CURL_SSL_IO_NEED_RECV;
        result = CURLE_OK;
        goto out;
      }
      if(ret != GNUTLS_E_SUCCESS) {
        CURL_TRC_CF(data, cf, "SSL shutdown, gnutls_bye error: '%s'(%d)",
                    gnutls_strerror((int)ret), (int)ret);
        result = CURLE_RECV_ERROR;
        goto out;
      }
    }
  }

  /* SSL should now have started the shutdown from our side. Since it
   * was not complete, we are lacking the close notify from the server. */
  for(i = 0; i < 10; ++i) {
    nread = gnutls_record_recv(backend->gtls.session, buf, sizeof(buf));
    if(nread <= 0)
      break;
  }
  if(nread > 0) {
    /* still data coming in? */
  }
  else if(nread == 0) {
    /* We got the close notify alert and are done. */
    *done = TRUE;
  }
  else if((nread == GNUTLS_E_AGAIN) || (nread == GNUTLS_E_INTERRUPTED)) {
    connssl->io_need = gnutls_record_get_direction(backend->gtls.session)?
      CURL_SSL_IO_NEED_SEND : CURL_SSL_IO_NEED_RECV;
  }
  else {
    CURL_TRC_CF(data, cf, "SSL shutdown, error: '%s'(%d)",
                gnutls_strerror((int)nread), (int)nread);
    result = CURLE_RECV_ERROR;
  }

out:
  cf->shutdown = (result || *done);
  return result;
}

static void gtls_close(struct Curl_cfilter *cf,
                       struct Curl_easy *data)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;

  (void) data;
  DEBUGASSERT(backend);
  CURL_TRC_CF(data, cf, "close");
  if(backend->gtls.session) {
    gnutls_deinit(backend->gtls.session);
    backend->gtls.session = NULL;
  }
  if(backend->gtls.shared_creds) {
    Curl_gtls_shared_creds_free(&backend->gtls.shared_creds);
  }
#ifdef USE_GNUTLS_SRP
  if(backend->gtls.srp_client_cred) {
    gnutls_srp_free_client_credentials(backend->gtls.srp_client_cred);
    backend->gtls.srp_client_cred = NULL;
  }
#endif
}

static ssize_t gtls_recv(struct Curl_cfilter *cf,
                         struct Curl_easy *data,
                         char *buf,
                         size_t buffersize,
                         CURLcode *curlcode)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;
  ssize_t ret;

  (void)data;
  DEBUGASSERT(backend);

  backend->gtls.io_result = CURLE_OK;
  ret = gnutls_record_recv(backend->gtls.session, buf, buffersize);
  if((ret == GNUTLS_E_AGAIN) || (ret == GNUTLS_E_INTERRUPTED)) {
    *curlcode = CURLE_AGAIN;
    ret = -1;
    goto out;
  }

  if(ret == GNUTLS_E_REHANDSHAKE) {
    /* BLOCKING call, this is bad but a work-around for now. Fixing this "the
       proper way" takes a whole lot of work. */
    CURLcode result = handshake(cf, data, FALSE, FALSE);
    if(result)
      /* handshake() writes error message on its own */
      *curlcode = result;
    else
      *curlcode = CURLE_AGAIN; /* then return as if this was a wouldblock */
    ret = -1;
    goto out;
  }

  if(ret < 0) {
    failf(data, "GnuTLS recv error (%d): %s",

          (int)ret, gnutls_strerror((int)ret));
    *curlcode = backend->gtls.io_result?
                backend->gtls.io_result : CURLE_RECV_ERROR;
    ret = -1;
    goto out;
  }

out:
  return ret;
}

static size_t gtls_version(char *buffer, size_t size)
{
  return msnprintf(buffer, size, "GnuTLS/%s", gnutls_check_version(NULL));
}

/* data might be NULL! */
static CURLcode gtls_random(struct Curl_easy *data,
                            unsigned char *entropy, size_t length)
{
  int rc;
  (void)data;
  rc = gnutls_rnd(GNUTLS_RND_RANDOM, entropy, length);
  return rc?CURLE_FAILED_INIT:CURLE_OK;
}

static CURLcode gtls_sha256sum(const unsigned char *tmp, /* input */
                               size_t tmplen,
                               unsigned char *sha256sum, /* output */
                               size_t sha256len)
{
  struct sha256_ctx SHA256pw;
  sha256_init(&SHA256pw);
  sha256_update(&SHA256pw, (unsigned int)tmplen, tmp);
  sha256_digest(&SHA256pw, (unsigned int)sha256len, sha256sum);
  return CURLE_OK;
}

static bool gtls_cert_status_request(void)
{
  return TRUE;
}

static void *gtls_get_internals(struct ssl_connect_data *connssl,
                                CURLINFO info UNUSED_PARAM)
{
  struct gtls_ssl_backend_data *backend =
    (struct gtls_ssl_backend_data *)connssl->backend;
  (void)info;
  DEBUGASSERT(backend);
  return backend->gtls.session;
}

const struct Curl_ssl Curl_ssl_gnutls = {
  { CURLSSLBACKEND_GNUTLS, "gnutls" }, /* info */

  SSLSUPP_CA_PATH  |
  SSLSUPP_CERTINFO |
  SSLSUPP_PINNEDPUBKEY |
  SSLSUPP_HTTPS_PROXY |
  SSLSUPP_CA_CACHE,

  sizeof(struct gtls_ssl_backend_data),

  gtls_init,                     /* init */
  gtls_cleanup,                  /* cleanup */
  gtls_version,                  /* version */
  Curl_none_check_cxn,           /* check_cxn */
  gtls_shutdown,                 /* shutdown */
  gtls_data_pending,             /* data_pending */
  gtls_random,                   /* random */
  gtls_cert_status_request,      /* cert_status_request */
  gtls_connect,                  /* connect */
  gtls_connect_nonblocking,      /* connect_nonblocking */
  Curl_ssl_adjust_pollset,       /* adjust_pollset */
  gtls_get_internals,            /* get_internals */
  gtls_close,                    /* close_one */
  Curl_none_close_all,           /* close_all */
  Curl_none_set_engine,          /* set_engine */
  Curl_none_set_engine_default,  /* set_engine_default */
  Curl_none_engines_list,        /* engines_list */
  Curl_none_false_start,         /* false_start */
  gtls_sha256sum,                /* sha256sum */
  NULL,                          /* associate_connection */
  NULL,                          /* disassociate_connection */
  gtls_recv,                     /* recv decrypted data */
  gtls_send,                     /* send data to encrypt */
};

#endif /* USE_GNUTLS */
