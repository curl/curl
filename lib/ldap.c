/***************************************************************************
 *                      _   _ ____  _
 *  Project         ___| | | |  _ \| |
 *                 / __| | | | |_) | |
 *                | (__| |_| |  _ <| |___
 *                 \___|\___/|_| \_\_____|
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

#include "curl_setup.h"

#if !defined(CURL_DISABLE_LDAP) && !defined(USE_OPENLDAP)

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/*
 * Notice that USE_OPENLDAP is only a source code selection switch. When
 * libcurl is built with USE_OPENLDAP defined the libcurl source code that
 * gets compiled is the code from openldap.c, otherwise the code that gets
 * compiled is the code from ldap.c.
 *
 * When USE_OPENLDAP is defined a recent version of the OpenLDAP library
 * might be required for compilation and runtime. In order to use ancient
 * OpenLDAP library versions, USE_OPENLDAP shall not be defined.
 */

/* Wincrypt must be included before anything that could include OpenSSL. */
#if defined(USE_WIN32_CRYPTO)
#include <wincrypt.h>
/* Undefine wincrypt conflicting symbols for BoringSSL. */
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#endif

#ifdef USE_WIN32_LDAP           /* Use Windows LDAP implementation. */
# ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable:4201)
# endif
# include <subauth.h>  /* for [P]UNICODE_STRING */
# ifdef _MSC_VER
#  pragma warning(pop)
# endif
# include <winldap.h>
# ifndef LDAP_VENDOR_NAME
#  error Your Platform SDK is NOT sufficient for LDAP support! \
         Update your Platform SDK, or disable LDAP support!
# else
#  include <winber.h>
# endif
#else
# define LDAP_DEPRECATED 1      /* Be sure ldap_init() is defined. */
# ifdef HAVE_LBER_H
#  include <lber.h>
# endif
# include <ldap.h>
# if (defined(HAVE_LDAP_SSL) && defined(HAVE_LDAP_SSL_H))
#  include <ldap_ssl.h>
# endif /* HAVE_LDAP_SSL && HAVE_LDAP_SSL_H */
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "cfilters.h"
#include "sendf.h"
#include "escape.h"
#include "progress.h"
#include "transfer.h"
#include "strcase.h"
#include "strparse.h"
#include "curl_ldap.h"
#include "curl_multibyte.h"
#include "curl_base64.h"
#include "connect.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#ifndef HAVE_LDAP_URL_PARSE

/* Use our own implementation. */

struct ldap_urldesc {
  char   *lud_host;
  int     lud_port;
#if defined(USE_WIN32_LDAP)
  TCHAR  *lud_dn;
  TCHAR **lud_attrs;
#else
  char   *lud_dn;
  char  **lud_attrs;
#endif
  int     lud_scope;
#if defined(USE_WIN32_LDAP)
  TCHAR  *lud_filter;
#else
  char   *lud_filter;
#endif
  char  **lud_exts;
  size_t    lud_attrs_dups; /* how many were dup'ed, this field is not in the
                               "real" struct so can only be used in code
                               without HAVE_LDAP_URL_PARSE defined */
};

#undef LDAPURLDesc
#define LDAPURLDesc struct ldap_urldesc

static int  _ldap_url_parse(struct Curl_easy *data,
                            const struct connectdata *conn,
                            LDAPURLDesc **ludp);
static void _ldap_free_urldesc(LDAPURLDesc *ludp);

#undef ldap_free_urldesc
#define ldap_free_urldesc       _ldap_free_urldesc
#endif

#ifdef DEBUG_LDAP
  #define LDAP_TRACE(x)   do { \
                            _ldap_trace("%u: ", __LINE__); \
                            _ldap_trace x; \
                          } while(0)

  static void _ldap_trace(const char *fmt, ...) CURL_PRINTF(1, 2);
#else
  #define LDAP_TRACE(x)   Curl_nop_stmt
#endif

#if defined(USE_WIN32_LDAP) && defined(ldap_err2string)
/* Use ANSI error strings in Unicode builds */
#undef ldap_err2string
#define ldap_err2string ldap_err2stringA
#endif

#if defined(USE_WIN32_LDAP) && defined(_MSC_VER) && (_MSC_VER <= 1700)
/* Workaround for warning:
   'type cast' : conversion from 'int' to 'void *' of greater size */
#undef LDAP_OPT_ON
#undef LDAP_OPT_OFF
#define LDAP_OPT_ON   ((void *)(size_t)1)
#define LDAP_OPT_OFF  ((void *)(size_t)0)
#endif

static CURLcode ldap_do(struct Curl_easy *data, bool *done);

/*
 * LDAP protocol handler.
 */

const struct Curl_handler Curl_handler_ldap = {
  "ldap",                               /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ldap_do,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  ZERO_NULL,                            /* follow */
  PORT_LDAP,                            /* defport */
  CURLPROTO_LDAP,                       /* protocol */
  CURLPROTO_LDAP,                       /* family */
  PROTOPT_NONE                          /* flags */
};

#ifdef HAVE_LDAP_SSL
/*
 * LDAPS protocol handler.
 */

const struct Curl_handler Curl_handler_ldaps = {
  "ldaps",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  ldap_do,                              /* do_it */
  ZERO_NULL,                            /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_getsock */
  ZERO_NULL,                            /* doing_getsock */
  ZERO_NULL,                            /* domore_getsock */
  ZERO_NULL,                            /* perform_getsock */
  ZERO_NULL,                            /* disconnect */
  ZERO_NULL,                            /* write_resp */
  ZERO_NULL,                            /* write_resp_hd */
  ZERO_NULL,                            /* connection_check */
  ZERO_NULL,                            /* attach connection */
  ZERO_NULL,                            /* follow */
  PORT_LDAPS,                           /* defport */
  CURLPROTO_LDAPS,                      /* protocol */
  CURLPROTO_LDAP,                       /* family */
  PROTOPT_SSL                           /* flags */
};
#endif

#if defined(USE_WIN32_LDAP)

#if defined(USE_WINDOWS_SSPI)
static int ldap_win_bind_auth(LDAP *server, const char *user,
                              const char *passwd, unsigned long authflags)
{
  ULONG method = 0;
  SEC_WINNT_AUTH_IDENTITY cred;
  int rc = LDAP_AUTH_METHOD_NOT_SUPPORTED;

  memset(&cred, 0, sizeof(cred));

#if defined(USE_SPNEGO)
  if(authflags & CURLAUTH_NEGOTIATE) {
    method = LDAP_AUTH_NEGOTIATE;
  }
  else
#endif
#if defined(USE_NTLM)
  if(authflags & CURLAUTH_NTLM) {
    method = LDAP_AUTH_NTLM;
  }
  else
#endif
#if !defined(CURL_DISABLE_DIGEST_AUTH)
  if(authflags & CURLAUTH_DIGEST) {
    method = LDAP_AUTH_DIGEST;
  }
  else
#endif
  {
    /* required anyway if one of upper preprocessor definitions enabled */
  }

  if(method && user && passwd) {
    CURLcode res = Curl_create_sspi_identity(user, passwd, &cred);
    rc = (int)res;
    if(!rc) {
      rc = (int)ldap_bind_s(server, NULL, (TCHAR *)&cred, method);
      Curl_sspi_free_identity(&cred);
    }
  }
  else {
    /* proceed with current user credentials */
    method = LDAP_AUTH_NEGOTIATE;
    rc = (int)ldap_bind_s(server, NULL, NULL, method);
  }
  return rc;
}
#endif /* #if defined(USE_WINDOWS_SSPI) */

static int ldap_win_bind(struct Curl_easy *data, LDAP *server,
                         const char *user, const char *passwd)
{
  int rc = LDAP_INVALID_CREDENTIALS;

  PTCHAR inuser = NULL;
  PTCHAR inpass = NULL;

  if(user && passwd && (data->set.httpauth & CURLAUTH_BASIC)) {
    inuser = curlx_convert_UTF8_to_tchar(user);
    inpass = curlx_convert_UTF8_to_tchar(passwd);

    rc = (int)ldap_simple_bind_s(server, inuser, inpass);

    curlx_unicodefree(inuser);
    curlx_unicodefree(inpass);
  }
#if defined(USE_WINDOWS_SSPI)
  else {
    rc = (int)ldap_win_bind_auth(server, user, passwd, data->set.httpauth);
  }
#endif

  return rc;
}
#endif /* #if defined(USE_WIN32_LDAP) */

#if defined(USE_WIN32_LDAP)
#define FREE_ON_WINLDAP(x) curlx_unicodefree(x)
#define curl_ldap_num_t ULONG
#else
#define FREE_ON_WINLDAP(x)
#define curl_ldap_num_t int
#endif


static CURLcode ldap_do(struct Curl_easy *data, bool *done)
{
  CURLcode result = CURLE_OK;
  int rc = 0;
  LDAP *server = NULL;
  LDAPURLDesc *ludp = NULL;
  LDAPMessage *ldapmsg = NULL;
  LDAPMessage *entryIterator;
  int num = 0;
  struct connectdata *conn = data->conn;
  int ldap_proto = LDAP_VERSION3;
  int ldap_ssl = 0;
  char *val_b64 = NULL;
  size_t val_b64_sz = 0;
#ifdef LDAP_OPT_NETWORK_TIMEOUT
  struct timeval ldap_timeout = {10, 0}; /* 10 sec connection/search timeout */
#endif
#if defined(USE_WIN32_LDAP)
  TCHAR *host = NULL;
#else
  char *host = NULL;
#endif
  char *user = NULL;
  char *passwd = NULL;

  *done = TRUE; /* unconditionally */
  infof(data, "LDAP local: LDAP Vendor = %s ; LDAP Version = %d",
        LDAP_VENDOR_NAME, LDAP_VENDOR_VERSION);
  infof(data, "LDAP local: %s", data->state.url);

#ifdef HAVE_LDAP_URL_PARSE
  rc = ldap_url_parse(data->state.url, &ludp);
#else
  rc = _ldap_url_parse(data, conn, &ludp);
#endif
  if(rc) {
    failf(data, "Bad LDAP URL: %s", ldap_err2string((curl_ldap_num_t)rc));
    result = CURLE_URL_MALFORMAT;
    goto quit;
  }

  /* Get the URL scheme (either ldap or ldaps) */
  if(Curl_conn_is_ssl(conn, FIRSTSOCKET))
    ldap_ssl = 1;
  infof(data, "LDAP local: trying to establish %s connection",
        ldap_ssl ? "encrypted" : "cleartext");

#if defined(USE_WIN32_LDAP)
  host = curlx_convert_UTF8_to_tchar(conn->host.name);
  if(!host) {
    result = CURLE_OUT_OF_MEMORY;

    goto quit;
  }
#else
  host = conn->host.name;
#endif

  if(data->state.aptr.user) {
    user = conn->user;
    passwd = conn->passwd;
  }

#ifdef LDAP_OPT_NETWORK_TIMEOUT
  ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, &ldap_timeout);
#endif
  ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &ldap_proto);

  if(ldap_ssl) {
#ifdef HAVE_LDAP_SSL
#ifdef USE_WIN32_LDAP
    /* Win32 LDAP SDK does not support insecure mode without CA! */
    server = ldap_sslinit(host, (curl_ldap_num_t)conn->primary.remote_port, 1);
    ldap_set_option(server, LDAP_OPT_SSL, LDAP_OPT_ON);
#else
    int ldap_option;
    char *ldap_ca = conn->ssl_config.CAfile;
#ifdef LDAP_OPT_X_TLS
    if(conn->ssl_config.verifypeer) {
      /* OpenLDAP SDK supports BASE64 files. */
      if((data->set.ssl.cert_type) &&
         (!strcasecompare(data->set.ssl.cert_type, "PEM"))) {
        failf(data, "LDAP local: ERROR OpenLDAP only supports PEM cert-type");
        result = CURLE_SSL_CERTPROBLEM;
        goto quit;
      }
      if(!ldap_ca) {
        failf(data, "LDAP local: ERROR PEM CA cert not set");
        result = CURLE_SSL_CERTPROBLEM;
        goto quit;
      }
      infof(data, "LDAP local: using PEM CA cert: %s", ldap_ca);
      rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, ldap_ca);
      if(rc != LDAP_SUCCESS) {
        failf(data, "LDAP local: ERROR setting PEM CA cert: %s",
                ldap_err2string(rc));
        result = CURLE_SSL_CERTPROBLEM;
        goto quit;
      }
      ldap_option = LDAP_OPT_X_TLS_DEMAND;
    }
    else
      ldap_option = LDAP_OPT_X_TLS_NEVER;

    rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &ldap_option);
    if(rc != LDAP_SUCCESS) {
      failf(data, "LDAP local: ERROR setting cert verify mode: %s",
              ldap_err2string(rc));
      result = CURLE_SSL_CERTPROBLEM;
      goto quit;
    }
    server = ldap_init(host, conn->primary.remote_port);
    if(!server) {
      failf(data, "LDAP local: Cannot connect to %s:%u",
            conn->host.dispname, conn->primary.remote_port);
      result = CURLE_COULDNT_CONNECT;
      goto quit;
    }
    ldap_option = LDAP_OPT_X_TLS_HARD;
    rc = ldap_set_option(server, LDAP_OPT_X_TLS, &ldap_option);
    if(rc != LDAP_SUCCESS) {
      failf(data, "LDAP local: ERROR setting SSL/TLS mode: %s",
              ldap_err2string(rc));
      result = CURLE_SSL_CERTPROBLEM;
      goto quit;
    }
/*
    rc = ldap_start_tls_s(server, NULL, NULL);
    if(rc != LDAP_SUCCESS) {
      failf(data, "LDAP local: ERROR starting SSL/TLS mode: %s",
              ldap_err2string(rc));
      result = CURLE_SSL_CERTPROBLEM;
      goto quit;
    }
*/
#else
    (void)ldap_option;
    (void)ldap_ca;
    /* we should probably never come up to here since configure
       should check in first place if we can support LDAP SSL/TLS */
    failf(data, "LDAP local: SSL/TLS not supported with this version "
            "of the OpenLDAP toolkit\n");
    result = CURLE_SSL_CERTPROBLEM;
    goto quit;
#endif
#endif
#endif /* CURL_LDAP_USE_SSL */
  }
  else if(data->set.use_ssl > CURLUSESSL_TRY) {
    failf(data, "LDAP local: explicit TLS not supported");
    result = CURLE_NOT_BUILT_IN;
    goto quit;
  }
  else {
    server = ldap_init(host, (curl_ldap_num_t)conn->primary.remote_port);
    if(!server) {
      failf(data, "LDAP local: Cannot connect to %s:%u",
            conn->host.dispname, conn->primary.remote_port);
      result = CURLE_COULDNT_CONNECT;
      goto quit;
    }
  }
#ifdef USE_WIN32_LDAP
  ldap_set_option(server, LDAP_OPT_PROTOCOL_VERSION, &ldap_proto);
  rc = ldap_win_bind(data, server, user, passwd);
#else
  rc = ldap_simple_bind_s(server, user, passwd);
#endif
  if(!ldap_ssl && rc) {
    ldap_proto = LDAP_VERSION2;
    ldap_set_option(server, LDAP_OPT_PROTOCOL_VERSION, &ldap_proto);
#ifdef USE_WIN32_LDAP
    rc = ldap_win_bind(data, server, user, passwd);
#else
    rc = ldap_simple_bind_s(server, user, passwd);
#endif
  }
  if(rc) {
#ifdef USE_WIN32_LDAP
    failf(data, "LDAP local: bind via ldap_win_bind %s",
          ldap_err2string((ULONG)rc));
#else
    failf(data, "LDAP local: bind via ldap_simple_bind_s %s",
          ldap_err2string(rc));
#endif
    result = CURLE_LDAP_CANNOT_BIND;
    goto quit;
  }

  Curl_pgrsSetDownloadCounter(data, 0);
  rc = (int)ldap_search_s(server, ludp->lud_dn,
                          (curl_ldap_num_t)ludp->lud_scope,
                          ludp->lud_filter, ludp->lud_attrs, 0, &ldapmsg);

  if(rc && rc != LDAP_SIZELIMIT_EXCEEDED) {
    failf(data, "LDAP remote: %s", ldap_err2string((curl_ldap_num_t)rc));
    result = CURLE_LDAP_SEARCH_FAILED;
    goto quit;
  }

  num = 0;
  for(entryIterator = ldap_first_entry(server, ldapmsg);
      entryIterator;
      entryIterator = ldap_next_entry(server, entryIterator), num++) {
    BerElement *ber = NULL;
#if defined(USE_WIN32_LDAP)
    TCHAR *attribute;
#else
    char *attribute;
#endif
    int i;

    /* Get the DN and write it to the client */
    {
      char *name;
      size_t name_len;
#if defined(USE_WIN32_LDAP)
      TCHAR *dn = ldap_get_dn(server, entryIterator);
      name = curlx_convert_tchar_to_UTF8(dn);
      if(!name) {
        ldap_memfree(dn);

        result = CURLE_OUT_OF_MEMORY;

        goto quit;
      }
#else
      char *dn = name = ldap_get_dn(server, entryIterator);
#endif
      name_len = strlen(name);

      result = Curl_client_write(data, CLIENTWRITE_BODY, "DN: ", 4);
      if(result) {
        FREE_ON_WINLDAP(name);
        ldap_memfree(dn);
        goto quit;
      }

      result = Curl_client_write(data, CLIENTWRITE_BODY, name, name_len);
      if(result) {
        FREE_ON_WINLDAP(name);
        ldap_memfree(dn);
        goto quit;
      }

      result = Curl_client_write(data, CLIENTWRITE_BODY, "\n", 1);
      if(result) {
        FREE_ON_WINLDAP(name);
        ldap_memfree(dn);

        goto quit;
      }

      FREE_ON_WINLDAP(name);
      ldap_memfree(dn);
    }

    /* Get the attributes and write them to the client */
    for(attribute = ldap_first_attribute(server, entryIterator, &ber);
        attribute;
        attribute = ldap_next_attribute(server, entryIterator, ber)) {
      BerValue **vals;
      size_t attr_len;
#if defined(USE_WIN32_LDAP)
      char *attr = curlx_convert_tchar_to_UTF8(attribute);
      if(!attr) {
        if(ber)
          ber_free(ber, 0);

        result = CURLE_OUT_OF_MEMORY;

        goto quit;
      }
#else
      char *attr = attribute;
#endif
      attr_len = strlen(attr);

      vals = ldap_get_values_len(server, entryIterator, attribute);
      if(vals) {
        for(i = 0; (vals[i] != NULL); i++) {
          result = Curl_client_write(data, CLIENTWRITE_BODY, "\t", 1);
          if(result) {
            ldap_value_free_len(vals);
            FREE_ON_WINLDAP(attr);
            ldap_memfree(attribute);
            if(ber)
              ber_free(ber, 0);

            goto quit;
          }

          result = Curl_client_write(data, CLIENTWRITE_BODY, attr, attr_len);
          if(result) {
            ldap_value_free_len(vals);
            FREE_ON_WINLDAP(attr);
            ldap_memfree(attribute);
            if(ber)
              ber_free(ber, 0);

            goto quit;
          }

          result = Curl_client_write(data, CLIENTWRITE_BODY, ": ", 2);
          if(result) {
            ldap_value_free_len(vals);
            FREE_ON_WINLDAP(attr);
            ldap_memfree(attribute);
            if(ber)
              ber_free(ber, 0);

            goto quit;
          }

          if((attr_len > 7) &&
             (strcmp(";binary", attr + (attr_len - 7)) == 0)) {
            /* Binary attribute, encode to base64. */
            result = Curl_base64_encode(vals[i]->bv_val, vals[i]->bv_len,
                                        &val_b64, &val_b64_sz);
            if(result) {
              ldap_value_free_len(vals);
              FREE_ON_WINLDAP(attr);
              ldap_memfree(attribute);
              if(ber)
                ber_free(ber, 0);

              goto quit;
            }

            if(val_b64_sz > 0) {
              result = Curl_client_write(data, CLIENTWRITE_BODY, val_b64,
                                         val_b64_sz);
              free(val_b64);
              if(result) {
                ldap_value_free_len(vals);
                FREE_ON_WINLDAP(attr);
                ldap_memfree(attribute);
                if(ber)
                  ber_free(ber, 0);

                goto quit;
              }
            }
          }
          else {
            result = Curl_client_write(data, CLIENTWRITE_BODY, vals[i]->bv_val,
                                       vals[i]->bv_len);
            if(result) {
              ldap_value_free_len(vals);
              FREE_ON_WINLDAP(attr);
              ldap_memfree(attribute);
              if(ber)
                ber_free(ber, 0);

              goto quit;
            }
          }

          result = Curl_client_write(data, CLIENTWRITE_BODY, "\n", 1);
          if(result) {
            ldap_value_free_len(vals);
            FREE_ON_WINLDAP(attr);
            ldap_memfree(attribute);
            if(ber)
              ber_free(ber, 0);

            goto quit;
          }
        }

        /* Free memory used to store values */
        ldap_value_free_len(vals);
      }

      /* Free the attribute as we are done with it */
      FREE_ON_WINLDAP(attr);
      ldap_memfree(attribute);

      result = Curl_client_write(data, CLIENTWRITE_BODY, "\n", 1);
      if(result)
        goto quit;
    }

    if(ber)
      ber_free(ber, 0);
  }

quit:
  if(ldapmsg) {
    ldap_msgfree(ldapmsg);
    LDAP_TRACE(("Received %d entries\n", num));
  }
  if(rc == LDAP_SIZELIMIT_EXCEEDED)
    infof(data, "There are more than %d entries", num);
  if(ludp)
    ldap_free_urldesc(ludp);
  if(server)
    ldap_unbind_s(server);

  FREE_ON_WINLDAP(host);

  /* no data to transfer */
  Curl_xfer_setup_nop(data);
  connclose(conn, "LDAP connection always disable reuse");

  return result;
}

#ifdef DEBUG_LDAP
static void _ldap_trace(const char *fmt, ...)
{
  static int do_trace = -1;
  va_list args;

  if(do_trace == -1) {
    const char *env = getenv("CURL_TRACE");
    curl_off_t e = 0;
    if(!Curl_str_number(&env, &e, INT_MAX))
      do_trace = e > 0;
  }
  if(!do_trace)
    return;

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}
#endif

#ifndef HAVE_LDAP_URL_PARSE

/*
 * Return scope-value for a scope-string.
 */
static int str2scope(const char *p)
{
  if(strcasecompare(p, "one"))
    return LDAP_SCOPE_ONELEVEL;
  if(strcasecompare(p, "onetree"))
    return LDAP_SCOPE_ONELEVEL;
  if(strcasecompare(p, "base"))
    return LDAP_SCOPE_BASE;
  if(strcasecompare(p, "sub"))
    return LDAP_SCOPE_SUBTREE;
  if(strcasecompare(p, "subtree"))
    return LDAP_SCOPE_SUBTREE;
  return -1;
}

/* number of entries in the attributes list */
static size_t num_entries(const char *s)
{
  size_t items = 1;

  s = strchr(s, ',');
  while(s) {
    items++;
    s = strchr(s + 1, ',');
  }
  return items;
}

/*
 * Break apart the pieces of an LDAP URL.
 * Syntax:
 *   ldap://<hostname>:<port>/<base_dn>?<attributes>?<scope>?<filter>?<ext>
 *
 * <hostname> already known from 'conn->host.name'.
 * <port>     already known from 'conn->remote_port'.
 * extract the rest from 'data->state.path+1'. All fields are optional.
 * e.g.
 *   ldap://<hostname>:<port>/?<attributes>?<scope>?<filter>
 * yields ludp->lud_dn = "".
 *
 * Defined in RFC4516 section 2.
 */
static int _ldap_url_parse2(struct Curl_easy *data,
                            const struct connectdata *conn, LDAPURLDesc *ludp)
{
  int rc = LDAP_SUCCESS;
  char *p;
  char *path;
  char *q = NULL;
  char *query = NULL;
  size_t i;

  if(!data ||
     !data->state.up.path ||
     data->state.up.path[0] != '/' ||
     !strncasecompare("LDAP", data->state.up.scheme, 4))
    return LDAP_INVALID_SYNTAX;

  ludp->lud_scope = LDAP_SCOPE_BASE;
  ludp->lud_port  = conn->remote_port;
  ludp->lud_host  = conn->host.name;

  /* Duplicate the path */
  p = path = strdup(data->state.up.path + 1);
  if(!path)
    return LDAP_NO_MEMORY;

  /* Duplicate the query if present */
  if(data->state.up.query) {
    q = query = strdup(data->state.up.query);
    if(!query) {
      free(path);
      return LDAP_NO_MEMORY;
    }
  }

  /* Parse the DN (Distinguished Name) */
  if(*p) {
    char *dn = p;
    char *unescaped;
    CURLcode result;

    LDAP_TRACE(("DN '%s'\n", dn));

    /* Unescape the DN */
    result = Curl_urldecode(dn, 0, &unescaped, NULL, REJECT_ZERO);
    if(result) {
      rc = LDAP_NO_MEMORY;

      goto quit;
    }

#if defined(USE_WIN32_LDAP)
    /* Convert the unescaped string to a tchar */
    ludp->lud_dn = curlx_convert_UTF8_to_tchar(unescaped);

    /* Free the unescaped string as we are done with it */
    free(unescaped);

    if(!ludp->lud_dn) {
      rc = LDAP_NO_MEMORY;

      goto quit;
    }
#else
    ludp->lud_dn = unescaped;
#endif
  }

  p = q;
  if(!p)
    goto quit;

  /* Parse the attributes. skip "??" */
  q = strchr(p, '?');
  if(q)
    *q++ = '\0';

  if(*p) {
    size_t count = num_entries(p); /* at least one */
    const char *atp = p;

    /* Allocate our array (+1 for the NULL entry) */
#if defined(USE_WIN32_LDAP)
    ludp->lud_attrs = calloc(count + 1, sizeof(TCHAR *));
#else
    ludp->lud_attrs = calloc(count + 1, sizeof(char *));
#endif
    if(!ludp->lud_attrs) {
      rc = LDAP_NO_MEMORY;
      goto quit;
    }

    for(i = 0; i < count; i++) {
      char *unescaped;
      CURLcode result;
      struct Curl_str out;

      if(Curl_str_until(&atp, &out, 1024, ','))
        break;

      LDAP_TRACE(("attr[%zu] '%.*s'\n", i, (int)out.len, out.str));

      /* Unescape the attribute */
      result = Curl_urldecode(out.str, out.len, &unescaped, NULL,
                              REJECT_ZERO);
      if(result) {
        rc = LDAP_NO_MEMORY;
        goto quit;
      }

#if defined(USE_WIN32_LDAP)
      /* Convert the unescaped string to a tchar */
      ludp->lud_attrs[i] = curlx_convert_UTF8_to_tchar(unescaped);

      /* Free the unescaped string as we are done with it */
      free(unescaped);

      if(!ludp->lud_attrs[i]) {
        rc = LDAP_NO_MEMORY;
        goto quit;
      }
#else
      ludp->lud_attrs[i] = unescaped;
#endif

      ludp->lud_attrs_dups++;
      if(Curl_str_single(&atp, ','))
        break;
    }
  }

  p = q;
  if(!p)
    goto quit;

  /* Parse the scope. skip "??" */
  q = strchr(p, '?');
  if(q)
    *q++ = '\0';

  if(*p) {
    ludp->lud_scope = str2scope(p);
    if(ludp->lud_scope == -1) {
      rc = LDAP_INVALID_SYNTAX;

      goto quit;
    }
    LDAP_TRACE(("scope %d\n", ludp->lud_scope));
  }

  p = q;
  if(!p)
    goto quit;

  /* Parse the filter */
  q = strchr(p, '?');
  if(q)
    *q++ = '\0';

  if(*p) {
    char *filter = p;
    char *unescaped;
    CURLcode result;

    LDAP_TRACE(("filter '%s'\n", filter));

    /* Unescape the filter */
    result = Curl_urldecode(filter, 0, &unescaped, NULL, REJECT_ZERO);
    if(result) {
      rc = LDAP_NO_MEMORY;

      goto quit;
    }

#if defined(USE_WIN32_LDAP)
    /* Convert the unescaped string to a tchar */
    ludp->lud_filter = curlx_convert_UTF8_to_tchar(unescaped);

    /* Free the unescaped string as we are done with it */
    free(unescaped);

    if(!ludp->lud_filter) {
      rc = LDAP_NO_MEMORY;

      goto quit;
    }
#else
    ludp->lud_filter = unescaped;
#endif
  }

  p = q;
  if(p && !*p) {
    rc = LDAP_INVALID_SYNTAX;

    goto quit;
  }

quit:
  free(path);
  free(query);

  return rc;
}

static int _ldap_url_parse(struct Curl_easy *data,
                           const struct connectdata *conn,
                           LDAPURLDesc **ludpp)
{
  LDAPURLDesc *ludp = calloc(1, sizeof(*ludp));
  int rc;

  *ludpp = NULL;
  if(!ludp)
    return LDAP_NO_MEMORY;

  rc = _ldap_url_parse2(data, conn, ludp);
  if(rc != LDAP_SUCCESS) {
    _ldap_free_urldesc(ludp);
    ludp = NULL;
  }
  *ludpp = ludp;
  return rc;
}

static void _ldap_free_urldesc(LDAPURLDesc *ludp)
{
  if(!ludp)
    return;

#if defined(USE_WIN32_LDAP)
  curlx_unicodefree(ludp->lud_dn);
  curlx_unicodefree(ludp->lud_filter);
#else
  free(ludp->lud_dn);
  free(ludp->lud_filter);
#endif

  if(ludp->lud_attrs) {
    size_t i;
    for(i = 0; i < ludp->lud_attrs_dups; i++) {
#if defined(USE_WIN32_LDAP)
      curlx_unicodefree(ludp->lud_attrs[i]);
#else
      free(ludp->lud_attrs[i]);
#endif
    }
    free(ludp->lud_attrs);
  }

  free(ludp);
}
#endif  /* !HAVE_LDAP_URL_PARSE */

#if defined(__GNUC__) && defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif  /* !CURL_DISABLE_LDAP && !USE_OPENLDAP */
