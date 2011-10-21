/***************************************************************************
 *                      _   _ ____  _
 *  Project         ___| | | |  _ \| |
 *                 / __| | | | |_) | |
 *                | (__| |_| |  _ <| |___
 *                 \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

#if !defined(CURL_DISABLE_LDAP) && !defined(USE_OPENLDAP)

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

#ifdef CURL_LDAP_WIN            /* Use Windows LDAP implementation. */
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

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "sendf.h"
#include "escape.h"
#include "progress.h"
#include "transfer.h"
#include "strequal.h"
#include "strtok.h"
#include "curl_ldap.h"
#include "curl_memory.h"
#include "curl_base64.h"
#include "rawstr.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "memdebug.h"

#ifndef HAVE_LDAP_URL_PARSE

/* Use our own implementation. */

typedef struct {
    char   *lud_host;
    int     lud_port;
    char   *lud_dn;
    char  **lud_attrs;
    int     lud_scope;
    char   *lud_filter;
    char  **lud_exts;
} CURL_LDAPURLDesc;

#undef LDAPURLDesc
#define LDAPURLDesc             CURL_LDAPURLDesc

static int  _ldap_url_parse (const struct connectdata *conn,
                             LDAPURLDesc **ludp);
static void _ldap_free_urldesc (LDAPURLDesc *ludp);

#undef ldap_free_urldesc
#define ldap_free_urldesc       _ldap_free_urldesc
#endif

#ifdef DEBUG_LDAP
  #define LDAP_TRACE(x)   do { \
                            _ldap_trace ("%u: ", __LINE__); \
                            _ldap_trace x; \
                          } WHILE_FALSE

  static void _ldap_trace (const char *fmt, ...);
#else
  #define LDAP_TRACE(x)   Curl_nop_stmt
#endif


static CURLcode Curl_ldap(struct connectdata *conn, bool *done);

/*
 * LDAP protocol handler.
 */

const struct Curl_handler Curl_handler_ldap = {
  "LDAP",                               /* scheme */
  ZERO_NULL,                            /* setup_connection */
  Curl_ldap,                            /* do_it */
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
  ZERO_NULL,                            /* readwrite */
  PORT_LDAP,                            /* defport */
  CURLPROTO_LDAP,                       /* protocol */
  PROTOPT_NONE                          /* flags */
};

#ifdef HAVE_LDAP_SSL
/*
 * LDAPS protocol handler.
 */

const struct Curl_handler Curl_handler_ldaps = {
  "LDAPS",                              /* scheme */
  ZERO_NULL,                            /* setup_connection */
  Curl_ldap,                            /* do_it */
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
  ZERO_NULL,                            /* readwrite */
  PORT_LDAPS,                           /* defport */
  CURLPROTO_LDAP | CURLPROTO_LDAPS,     /* protocol */
  PROTOPT_SSL                           /* flags */
};
#endif


static CURLcode Curl_ldap(struct connectdata *conn, bool *done)
{
  CURLcode status = CURLE_OK;
  int rc = 0;
  LDAP *server = NULL;
  LDAPURLDesc *ludp = NULL;
  LDAPMessage *result = NULL;
  LDAPMessage *entryIterator;
  int num = 0;
  struct SessionHandle *data=conn->data;
  int ldap_proto = LDAP_VERSION3;
  int ldap_ssl = 0;
  char *val_b64 = NULL;
  size_t val_b64_sz = 0;
  curl_off_t dlsize = 0;
#ifdef LDAP_OPT_NETWORK_TIMEOUT
  struct timeval ldap_timeout = {10,0}; /* 10 sec connection/search timeout */
#endif

  *done = TRUE; /* unconditionally */
  infof(data, "LDAP local: LDAP Vendor = %s ; LDAP Version = %d\n",
          LDAP_VENDOR_NAME, LDAP_VENDOR_VERSION);
  infof(data, "LDAP local: %s\n", data->change.url);

#ifdef HAVE_LDAP_URL_PARSE
  rc = ldap_url_parse(data->change.url, &ludp);
#else
  rc = _ldap_url_parse(conn, &ludp);
#endif
  if(rc != 0) {
    failf(data, "LDAP local: %s", ldap_err2string(rc));
    status = CURLE_LDAP_INVALID_URL;
    goto quit;
  }

  /* Get the URL scheme ( either ldap or ldaps ) */
  if(conn->given->flags & PROTOPT_SSL)
    ldap_ssl = 1;
  infof(data, "LDAP local: trying to establish %s connection\n",
          ldap_ssl ? "encrypted" : "cleartext");

#ifdef LDAP_OPT_NETWORK_TIMEOUT
  ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, &ldap_timeout);
#endif
  ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &ldap_proto);

  if(ldap_ssl) {
#ifdef HAVE_LDAP_SSL
#ifdef CURL_LDAP_WIN
    /* Win32 LDAP SDK doesn't support insecure mode without CA! */
    server = ldap_sslinit(conn->host.name, (int)conn->port, 1);
    ldap_set_option(server, LDAP_OPT_SSL, LDAP_OPT_ON);
#else
    int ldap_option;
    char* ldap_ca = data->set.str[STRING_SSL_CAFILE];
#if defined(CURL_HAS_NOVELL_LDAPSDK)
    rc = ldapssl_client_init(NULL, NULL);
    if(rc != LDAP_SUCCESS) {
      failf(data, "LDAP local: ldapssl_client_init %s", ldap_err2string(rc));
      status = CURLE_SSL_CERTPROBLEM;
      goto quit;
    }
    if(data->set.ssl.verifypeer) {
      /* Novell SDK supports DER or BASE64 files. */
      int cert_type = LDAPSSL_CERT_FILETYPE_B64;
      if((data->set.str[STRING_CERT_TYPE]) &&
         (Curl_raw_equal(data->set.str[STRING_CERT_TYPE], "DER")))
        cert_type = LDAPSSL_CERT_FILETYPE_DER;
      if(!ldap_ca) {
        failf(data, "LDAP local: ERROR %s CA cert not set!",
              (cert_type == LDAPSSL_CERT_FILETYPE_DER ? "DER" : "PEM"));
        status = CURLE_SSL_CERTPROBLEM;
        goto quit;
      }
      infof(data, "LDAP local: using %s CA cert '%s'\n",
              (cert_type == LDAPSSL_CERT_FILETYPE_DER ? "DER" : "PEM"),
              ldap_ca);
      rc = ldapssl_add_trusted_cert(ldap_ca, cert_type);
      if(rc != LDAP_SUCCESS) {
        failf(data, "LDAP local: ERROR setting %s CA cert: %s",
                (cert_type == LDAPSSL_CERT_FILETYPE_DER ? "DER" : "PEM"),
                ldap_err2string(rc));
        status = CURLE_SSL_CERTPROBLEM;
        goto quit;
      }
      ldap_option = LDAPSSL_VERIFY_SERVER;
    }
    else
      ldap_option = LDAPSSL_VERIFY_NONE;
    rc = ldapssl_set_verify_mode(ldap_option);
    if(rc != LDAP_SUCCESS) {
      failf(data, "LDAP local: ERROR setting cert verify mode: %s",
              ldap_err2string(rc));
      status = CURLE_SSL_CERTPROBLEM;
      goto quit;
    }
    server = ldapssl_init(conn->host.name, (int)conn->port, 1);
    if(server == NULL) {
      failf(data, "LDAP local: Cannot connect to %s:%hu",
              conn->host.name, conn->port);
      status = CURLE_COULDNT_CONNECT;
      goto quit;
    }
#elif defined(LDAP_OPT_X_TLS)
    if(data->set.ssl.verifypeer) {
      /* OpenLDAP SDK supports BASE64 files. */
      if((data->set.str[STRING_CERT_TYPE]) &&
         (!Curl_raw_equal(data->set.str[STRING_CERT_TYPE], "PEM"))) {
        failf(data, "LDAP local: ERROR OpenLDAP only supports PEM cert-type!");
        status = CURLE_SSL_CERTPROBLEM;
        goto quit;
      }
      if(!ldap_ca) {
        failf(data, "LDAP local: ERROR PEM CA cert not set!");
        status = CURLE_SSL_CERTPROBLEM;
        goto quit;
      }
      infof(data, "LDAP local: using PEM CA cert: %s\n", ldap_ca);
      rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, ldap_ca);
      if(rc != LDAP_SUCCESS) {
        failf(data, "LDAP local: ERROR setting PEM CA cert: %s",
                ldap_err2string(rc));
        status = CURLE_SSL_CERTPROBLEM;
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
      status = CURLE_SSL_CERTPROBLEM;
      goto quit;
    }
    server = ldap_init(conn->host.name, (int)conn->port);
    if(server == NULL) {
      failf(data, "LDAP local: Cannot connect to %s:%hu",
              conn->host.name, conn->port);
      status = CURLE_COULDNT_CONNECT;
      goto quit;
    }
    ldap_option = LDAP_OPT_X_TLS_HARD;
    rc = ldap_set_option(server, LDAP_OPT_X_TLS, &ldap_option);
    if(rc != LDAP_SUCCESS) {
      failf(data, "LDAP local: ERROR setting SSL/TLS mode: %s",
              ldap_err2string(rc));
      status = CURLE_SSL_CERTPROBLEM;
      goto quit;
    }
/*
    rc = ldap_start_tls_s(server, NULL, NULL);
    if(rc != LDAP_SUCCESS) {
      failf(data, "LDAP local: ERROR starting SSL/TLS mode: %s",
              ldap_err2string(rc));
      status = CURLE_SSL_CERTPROBLEM;
      goto quit;
    }
*/
#else
    /* we should probably never come up to here since configure
       should check in first place if we can support LDAP SSL/TLS */
    failf(data, "LDAP local: SSL/TLS not supported with this version "
            "of the OpenLDAP toolkit\n");
    status = CURLE_SSL_CERTPROBLEM;
    goto quit;
#endif
#endif
#endif /* CURL_LDAP_USE_SSL */
  }
  else {
    server = ldap_init(conn->host.name, (int)conn->port);
    if(server == NULL) {
      failf(data, "LDAP local: Cannot connect to %s:%hu",
              conn->host.name, conn->port);
      status = CURLE_COULDNT_CONNECT;
      goto quit;
    }
  }
#ifdef CURL_LDAP_WIN
  ldap_set_option(server, LDAP_OPT_PROTOCOL_VERSION, &ldap_proto);
#endif

  rc = ldap_simple_bind_s(server,
                          conn->bits.user_passwd ? conn->user : NULL,
                          conn->bits.user_passwd ? conn->passwd : NULL);
  if(!ldap_ssl && rc != 0) {
    ldap_proto = LDAP_VERSION2;
    ldap_set_option(server, LDAP_OPT_PROTOCOL_VERSION, &ldap_proto);
    rc = ldap_simple_bind_s(server,
                            conn->bits.user_passwd ? conn->user : NULL,
                            conn->bits.user_passwd ? conn->passwd : NULL);
  }
  if(rc != 0) {
    failf(data, "LDAP local: ldap_simple_bind_s %s", ldap_err2string(rc));
    status = CURLE_LDAP_CANNOT_BIND;
    goto quit;
  }

  rc = ldap_search_s(server, ludp->lud_dn, ludp->lud_scope,
                     ludp->lud_filter, ludp->lud_attrs, 0, &result);

  if(rc != 0 && rc != LDAP_SIZELIMIT_EXCEEDED) {
    failf(data, "LDAP remote: %s", ldap_err2string(rc));
    status = CURLE_LDAP_SEARCH_FAILED;
    goto quit;
  }

  for(num = 0, entryIterator = ldap_first_entry(server, result);
      entryIterator;
      entryIterator = ldap_next_entry(server, entryIterator), num++) {
    BerElement *ber = NULL;
    char  *attribute;       /*! suspicious that this isn't 'const' */
    char  *dn = ldap_get_dn(server, entryIterator);
    int i;

    Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"DN: ", 4);
    Curl_client_write(conn, CLIENTWRITE_BODY, (char *)dn, 0);
    Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 1);

    dlsize += strlen(dn)+5;

    for(attribute = ldap_first_attribute(server, entryIterator, &ber);
        attribute;
        attribute = ldap_next_attribute(server, entryIterator, ber)) {
      BerValue **vals = ldap_get_values_len(server, entryIterator, attribute);

      if(vals != NULL) {
        for(i = 0; (vals[i] != NULL); i++) {
          Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\t", 1);
          Curl_client_write(conn, CLIENTWRITE_BODY, (char *) attribute, 0);
          Curl_client_write(conn, CLIENTWRITE_BODY, (char *)": ", 2);
          dlsize += strlen(attribute)+3;

          if((strlen(attribute) > 7) &&
              (strcmp(";binary",
                      (char *)attribute +
                      (strlen((char *)attribute) - 7)) == 0)) {
            /* Binary attribute, encode to base64. */
            CURLcode error = Curl_base64_encode(data,
                                                vals[i]->bv_val,
                                                vals[i]->bv_len,
                                                &val_b64,
                                                &val_b64_sz);
            if(error) {
              ldap_value_free_len(vals);
              ldap_memfree(attribute);
              ldap_memfree(dn);
              if(ber)
                ber_free(ber, 0);
              status = error;
              goto quit;
            }
            if(val_b64_sz > 0) {
              Curl_client_write(conn, CLIENTWRITE_BODY, val_b64, val_b64_sz);
              free(val_b64);
              dlsize += val_b64_sz;
            }
          }
          else {
            Curl_client_write(conn, CLIENTWRITE_BODY, vals[i]->bv_val,
                              vals[i]->bv_len);
            dlsize += vals[i]->bv_len;
          }
          Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 0);
          dlsize++;
        }

        /* Free memory used to store values */
        ldap_value_free_len(vals);
      }
      Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 1);
      dlsize++;
      Curl_pgrsSetDownloadCounter(data, dlsize);
      ldap_memfree(attribute);
    }
    ldap_memfree(dn);
    if(ber)
       ber_free(ber, 0);
  }

quit:
  if(result) {
    ldap_msgfree(result);
    LDAP_TRACE (("Received %d entries\n", num));
  }
  if(rc == LDAP_SIZELIMIT_EXCEEDED)
    infof(data, "There are more than %d entries\n", num);
  if(ludp)
    ldap_free_urldesc(ludp);
  if(server)
    ldap_unbind_s(server);
#if defined(HAVE_LDAP_SSL) && defined(CURL_HAS_NOVELL_LDAPSDK)
  if(ldap_ssl)
    ldapssl_client_deinit();
#endif /* HAVE_LDAP_SSL && CURL_HAS_NOVELL_LDAPSDK */

  /* no data to transfer */
  Curl_setup_transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
  conn->bits.close = TRUE;

  return status;
}

#ifdef DEBUG_LDAP
static void _ldap_trace (const char *fmt, ...)
{
  static int do_trace = -1;
  va_list args;

  if(do_trace == -1) {
    const char *env = getenv("CURL_TRACE");
    do_trace = (env && strtol(env, NULL, 10) > 0);
  }
  if(!do_trace)
    return;

  va_start (args, fmt);
  vfprintf (stderr, fmt, args);
  va_end (args);
}
#endif

#ifndef HAVE_LDAP_URL_PARSE

/*
 * Return scope-value for a scope-string.
 */
static int str2scope (const char *p)
{
  if(strequal(p, "one"))
     return LDAP_SCOPE_ONELEVEL;
  if(strequal(p, "onetree"))
     return LDAP_SCOPE_ONELEVEL;
  if(strequal(p, "base"))
     return LDAP_SCOPE_BASE;
  if(strequal(p, "sub"))
     return LDAP_SCOPE_SUBTREE;
  if(strequal( p, "subtree"))
     return LDAP_SCOPE_SUBTREE;
  return (-1);
}

/*
 * Split 'str' into strings separated by commas.
 * Note: res[] points into 'str'.
 */
static char **split_str (char *str)
{
  char **res, *lasts, *s;
  int  i;

  for(i = 2, s = strchr(str,','); s; i++)
    s = strchr(++s,',');

  res = calloc(i, sizeof(char*));
  if(!res)
    return NULL;

  for(i = 0, s = strtok_r(str, ",", &lasts); s;
      s = strtok_r(NULL, ",", &lasts), i++)
    res[i] = s;
  return res;
}

/*
 * Unescape the LDAP-URL components
 */
static bool unescape_elements (void *data, LDAPURLDesc *ludp)
{
  int i;

  if(ludp->lud_filter) {
    ludp->lud_filter = curl_easy_unescape(data, ludp->lud_filter, 0, NULL);
    if(!ludp->lud_filter)
       return (FALSE);
  }

  for(i = 0; ludp->lud_attrs && ludp->lud_attrs[i]; i++) {
    ludp->lud_attrs[i] = curl_easy_unescape(data, ludp->lud_attrs[i], 0, NULL);
    if(!ludp->lud_attrs[i])
      return (FALSE);
  }

  for(i = 0; ludp->lud_exts && ludp->lud_exts[i]; i++) {
    ludp->lud_exts[i] = curl_easy_unescape(data, ludp->lud_exts[i], 0, NULL);
    if(!ludp->lud_exts[i])
      return (FALSE);
  }

  if(ludp->lud_dn) {
    char *dn = ludp->lud_dn;
    char *new_dn = curl_easy_unescape(data, dn, 0, NULL);

    free(dn);
    ludp->lud_dn = new_dn;
    if(!new_dn)
       return (FALSE);
  }
  return (TRUE);
}

/*
 * Break apart the pieces of an LDAP URL.
 * Syntax:
 *   ldap://<hostname>:<port>/<base_dn>?<attributes>?<scope>?<filter>?<ext>
 *
 * <hostname> already known from 'conn->host.name'.
 * <port>     already known from 'conn->remote_port'.
 * extract the rest from 'conn->data->state.path+1'. All fields are optional.
 * e.g.
 *   ldap://<hostname>:<port>/?<attributes>?<scope>?<filter>
 * yields ludp->lud_dn = "".
 *
 * Defined in RFC4516 section 2.
 */
static int _ldap_url_parse2 (const struct connectdata *conn, LDAPURLDesc *ludp)
{
  char *p, *q;
  int i;

  if(!conn->data ||
      !conn->data->state.path ||
      conn->data->state.path[0] != '/' ||
      !checkprefix("LDAP", conn->data->change.url))
    return LDAP_INVALID_SYNTAX;

  ludp->lud_scope = LDAP_SCOPE_BASE;
  ludp->lud_port  = conn->remote_port;
  ludp->lud_host  = conn->host.name;

  /* parse DN (Distinguished Name).
   */
  ludp->lud_dn = strdup(conn->data->state.path+1);
  if(!ludp->lud_dn)
    return LDAP_NO_MEMORY;

  p = strchr(ludp->lud_dn, '?');
  LDAP_TRACE (("DN '%.*s'\n", p ? (size_t)(p-ludp->lud_dn) :
               strlen(ludp->lud_dn), ludp->lud_dn));

  if(!p)
    goto success;

  *p++ = '\0';

  /* parse attributes. skip "??".
   */
  q = strchr(p, '?');
  if(q)
    *q++ = '\0';

  if(*p && *p != '?') {
    ludp->lud_attrs = split_str(p);
    if(!ludp->lud_attrs)
      return LDAP_NO_MEMORY;

    for(i = 0; ludp->lud_attrs[i]; i++)
      LDAP_TRACE (("attr[%d] '%s'\n", i, ludp->lud_attrs[i]));
  }

  p = q;
  if(!p)
    goto success;

  /* parse scope. skip "??"
   */
  q = strchr(p, '?');
  if(q)
    *q++ = '\0';

  if(*p && *p != '?') {
    ludp->lud_scope = str2scope(p);
    if(ludp->lud_scope == -1)
      return LDAP_INVALID_SYNTAX;
    LDAP_TRACE (("scope %d\n", ludp->lud_scope));
  }

  p = q;
  if(!p)
    goto success;

  /* parse filter
   */
  q = strchr(p, '?');
  if(q)
    *q++ = '\0';
  if(!*p)
    return LDAP_INVALID_SYNTAX;

  ludp->lud_filter = p;
  LDAP_TRACE (("filter '%s'\n", ludp->lud_filter));

  p = q;
  if(!p)
    goto success;

  /* parse extensions
   */
  ludp->lud_exts = split_str(p);
  if(!ludp->lud_exts)
    return LDAP_NO_MEMORY;

  for(i = 0; ludp->lud_exts[i]; i++)
    LDAP_TRACE (("exts[%d] '%s'\n", i, ludp->lud_exts[i]));

  success:
  if(!unescape_elements(conn->data, ludp))
    return LDAP_NO_MEMORY;
  return LDAP_SUCCESS;
}

static int _ldap_url_parse (const struct connectdata *conn,
                            LDAPURLDesc **ludpp)
{
  LDAPURLDesc *ludp = calloc(1, sizeof(*ludp));
  int rc;

  *ludpp = NULL;
  if(!ludp)
     return LDAP_NO_MEMORY;

  rc = _ldap_url_parse2 (conn, ludp);
  if(rc != LDAP_SUCCESS) {
    _ldap_free_urldesc(ludp);
    ludp = NULL;
  }
  *ludpp = ludp;
  return (rc);
}

static void _ldap_free_urldesc (LDAPURLDesc *ludp)
{
  int i;

  if(!ludp)
    return;

  if(ludp->lud_dn)
    free(ludp->lud_dn);

  if(ludp->lud_filter)
    free(ludp->lud_filter);

  if(ludp->lud_attrs) {
    for(i = 0; ludp->lud_attrs[i]; i++)
      free(ludp->lud_attrs[i]);
    free(ludp->lud_attrs);
  }

  if(ludp->lud_exts) {
    for(i = 0; ludp->lud_exts[i]; i++)
      free(ludp->lud_exts[i]);
    free(ludp->lud_exts);
  }
  free (ludp);
}
#endif  /* !HAVE_LDAP_URL_PARSE */
#endif  /* !CURL_DISABLE_LDAP && !USE_OPENLDAP */
