/***************************************************************************
 *                      _   _ ____  _
 *  Project         ___| | | |  _ \| |
 *                 / __| | | | |_) | |
 *                | (__| |_| |  _ <| |___
 *                 \___|\___/|_| \_\_____|
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

#include "setup.h"

#ifndef CURL_DISABLE_LDAP
/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef NEED_MALLOC_H
#include <malloc.h>
#endif
#include <errno.h>

#ifdef CURL_LDAP_HYBRID         /* If W$ definitions are needed. */
# include <windows.h>
  /* Remember we are NOT in a W$ compiler! */
# undef WIN32
# undef _WIN32
# undef __WIN32__
#endif

#ifdef CURL_LDAP_WIN            /* Use W$ LDAP implementation. */
# include <winldap.h>
#else
#define LDAP_DEPRECATED 1       /* Be sure ldap_init() is defined. */
# include <ldap.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "sendf.h"
#include "escape.h"
#include "transfer.h"
#include "strequal.h"
#include "strtok.h"
#include "curl_ldap.h"
#include "memory.h"
#include "base64.h"

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

#ifndef LDAP_SIZELIMIT_EXCEEDED
#define LDAP_SIZELIMIT_EXCEEDED 4
#endif
#ifndef LDAP_VERSION2
#define LDAP_VERSION2 2
#endif
#ifndef LDAP_VERSION3
#define LDAP_VERSION3 3
#endif
#ifndef LDAP_OPT_PROTOCOL_VERSION
#define LDAP_OPT_PROTOCOL_VERSION 0x0011
#endif

#ifdef DEBUG_LDAP
  #define LDAP_TRACE(x)   do { \
                            _ldap_trace ("%u: ", __LINE__); \
                            _ldap_trace x; \
                          } while (0)

  static void _ldap_trace (const char *fmt, ...);
#else
  #define LDAP_TRACE(x)   ((void)0)
#endif


CURLcode Curl_ldap(struct connectdata *conn, bool *done)
{
  CURLcode status = CURLE_OK;
  int rc = 0;
  LDAP *server;
  LDAPURLDesc *ludp = NULL;
  const char *mod_name;
  LDAPMessage *result;
  LDAPMessage *entryIterator;
  int num = 0;
  struct SessionHandle *data=conn->data;
  int ldap_proto;
  char *val_b64;
  size_t val_b64_sz;

  *done = TRUE; /* unconditionally */
  infof(data, "LDAP local: %s\n", data->change.url);

  server = ldap_init(conn->host.name, (int)conn->port);
  if (server == NULL) {
    failf(data, "LDAP local: Cannot connect to %s:%d",
          conn->host.name, conn->port);
    status = CURLE_COULDNT_CONNECT;
    goto quit;
  }

  ldap_proto = LDAP_VERSION3;
  ldap_set_option(server, LDAP_OPT_PROTOCOL_VERSION, &ldap_proto);
  rc = ldap_simple_bind_s(server,
                          conn->bits.user_passwd ? conn->user : NULL,
                          conn->bits.user_passwd ? conn->passwd : NULL);
  if (rc != 0) {
    ldap_proto = LDAP_VERSION2;
    ldap_set_option(server, LDAP_OPT_PROTOCOL_VERSION, &ldap_proto);
    rc = ldap_simple_bind_s(server,
                            conn->bits.user_passwd ? conn->user : NULL,
                            conn->bits.user_passwd ? conn->passwd : NULL);
  }
  if (rc != 0) {
     failf(data, "LDAP local: %s", ldap_err2string(rc));
     status = CURLE_LDAP_CANNOT_BIND;
     goto quit;
  }

#ifndef HAVE_LDAP_URL_PARSE
  rc = _ldap_url_parse(conn, &ludp);
#else
  rc = ldap_url_parse(data->change.url, &ludp);
#endif

  if (rc != 0) {
     failf(data, "LDAP local: %s", ldap_err2string(rc));
     status = CURLE_LDAP_INVALID_URL;
     goto quit;
  }

  rc = ldap_search_s(server, ludp->lud_dn, ludp->lud_scope,
                     ludp->lud_filter, ludp->lud_attrs, 0, &result);

  if (rc != 0 && rc != LDAP_SIZELIMIT_EXCEEDED) {
    failf(data, "LDAP remote: %s", ldap_err2string(rc));
    status = CURLE_LDAP_SEARCH_FAILED;
    goto quit;
  }

  for(num = 0, entryIterator = ldap_first_entry(server, result);
      entryIterator;
      entryIterator = ldap_next_entry(server, entryIterator), num++)
  {
    BerElement *ber = NULL;
    char  *attribute;       /*! suspicious that this isn't 'const' */
    char  *dn = ldap_get_dn(server, entryIterator);
    int i;

    Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"DN: ", 4);
    Curl_client_write(conn, CLIENTWRITE_BODY, (char *)dn, 0);
    Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 1);

    for (attribute = ldap_first_attribute(server, entryIterator, &ber);
         attribute;
         attribute = ldap_next_attribute(server, entryIterator, ber))
    {
      BerValue **vals = ldap_get_values_len(server, entryIterator, attribute);

      if (vals != NULL)
      {
        for (i = 0; (vals[i] != NULL); i++)
        {
          Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\t", 1);
          Curl_client_write(conn, CLIENTWRITE_BODY, (char *) attribute, 0);
          Curl_client_write(conn, CLIENTWRITE_BODY, (char *)": ", 2);
          if ((strlen(attribute) > 7) &&
              (strcmp(";binary",
                      (char *)attribute +
                      (strlen((char *)attribute) - 7)) == 0)) {
            /* Binary attribute, encode to base64. */
            val_b64_sz = Curl_base64_encode(conn->data,
                                            vals[i]->bv_val,
                                            vals[i]->bv_len,
                                            &val_b64);
            if (val_b64_sz > 0) {
              Curl_client_write(conn, CLIENTWRITE_BODY, val_b64, val_b64_sz);
              free(val_b64);
            }
          } else
            Curl_client_write(conn, CLIENTWRITE_BODY, vals[i]->bv_val,
                              vals[i]->bv_len);
          Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 0);
        }

        /* Free memory used to store values */
        ldap_value_free_len(vals);
      }
      Curl_client_write(conn, CLIENTWRITE_BODY, (char *)"\n", 1);

      ldap_memfree(attribute);
    }
    ldap_memfree(dn);
    if (ber)
       ber_free(ber, 0);
  }

quit:
  LDAP_TRACE (("Received %d entries\n", num));
  if (rc == LDAP_SIZELIMIT_EXCEEDED)
     infof(data, "There are more than %d entries\n", num);
  if (ludp)
     ldap_free_urldesc(ludp);
  if (server)
     ldap_unbind_s(server);

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

  if (do_trace == -1) {
    const char *env = getenv("CURL_TRACE");
    do_trace = (env && atoi(env) > 0);
  }
  if (!do_trace)
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
  if (!stricmp(p, "one"))
     return LDAP_SCOPE_ONELEVEL;
  if (!stricmp(p, "onetree"))
     return LDAP_SCOPE_ONELEVEL;
  if (!stricmp(p, "base"))
     return LDAP_SCOPE_BASE;
  if (!stricmp(p, "sub"))
     return LDAP_SCOPE_SUBTREE;
  if (!stricmp( p, "subtree"))
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

  for (i = 2, s = strchr(str,','); s; i++)
     s = strchr(++s,',');

  res = calloc(i, sizeof(char*));
  if (!res)
    return NULL;

  for (i = 0, s = strtok_r(str, ",", &lasts); s;
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

  if (ludp->lud_filter) {
    ludp->lud_filter = curl_easy_unescape(data, ludp->lud_filter, 0, NULL);
    if (!ludp->lud_filter)
       return (FALSE);
  }

  for (i = 0; ludp->lud_attrs && ludp->lud_attrs[i]; i++) {
    ludp->lud_attrs[i] = curl_easy_unescape(data, ludp->lud_attrs[i], 0, NULL);
    if (!ludp->lud_attrs[i])
       return (FALSE);
  }

  for (i = 0; ludp->lud_exts && ludp->lud_exts[i]; i++) {
    ludp->lud_exts[i] = curl_easy_unescape(data, ludp->lud_exts[i], 0, NULL);
    if (!ludp->lud_exts[i])
       return (FALSE);
  }

  if (ludp->lud_dn) {
    char *dn = ludp->lud_dn;
    char *new_dn = curl_easy_unescape(data, dn, 0, NULL);

    free(dn);
    ludp->lud_dn = new_dn;
    if (!new_dn)
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
 * extract the rest from 'conn->data->reqdata.path+1'. All fields are optional.
 * e.g.
 *   ldap://<hostname>:<port>/?<attributes>?<scope>?<filter>
 * yields ludp->lud_dn = "".
 *
 * Ref. http://developer.netscape.com/docs/manuals/dirsdk/csdk30/url.htm#2831915
 */
static int _ldap_url_parse2 (const struct connectdata *conn, LDAPURLDesc *ludp)
{
  char *p, *q;
  int i;

  if (!conn->data ||
      !conn->data->reqdata.path ||
      conn->data->reqdata.path[0] != '/' ||
      !checkprefix(conn->protostr, conn->data->change.url))
    return LDAP_INVALID_SYNTAX;

  ludp->lud_scope = LDAP_SCOPE_BASE;
  ludp->lud_port  = conn->remote_port;
  ludp->lud_host  = conn->host.name;

  /* parse DN (Distinguished Name).
   */
  ludp->lud_dn = strdup(conn->data->reqdata.path+1);
  if (!ludp->lud_dn)
    return LDAP_NO_MEMORY;

  p = strchr(ludp->lud_dn, '?');
  LDAP_TRACE (("DN '%.*s'\n", p ? (size_t)(p-ludp->lud_dn) :
               strlen(ludp->lud_dn), ludp->lud_dn));

  if (!p)
    goto success;

  *p++ = '\0';

  /* parse attributes. skip "??".
   */
  q = strchr(p, '?');
  if (q)
    *q++ = '\0';

  if (*p && *p != '?') {
    ludp->lud_attrs = split_str(p);
    if (!ludp->lud_attrs)
      return LDAP_NO_MEMORY;

    for (i = 0; ludp->lud_attrs[i]; i++)
      LDAP_TRACE (("attr[%d] '%s'\n", i, ludp->lud_attrs[i]));
  }

  p = q;
  if (!p)
    goto success;

  /* parse scope. skip "??"
   */
  q = strchr(p, '?');
  if (q)
    *q++ = '\0';

  if (*p && *p != '?') {
    ludp->lud_scope = str2scope(p);
    if (ludp->lud_scope == -1)
      return LDAP_INVALID_SYNTAX;
    LDAP_TRACE (("scope %d\n", ludp->lud_scope));
  }

  p = q;
  if (!p)
    goto success;

  /* parse filter
   */
  q = strchr(p, '?');
  if (q)
    *q++ = '\0';
  if (!*p)
    return LDAP_INVALID_SYNTAX;

  ludp->lud_filter = p;
  LDAP_TRACE (("filter '%s'\n", ludp->lud_filter));

  p = q;
  if (!p)
    goto success;

  /* parse extensions
   */
  ludp->lud_exts = split_str(p);
  if (!ludp->lud_exts)
    return LDAP_NO_MEMORY;

  for (i = 0; ludp->lud_exts[i]; i++)
    LDAP_TRACE (("exts[%d] '%s'\n", i, ludp->lud_exts[i]));

  success:
  if (!unescape_elements(conn->data, ludp))
    return LDAP_NO_MEMORY;
  return LDAP_SUCCESS;
}

static int _ldap_url_parse (const struct connectdata *conn,
                            LDAPURLDesc **ludpp)
{
  LDAPURLDesc *ludp = calloc(sizeof(*ludp), 1);
  int rc;

  *ludpp = NULL;
  if (!ludp)
     return LDAP_NO_MEMORY;

  rc = _ldap_url_parse2 (conn, ludp);
  if (rc != LDAP_SUCCESS) {
    _ldap_free_urldesc(ludp);
    ludp = NULL;
  }
  *ludpp = ludp;
  return (rc);
}

static void _ldap_free_urldesc (LDAPURLDesc *ludp)
{
  int i;

  if (!ludp)
     return;

  if (ludp->lud_dn)
     free(ludp->lud_dn);

  if (ludp->lud_filter)
     free(ludp->lud_filter);

  if (ludp->lud_attrs) {
    for (i = 0; ludp->lud_attrs[i]; i++)
       free(ludp->lud_attrs[i]);
    free(ludp->lud_attrs);
  }

  if (ludp->lud_exts) {
    for (i = 0; ludp->lud_exts[i]; i++)
       free(ludp->lud_exts[i]);
    free(ludp->lud_exts);
  }
  free (ludp);
}
#endif  /* HAVE_LDAP_URL_PARSE */
#endif  /* CURL_DISABLE_LDAP */
