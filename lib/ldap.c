/***************************************************************************
 *                      _   _ ____  _
 *  Project         ___| | | |  _ \| |
 *                 / __| | | | |_) | |
 *                | (__| |_| |  _ <| |___
 *                \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <errno.h>

#if defined(WIN32)
# include <windows.h>
# include <malloc.h>
# include <winldap.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_DLFCN_H
# include <dlfcn.h>
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "sendf.h"
#include "escape.h"
#include "transfer.h"
#include "strequal.h"
#include "strtok.h"
#include "ldap.h"
#include "memory.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

#include "memdebug.h"

/* WLdap32.dll functions are *not* stdcall. Must call these via __cdecl
 * pointers in case libcurl was compiled as fastcall (cl -Gr). Watcom
 * uses fastcall by default.
 */
#if !defined(WIN32) && !defined(__cdecl)
#define __cdecl
#endif

#ifndef LDAP_SIZELIMIT_EXCEEDED
#define LDAP_SIZELIMIT_EXCEEDED 4
#endif

#define DLOPEN_MODE   RTLD_LAZY  /*! assume all dlopen() implementations have
                                   this */

#if defined(RTLD_LAZY_GLOBAL)    /* It turns out some systems use this: */
# undef  DLOPEN_MODE
# define DLOPEN_MODE  RTLD_LAZY_GLOBAL
#elif defined(RTLD_GLOBAL)
# undef  DLOPEN_MODE
# define DLOPEN_MODE  (RTLD_LAZY | RTLD_GLOBAL)
#endif

#define DYNA_GET_FUNCTION(type, fnc) do { \
          (fnc) = (type)DynaGetFunction(#fnc); \
          if ((fnc) == NULL) \
             return CURLE_FUNCTION_NOT_FOUND; \
        } while (0)

/*! CygWin etc. configure could set these, but we don't want it.
 * Must use WLdap32.dll code.
 */
#if defined(WIN32)
#undef HAVE_DLOPEN
#undef HAVE_LIBDL
#endif

typedef void * (*dynafunc)(void *input);

/***********************************************************************
 */
#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL) || defined(WIN32)
static void *libldap = NULL;
#ifndef WIN32
static void *liblber = NULL;
#endif
#endif

static int DynaOpen(const char **mod_name)
{
#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL)
  if (libldap == NULL) {
    /*
     * libldap.so should be able to resolve its dependency on
     * liblber.so automatically, but since it does not we will
     * handle it here by opening liblber.so as global.
     */
    *mod_name = "liblber.so";
    liblber = dlopen(*mod_name, DLOPEN_MODE);

    /* Assume loading libldap.so will fail if loading of liblber.so failed
     */
    if (liblber)  {
      *mod_name = "libldap.so";
      libldap = dlopen(*mod_name, RTLD_LAZY);
    }
  }
  return (libldap != NULL && liblber != NULL);

#elif defined(WIN32)
  *mod_name = "wldap32.dll";
  if (!libldap)
    libldap = (void*)LoadLibrary(*mod_name);
  return (libldap != NULL);

#else
  (void) mod_name;
  return (0);
#endif
}

static void DynaClose(void)
{
#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL)
  if (libldap) {
    dlclose(libldap);
    libldap=NULL;
  }
  if (liblber) {
    dlclose(liblber);
    liblber=NULL;
  }
#elif defined(WIN32)
  if (libldap) {
    FreeLibrary ((HMODULE)libldap);
    libldap = NULL;
  }
#endif
}

static dynafunc DynaGetFunction(const char *name)
{
  dynafunc func = (dynafunc)NULL;

#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL)
  if (libldap) {
    /* This typecast magic below was brought by Joe Halpin. In ISO C, you
     * cannot typecast a data pointer to a function pointer, but that's
     * exactly what we need to do here to avoid compiler warnings on picky
     * compilers! */
    *(void**) (&func) = dlsym(libldap, name);
  }
#elif defined(WIN32)
  if (libldap) {
    func = (dynafunc)GetProcAddress((HINSTANCE)libldap, name);
  }
#else
  (void) name;
#endif
  return func;
}

/***********************************************************************
 */
typedef struct ldap_url_desc {
    struct ldap_url_desc *lud_next;
    char   *lud_scheme;
    char   *lud_host;
    int     lud_port;
    char   *lud_dn;
    char  **lud_attrs;
    int     lud_scope;
    char   *lud_filter;
    char  **lud_exts;
    int     lud_crit_exts;
} LDAPURLDesc;

#ifdef WIN32
static int  _ldap_url_parse (const struct connectdata *conn,
                             LDAPURLDesc **ludp);
static void _ldap_free_urldesc (LDAPURLDesc *ludp);

static void (*ldap_free_urldesc)(LDAPURLDesc *) = _ldap_free_urldesc;
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
#ifndef WIN32
  int    (*ldap_url_parse)(char *, LDAPURLDesc **);
  void   (*ldap_free_urldesc)(void *);
#endif
  void  *(__cdecl *ldap_init)(char *, int);
  int    (__cdecl *ldap_simple_bind_s)(void *, char *, char *);
  int    (__cdecl *ldap_unbind_s)(void *);
  int    (__cdecl *ldap_search_s)(void *, char *, int, char *, char **,
                                  int, void **);
  void  *(__cdecl *ldap_first_entry)(void *, void *);
  void  *(__cdecl *ldap_next_entry)(void *, void *);
  char  *(__cdecl *ldap_err2string)(int);
  char  *(__cdecl *ldap_get_dn)(void *, void *);
  char  *(__cdecl *ldap_first_attribute)(void *, void *, void **);
  char  *(__cdecl *ldap_next_attribute)(void *, void *, void *);
  char **(__cdecl *ldap_get_values)(void *, void *, const char *);
  void   (__cdecl *ldap_value_free)(char **);
  void   (__cdecl *ldap_memfree)(void *);
  void   (__cdecl *ber_free)(void *, int);

  void *server;
  LDAPURLDesc *ludp = NULL;
  const char *mod_name;
  void *result;
  void *entryIterator;     /*! type should be 'LDAPMessage *' */
  int num = 0;
  struct SessionHandle *data=conn->data;

  *done = TRUE; /* unconditionally */
  infof(data, "LDAP local: %s\n", data->change.url);

  if (!DynaOpen(&mod_name)) {
    failf(data, "The %s LDAP library/libraries couldn't be opened", mod_name);
    return CURLE_LIBRARY_NOT_FOUND;
  }

  /* The types are needed because ANSI C distinguishes between
   * pointer-to-object (data) and pointer-to-function.
   */
  DYNA_GET_FUNCTION(void *(__cdecl *)(char *, int), ldap_init);
  DYNA_GET_FUNCTION(int (__cdecl *)(void *, char *, char *), ldap_simple_bind_s);
  DYNA_GET_FUNCTION(int (__cdecl *)(void *), ldap_unbind_s);
#ifndef WIN32
  DYNA_GET_FUNCTION(int (*)(char *, LDAPURLDesc **), ldap_url_parse);
  DYNA_GET_FUNCTION(void (*)(void *), ldap_free_urldesc);
#endif
  DYNA_GET_FUNCTION(int (__cdecl *)(void *, char *, int, char *, char **, int,
                            void **), ldap_search_s);
  DYNA_GET_FUNCTION(void *(__cdecl *)(void *, void *), ldap_first_entry);
  DYNA_GET_FUNCTION(void *(__cdecl *)(void *, void *), ldap_next_entry);
  DYNA_GET_FUNCTION(char *(__cdecl *)(int), ldap_err2string);
  DYNA_GET_FUNCTION(char *(__cdecl *)(void *, void *), ldap_get_dn);
  DYNA_GET_FUNCTION(char *(__cdecl *)(void *, void *, void **), ldap_first_attribute);
  DYNA_GET_FUNCTION(char *(__cdecl *)(void *, void *, void *), ldap_next_attribute);
  DYNA_GET_FUNCTION(char **(__cdecl *)(void *, void *, const char *), ldap_get_values);
  DYNA_GET_FUNCTION(void (__cdecl *)(char **), ldap_value_free);
  DYNA_GET_FUNCTION(void (__cdecl *)(void *), ldap_memfree);
  DYNA_GET_FUNCTION(void (__cdecl *)(void *, int), ber_free);

  server = (*ldap_init)(conn->host.name, (int)conn->port);
  if (server == NULL) {
    failf(data, "LDAP local: Cannot connect to %s:%d",
          conn->host.name, conn->port);
    status = CURLE_COULDNT_CONNECT;
    goto quit;
  }

  rc = (*ldap_simple_bind_s)(server,
                             conn->bits.user_passwd ? conn->user : NULL,
                             conn->bits.user_passwd ? conn->passwd : NULL);
  if (rc != 0) {
     failf(data, "LDAP local: %s", (*ldap_err2string)(rc));
     status = CURLE_LDAP_CANNOT_BIND;
     goto quit;
  }

#ifdef WIN32
  rc = _ldap_url_parse(conn, &ludp);
#else
  rc = (*ldap_url_parse)(data->change.url, &ludp);
#endif

  if (rc != 0) {
     failf(data, "LDAP local: %s", (*ldap_err2string)(rc));
     status = CURLE_LDAP_INVALID_URL;
     goto quit;
  }

  rc = (*ldap_search_s)(server, ludp->lud_dn, ludp->lud_scope,
                        ludp->lud_filter, ludp->lud_attrs, 0, &result);

  if (rc != 0 && rc != LDAP_SIZELIMIT_EXCEEDED) {
    failf(data, "LDAP remote: %s", (*ldap_err2string)(rc));
    status = CURLE_LDAP_SEARCH_FAILED;
    goto quit;
  }

  for(num = 0, entryIterator = (*ldap_first_entry)(server, result);
      entryIterator;
      entryIterator = (*ldap_next_entry)(server, entryIterator), num++)
  {
    void  *ber = NULL;      /*! is really 'BerElement **' */
    void  *attribute;       /*! suspicious that this isn't 'const' */
    char  *dn = (*ldap_get_dn)(server, entryIterator);
    int i;

    Curl_client_write(data, CLIENTWRITE_BODY, (char *)"DN: ", 4);
    Curl_client_write(data, CLIENTWRITE_BODY, (char *)dn, 0);
    Curl_client_write(data, CLIENTWRITE_BODY, (char *)"\n", 1);

    for (attribute = (*ldap_first_attribute)(server, entryIterator, &ber);
         attribute;
         attribute = (*ldap_next_attribute)(server, entryIterator, ber))
    {
      char **vals = (*ldap_get_values)(server, entryIterator, attribute);

      if (vals != NULL)
      {
        for (i = 0; (vals[i] != NULL); i++)
        {
          Curl_client_write(data, CLIENTWRITE_BODY, (char *)"\t", 1);
          Curl_client_write(data, CLIENTWRITE_BODY, (char*) attribute, 0);
          Curl_client_write(data, CLIENTWRITE_BODY, (char *)": ", 2);
          Curl_client_write(data, CLIENTWRITE_BODY, vals[i], 0);
          Curl_client_write(data, CLIENTWRITE_BODY, (char *)"\n", 0);
        }

        /* Free memory used to store values */
        (*ldap_value_free)(vals);
      }
      Curl_client_write(data, CLIENTWRITE_BODY, (char *)"\n", 1);

      (*ldap_memfree)(attribute);
    }
    (*ldap_memfree)(dn);
    if (ber)
       (*ber_free)(ber, 0);
  }

quit:
  LDAP_TRACE (("Received %d entries\n", num));
  if (rc == LDAP_SIZELIMIT_EXCEEDED)
     infof(data, "There are more than %d entries\n", num);
  if (ludp)
     (*ldap_free_urldesc)(ludp);
  if (server)
     (*ldap_unbind_s)(server);

  DynaClose();

  /* no data to transfer */
  Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);

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

#ifdef WIN32
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
static bool unescape_elements (LDAPURLDesc *ludp)
{
  int i;

  if (ludp->lud_filter) {
    ludp->lud_filter = curl_unescape(ludp->lud_filter, 0);
    if (!ludp->lud_filter)
       return (FALSE);
  }

  for (i = 0; ludp->lud_attrs && ludp->lud_attrs[i]; i++) {
    ludp->lud_attrs[i] = curl_unescape(ludp->lud_attrs[i], 0);
    if (!ludp->lud_attrs[i])
       return (FALSE);
  }

  for (i = 0; ludp->lud_exts && ludp->lud_exts[i]; i++) {
    ludp->lud_exts[i] = curl_unescape(ludp->lud_exts[i], 0);
    if (!ludp->lud_exts[i])
       return (FALSE);
  }

  if (ludp->lud_dn) {
    char *dn = ludp->lud_dn;
    char *new_dn = curl_unescape(dn, 0);

    free(dn);
    if (!new_dn)
       return (FALSE);
    ludp->lud_dn = new_dn;
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
 * extract the rest from 'conn->path+1'. All fields are optional. e.g.
 *   ldap://<hostname>:<port>/?<attributes>?<scope>?<filter> yields ludp->lud_dn = "".
 *
 * Ref. http://developer.netscape.com/docs/manuals/dirsdk/csdk30/url.htm#2831915
 */
static int _ldap_url_parse2 (const struct connectdata *conn, LDAPURLDesc *ludp)
{
  char *p, *q;
  int i;

  if (!conn->path || conn->path[0] != '/' ||
      !checkprefix(conn->protostr, conn->data->change.url))
     return LDAP_INVALID_SYNTAX;

  ludp->lud_scope = LDAP_SCOPE_BASE;
  ludp->lud_port  = conn->remote_port;
  ludp->lud_host  = conn->host.name;

  /* parse DN (Distinguished Name).
   */
  ludp->lud_dn = strdup(conn->path+1);
  if (!ludp->lud_dn)
     return LDAP_NO_MEMORY;

  p = strchr(ludp->lud_dn, '?');
  LDAP_TRACE (("DN '%.*s'\n", p ? (size_t)(p-ludp->lud_dn) : strlen(ludp->lud_dn),
               ludp->lud_dn));

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
  if (!unescape_elements(ludp))
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
#endif  /* WIN32 */
#endif  /* CURL_DISABLE_LDAP */
