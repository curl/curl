/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2004, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#if defined(WIN32) && !defined(__GNUC__)
#else
# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif
# ifdef HAVE_DLFCN_H
#  include <dlfcn.h>
# endif
#endif

#include "urldata.h"
#include <curl/curl.h>
#include "sendf.h"
#include "escape.h"
#include "transfer.h"
#include "ldap.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

typedef void * (*dynafunc)(void *input);

#define DYNA_GET_FUNCTION(type, fnc) \
  (fnc) = (type)DynaGetFunction(#fnc); \
  if ((fnc) == NULL) { \
    return CURLE_FUNCTION_NOT_FOUND; \
  }

/***********************************************************************
 */
static void *libldap = NULL;
static void *liblber = NULL;

static void DynaOpen(void)
{
#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL)
  if (libldap == NULL) {
    /*
     * libldap.so should be able to resolve its dependency on
     * liblber.so automatically, but since it does not we will
     * handle it here by opening liblber.so as global.
     */
    liblber = dlopen("liblber.so",
#ifdef RTLD_LAZY_GLOBAL /* It turns out some systems use this: */
           RTLD_LAZY_GLOBAL
#else
#ifdef RTLD_GLOBAL
           RTLD_LAZY | RTLD_GLOBAL
#else
           /* and some systems don't have the RTLD_GLOBAL symbol */
           RTLD_LAZY
#endif
#endif
           );
    libldap = dlopen("libldap.so", RTLD_LAZY);
  }
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
#endif
}

static dynafunc DynaGetFunction(const char *name)
{
  dynafunc func = (dynafunc)NULL;

#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL)
  if (libldap) {
    func = (dynafunc) dlsym(libldap, name);
  }
#endif
  
  return func;
}

/***********************************************************************
 */
typedef struct ldap_url_desc {
	struct ldap_url_desc *lud_next;
        char    *lud_scheme;
	char    *lud_host;
	int     lud_port;
	char    *lud_dn;
	char    **lud_attrs;
	int     lud_scope;
	char    *lud_filter;
	char    **lud_exts;
	int     lud_crit_exts;
} LDAPURLDesc;


CURLcode Curl_ldap(struct connectdata *conn)
{
  CURLcode status = CURLE_OK;
  int rc;
  void *(*ldap_init)(char *, int);
  int (*ldap_simple_bind_s)(void *, char *, char *);
  int (*ldap_unbind_s)(void *);
  int (*ldap_url_parse)(char *, LDAPURLDesc **);
  void (*ldap_free_urldesc)(void *);
  int (*ldap_search_s)(void *, char *, int, char *, char **, int, void **);
  int (*ldap_search_st)(void *, char *, int, char *, char **, int, void *, void **);
  void *(*ldap_first_entry)(void *, void *);
  void *(*ldap_next_entry)(void *, void *);
  char *(*ldap_err2string)(int);
  char *(*ldap_get_dn)(void *, void *);
  char *(*ldap_first_attribute)(void *, void *, void **);
  char *(*ldap_next_attribute)(void *, void *, void *);
  char **(*ldap_get_values)(void *, void *, char *);
  void (*ldap_value_free)(char **);
  void (*ldap_memfree)(void *);
  void (*ber_free)(void *, int);
 
  void *server;
  LDAPURLDesc *ludp;
  void *result;
  void *entryIterator;
  void *ber;
  void *attribute;

  struct SessionHandle *data=conn->data;
  
  infof(data, "LDAP: %s\n", data->change.url);

  DynaOpen();
  if (libldap == NULL) {
    failf(data, "The needed LDAP library/libraries couldn't be opened");
    return CURLE_LIBRARY_NOT_FOUND;
  }

  /* The types are needed because ANSI C distinguishes between
   * pointer-to-object (data) and pointer-to-function.
   */
  DYNA_GET_FUNCTION(void *(*)(char *, int), ldap_init);
  DYNA_GET_FUNCTION(int (*)(void *, char *, char *), ldap_simple_bind_s);
  DYNA_GET_FUNCTION(int (*)(void *), ldap_unbind_s);
  DYNA_GET_FUNCTION(int (*)(char *, LDAPURLDesc **), ldap_url_parse);
  DYNA_GET_FUNCTION(void (*)(void *), ldap_free_urldesc);
  DYNA_GET_FUNCTION(int (*)(void *, char *, int, char *, char **, int, void **), ldap_search_s);
  DYNA_GET_FUNCTION(int (*)(void *, char *, int, char *, char **, int, void *, void **), ldap_search_st);
  DYNA_GET_FUNCTION(void *(*)(void *, void *), ldap_first_entry);
  DYNA_GET_FUNCTION(void *(*)(void *, void *), ldap_next_entry);
  DYNA_GET_FUNCTION(char *(*)(int), ldap_err2string);
  DYNA_GET_FUNCTION(char *(*)(void *, void *), ldap_get_dn);
  DYNA_GET_FUNCTION(char *(*)(void *, void *, void **), ldap_first_attribute);
  DYNA_GET_FUNCTION(char *(*)(void *, void *, void *), ldap_next_attribute);
  DYNA_GET_FUNCTION(char **(*)(void *, void *, char *), ldap_get_values);
  DYNA_GET_FUNCTION(void (*)(char **), ldap_value_free);
  DYNA_GET_FUNCTION(void (*)(void *), ldap_memfree);
  DYNA_GET_FUNCTION(void (*)(void *, int), ber_free);
  
  server = ldap_init(conn->host.name, conn->port);
  if (server == NULL) {
    failf(data, "LDAP: Cannot connect to %s:%d",
	  conn->host.name, conn->port);
    status = CURLE_COULDNT_CONNECT;
  }
  else {
    rc = ldap_simple_bind_s(server,
                            conn->bits.user_passwd?conn->user:NULL,
                            conn->bits.user_passwd?conn->passwd:NULL);
    if (rc != 0) {
      failf(data, "LDAP: %s", ldap_err2string(rc));
      status = CURLE_LDAP_CANNOT_BIND;
    }
    else {
      rc = ldap_url_parse(data->change.url, &ludp);
      if (rc != 0) {
	failf(data, "LDAP: %s", ldap_err2string(rc));
	status = CURLE_LDAP_INVALID_URL;
      }
      else {
	rc = ldap_search_s(server, ludp->lud_dn, ludp->lud_scope,
                           ludp->lud_filter, ludp->lud_attrs, 0, &result);
	if (rc != 0) {
	  failf(data, "LDAP: %s", ldap_err2string(rc));
	  status = CURLE_LDAP_SEARCH_FAILED;
	}
	else {
	  for (entryIterator = ldap_first_entry(server, result);
	       entryIterator;
	       entryIterator = ldap_next_entry(server, entryIterator)) {
            char *dn = ldap_get_dn(server, entryIterator);
            char **vals;
            int i;
            
            Curl_client_write(data, CLIENTWRITE_BODY, (char *)"DN: ", 4);
            Curl_client_write(data, CLIENTWRITE_BODY, dn, 0);
            Curl_client_write(data, CLIENTWRITE_BODY, (char *)"\n", 1);
            for(attribute = ldap_first_attribute(server, entryIterator,
                                                 &ber); 
                attribute; 
                attribute = ldap_next_attribute(server, entryIterator,
                                                ber) ) {
              vals = ldap_get_values(server, entryIterator, attribute);
              if (vals != NULL) {
                for(i = 0; (vals[i] != NULL); i++) {
                  Curl_client_write(data, CLIENTWRITE_BODY, (char*)"\t", 1);
                  Curl_client_write(data, CLIENTWRITE_BODY, attribute, 0);
                  Curl_client_write(data, CLIENTWRITE_BODY, (char *)": ", 2);
                  Curl_client_write(data, CLIENTWRITE_BODY, vals[i], 0);
                  Curl_client_write(data, CLIENTWRITE_BODY, (char *)"\n", 0);
                }
              }

              /* Free memory used to store values */
              ldap_value_free(vals);
            }
            Curl_client_write(data, CLIENTWRITE_BODY, (char *)"\n", 1);
            
            ldap_memfree(attribute);
            ldap_memfree(dn);
            if (ber) ber_free(ber, 0);
          }
	}

	ldap_free_urldesc(ludp);
      }
      ldap_unbind_s(server);
    }
  }
  DynaClose();

  /* no data to transfer */
  Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
  
  return status;
}
#endif
