/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2002, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>


#define DYNA_GET_FUNCTION(type, fnc) \
  (fnc) = (type)DynaGetFunction(#fnc); \
  if ((fnc) == NULL) { \
    return CURLE_FUNCTION_NOT_FOUND; \
  } \

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
    dlopen("liblber.so",
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

static void * DynaGetFunction(const char *name)
{
  void *func = NULL;

#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL)
  if (libldap) {
    func = dlsym(libldap, name);
  }
#endif
  
  return func;
}

static int WriteProc(void *param, char *text, int len)
{
  struct SessionHandle *data = (struct SessionHandle *)param;
  len = 0; /* prevent compiler warning */
  Curl_client_write(data, CLIENTWRITE_BODY, text, 0);
  return 0;
}

/***********************************************************************
 */
CURLcode Curl_ldap(struct connectdata *conn)
{
  CURLcode status = CURLE_OK;
  int rc;
  void *(*ldap_open)(char *, int);
  int (*ldap_simple_bind_s)(void *, char *, char *);
  int (*ldap_unbind_s)(void *);
  int (*ldap_url_search_s)(void *, char *, int, void **);
  void *(*ldap_first_entry)(void *, void *);
  void *(*ldap_next_entry)(void *, void *);
  char *(*ldap_err2string)(int);
  int (*ldap_entry2text)(void *, char *, void *, void *, char **, char **, int (*)(void *, char *, int), void *, char *, int, unsigned long);
  int (*ldap_entry2html)(void *, char *, void *, void *, char **, char **, int (*)(void *, char *, int), void *, char *, int, unsigned long, char *, char *);
  void *server;
  void *result;
  void *entryIterator;

  int ldaptext;
  struct SessionHandle *data=conn->data;
  
  infof(data, "LDAP: %s\n", data->change.url);

  DynaOpen();
  if (libldap == NULL) {
    failf(data, "The needed LDAP library/libraries couldn't be opened");
    return CURLE_LIBRARY_NOT_FOUND;
  }

  ldaptext = data->set.ftp_ascii; /* This is a dirty hack */
  
  /* The types are needed because ANSI C distinguishes between
   * pointer-to-object (data) and pointer-to-function.
   */
  DYNA_GET_FUNCTION(void *(*)(char *, int), ldap_open);
  DYNA_GET_FUNCTION(int (*)(void *, char *, char *), ldap_simple_bind_s);
  DYNA_GET_FUNCTION(int (*)(void *), ldap_unbind_s);
  DYNA_GET_FUNCTION(int (*)(void *, char *, int, void **), ldap_url_search_s);
  DYNA_GET_FUNCTION(void *(*)(void *, void *), ldap_first_entry);
  DYNA_GET_FUNCTION(void *(*)(void *, void *), ldap_next_entry);
  DYNA_GET_FUNCTION(char *(*)(int), ldap_err2string);
  DYNA_GET_FUNCTION(int (*)(void *, char *, void *, void *, char **, char **, int (*)(void *, char *, int), void *, char *, int, unsigned long), ldap_entry2text);
  DYNA_GET_FUNCTION(int (*)(void *, char *, void *, void *, char **, char **, int (*)(void *, char *, int), void *, char *, int, unsigned long, char *, char *), ldap_entry2html);
  
  server = ldap_open(conn->hostname, conn->port);
  if (server == NULL) {
    failf(data, "LDAP: Cannot connect to %s:%d",
	  conn->hostname, conn->port);
    status = CURLE_COULDNT_CONNECT;
  } else {
    rc = ldap_simple_bind_s(server,
                            conn->bits.user_passwd?data->state.user:NULL,
                            conn->bits.user_passwd?data->state.passwd:NULL);
    if (rc != 0) {
      failf(data, "LDAP: %s", ldap_err2string(rc));
      status = CURLE_LDAP_CANNOT_BIND;
    } else {
      rc = ldap_url_search_s(server, data->change.url, 0, &result);
      if (rc != 0) {
	failf(data, "LDAP: %s", ldap_err2string(rc));
	status = CURLE_LDAP_SEARCH_FAILED;
      } else {
	for (entryIterator = ldap_first_entry(server, result);
	     entryIterator;
	     entryIterator = ldap_next_entry(server, entryIterator))
	  {
	    if (ldaptext) {
	      rc = ldap_entry2text(server, NULL, entryIterator, NULL,
				   NULL, NULL, WriteProc, data,
				   (char *)"", 0, 0);
	      if (rc != 0) {
		failf(data, "LDAP: %s", ldap_err2string(rc));
		status = CURLE_LDAP_SEARCH_FAILED;
	      }
	    } else {
	      rc = ldap_entry2html(server, NULL, entryIterator, NULL,
				   NULL, NULL, WriteProc, data,
				   (char *)"", 0, 0, NULL, NULL);
	      if (rc != 0) {
		failf(data, "LDAP: %s", ldap_err2string(rc));
		status = CURLE_LDAP_SEARCH_FAILED;
	      }
	    }
	  }
      }
      ldap_unbind_s(server);
    }
  }
  DynaClose();

  /* no data to transfer */
  Curl_Transfer(conn, -1, -1, FALSE, NULL, -1, NULL);
  
  return status;
}

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
#endif
