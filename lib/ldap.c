/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Contributor(s):
 *  Bjørn Reese <breese@mail1.stofanet.dk>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

/* -- WIN32 approved -- */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "setup.h"

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

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>


#define DYNA_GET_FUNCTION(type, fnc) \
  (fnc) = (type)DynaGetFunction(#fnc); \
  if ((fnc) == NULL) { \
    return URG_FUNCTION_NOT_FOUND; \
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
    dlopen("liblber.so", RTLD_LAZY | RTLD_GLOBAL);
    libldap = dlopen("libldap.so", RTLD_LAZY);
  }
#endif
}

static void DynaClose(void)
{
#if defined(HAVE_DLOPEN) || defined(HAVE_LIBDL)
  if (libldap) {
    dlclose(libldap);
  }
  if (liblber) {
    dlclose(liblber);
  }
#endif
}

static void * DynaGetFunction(char *name)
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
  struct UrlData *data = (struct UrlData *)param;
  
  printf("%s\n", text);
  return 0;
}

/***********************************************************************
 */
UrgError ldap(struct UrlData *data, char *path, long *bytecount)
{
  UrgError status = URG_OK;
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
#if 0
  char *dn;
  char **attrArray;
  char *attrIterator;
  char *attrString;
  void *dummy;
#endif
  int ldaptext;
  
  infof(data, "LDAP: %s %s\n", data->url);

  DynaOpen();
  if (libldap == NULL) {
    failf(data, "The needed LDAP library/libraries couldn't be opened");
    return URG_LIBRARY_NOT_FOUND;
  }

  ldaptext = data->conf & CONF_FTPASCII; /* This is a dirty hack */
  
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
  
  server = ldap_open(data->hostname, data->port);
  if (server == NULL) {
    failf(data, "LDAP: Cannot connect to %s:%d",
	  data->hostname, data->port);
    status = URG_COULDNT_CONNECT;
  } else {
    rc = ldap_simple_bind_s(server, data->user, data->passwd);
    if (rc != 0) {
      failf(data, "LDAP: %s", ldap_err2string(rc));
      status = URG_LDAP_CANNOT_BIND;
    } else {
      rc = ldap_url_search_s(server, data->url, 0, &result);
      if (rc != 0) {
	failf(data, "LDAP: %s", ldap_err2string(rc));
	status = URG_LDAP_SEARCH_FAILED;
      } else {
	for (entryIterator = ldap_first_entry(server, result);
	     entryIterator;
	     entryIterator = ldap_next_entry(server, entryIterator))
	  {
	    if (ldaptext) {
	      rc = ldap_entry2text(server, NULL, entryIterator, NULL,
				   NULL, NULL, WriteProc, data,
				   "", 0, 0);
	      if (rc != 0) {
		failf(data, "LDAP: %s", ldap_err2string(rc));
		status = URG_LDAP_SEARCH_FAILED;
	      }
	    } else {
	      rc = ldap_entry2html(server, NULL, entryIterator, NULL,
				   NULL, NULL, WriteProc, data,
				   "", 0, 0, NULL, NULL);
	      if (rc != 0) {
		failf(data, "LDAP: %s", ldap_err2string(rc));
		status = URG_LDAP_SEARCH_FAILED;
	      }
	    }
	  }
      }
      ldap_unbind_s(server);
    }
  }
  DynaClose();
  
  return status;
}
