#ifndef __SETUP_H
#define __SETUP_H
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

/* MN 06/07/02 */
/* #define HTTP_ONLY
*/
#ifdef HTTP_ONLY
#define CURL_DISABLE_FTP
#define CURL_DISABLE_LDAP
#define CURL_DISABLE_TELNET
#define CURL_DISABLE_DICT
#define CURL_DISABLE_FILE
#define CURL_DISABLE_GOPHER
#endif

#if !defined(WIN32) && defined(_WIN32)
/* This _might_ be a good Borland fix. Please report whether this works or
   not! */
#define WIN32
#endif

#ifdef HAVE_CONFIG_H

#ifdef VMS
#include "config-vms.h"
#else
#include "config.h" /* the configure script results */
#endif

#else
#ifdef WIN32
/* hand-modified win32 config.h! */
#include "config-win32.h"
#endif
#ifdef macintosh
/* hand-modified MacOS config.h! */
#include "config-mac.h"
#endif

#endif

#ifndef __cplusplus        /* (rabe) */
typedef unsigned char bool;
#define typedef_bool
#endif                     /* (rabe) */

#ifdef NEED_REENTRANT
/* Solaris machines needs _REENTRANT set for a few function prototypes and
   things to appear in the #include files. We need to #define it before all
   #include files */
#define _REENTRANT
#endif


#include <stdio.h>
#ifndef OS
#ifdef WIN32
#define OS "win32"
#else
#define OS "unknown"
#endif
#endif

#if defined(HAVE_X509_H) && defined(HAVE_SSL_H) && defined(HAVE_RSA_H) && \
defined(HAVE_PEM_H) && defined(HAVE_ERR_H) && defined(HAVE_CRYPTO_H) && \
defined(HAVE_LIBSSL) && defined(HAVE_LIBCRYPTO)
  /* the six important includes files all exist and so do both libs,
     defined SSLeay usage */
#define USE_SSLEAY 1
#endif
#if defined(HAVE_OPENSSL_X509_H) && defined(HAVE_OPENSSL_SSL_H) && \
defined(HAVE_OPENSSL_RSA_H) && defined(HAVE_OPENSSL_PEM_H) && \
defined(HAVE_OPENSSL_ERR_H) && defined(HAVE_OPENSSL_CRYPTO_H) && \
defined(HAVE_LIBSSL) && defined(HAVE_LIBCRYPTO)
  /* the six important includes files all exist and so do both libs,
     defined SSLeay usage */
#define USE_SSLEAY 1
#define USE_OPENSSL 1
#endif

#ifndef STDC_HEADERS /* no standard C headers! */
#ifdef	VMS
#include "../include/curl/stdcheaders.h"
#else
#include <curl/stdcheaders.h>
#endif

#else
#ifdef _AIX
#include <curl/stdcheaders.h>
#endif
#endif

/* Below we define four functions. They should
   1. close a socket
   2. read from a socket
   3. write to a socket

   4. set the SIGALRM signal timeout
   5. set dir/file naming defines
   */

#ifdef WIN32
#if !defined(__GNUC__) || defined(__MINGW32__)
#define sclose(x) closesocket(x)
#define sread(x,y,z) recv(x,y,z,0)
#define swrite(x,y,z) (size_t)send(x,y,z,0)
#undef HAVE_ALARM
#else
     /* gcc-for-win is still good :) */
#define sclose(x) close(x)
#define sread(x,y,z) recv(x,y,z,0)
#define swrite(x,y,z) send(x,y,z,0)
#define HAVE_ALARM
#endif

#define PATH_CHAR     ";"
#define DIR_CHAR      "\\"
#define DOT_CHAR      "_"

#else
#define sclose(x) close(x)
#define sread(x,y,z) recv(x,y,z,0)
#define swrite(x,y,z) send(x,y,z,0)
#define HAVE_ALARM

#define PATH_CHAR     ":"
#define DIR_CHAR      "/"
#define DOT_CHAR      "."

#ifdef HAVE_STRCASECMP
/* this is for "-ansi -Wall -pedantic" to stop complaining! */
extern int (strcasecmp)(const char *s1, const char *s2);
extern int (strncasecmp)(const char *s1, const char *s2, size_t n);
#ifndef fileno /* sunos 4 have this as a macro! */
int fileno( FILE *stream);
#endif
#endif

#endif

/*
 * Curl_addrinfo MUST be used for name resolving information.
 * Information regarding a single IP witin a Curl_addrinfo MUST be stored in
 * a Curl_ipconnect struct.
 */
#ifdef ENABLE_IPV6
typedef struct addrinfo Curl_addrinfo;
typedef struct addrinfo Curl_ipconnect;
#else
typedef struct hostent Curl_addrinfo;
typedef struct in_addr Curl_ipconnect;
#endif



#endif /* __CONFIG_H */
