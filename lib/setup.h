#ifndef __SETUP_H
#define __SETUP_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/



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
/* include the hand-modified win32 adjusted config.h! */
#include "../config-win32.h"
#endif
#endif

#ifndef __cplusplus        /* (rabe) */
typedef char bool;
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
#include "curl/stdcheaders.h"
#endif
#else
#ifdef _AIX
#include "curl/stdcheaders.h"
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
#define myalarm(x) /* win32 is a silly system */
#else
     /* gcc-for-win is still good :) */
#define sclose(x) close(x)
#define sread(x,y,z) recv(x,y,z,0)
#define swrite(x,y,z) send(x,y,z,0)
#define myalarm(x) alarm(x)
#endif

#define PATH_CHAR     ";"
#define DIR_CHAR      "\\"
#define DOT_CHAR      "_"

#else
#define sclose(x) close(x)
#define sread(x,y,z) read(x,y,z)
#define swrite(x,y,z) write(x,y,z)
#define myalarm(x) alarm(x)

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

#endif /* __CONFIG_H */
