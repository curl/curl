#ifndef __SETUP_H
#define __SETUP_H
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
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
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

#include <stdio.h>

#if !defined(WIN32) && defined(_WIN32)
/* This _might_ be a good Borland fix. Please report whether this works or
   not! */
#define WIN32
#endif

#ifdef HAVE_CONFIG_H
#include "config.h" /* the configure script results */
#else
#ifdef WIN32
/* include the hand-modified win32 adjusted config.h! */
#include "../config-win32.h"
#endif
#endif



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
#include "curl/stdcheaders.h"
#else
#ifdef _AIX
#include "curl/stdcheaders.h"
#endif
#endif

#if 0 /* zlib experiments are halted 17th october, 1999 (Daniel) */
#if defined(HAVE_ZLIB_H) && defined(HAVE_LIBZ)
     /* Both lib and header file exist, we have libz! */
#define USE_ZLIB
#endif
#endif

#ifdef HAVE_STRCASECMP
#define strnequal(x,y,z) !(strncasecmp)(x,y,z)
#define strequal(x,y) !(strcasecmp)(x,y)

#else
#define strnequal(x,y,z) !strnicmp(x,y,z)
#define strequal(x,y) !stricmp(x,y)
#endif

/* Below we define four functions. They should
   1. close a socket
   2. read from a socket
   3. write to a socket
   (Hopefully, only win32-crap do this weird name changing)

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
#define sread(x,y,z) read(x,y,z)
#define swrite(x,y,z) write(x,y,z)
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

/*
 * FIXME: code for getting a passwd in windows/non termcap/signal systems?
 */
#ifndef WIN32
#define get_password(x) getpass(x)
#else
#define get_password(x) 
#endif

#endif /* __CONFIG_H */
