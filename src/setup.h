#ifndef __CLIENT_SETUP_H
#define __CLIENT_SETUP_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2003, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if !defined(WIN32) && defined(__WIN32__)
/* Borland fix */
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
#include "config-win32.h"
#endif
#ifdef macintosh
/* this is not the same as Mac OS X */
#include "config-mac.h"
#endif
#ifdef __riscos__
#include "config-riscos.h"
#endif
#endif

#ifdef CURLDEBUG
/* This is an ugly hack for CURLDEBUG conditions only. We need to include
   the file here, since it might set the _FILE_OFFSET_BITS define, which must
   be set BEFORE all normal system headers. */
#include "../lib/setup.h"
#endif

#include <stdio.h>

#ifndef OS
#define OS "unknown"
#endif

#if !defined(fileno) && !defined(WIN32) /* sunos 4 have this as a macro! */
int fileno( FILE *stream);
#endif

#ifdef WIN32
#define DIR_CHAR      "\\"
#define DOT_CHAR      "_"
#else
#ifdef __EMX__
/* 20000318 mgs
 * OS/2 supports leading dots in filenames if the volume is formatted
 * with JFS or HPFS. */
#define DIR_CHAR      "\\"
#define DOT_CHAR      "."
#else

#ifdef DJGPP
#include <tcp.h>
#ifdef word
#undef word
#endif
#define DIR_CHAR      "/"
#define DOT_CHAR      "_"
#else

#define DIR_CHAR      "/"
#define DOT_CHAR      "."

#endif /* !DJGPP */
#endif /* !__EMX__ */
#endif /* !WIN32 */

#ifdef __riscos__
#define USE_ENVIRONMENT
#endif

#endif /* __SETUP_H */
