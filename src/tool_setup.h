#ifndef HEADER_CURL_TOOL_SETUP_H
#define HEADER_CURL_TOOL_SETUP_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#define CURL_NO_OLDIES

/*
 * curl_setup.h may define preprocessor macros such as _FILE_OFFSET_BITS and
 * _LARGE_FILES in order to support files larger than 2 GB. On platforms
 * where this happens it is mandatory that these macros are defined before
 * any system header file is included, otherwise file handling function
 * prototypes will be misdeclared and curl tool may not build properly;
 * therefore we must include curl_setup.h before curl.h when building curl.
 */

#include "curl_setup.h" /* from the lib directory */

extern FILE *tool_stderr;

/*
 * curl tool certainly uses libcurl's external interface.
 */

#include <curl/curl.h> /* external interface */

/*
 * Platform specific stuff.
 */

#ifdef macintosh
#  define main(x,y) curl_main(x,y)
#endif

#ifndef OS
#  define OS "unknown"
#endif

#ifndef UNPRINTABLE_CHAR
   /* define what to use for unprintable characters */
#  define UNPRINTABLE_CHAR '.'
#endif

#ifndef HAVE_STRDUP
#  include "tool_strdup.h"
#endif

#if defined(_WIN32)
/* set in win32_init() */
extern LARGE_INTEGER tool_freq;
extern bool tool_isVistaOrGreater;
/* set in init_terminal() */
extern bool tool_term_has_bold;
#endif

#if defined(_WIN32) && !defined(HAVE_FTRUNCATE)

int tool_ftruncate64(int fd, curl_off_t where);

#undef  ftruncate
#define ftruncate(fd,where) tool_ftruncate64(fd,where)

#define HAVE_FTRUNCATE 1
#define USE_TOOL_FTRUNCATE 1

#endif /* _WIN32 && ! HAVE_FTRUNCATE */


#endif /* HEADER_CURL_TOOL_SETUP_H */
