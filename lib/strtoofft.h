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

#ifndef _CURL_STRTOOFFT_R_H
#define _CURL_STRTOOFFT_R_H

#include "setup.h"
#include <stddef.h>

/* Determine what type of file offset conversion handling we wish to use.  For
 * systems with a 32-bit curl_off_t type, we should use strtol.  For systems
 * with a 64-bit curl_off_t type, we should use strtoll if it exists, and if
 * not, should try to emulate its functionality.  At any rate, we define
 * 'strtoofft' such that it can be used to work with curl_off_t's regardless.
 */
#if SIZEOF_CURL_OFF_T > 4
#if HAVE_STRTOLL
#define strtoofft strtoll
#else
long long Curl_strtoll(const char *nptr, char **endptr, int base);
#define strtoofft Curl_strtoll
#define NEED_CURL_STRTOLL
#endif
#else
#define strtoofft strtol
#endif

#endif

