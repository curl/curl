#ifndef __STREQUAL_H
#define __STREQUAL_H
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

/*
 * These two actually are public functions.
 */
int curl_strequal(const char *first, const char *second);
int curl_strnequal(const char *first, const char *second, size_t max);

#define strequal(a,b) curl_strequal(a,b)
#define strnequal(a,b,c) curl_strnequal(a,b,c)

/* checkprefix() is a shorter version of the above, used when the first
   argument is zero-byte terminated */
#define checkprefix(a,b)    strnequal(a,b,strlen(a))

#ifndef HAVE_STRLCAT
#define strlcat(x,y,z) Curl_strlcat(x,y,z)
size_t Curl_strlcat(char *dst, const char *src, size_t siz);
#endif

#endif
