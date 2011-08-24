#ifndef HEADER_CURL_WARNLESS_H
#define HEADER_CURL_WARNLESS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

unsigned short curlx_ultous(unsigned long ulnum);

unsigned char curlx_ultouc(unsigned long ulnum);

int curlx_uztosi(size_t uznum);

int curlx_sltosi(long slnum);

unsigned int curlx_sltoui(long slnum);

unsigned short curlx_sltous(long slnum);

ssize_t curlx_uztosz(size_t uznum);

size_t curlx_sotouz(curl_off_t sonum);

size_t curlx_sitouz(int sinum);

#if defined(__INTEL_COMPILER) && defined(__unix__)

int curlx_FD_ISSET(int fd, fd_set *fdset);

void curlx_FD_SET(int fd, fd_set *fdset);

void curlx_FD_ZERO(fd_set *fdset);

unsigned short curlx_htons(unsigned short usnum);

unsigned short curlx_ntohs(unsigned short usnum);

#ifndef BUILDING_WARNLESS_C
#  undef  FD_ISSET
#  define FD_ISSET(a,b) curlx_FD_ISSET((a),(b))
#  undef  FD_SET
#  define FD_SET(a,b)   curlx_FD_SET((a),(b))
#  undef  FD_ZERO
#  define FD_ZERO(a)    curlx_FD_ZERO((a))
#  undef  htons
#  define htons(a)      curlx_htons((a))
#  undef  ntohs
#  define ntohs(a)      curlx_ntohs((a))
#endif

#endif /* __INTEL_COMPILER && __unix__ */

#endif /* HEADER_CURL_WARNLESS_H */
