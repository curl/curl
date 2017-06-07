#ifndef HEADER_CURL_WARNLESS_H
#define HEADER_CURL_WARNLESS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#ifdef USE_WINSOCK
#include <curl/curl.h> /* for curl_socket_t */
#endif

unsigned short Curl_ultous(unsigned long ulnum);
unsigned char Curl_ultouc(unsigned long ulnum);
int Curl_ultosi(unsigned long ulnum);
int Curl_uztosi(size_t uznum);
curl_off_t Curl_uztoso(size_t uznum);
unsigned long Curl_uztoul(size_t uznum);
unsigned int Curl_uztoui(size_t uznum);
int Curl_sltosi(long slnum);
unsigned int Curl_sltoui(long slnum);
unsigned short Curl_sltous(long slnum);
ssize_t Curl_uztosz(size_t uznum);
size_t Curl_sotouz(curl_off_t sonum);
int Curl_sztosi(ssize_t sznum);
unsigned short Curl_uitous(unsigned int uinum);
unsigned char Curl_uitouc(unsigned int uinum);
int Curl_uitosi(unsigned int uinum);
size_t Curl_sitouz(int sinum);

#ifdef USE_WINSOCK
int Curl_sktosi(curl_socket_t s);
curl_socket_t Curl_sitosk(int i);
#endif /* USE_WINSOCK */

#if defined(WIN32) || defined(_WIN32)
ssize_t Curl_read(int fd, void *buf, size_t count);
ssize_t Curl_write(int fd, const void *buf, size_t count);

#ifndef BUILDING_WARNLESS_C
#  undef  read
#  define read(fd, buf, count)  Curl_read(fd, buf, count)
#  undef  write
#  define write(fd, buf, count) Curl_write(fd, buf, count)
#endif

#endif /* WIN32 || _WIN32 */

#if defined(__INTEL_COMPILER) && defined(__unix__)
int Curl_FD_ISSET(int fd, fd_set *fdset);
void Curl_FD_SET(int fd, fd_set *fdset);
void Curl_FD_ZERO(fd_set *fdset);
unsigned short Curl_htons(unsigned short usnum);
unsigned short Curl_ntohs(unsigned short usnum);

#ifndef BUILDING_WARNLESS_C
#  undef  FD_ISSET
#  define FD_ISSET(a,b) Curl_FD_ISSET((a),(b))
#  undef  FD_SET
#  define FD_SET(a,b)   Curl_FD_SET((a),(b))
#  undef  FD_ZERO
#  define FD_ZERO(a)    Curl_FD_ZERO((a))
#  undef  htons
#  define htons(a)      Curl_htons((a))
#  undef  ntohs
#  define ntohs(a)      Curl_ntohs((a))
#endif

#endif /* __INTEL_COMPILER && __unix__ */
#endif /* HEADER_CURL_WARNLESS_H */
