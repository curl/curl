/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

#include "curl_setup.h"

#if defined(__INTEL_COMPILER) && defined(__unix__)

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#endif /* __INTEL_COMPILER && __unix__ */

#define BUILDING_WARNLESS_C 1

#include "warnless.h"

#define CURL_MASK_SCHAR  0x7F
#define CURL_MASK_UCHAR  0xFF

#if (SIZEOF_SHORT == 2)
#  define CURL_MASK_SSHORT  0x7FFF
#  define CURL_MASK_USHORT  0xFFFF
#elif (SIZEOF_SHORT == 4)
#  define CURL_MASK_SSHORT  0x7FFFFFFF
#  define CURL_MASK_USHORT  0xFFFFFFFF
#elif (SIZEOF_SHORT == 8)
#  define CURL_MASK_SSHORT  0x7FFFFFFFFFFFFFFF
#  define CURL_MASK_USHORT  0xFFFFFFFFFFFFFFFF
#else
#  error "SIZEOF_SHORT not defined"
#endif

#if (SIZEOF_INT == 2)
#  define CURL_MASK_SINT  0x7FFF
#  define CURL_MASK_UINT  0xFFFF
#elif (SIZEOF_INT == 4)
#  define CURL_MASK_SINT  0x7FFFFFFF
#  define CURL_MASK_UINT  0xFFFFFFFF
#elif (SIZEOF_INT == 8)
#  define CURL_MASK_SINT  0x7FFFFFFFFFFFFFFF
#  define CURL_MASK_UINT  0xFFFFFFFFFFFFFFFF
#elif (SIZEOF_INT == 16)
#  define CURL_MASK_SINT  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
#  define CURL_MASK_UINT  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
#else
#  error "SIZEOF_INT not defined"
#endif

#if (SIZEOF_LONG == 2)
#  define CURL_MASK_SLONG  0x7FFFL
#  define CURL_MASK_ULONG  0xFFFFUL
#elif (SIZEOF_LONG == 4)
#  define CURL_MASK_SLONG  0x7FFFFFFFL
#  define CURL_MASK_ULONG  0xFFFFFFFFUL
#elif (SIZEOF_LONG == 8)
#  define CURL_MASK_SLONG  0x7FFFFFFFFFFFFFFFL
#  define CURL_MASK_ULONG  0xFFFFFFFFFFFFFFFFUL
#elif (SIZEOF_LONG == 16)
#  define CURL_MASK_SLONG  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL
#  define CURL_MASK_ULONG  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFUL
#else
#  error "SIZEOF_LONG not defined"
#endif

#if (SIZEOF_CURL_OFF_T == 2)
#  define CURL_MASK_SCOFFT  CURL_OFF_T_C(0x7FFF)
#  define CURL_MASK_UCOFFT  CURL_OFF_TU_C(0xFFFF)
#elif (SIZEOF_CURL_OFF_T == 4)
#  define CURL_MASK_SCOFFT  CURL_OFF_T_C(0x7FFFFFFF)
#  define CURL_MASK_UCOFFT  CURL_OFF_TU_C(0xFFFFFFFF)
#elif (SIZEOF_CURL_OFF_T == 8)
#  define CURL_MASK_SCOFFT  CURL_OFF_T_C(0x7FFFFFFFFFFFFFFF)
#  define CURL_MASK_UCOFFT  CURL_OFF_TU_C(0xFFFFFFFFFFFFFFFF)
#elif (SIZEOF_CURL_OFF_T == 16)
#  define CURL_MASK_SCOFFT  CURL_OFF_T_C(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
#  define CURL_MASK_UCOFFT  CURL_OFF_TU_C(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
#else
#  error "SIZEOF_CURL_OFF_T not defined"
#endif

#if (SIZEOF_SIZE_T == SIZEOF_SHORT)
#  define CURL_MASK_SSIZE_T  CURL_MASK_SSHORT
#  define CURL_MASK_USIZE_T  CURL_MASK_USHORT
#elif (SIZEOF_SIZE_T == SIZEOF_INT)
#  define CURL_MASK_SSIZE_T  CURL_MASK_SINT
#  define CURL_MASK_USIZE_T  CURL_MASK_UINT
#elif (SIZEOF_SIZE_T == SIZEOF_LONG)
#  define CURL_MASK_SSIZE_T  CURL_MASK_SLONG
#  define CURL_MASK_USIZE_T  CURL_MASK_ULONG
#elif (SIZEOF_SIZE_T == SIZEOF_CURL_OFF_T)
#  define CURL_MASK_SSIZE_T  CURL_MASK_SCOFFT
#  define CURL_MASK_USIZE_T  CURL_MASK_UCOFFT
#else
#  error "SIZEOF_SIZE_T not defined"
#endif

/*
** unsigned long to unsigned short
*/

unsigned short curlx_ultous(unsigned long ulnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(ulnum <= (unsigned long) CURL_MASK_USHORT);
  return (unsigned short)(ulnum & (unsigned long) CURL_MASK_USHORT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** unsigned long to unsigned char
*/

unsigned char curlx_ultouc(unsigned long ulnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(ulnum <= (unsigned long) CURL_MASK_UCHAR);
  return (unsigned char)(ulnum & (unsigned long) CURL_MASK_UCHAR);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** unsigned long to signed int
*/

int curlx_ultosi(unsigned long ulnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(ulnum <= (unsigned long) CURL_MASK_SINT);
  return (int)(ulnum & (unsigned long) CURL_MASK_SINT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** unsigned size_t to signed curl_off_t
*/

curl_off_t curlx_uztoso(size_t uznum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#elif defined(_MSC_VER)
#  pragma warning(push)
#  pragma warning(disable:4310) /* cast truncates constant value */
#endif

  DEBUGASSERT(uznum <= (size_t) CURL_MASK_SCOFFT);
  return (curl_off_t)(uznum & (size_t) CURL_MASK_SCOFFT);

#if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  pragma warning(pop)
#endif
}

/*
** unsigned size_t to signed int
*/

int curlx_uztosi(size_t uznum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(uznum <= (size_t) CURL_MASK_SINT);
  return (int)(uznum & (size_t) CURL_MASK_SINT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** unsigned size_t to unsigned long
*/

unsigned long curlx_uztoul(size_t uznum)
{
#ifdef __INTEL_COMPILER
# pragma warning(push)
# pragma warning(disable:810) /* conversion may lose significant bits */
#endif

#if (SIZEOF_LONG < SIZEOF_SIZE_T)
  DEBUGASSERT(uznum <= (size_t) CURL_MASK_ULONG);
#endif
  return (unsigned long)(uznum & (size_t) CURL_MASK_ULONG);

#ifdef __INTEL_COMPILER
# pragma warning(pop)
#endif
}

/*
** unsigned size_t to unsigned int
*/

unsigned int curlx_uztoui(size_t uznum)
{
#ifdef __INTEL_COMPILER
# pragma warning(push)
# pragma warning(disable:810) /* conversion may lose significant bits */
#endif

#if (SIZEOF_INT < SIZEOF_SIZE_T)
  DEBUGASSERT(uznum <= (size_t) CURL_MASK_UINT);
#endif
  return (unsigned int)(uznum & (size_t) CURL_MASK_UINT);

#ifdef __INTEL_COMPILER
# pragma warning(pop)
#endif
}

/*
** signed long to signed int
*/

int curlx_sltosi(long slnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(slnum >= 0);
#if (SIZEOF_INT < SIZEOF_LONG)
  DEBUGASSERT((unsigned long) slnum <= (unsigned long) CURL_MASK_SINT);
#endif
  return (int)(slnum & (long) CURL_MASK_SINT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** signed long to unsigned int
*/

unsigned int curlx_sltoui(long slnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(slnum >= 0);
#if (SIZEOF_INT < SIZEOF_LONG)
  DEBUGASSERT((unsigned long) slnum <= (unsigned long) CURL_MASK_UINT);
#endif
  return (unsigned int)(slnum & (long) CURL_MASK_UINT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** signed long to unsigned short
*/

unsigned short curlx_sltous(long slnum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(slnum >= 0);
  DEBUGASSERT((unsigned long) slnum <= (unsigned long) CURL_MASK_USHORT);
  return (unsigned short)(slnum & (long) CURL_MASK_USHORT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** unsigned size_t to signed ssize_t
*/

ssize_t curlx_uztosz(size_t uznum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(uznum <= (size_t) CURL_MASK_SSIZE_T);
  return (ssize_t)(uznum & (size_t) CURL_MASK_SSIZE_T);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** signed curl_off_t to unsigned size_t
*/

size_t curlx_sotouz(curl_off_t sonum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(sonum >= 0);
  return (size_t)(sonum & (curl_off_t) CURL_MASK_USIZE_T);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** signed ssize_t to signed int
*/

int curlx_sztosi(ssize_t sznum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(sznum >= 0);
#if (SIZEOF_INT < SIZEOF_SIZE_T)
  DEBUGASSERT((size_t) sznum <= (size_t) CURL_MASK_SINT);
#endif
  return (int)(sznum & (ssize_t) CURL_MASK_SINT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** unsigned int to unsigned short
*/

unsigned short curlx_uitous(unsigned int uinum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(uinum <= (unsigned int) CURL_MASK_USHORT);
  return (unsigned short) (uinum & (unsigned int) CURL_MASK_USHORT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

/*
** signed int to unsigned size_t
*/

size_t curlx_sitouz(int sinum)
{
#ifdef __INTEL_COMPILER
#  pragma warning(push)
#  pragma warning(disable:810) /* conversion may lose significant bits */
#endif

  DEBUGASSERT(sinum >= 0);
  return (size_t) sinum;

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
#endif
}

#ifdef USE_WINSOCK

/*
** curl_socket_t to signed int
*/

int curlx_sktosi(curl_socket_t s)
{
  return (int)((ssize_t) s);
}

/*
** signed int to curl_socket_t
*/

curl_socket_t curlx_sitosk(int i)
{
  return (curl_socket_t)((ssize_t) i);
}

#endif /* USE_WINSOCK */

#if defined(WIN32) || defined(_WIN32)

ssize_t curlx_read(int fd, void *buf, size_t count)
{
  return (ssize_t)read(fd, buf, curlx_uztoui(count));
}

ssize_t curlx_write(int fd, const void *buf, size_t count)
{
  return (ssize_t)write(fd, buf, curlx_uztoui(count));
}

#endif /* WIN32 || _WIN32 */

#if defined(__INTEL_COMPILER) && defined(__unix__)

int curlx_FD_ISSET(int fd, fd_set *fdset)
{
  #pragma warning(push)
  #pragma warning(disable:1469) /* clobber ignored */
  return FD_ISSET(fd, fdset);
  #pragma warning(pop)
}

void curlx_FD_SET(int fd, fd_set *fdset)
{
  #pragma warning(push)
  #pragma warning(disable:1469) /* clobber ignored */
  FD_SET(fd, fdset);
  #pragma warning(pop)
}

void curlx_FD_ZERO(fd_set *fdset)
{
  #pragma warning(push)
  #pragma warning(disable:593) /* variable was set but never used */
  FD_ZERO(fdset);
  #pragma warning(pop)
}

unsigned short curlx_htons(unsigned short usnum)
{
#if (__INTEL_COMPILER == 910) && defined(__i386__)
  return (unsigned short)(((usnum << 8) & 0xFF00) | ((usnum >> 8) & 0x00FF));
#else
  #pragma warning(push)
  #pragma warning(disable:810) /* conversion may lose significant bits */
  return htons(usnum);
  #pragma warning(pop)
#endif
}

unsigned short curlx_ntohs(unsigned short usnum)
{
#if (__INTEL_COMPILER == 910) && defined(__i386__)
  return (unsigned short)(((usnum << 8) & 0xFF00) | ((usnum >> 8) & 0x00FF));
#else
  #pragma warning(push)
  #pragma warning(disable:810) /* conversion may lose significant bits */
  return ntohs(usnum);
  #pragma warning(pop)
#endif
}

#endif /* __INTEL_COMPILER && __unix__ */
