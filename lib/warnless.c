/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"

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

#if (CURL_SIZEOF_LONG == 2)
#  define CURL_MASK_SLONG  0x7FFFL
#  define CURL_MASK_ULONG  0xFFFFUL
#elif (CURL_SIZEOF_LONG == 4)
#  define CURL_MASK_SLONG  0x7FFFFFFFL
#  define CURL_MASK_ULONG  0xFFFFFFFFUL
#elif (CURL_SIZEOF_LONG == 8)
#  define CURL_MASK_SLONG  0x7FFFFFFFFFFFFFFFL
#  define CURL_MASK_ULONG  0xFFFFFFFFFFFFFFFFUL
#elif (CURL_SIZEOF_LONG == 16)
#  define CURL_MASK_SLONG  0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFL
#  define CURL_MASK_ULONG  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFUL
#else
#  error "CURL_SIZEOF_LONG not defined"
#endif

#if (CURL_SIZEOF_CURL_OFF_T == 2)
#  define CURL_MASK_SCOFFT  CURL_OFF_T_C(0x7FFF)
#  define CURL_MASK_UCOFFT  CURL_OFF_TU_C(0xFFFF)
#elif (CURL_SIZEOF_CURL_OFF_T == 4)
#  define CURL_MASK_SCOFFT  CURL_OFF_T_C(0x7FFFFFFF)
#  define CURL_MASK_UCOFFT  CURL_OFF_TU_C(0xFFFFFFFF)
#elif (CURL_SIZEOF_CURL_OFF_T == 8)
#  define CURL_MASK_SCOFFT  CURL_OFF_T_C(0x7FFFFFFFFFFFFFFF)
#  define CURL_MASK_UCOFFT  CURL_OFF_TU_C(0xFFFFFFFFFFFFFFFF)
#elif (CURL_SIZEOF_CURL_OFF_T == 16)
#  define CURL_MASK_SCOFFT  CURL_OFF_T_C(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
#  define CURL_MASK_UCOFFT  CURL_OFF_TU_C(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
#else
#  error "CURL_SIZEOF_CURL_OFF_T not defined"
#endif

#if (SIZEOF_SIZE_T == SIZEOF_SHORT)
#  define CURL_MASK_SSIZE_T  CURL_MASK_SSHORT
#  define CURL_MASK_USIZE_T  CURL_MASK_USHORT
#elif (SIZEOF_SIZE_T == SIZEOF_INT)
#  define CURL_MASK_SSIZE_T  CURL_MASK_SINT
#  define CURL_MASK_USIZE_T  CURL_MASK_UINT
#elif (SIZEOF_SIZE_T == CURL_SIZEOF_LONG)
#  define CURL_MASK_SSIZE_T  CURL_MASK_SLONG
#  define CURL_MASK_USIZE_T  CURL_MASK_ULONG
#elif (SIZEOF_SIZE_T == CURL_SIZEOF_CURL_OFF_T)
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

  return (unsigned char)(ulnum & (unsigned long) CURL_MASK_UCHAR);

#ifdef __INTEL_COMPILER
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

  return (int)(uznum & (size_t) CURL_MASK_SINT);

#ifdef __INTEL_COMPILER
#  pragma warning(pop)
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
