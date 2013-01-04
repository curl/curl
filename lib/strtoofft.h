#ifndef HEADER_CURL_STRTOOFFT_H
#define HEADER_CURL_STRTOOFFT_H
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

/*
 * Determine which string to integral data type conversion function we use
 * to implement string conversion to our curl_off_t integral data type.
 *
 * Notice that curl_off_t might be 64 or 32 bit wide, and that it might use
 * an underlying data type which might be 'long', 'int64_t', 'long long' or
 * '__int64' and more remotely other data types.
 *
 * On systems where the size of curl_off_t is greater than the size of 'long'
 * the conversion function to use is strtoll() if it is available, otherwise,
 * we emulate its functionality with our own clone.
 *
 * On systems where the size of curl_off_t is smaller or equal than the size
 * of 'long' the conversion function to use is strtol().
 */

#if (CURL_SIZEOF_CURL_OFF_T > CURL_SIZEOF_LONG)
#  ifdef HAVE_STRTOLL
#    define curlx_strtoofft strtoll
#  else
#    if defined(_MSC_VER) && (_MSC_VER >= 1300) && (_INTEGRAL_MAX_BITS >= 64)
       _CRTIMP __int64 __cdecl _strtoi64(const char *, char **, int);
#      define curlx_strtoofft _strtoi64
#    else
       curl_off_t curlx_strtoll(const char *nptr, char **endptr, int base);
#      define curlx_strtoofft curlx_strtoll
#      define NEED_CURL_STRTOLL 1
#    endif
#  endif
#else
#  define curlx_strtoofft strtol
#endif

#if (CURL_SIZEOF_CURL_OFF_T == 4)
#  define CURL_OFF_T_MAX CURL_OFF_T_C(0x7FFFFFFF)
#else
   /* assume CURL_SIZEOF_CURL_OFF_T == 8 */
#  define CURL_OFF_T_MAX CURL_OFF_T_C(0x7FFFFFFFFFFFFFFF)
#endif
#define CURL_OFF_T_MIN (-CURL_OFF_T_MAX - CURL_OFF_T_C(1))

#endif /* HEADER_CURL_STRTOOFFT_H */
