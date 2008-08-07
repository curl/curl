#ifndef __CURL_CURLRULES_H
#define __CURL_CURLRULES_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2008, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* ================================================================ */
/*                    COMPILE TIME SANITY CHECKS                    */
/* ================================================================ */

/*
 * NOTE 1:
 * -------
 *
 * All checks done in this file are intentionally placed in a public
 * header file which is pulled by curl/curl.h when an application is
 * being built using an already built libcurl library. Additionally
 * this file is also included and used when building the library.
 *
 * If compilation fails on this file it is certainly sure that the
 * problem is elsewhere. It could be a problem in the curlbuild.h
 * header file, or simply that you are using different compilation
 * settings than those used to build the library.
 *
 * Nothing in this file is intended to be modified or adjusted by the
 * curl library user nor by the curl library builder.
 *
 * Do not deactivate any check, these are done to make sure that the
 * library is properly built and used.
 *
 * You can find further help on the libcurl development mailing list:
 * http://cool.haxx.se/mailman/listinfo/curl-library/
 *
 * NOTE 2
 * ------
 *
 * Some of the following compile time checks are based on the fact
 * that the dimension of a constant array can not be a negative one.
 * In this way if the compile time verification fails, the compilation
 * will fail issuing an error. The error description wording is compiler
 * dependant but it will be quite similar to one of the following:
 *
 *   "negative subscript or subscript is too large"
 *   "array must have at least one element"
 *   "-1 is an illegal array size"
 *   "size of array is negative"
 *
 * If you are building an application which tries to use an already
 * built libcurl library and you are getting this kind of errors on
 * this file, it is a clear indication that there is a mismatch between
 * how the library was built and how you are trying to use it for your
 * application. Your already compiled or binary library provider is the
 * only one who can give you the details you need to properly use it.
 */

/*
 * Verify that some macros are actually defined.
 */

#ifndef CURL_OFF_T
#  error "CURL_OFF_T definition is missing!"
   Error Compilation_aborted_CURL_OFF_T_is_missing
#endif

#ifndef CURL_FMT_OFF_T
#  error "CURL_FMT_OFF_T definition is missing!"
   Error Compilation_aborted_CURL_FMT_OFF_T_is_missing
#endif

#ifndef CURL_FMT_OFF_TU
#  error "CURL_FMT_OFF_TU definition is missing!"
   Error Compilation_aborted_CURL_FMT_OFF_TU_is_missing
#endif

#ifndef CURL_FORMAT_OFF_T
#  error "CURL_FORMAT_OFF_T definition is missing!"
   Error Compilation_aborted_CURL_FORMAT_OFF_T_is_missing
#endif

#ifndef CURL_SIZEOF_CURL_OFF_T
#  error "CURL_SIZEOF_CURL_OFF_T definition is missing!"
   Error Compilation_aborted_CURL_SIZEOF_CURL_OFF_T_is_missing
#endif

/*
 * Macros private to this header file.
 */

#define CurlchkszEQ(t, s) sizeof(t) == s ? 1 : -1

#define CurlchkszGE(t1, t2) sizeof(t1) >= sizeof(t2) ? 1 : -1

/*
 * Verify that the size previously defined and expected for
 * curl_off_t is actually the the same as the one reported
 * by sizeof() at compile time.
 */

typedef char
  __curl_rule_01__
    [CurlchkszEQ(curl_off_t, CURL_SIZEOF_CURL_OFF_T)];

/*
 * Verify at compile time that the size of curl_off_t as reported
 * by sizeof() is greater or equal than the one reported for long
 * for the current compilation.
 */

typedef char
  __curl_rule_02__
    [CurlchkszGE(curl_off_t, long)];

/*
 * Get rid of macros private to this header file.
 */

#undef CurlchkszEQ
#undef CurlchkszGE

/*
 * Get rid of macros not intended to exist beyond this point.
 */

#undef CURL_PULL_SYS_TYPES_H
#undef CURL_PULL_STDINT_H
#undef CURL_PULL_INTTYPES_H

#undef CURL_OFF_T

#endif /* __CURL_CURLRULES_H */
