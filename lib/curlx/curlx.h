#ifndef HEADER_CURL_CURLX_H
#define HEADER_CURL_CURLX_H
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

/*
 * Defines protos and includes all header files that provide the curlx_*
 * functions. The curlx_* functions are not part of the libcurl API, but are
 * stand-alone functions whose sources can be built and linked by apps if need
 * be.
 */

#include "base64.h" /* for curlx_base64* */
#include "basename.h" /* for curlx_basename() */
#include "binmode.h" /* for macro CURLX_SET_BINMODE() */
#include "dynbuf.h" /* for curlx_dyn_*() */
#include "fopen.h" /* for curlx_f*() */
#include "inet_ntop.h" /* for curlx_inet_ntop() */
#include "inet_pton.h" /* for curlx_inet_pton() */
#include "multibyte.h" /* for curlx_convert_*() */
#include "nonblock.h" /* for curlx_nonblock() */
#include "strcopy.h" /* for curlx_strcopy() */
#include "strdup.h" /* for curlx_memdup*() and curlx_tcsdup() */
#include "strerr.h" /* for curlx_strerror() */
#include "strparse.h" /* for curlx_str_* parsing functions */
#include "timediff.h" /* for timediff_t type and related functions */
#include "timeval.h" /* for curlx_now type and related functions */
#include "version_win32.h" /* for curlx_verify_windows_version() */
#include "wait.h" /* for curlx_wait_ms() */
#include "winapi.h" /* for curlx_winapi_strerror() */

#endif /* HEADER_CURL_CURLX_H */
