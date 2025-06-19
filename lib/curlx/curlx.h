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

#include "binmode.h"
/* "binmode.h" provides macro CURLX_SET_BINMODE() */

#include "nonblock.h"
/* "nonblock.h" provides curlx_nonblock() */

#include "warnless.h"
/* "warnless.h" provides functions:

  curlx_ultous()
  curlx_ultouc()
  curlx_uztosi()
*/

#include "multibyte.h"
/* "multibyte.h" provides these functions and macros:

  curlx_convert_UTF8_to_wchar()
  curlx_convert_wchar_to_UTF8()
  curlx_convert_UTF8_to_tchar()
  curlx_convert_tchar_to_UTF8()
  curlx_unicodefree()
*/

#include "version_win32.h"
/* provides curlx_verify_windows_version() */

#include "strparse.h"
/* The curlx_str_* parsing functions */

#include "dynbuf.h"
/* The curlx_dyn_* functions */

#include "base64.h"
#include "timeval.h"
#include "timediff.h"

#include "wait.h"
/* for curlx_wait_ms */

#include "winapi.h"
/* for curlx_winapi_strerror */

#include "inet_pton.h"
/* for curlx_inet_pton */

#include "inet_ntop.h"
/* for curlx_inet_ntop */

#endif /* HEADER_CURL_CURLX_H */
