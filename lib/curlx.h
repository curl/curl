#ifndef HEADER_FETCH_FETCHX_H
#define HEADER_FETCH_FETCHX_H
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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

/*
 * Defines protos and includes all header files that provide the fetchx_*
 * functions. The fetchx_* functions are not part of the libfetch API, but are
 * stand-alone functions whose sources can be built and linked by apps if need
 * be.
 */

/* map standard printf functions to fetch implementations */
#include "fetch_printf.h"

#include "strcase.h"
/* "strcase.h" provides the strcasecompare protos */

#include "strtoofft.h"
/* "strtoofft.h" provides this function: fetchx_strtoofft(), returns a
   fetch_off_t number from a given string.
*/

#include "nonblock.h"
/* "nonblock.h" provides fetchx_nonblock() */

#include "warnless.h"
/* "warnless.h" provides functions:

  fetchx_ultous()
  fetchx_ultouc()
  fetchx_uztosi()
*/

#include "fetch_multibyte.h"
/* "fetch_multibyte.h" provides these functions and macros:

  fetchx_convert_UTF8_to_wchar()
  fetchx_convert_wchar_to_UTF8()
  fetchx_convert_UTF8_to_tchar()
  fetchx_convert_tchar_to_UTF8()
  fetchx_unicodefree()
*/

#include "version_win32.h"
/* "version_win32.h" provides fetchx_verify_windows_version() */

#endif /* HEADER_FETCH_FETCHX_H */
