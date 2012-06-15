#ifndef HEADER_CURL_MULTIBYTE_H
#define HEADER_CURL_MULTIBYTE_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(USE_WIN32_IDN) || \
   (defined(USE_WINDOWS_SSPI) && (defined(_WIN32_WCE) || defined(UNICODE)))

 /*
  * MultiByte conversions using Windows kernel32 library.
  */

#include <tchar.h>

wchar_t *Curl_convert_UTF8_to_wchar(const char *str_utf8);
const char *Curl_convert_wchar_to_UTF8(const wchar_t *str_w);

#endif /* USE_WIN32_IDN || (USE_WINDOWS_SSPI && (_WIN32_WCE || UNICODE)) */

#endif /* HEADER_CURL_MULTIBYTE_H */
