/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#include <curl/curl.h>

#if defined(USE_WIN32_IDN) || ((defined(USE_WINDOWS_SSPI) || \
                                defined(USE_WIN32_LDAP)) && defined(UNICODE))

 /*
  * MultiByte conversions using Windows kernel32 library.
  */

#include "curl_multibyte.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

wchar_t *Curl_convert_UTF8_to_wchar(const char *str_utf8)
{
  wchar_t *str_w = NULL;

  if(str_utf8) {
    int str_w_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                        str_utf8, -1, NULL, 0);
    if(str_w_len > 0) {
      str_w = malloc(str_w_len * sizeof(wchar_t));
      if(str_w) {
        if(MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, str_w,
                               str_w_len) == 0) {
          free(str_w);
          return NULL;
        }
      }
    }
  }

  return str_w;
}

char *Curl_convert_wchar_to_UTF8(const wchar_t *str_w)
{
  char *str_utf8 = NULL;

  if(str_w) {
    int bytes = WideCharToMultiByte(CP_UTF8, 0, str_w, -1,
                                    NULL, 0, NULL, NULL);
    if(bytes > 0) {
      str_utf8 = malloc(bytes);
      if(str_utf8) {
        if(WideCharToMultiByte(CP_UTF8, 0, str_w, -1, str_utf8, bytes,
                               NULL, NULL) == 0) {
          free(str_utf8);
          return NULL;
        }
      }
    }
  }

  return str_utf8;
}

#endif /* USE_WIN32_IDN || ((USE_WINDOWS_SSPI || USE_WIN32_LDAP) && UNICODE) */
