/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
  * IDN conversions using Windows kernel32 and normaliz libraries.
  */

#include "curl_setup.h"

#ifdef USE_WIN32_IDN

#include "curl_multibyte.h"
#include "curl_memory.h"
#include "warnless.h"

  /* The last #include file should be: */
#include "memdebug.h"

#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x600
WINBASEAPI int WINAPI IdnToAscii(DWORD dwFlags,
                                 const WCHAR *lpUnicodeCharStr,
                                 int cchUnicodeChar,
                                 WCHAR *lpASCIICharStr,
                                 int cchASCIIChar);
WINBASEAPI int WINAPI IdnToUnicode(DWORD dwFlags,
                                   const WCHAR *lpASCIICharStr,
                                   int cchASCIIChar,
                                   WCHAR *lpUnicodeCharStr,
                                   int cchUnicodeChar);
#endif

#define IDN_MAX_LENGTH 255

bool Curl_win32_idn_to_ascii(const char *in, char **out);
bool Curl_win32_ascii_to_idn(const char *in, char **out);

bool Curl_win32_idn_to_ascii(const char *in, char **out)
{
  bool success = FALSE;

  wchar_t *in_w = curlx_convert_UTF8_to_wchar(in);
  if(in_w) {
    wchar_t punycode[IDN_MAX_LENGTH];
    int chars = IdnToAscii(0, in_w, -1, punycode, IDN_MAX_LENGTH);
    curlx_unicodefree(in_w);
    if(chars) {
      char *mstr = curlx_convert_wchar_to_UTF8(punycode);
      if(mstr) {
        *out = strdup(mstr);
        curlx_unicodefree(mstr);
        if(*out)
          success = TRUE;
      }
    }
  }

  return success;
}

bool Curl_win32_ascii_to_idn(const char *in, char **out)
{
  bool success = FALSE;

  wchar_t *in_w = curlx_convert_UTF8_to_wchar(in);
  if(in_w) {
    size_t in_len = wcslen(in_w) + 1;
    wchar_t unicode[IDN_MAX_LENGTH];
    int chars = IdnToUnicode(0, in_w, curlx_uztosi(in_len),
                             unicode, IDN_MAX_LENGTH);
    curlx_unicodefree(in_w);
    if(chars) {
      char *mstr = curlx_convert_wchar_to_UTF8(unicode);
      if(mstr) {
        *out = strdup(mstr);
        curlx_unicodefree(mstr);
        if(*out)
          success = TRUE;
      }
    }
  }

  return success;
}

#endif /* USE_WIN32_IDN */
