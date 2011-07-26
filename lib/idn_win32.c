/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

 /*
  * IDN conversions using Windows kernel32 and normaliz libraries.
  */

#include "setup.h"

#ifdef USE_WIN32_IDN

#include <tchar.h>

#ifdef WANT_IDN_PROTOTYPES
WINBASEAPI int WINAPI IdnToAscii(DWORD, LPCWSTR, int, LPWSTR, int);
WINBASEAPI int WINAPI IdnToUnicode(DWORD, LPCWSTR, int, LPWSTR, int);
#endif

#define IDN_MAX_LENGTH 255

static wchar_t *_curl_win32_UTF8_to_wchar(const char *str_utf8)
{
  wchar_t *str_w = NULL;

  if(str_utf8) {
    int str_w_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                        str_utf8, -1, NULL, 0);
    if(str_w_len) {
      str_w = malloc(str_w_len * sizeof(wchar_t));
      if(str_w) {
        if(MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, str_w,
                                str_w_len) == 0) {
          free(str_w);
          str_w = NULL;
        }
      }
    }
  }

  return str_w;
}

static const char *_curl_win32_wchar_to_UTF8(const wchar_t *str_w)
{
  char *str_utf8 = NULL;

  if(str_w) {
    size_t str_utf8_len = WideCharToMultiByte(CP_UTF8, 0, str_w, -1, NULL,
                                              0, NULL, NULL);
    if(str_utf8_len) {
      str_utf8 = malloc(str_utf8_len * sizeof(wchar_t));
      if(str_utf8) {
        if(WideCharToMultiByte(CP_UTF8, 0, str_w, -1, str_utf8, str_utf8_len,
                                NULL, FALSE) == 0) {
          (void) GetLastError();
          free((void *)str_utf8);
          str_utf8 = NULL;
        }
      }
    }
    else {
      (void) GetLastError();
    }
  }

  return str_utf8;
}

int curl_win32_idn_to_ascii(const char *in, char **out)
{
  wchar_t *in_w = _curl_win32_UTF8_to_wchar(in);
  if(in_w) {
    wchar_t punycode[IDN_MAX_LENGTH];
    if(IdnToAscii(0, in_w, -1, punycode, IDN_MAX_LENGTH) == 0) {
      wprintf(L"ERROR %d converting to Punycode\n", GetLastError());
      free(in_w);
      return 0;
    }
    free(in_w);

    *out = (char *)_curl_win32_wchar_to_UTF8(punycode);
    if(!(*out)) {
      return 0;
    }
  }
  return 1;
}

int curl_win32_ascii_to_idn(const char *in, size_t in_len, char **out_utf8)
{
  if(in) {
    WCHAR unicode[IDN_MAX_LENGTH];

    if(IdnToUnicode(0, (wchar_t *)in, -1, unicode, IDN_MAX_LENGTH) == 0) {
      wprintf(L"ERROR %d converting to Punycode\n", GetLastError());
      return 0;
    }
    else {
      const char *out_utf8 = _curl_win32_wchar_to_UTF8(unicode);
      if(!out_utf8) {
        return 0;
      }
    }
  }
  return 1;
}

#endif /* USE_WIN32_IDN */
