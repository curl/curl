/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#ifdef USE_WIN32_IDN

#include "curl_multibyte.h"

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

#ifdef WANT_IDN_PROTOTYPES
#  if defined(_SAL_VERSION)
WINNORMALIZEAPI int WINAPI
IdnToAscii(_In_                           DWORD    dwFlags,
           _In_reads_(cchUnicodeChar)     LPCWSTR  lpUnicodeCharStr,
           _In_                           int      cchUnicodeChar,
           _Out_writes_opt_(cchASCIIChar) LPWSTR   lpASCIICharStr,
           _In_                           int      cchASCIIChar);
WINNORMALIZEAPI int WINAPI
IdnToUnicode(_In_                             DWORD   dwFlags,
             _In_reads_(cchASCIIChar)         LPCWSTR lpASCIICharStr,
             _In_                             int     cchASCIIChar,
             _Out_writes_opt_(cchUnicodeChar) LPWSTR  lpUnicodeCharStr,
             _In_                             int     cchUnicodeChar);
#  else
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
#  endif
#endif

#define IDN_MAX_LENGTH 255

int curl_win32_idn_to_ascii(const char *in, char **out);
int curl_win32_ascii_to_idn(const char *in, size_t in_len, char **out_utf8);

int curl_win32_idn_to_ascii(const char *in, char **out)
{
  wchar_t *in_w = Curl_convert_UTF8_to_wchar(in);
  if(in_w) {
    wchar_t punycode[IDN_MAX_LENGTH];
    if(IdnToAscii(0, in_w, -1, punycode, IDN_MAX_LENGTH) == 0) {
      wprintf(L"ERROR %d converting to Punycode\n", GetLastError());
      free(in_w);
      return 0;
    }
    free(in_w);

    *out = Curl_convert_wchar_to_UTF8(punycode);
    if(!*out)
      return 0;
  }
  return 1;
}

int curl_win32_ascii_to_idn(const char *in, size_t in_len, char **out_utf8)
{
  (void)in_len; /* unused */
  if(in) {
    WCHAR unicode[IDN_MAX_LENGTH];

    if(IdnToUnicode(0, (wchar_t *)in, -1, unicode, IDN_MAX_LENGTH) == 0) {
      wprintf(L"ERROR %d converting to Punycode\n", GetLastError());
      return 0;
    }
    else {
      *out_utf8 = Curl_convert_wchar_to_UTF8(unicode);
      if(!*out_utf8)
        return 0;
    }
  }
  return 1;
}

#endif /* USE_WIN32_IDN */
