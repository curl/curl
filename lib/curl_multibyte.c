/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

/*
 * This file is 'mem-include-scan' clean, which means memdebug.h and
 * curl_memory.h are purposely not included in this file. See test 1132.
 *
 * The functions in this file are curlx functions which are not tracked by the
 * curl memory tracker memdebug.
 */

#include "curl_setup.h"

#if defined(WIN32)

#include "curl_multibyte.h"

/* utf8_strict_codepoint_count:
Count the number of Unicode codepoints encoded in a UTF-8 string.

Note that a UTF-8 BOM is a codepoint and is counted.

This function also tests for valid UTF-8 in accordance with the Unicode
Standard, Section Conformance 3.9, Table 3-7, Well-Formed UTF-8 Byte Sequences.
http://www.unicode.org/versions/Unicode7.0.0/ch03.pdf#G7404

The UTF-8 conformance in this function must remain strict, its purpose is to
test for exactly that. Any byte sequence that is not well-formed is an error.

Success: (>= 0) The number of codepoints in valid UTF-8 string 'str'.
Failure: (-1) String 'str' is not valid UTF-8.
*/
curl_off_t curlx_utf8_strict_codepoint_count(const char *str)
{
  const unsigned char *ch = (const unsigned char *)str;
  const curl_off_t error = -1;
  curl_off_t count = 0;

  for(; *ch; ++ch, ++count) {
    unsigned char first = *ch; /* first byte */
    if(count == CURL_OFF_T_MAX)
      return error;
    if(*ch <= 0x7F)
      continue;
    if(*ch < 0xC2 || *ch > 0xF4)
      return error;
    ++ch; /* second byte */
    if(*ch < (first == 0xE0 ? 0xA0 : (first == 0xF0 ? 0x90 : 0x80)) ||
       *ch > (first == 0xED ? 0x9F : (first == 0xF4 ? 0x8F : 0xBF)))
      return error;
    if(first <= 0xDF)
      continue;
    ++ch; /* third byte */
    if(*ch < 0x80 || *ch > 0xBF)
      return error;
    if(first <= 0xEF)
      continue;
    ++ch; /* fourth byte */
    if(*ch < 0x80 || *ch > 0xBF)
      return error;
  }

  return count;
}

/*
 * MultiByte conversions using Windows kernel32 library.
 */

wchar_t *curlx_convert_UTF8_to_wchar(const char *str_utf8)
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

char *curlx_convert_wchar_to_UTF8(const wchar_t *str_w)
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

#endif /* WIN32 */

#if defined(USE_WIN32_LARGE_FILES) || defined(USE_WIN32_SMALL_FILES)

int curlx_win32_open(const char *filename, int oflag, ...)
{
  int pmode = 0;

  va_list param;
  va_start(param, oflag);
  if(oflag & O_CREAT)
    pmode = va_arg(param, int);
  va_end(param);

#ifdef _UNICODE
  if(curlx_is_str_utf8(filename)) {
    int result = -1;
    wchar_t *filename_w = curlx_convert_UTF8_to_wchar(filename);
    if(filename_w) {
      result = _wopen(filename_w, oflag, pmode);
      free(filename_w);
    }
    else
      errno = EINVAL;
    return result;
  }
  else
#endif
    return (_open)(filename, oflag, pmode);
}

FILE *curlx_win32_fopen(const char *filename, const char *mode)
{
#ifdef _UNICODE
  if(curlx_is_str_utf8(filename)) {
    FILE *result = NULL;
    wchar_t *filename_w = curlx_convert_UTF8_to_wchar(filename);
    wchar_t *mode_w = curlx_convert_UTF8_to_wchar(mode);
    if(filename_w && mode_w)
      result = _wfopen(filename_w, mode_w);
    else
      errno = EINVAL;
    free(filename_w);
    free(mode_w);
    return result;
  }
  else
#endif
    return (fopen)(filename, mode);
}

int curlx_win32_stat(const char *path, struct_stat *buffer)
{
#ifdef _UNICODE
  if(curlx_is_str_utf8(path)) {
    int result = -1;
    wchar_t *path_w = curlx_convert_UTF8_to_wchar(path);
    if(path_w) {
#if defined(USE_WIN32_SMALL_FILES)
      result = _wstat(path_w, buffer);
#else
      result = _wstati64(path_w, buffer);
#endif
      free(path_w);
    }
    else
      errno = EINVAL;
    return result;
  }
  else
#endif
  {
#if defined(USE_WIN32_SMALL_FILES)
    return _stat(path, buffer);
#else
    return _stati64(path, buffer);
#endif
  }
}

int curlx_win32_access(const char *path, int mode)
{
#if defined(_UNICODE)
  if(curlx_is_str_utf8(path)) {
    int result = -1;
    wchar_t *path_w = curlx_convert_UTF8_to_wchar(path);
    if(path_w) {
      result = _waccess(path_w, mode);
      free(path_w);
    }
    else
      errno = EINVAL;
    return result;
  }
  else
#endif
    return _access(path, mode);
}

#endif /* USE_WIN32_LARGE_FILES || USE_WIN32_SMALL_FILES */
