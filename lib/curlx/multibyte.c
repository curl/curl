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
 * This file is 'mem-include-scan' clean, which means its memory allocations
 * are not tracked by the curl memory tracker memdebug, so they must not use
 * `CURLDEBUG` macro replacements in memdebug.h for free, malloc, etc. To avoid
 * these macro replacements, wrap the names in parentheses to call the original
 * versions: `ptr = (malloc)(123)`, `(free)(ptr)`, etc.
 */

#include "../curl_setup.h"

#ifdef _WIN32

#include "multibyte.h"

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
      str_w = (malloc)(str_w_len * sizeof(wchar_t));
      if(str_w) {
        if(MultiByteToWideChar(CP_UTF8, 0, str_utf8, -1, str_w,
                               str_w_len) == 0) {
          (free)(str_w);
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
      str_utf8 = (malloc)(bytes);
      if(str_utf8) {
        if(WideCharToMultiByte(CP_UTF8, 0, str_w, -1, str_utf8, bytes,
                               NULL, NULL) == 0) {
          (free)(str_utf8);
          return NULL;
        }
      }
    }
  }

  return str_utf8;
}

#ifndef UNDER_CE

/* declare GetFullPathNameW for mingw-w64 UWP builds targeting old windows */
#if defined(CURL_WINDOWS_UWP) && defined(__MINGW32__) && \
  (_WIN32_WINNT < _WIN32_WINNT_WIN10)
WINBASEAPI DWORD WINAPI GetFullPathNameW(LPCWSTR, DWORD, LPWSTR, LPWSTR *);
#endif

/* Fix excessive paths (paths that exceed MAX_PATH length of 260).
 *
 * This is a helper function to fix paths that would exceed the MAX_PATH
 * limitation check done by Windows APIs. It does so by normalizing the passed
 * in filename or path 'in' to its full canonical path, and if that path is
 * longer than MAX_PATH then setting 'out' to "\\?\" prefix + that full path.
 *
 * For example 'in' filename255chars in current directory C:\foo\bar is
 * fixed as \\?\C:\foo\bar\filename255chars for 'out' which will tell Windows
 * it is ok to access that filename even though the actual full path is longer
 * than 260 chars.
 *
 * For non-Unicode builds this function may fail sometimes because only the
 * Unicode versions of some Windows API functions can access paths longer than
 * MAX_PATH, for example GetFullPathNameW which is used in this function. When
 * the full path is then converted from Unicode to multibyte that fails if any
 * directories in the path contain characters not in the current codepage.
 */
static bool fix_excessive_path(const TCHAR *in, TCHAR **out)
{
  size_t needed, count;
  const wchar_t *in_w;
  wchar_t *fbuf = NULL;

  /* MS documented "approximate" limit for the maximum path length */
  const size_t max_path_len = 32767;

#ifndef _UNICODE
  wchar_t *ibuf = NULL;
  char *obuf = NULL;
#endif

  *out = NULL;

  /* skip paths already normalized */
  if(!_tcsncmp(in, _T("\\\\?\\"), 4))
    goto cleanup;

#ifndef _UNICODE
  /* convert multibyte input to unicode */
  needed = mbstowcs(NULL, in, 0);
  if(needed == (size_t)-1 || needed >= max_path_len)
    goto cleanup;
  ++needed; /* for NUL */
  ibuf = (malloc)(needed * sizeof(wchar_t));
  if(!ibuf)
    goto cleanup;
  count = mbstowcs(ibuf, in, needed);
  if(count == (size_t)-1 || count >= needed)
    goto cleanup;
  in_w = ibuf;
#else
  in_w = in;
#endif

  /* GetFullPathNameW returns the normalized full path in unicode. It converts
     forward slashes to backslashes, processes .. to remove directory segments,
     etc. Unlike GetFullPathNameA it can process paths that exceed MAX_PATH. */
  needed = (size_t)GetFullPathNameW(in_w, 0, NULL, NULL);
  if(!needed || needed > max_path_len)
    goto cleanup;
  /* skip paths that are not excessive and do not need modification */
  if(needed <= MAX_PATH)
    goto cleanup;
  fbuf = (malloc)(needed * sizeof(wchar_t));
  if(!fbuf)
    goto cleanup;
  count = (size_t)GetFullPathNameW(in_w, (DWORD)needed, fbuf, NULL);
  if(!count || count >= needed)
    goto cleanup;

  /* prepend \\?\ or \\?\UNC\ to the excessively long path.
   *
   * c:\longpath            --->    \\?\c:\longpath
   * \\.\c:\longpath        --->    \\?\c:\longpath
   * \\?\c:\longpath        --->    \\?\c:\longpath  (unchanged)
   * \\server\c$\longpath   --->    \\?\UNC\server\c$\longpath
   *
   * https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
   */
  if(!wcsncmp(fbuf, L"\\\\?\\", 4))
    ; /* do nothing */
  else if(!wcsncmp(fbuf, L"\\\\.\\", 4))
    fbuf[2] = '?';
  else if(!wcsncmp(fbuf, L"\\\\.", 3) || !wcsncmp(fbuf, L"\\\\?", 3)) {
    /* Unexpected, not UNC. The formatting doc doesn't allow this AFAICT. */
    goto cleanup;
  }
  else {
    wchar_t *temp;

    if(!wcsncmp(fbuf, L"\\\\", 2)) {
      /* "\\?\UNC\" + full path without "\\" + null */
      needed = 8 + (count - 2) + 1;
      if(needed > max_path_len)
        goto cleanup;

      temp = (malloc)(needed * sizeof(wchar_t));
      if(!temp)
        goto cleanup;

      wcsncpy(temp, L"\\\\?\\UNC\\", 8);
      wcscpy(temp + 8, fbuf + 2);
    }
    else {
      /* "\\?\" + full path + null */
      needed = 4 + count + 1;
      if(needed > max_path_len)
        goto cleanup;

      temp = (malloc)(needed * sizeof(wchar_t));
      if(!temp)
        goto cleanup;

      wcsncpy(temp, L"\\\\?\\", 4);
      wcscpy(temp + 4, fbuf);
    }

    (free)(fbuf);
    fbuf = temp;
  }

#ifndef _UNICODE
  /* convert unicode full path to multibyte output */
  needed = wcstombs(NULL, fbuf, 0);
  if(needed == (size_t)-1 || needed >= max_path_len)
    goto cleanup;
  ++needed; /* for NUL */
  obuf = (malloc)(needed);
  if(!obuf)
    goto cleanup;
  count = wcstombs(obuf, fbuf, needed);
  if(count == (size_t)-1 || count >= needed)
    goto cleanup;
  *out = obuf;
  obuf = NULL;
#else
  *out = fbuf;
  fbuf = NULL;
#endif

cleanup:
  (free)(fbuf);
#ifndef _UNICODE
  (free)(ibuf);
  (free)(obuf);
#endif
  return *out ? true : false;
}

int curlx_win32_open(const char *filename, int oflag, ...)
{
  int pmode = 0;
  int result = -1;
  TCHAR *fixed = NULL;
  const TCHAR *target = NULL;

#ifdef _UNICODE
  wchar_t *filename_w = curlx_convert_UTF8_to_wchar(filename);
#endif

  va_list param;
  va_start(param, oflag);
  if(oflag & O_CREAT)
    pmode = va_arg(param, int);
  va_end(param);

#ifdef _UNICODE
  if(filename_w) {
    if(fix_excessive_path(filename_w, &fixed))
      target = fixed;
    else
      target = filename_w;
    result = _wopen(target, oflag, pmode);
    curlx_unicodefree(filename_w);
  }
  else
    /* !checksrc! disable ERRNOVAR 1 */
    CURL_SETERRNO(EINVAL);
#else
  if(fix_excessive_path(filename, &fixed))
    target = fixed;
  else
    target = filename;
  result = _open(target, oflag, pmode);
#endif

  (free)(fixed);
  return result;
}

FILE *curlx_win32_fopen(const char *filename, const char *mode)
{
  FILE *result = NULL;
  TCHAR *fixed = NULL;
  const TCHAR *target = NULL;

#ifdef _UNICODE
  wchar_t *filename_w = curlx_convert_UTF8_to_wchar(filename);
  wchar_t *mode_w = curlx_convert_UTF8_to_wchar(mode);
  if(filename_w && mode_w) {
    if(fix_excessive_path(filename_w, &fixed))
      target = fixed;
    else
      target = filename_w;
    result = _wfopen(target, mode_w);
  }
  else
    /* !checksrc! disable ERRNOVAR 1 */
    CURL_SETERRNO(EINVAL);
  curlx_unicodefree(filename_w);
  curlx_unicodefree(mode_w);
#else
  if(fix_excessive_path(filename, &fixed))
    target = fixed;
  else
    target = filename;
  result = (fopen)(target, mode);
#endif

  (free)(fixed);
  return result;
}

int curlx_win32_stat(const char *path, struct_stat *buffer)
{
  int result = -1;
  TCHAR *fixed = NULL;
  const TCHAR *target = NULL;

#ifdef _UNICODE
  wchar_t *path_w = curlx_convert_UTF8_to_wchar(path);
  if(path_w) {
    if(fix_excessive_path(path_w, &fixed))
      target = fixed;
    else
      target = path_w;
#ifndef USE_WIN32_LARGE_FILES
    result = _wstat(target, buffer);
#else
    result = _wstati64(target, buffer);
#endif
    curlx_unicodefree(path_w);
  }
  else
    /* !checksrc! disable ERRNOVAR 1 */
    CURL_SETERRNO(EINVAL);
#else
  if(fix_excessive_path(path, &fixed))
    target = fixed;
  else
    target = path;
#ifndef USE_WIN32_LARGE_FILES
  result = _stat(target, buffer);
#else
  result = _stati64(target, buffer);
#endif
#endif

  (free)(fixed);
  return result;
}

#endif /* UNDER_CE */

#endif /* _WIN32 */
