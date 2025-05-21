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
#include "../curl_setup.h"

/*
 * curlx_winapi_strerror:
 * Variant of Curl_strerror if the error code is definitely Windows API.
 */
#ifdef _WIN32
#include "winapi.h"

#ifdef BUILDING_LIBCURL
#include <curl/mprintf.h>
#define SNPRINTF curl_msnprintf
#else
/* when built for the test servers */

/* adjust for old MSVC */
#if defined(_MSC_VER) && (_MSC_VER < 1900)
# define SNPRINTF _snprintf
#else
#define SNPRINTF snprintf
#endif

#endif /* !BUILDING_LIBCURL */

#ifdef _WIN32
/* This is a helper function for Curl_strerror that converts Windows API error
 * codes (GetLastError) to error messages.
 * Returns NULL if no error message was found for error code.
 */
const char *curlx_get_winapi_error(int err, char *buf, size_t buflen)
{
  char *p;
  wchar_t wbuf[256];

  if(!buflen)
    return NULL;

  *buf = '\0';
  *wbuf = L'\0';

  /* We return the local codepage version of the error string because if it is
     output to the user's terminal it will likely be with functions which
     expect the local codepage (eg fprintf, failf, infof).
     FormatMessageW -> wcstombs is used for Windows CE compatibility. */
  if(FormatMessageW((FORMAT_MESSAGE_FROM_SYSTEM |
                     FORMAT_MESSAGE_IGNORE_INSERTS), NULL, (DWORD)err,
                    LANG_NEUTRAL, wbuf, CURL_ARRAYSIZE(wbuf), NULL)) {
    size_t written = wcstombs(buf, wbuf, buflen - 1);
    if(written != (size_t)-1)
      buf[written] = '\0';
    else
      *buf = '\0';
  }

  /* Truncate multiple lines */
  p = strchr(buf, '\n');
  if(p) {
    if(p > buf && *(p-1) == '\r')
      *(p-1) = '\0';
    else
      *p = '\0';
  }

  return *buf ? buf : NULL;
}
#endif /* _WIN32 */

const char *curlx_winapi_strerror(DWORD err, char *buf, size_t buflen)
{
#ifdef _WIN32
  DWORD old_win_err = GetLastError();
#endif
  int old_errno = errno;

  if(!buflen)
    return NULL;

  *buf = '\0';

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(!curlx_get_winapi_error((int)err, buf, buflen)) {
#if defined(__GNUC__) && __GNUC__ >= 7
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wformat-truncation=1"
#endif
    /* some GCC compilers cause false positive warnings if we allow this
       warning */
    SNPRINTF(buf, buflen, "Unknown error %lu (0x%08lX)", err, err);
#if defined(__GNUC__) && __GNUC__ >= 7
#pragma GCC diagnostic pop
#endif

  }
#else
  {
    const char *txt = (err == ERROR_SUCCESS) ? "No error" : "Error";
    if(strlen(txt) < buflen)
      strcpy(buf, txt);
  }
#endif

  if(errno != old_errno)
    CURL_SETERRNO(old_errno);

#ifdef _WIN32
  if(old_win_err != GetLastError())
    SetLastError(old_win_err);
#endif

  return buf;
}

#if !defined(LOAD_WITH_ALTERED_SEARCH_PATH)
#define LOAD_WITH_ALTERED_SEARCH_PATH  0x00000008
#endif

#if !defined(LOAD_LIBRARY_SEARCH_SYSTEM32)
#define LOAD_LIBRARY_SEARCH_SYSTEM32   0x00000800
#endif

/* We use our own typedef here since some headers might lack these */
typedef HMODULE (APIENTRY *LOADLIBRARYEX_FN)(LPCTSTR, HANDLE, DWORD);

/* See function definitions in winbase.h */
#ifdef UNICODE
#  ifdef UNDER_CE
#    define LOADLIBARYEX  L"LoadLibraryExW"
#  else
#    define LOADLIBARYEX  "LoadLibraryExW"
#  endif
#else
#  define LOADLIBARYEX    "LoadLibraryExA"
#endif

/*
 * curlx_winapi_load_library()
 *
 * This is used to dynamically load DLLs using the most secure method available
 * for the version of Windows that we are running on.
 *
 * Parameters:
 *
 * filename  [in] - The filename or full path of the DLL to load. If only the
 *                  filename is passed then the DLL will be loaded from the
 *                  Windows system directory.
 *
 * Returns the handle of the module on success; otherwise NULL.
 */
HMODULE curlx_winapi_load_library(LPCTSTR filename)
{
#if !defined(CURL_WINDOWS_UWP) && !defined(UNDER_CE)
  HMODULE hModule = NULL;
  LOADLIBRARYEX_FN pLoadLibraryEx = NULL;

  /* Get a handle to kernel32 so we can access its functions at runtime */
  HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
  if(!hKernel32)
    return NULL;

  /* Attempt to find LoadLibraryEx() which is only available on Windows 2000
     and above */
  pLoadLibraryEx =
    CURLX_FUNCTION_CAST(LOADLIBRARYEX_FN,
                        (GetProcAddress(hKernel32, LOADLIBARYEX)));

  /* Detect if there is already a path in the filename and load the library if
     there is. Note: Both back slashes and forward slashes have been supported
     since the earlier days of DOS at an API level although they are not
     supported by command prompt */
  if(_tcspbrk(filename, TEXT("\\/"))) {
    /** !checksrc! disable BANNEDFUNC 1 **/
    hModule = pLoadLibraryEx ?
      pLoadLibraryEx(filename, NULL, LOAD_WITH_ALTERED_SEARCH_PATH) :
      LoadLibrary(filename);
  }
  /* Detect if KB2533623 is installed, as LOAD_LIBRARY_SEARCH_SYSTEM32 is only
     supported on Windows Vista, Windows Server 2008, Windows 7 and Windows
     Server 2008 R2 with this patch or natively on Windows 8 and above */
  else if(pLoadLibraryEx && GetProcAddress(hKernel32, "AddDllDirectory")) {
    /* Load the DLL from the Windows system directory */
    hModule = pLoadLibraryEx(filename, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  }
  else {
    /* Attempt to get the Windows system path */
    UINT systemdirlen = GetSystemDirectory(NULL, 0);
    if(systemdirlen) {
      /* Allocate space for the full DLL path (Room for the null terminator
         is included in systemdirlen) */
      size_t filenamelen = _tcslen(filename);
      TCHAR *path = malloc(sizeof(TCHAR) * (systemdirlen + 1 + filenamelen));
      if(path && GetSystemDirectory(path, systemdirlen)) {
        /* Calculate the full DLL path */
        _tcscpy(path + _tcslen(path), TEXT("\\"));
        _tcscpy(path + _tcslen(path), filename);

        /* Load the DLL from the Windows system directory */
        /** !checksrc! disable BANNEDFUNC 1 **/
        hModule = pLoadLibraryEx ?
          pLoadLibraryEx(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH) :
          LoadLibrary(path);

      }
      free(path);
    }
  }
  return hModule;
#else
  /* the Universal Windows Platform (UWP) cannot do this */
  (void)filename;
  return NULL;
#endif
}

#endif /* _WIN32 */
