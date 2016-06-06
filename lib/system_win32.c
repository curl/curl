/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2016, Steve Holme, <steve_holme@hotmail.com>.
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

#if defined(WIN32)

#include <curl/curl.h>
#include "system_win32.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#if defined(USE_WINDOWS_SSPI) || (!defined(CURL_DISABLE_TELNET) && \
                                  defined(USE_WINSOCK))


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
#  ifdef _WIN32_WCE
#    define LOADLIBARYEX  L"LoadLibraryExW"
#  else
#    define LOADLIBARYEX  "LoadLibraryExW"
#  endif
#else
#  define LOADLIBARYEX    "LoadLibraryExA"
#endif

#endif /* USE_WINDOWS_SSPI || (!CURL_DISABLE_TELNET && USE_WINSOCK) */

/*
 * Curl_verify_windows_version()
 *
 * This is used to verify if we are running on a specific windows version.
 *
 * Parameters:
 *
 * majorVersion [in] - The major version number.
 * minorVersion [in] - The minor version number.
 * platform     [in] - The optional platform identifer.
 * condition    [in] - The test condition used to specifier whether we are
 *                     checking a version less then, equal to or greater than
 *                     what is specified in the major and minor version
 *                     numbers.
 *
 * Returns TRUE if matched; otherwise FALSE.
 */
bool Curl_verify_windows_version(const unsigned int majorVersion,
                                 const unsigned int minorVersion,
                                 const PlatformIdentifier platform,
                                 const VersionCondition condition)
{
  bool matched = FALSE;

#if !defined(_WIN32_WINNT) || !defined(_WIN32_WINNT_WIN2K) || \
    (_WIN32_WINNT < _WIN32_WINNT_WIN2K)
  OSVERSIONINFO osver;

  memset(&osver, 0, sizeof(osver));
  osver.dwOSVersionInfoSize = sizeof(osver);

  /* Find out Windows version */
  if(GetVersionEx(&osver)) {
    /* Verify the Operating System version number */
    switch(condition) {
    case VERSION_LESS_THAN:
      if(osver.dwMajorVersion < majorVersion ||
        (osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion < minorVersion))
        matched = TRUE;
      break;

    case VERSION_LESS_THAN_EQUAL:
      if(osver.dwMajorVersion <= majorVersion &&
         osver.dwMinorVersion <= minorVersion)
        matched = TRUE;
      break;

    case VERSION_EQUAL:
      if(osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion == minorVersion)
        matched = TRUE;
      break;

    case VERSION_GREATER_THAN_EQUAL:
      if(osver.dwMajorVersion >= majorVersion &&
         osver.dwMinorVersion >= minorVersion)
        matched = TRUE;
      break;

    case VERSION_GREATER_THAN:
      if(osver.dwMajorVersion > majorVersion ||
        (osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion > minorVersion))
        matched = TRUE;
      break;
    }

    /* Verify the platform identifier (if necessary) */
    if(matched && platform != PLATFORM_DONT_CARE) {
      switch(platform) {
      case PLATFORM_WINDOWS:
        if(osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS)
          matched = FALSE;
        break;

      case PLATFORM_WINNT:
        if(osver.dwPlatformId != VER_PLATFORM_WIN32_NT)
          matched = FALSE;
      }
    }
  }
#else
  ULONGLONG cm = 0;
  OSVERSIONINFOEX osver;
  BYTE majorCondition;
  BYTE minorCondition;
  BYTE spMajorCondition;
  BYTE spMinorCondition;

  switch(condition) {
  case VERSION_LESS_THAN:
    majorCondition = VER_LESS;
    minorCondition = VER_LESS;
    spMajorCondition = VER_LESS_EQUAL;
    spMinorCondition = VER_LESS_EQUAL;
    break;

  case VERSION_LESS_THAN_EQUAL:
    majorCondition = VER_LESS_EQUAL;
    minorCondition = VER_LESS_EQUAL;
    spMajorCondition = VER_LESS_EQUAL;
    spMinorCondition = VER_LESS_EQUAL;
    break;

  case VERSION_EQUAL:
    majorCondition = VER_EQUAL;
    minorCondition = VER_EQUAL;
    spMajorCondition = VER_GREATER_EQUAL;
    spMinorCondition = VER_GREATER_EQUAL;
    break;

  case VERSION_GREATER_THAN_EQUAL:
    majorCondition = VER_GREATER_EQUAL;
    minorCondition = VER_GREATER_EQUAL;
    spMajorCondition = VER_GREATER_EQUAL;
    spMinorCondition = VER_GREATER_EQUAL;
    break;

  case VERSION_GREATER_THAN:
    majorCondition = VER_GREATER;
    minorCondition = VER_GREATER;
    spMajorCondition = VER_GREATER_EQUAL;
    spMinorCondition = VER_GREATER_EQUAL;
    break;

  default:
    return FALSE;
  }

  memset(&osver, 0, sizeof(osver));
  osver.dwOSVersionInfoSize = sizeof(osver);
  osver.dwMajorVersion = majorVersion;
  osver.dwMinorVersion = minorVersion;
  if(platform == PLATFORM_WINDOWS)
    osver.dwPlatformId = VER_PLATFORM_WIN32_WINDOWS;
  else if(platform == PLATFORM_WINNT)
    osver.dwPlatformId = VER_PLATFORM_WIN32_NT;

  cm = VerSetConditionMask(cm, VER_MAJORVERSION, majorCondition);
  cm = VerSetConditionMask(cm, VER_MINORVERSION, minorCondition);
  cm = VerSetConditionMask(cm, VER_SERVICEPACKMAJOR, spMajorCondition);
  cm = VerSetConditionMask(cm, VER_SERVICEPACKMINOR, spMinorCondition);
  if(platform != PLATFORM_DONT_CARE)
    cm = VerSetConditionMask(cm, VER_PLATFORMID, VER_EQUAL);

  if(VerifyVersionInfo(&osver, (VER_MAJORVERSION | VER_MINORVERSION |
                                VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR),
                       cm))
    matched = TRUE;
#endif

  return matched;
}

#if defined(USE_WINDOWS_SSPI) || (!defined(CURL_DISABLE_TELNET) && \
                                  defined(USE_WINSOCK))

/*
 * Curl_load_library()
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
HMODULE Curl_load_library(LPCTSTR filename)
{
  HMODULE hModule = NULL;
  LOADLIBRARYEX_FN pLoadLibraryEx = NULL;

  /* Get a handle to kernel32 so we can access it's functions at runtime */
  HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32"));
  if(!hKernel32)
    return NULL;

  /* Attempt to find LoadLibraryEx() which is only available on Windows 2000
     and above */
  pLoadLibraryEx = (LOADLIBRARYEX_FN) GetProcAddress(hKernel32, LOADLIBARYEX);

  /* Detect if there's already a path in the filename and load the library if
     there is. Note: Both back slashes and forward slashes have been supported
     since the earlier days of DOS at an API level although they are not
     supported by command prompt */
  if(_tcspbrk(filename, TEXT("\\/"))) {
    /** !checksrc! disable BANNEDFUNC 1 **/
    hModule = pLoadLibraryEx ?
      pLoadLibraryEx(filename, NULL, LOAD_WITH_ALTERED_SEARCH_PATH) :
      LoadLibrary(filename);
  }
  /* Detect if KB2533623 is installed, as LOAD_LIBARY_SEARCH_SYSTEM32 is only
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

        free(path);
      }
    }
  }

  return hModule;
}

#endif /* USE_WINDOWS_SSPI || (!CURL_DISABLE_TELNET && USE_WINSOCK) */

#endif /* WIN32 */
