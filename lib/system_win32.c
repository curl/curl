/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2016 - 2020, Steve Holme, <steve_holme@hotmail.com>.
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
#include "loadlibrary.h"
#include "curl_sspi.h"
#include "warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

LARGE_INTEGER Curl_freq;
bool Curl_isVistaOrGreater;

/* Handle of iphlpapp.dll */
static HMODULE s_hIpHlpApiDll = NULL;

/* Pointer to the if_nametoindex function */
IF_NAMETOINDEX_FN Curl_if_nametoindex = NULL;

/* Curl_win32_init() performs win32 global initialization */
CURLcode Curl_win32_init(long flags)
{
  /* CURL_GLOBAL_WIN32 controls the *optional* part of the initialization which
     is just for Winsock at the moment. Any required win32 initialization
     should take place after this block. */
  if(flags & CURL_GLOBAL_WIN32) {
#ifdef USE_WINSOCK
    WORD wVersionRequested;
    WSADATA wsaData;
    int res;

#if defined(ENABLE_IPV6) && (USE_WINSOCK < 2)
#error IPV6_requires_winsock2
#endif

    wVersionRequested = MAKEWORD(USE_WINSOCK, USE_WINSOCK);

    res = WSAStartup(wVersionRequested, &wsaData);

    if(res != 0)
      /* Tell the user that we couldn't find a usable */
      /* winsock.dll.     */
      return CURLE_FAILED_INIT;

    /* Confirm that the Windows Sockets DLL supports what we need.*/
    /* Note that if the DLL supports versions greater */
    /* than wVersionRequested, it will still return */
    /* wVersionRequested in wVersion. wHighVersion contains the */
    /* highest supported version. */

    if(LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
       HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested) ) {
      /* Tell the user that we couldn't find a usable */

      /* winsock.dll. */
      WSACleanup();
      return CURLE_FAILED_INIT;
    }
    /* The Windows Sockets DLL is acceptable. Proceed. */
  #elif defined(USE_LWIPSOCK)
    lwip_init();
  #endif
  } /* CURL_GLOBAL_WIN32 */

#ifdef USE_WINDOWS_SSPI
  {
    CURLcode result = Curl_sspi_global_init();
    if(result)
      return result;
  }
#endif

  s_hIpHlpApiDll = Curl_load_library(TEXT("iphlpapi.dll"));
  if(s_hIpHlpApiDll) {
    /* Get the address of the if_nametoindex function */
    IF_NAMETOINDEX_FN pIfNameToIndex =
      CURLX_FUNCTION_CAST(IF_NAMETOINDEX_FN,
                          (GetProcAddress(s_hIpHlpApiDll, "if_nametoindex")));

    if(pIfNameToIndex)
      Curl_if_nametoindex = pIfNameToIndex;
  }

  if(Curl_verify_windows_version(6, 0, PLATFORM_WINNT,
                                 VERSION_GREATER_THAN_EQUAL)) {
    Curl_isVistaOrGreater = TRUE;
  }
  else
    Curl_isVistaOrGreater = FALSE;

  QueryPerformanceFrequency(&Curl_freq);
  return CURLE_OK;
}

/* Curl_win32_cleanup() is the opposite of Curl_win32_init() */
void Curl_win32_cleanup(long init_flags)
{
  if(s_hIpHlpApiDll) {
    FreeLibrary(s_hIpHlpApiDll);
    s_hIpHlpApiDll = NULL;
    Curl_if_nametoindex = NULL;
  }

#ifdef USE_WINDOWS_SSPI
  Curl_sspi_global_cleanup();
#endif

  if(init_flags & CURL_GLOBAL_WIN32) {
#ifdef USE_WINSOCK
    WSACleanup();
#endif
  }
}

#if !defined(LOAD_WITH_ALTERED_SEARCH_PATH)
#define LOAD_WITH_ALTERED_SEARCH_PATH  0x00000008
#endif

#if !defined(LOAD_LIBRARY_SEARCH_SYSTEM32)
#define LOAD_LIBRARY_SEARCH_SYSTEM32   0x00000800
#endif

/*
 * Curl_verify_windows_version()
 *
 * This is used to verify if we are running on a specific windows version.
 *
 * Parameters:
 *
 * majorVersion [in] - The major version number.
 * minorVersion [in] - The minor version number.
 * platform     [in] - The optional platform identifier.
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

#if defined(CURL_WINDOWS_APP)
  /* We have no way to determine the Windows version from Windows apps,
     so let's assume we're running on the target Windows version. */
  const WORD fullVersion = MAKEWORD(minorVersion, majorVersion);
  const WORD targetVersion = (WORD)_WIN32_WINNT;

  switch(condition) {
  case VERSION_LESS_THAN:
    matched = targetVersion < fullVersion;
    break;

  case VERSION_LESS_THAN_EQUAL:
    matched = targetVersion <= fullVersion;
    break;

  case VERSION_EQUAL:
    matched = targetVersion == fullVersion;
    break;

  case VERSION_GREATER_THAN_EQUAL:
    matched = targetVersion >= fullVersion;
    break;

  case VERSION_GREATER_THAN:
    matched = targetVersion > fullVersion;
    break;
  }

  if(matched && (platform == PLATFORM_WINDOWS)) {
    /* we're always running on PLATFORM_WINNT */
    matched = FALSE;
  }
#elif !defined(_WIN32_WINNT) || !defined(_WIN32_WINNT_WIN2K) || \
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
      if(osver.dwMajorVersion < majorVersion ||
        (osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion <= minorVersion))
        matched = TRUE;
      break;

    case VERSION_EQUAL:
      if(osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion == minorVersion)
        matched = TRUE;
      break;

    case VERSION_GREATER_THAN_EQUAL:
      if(osver.dwMajorVersion > majorVersion ||
        (osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion >= minorVersion))
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
    if(matched) {
      switch(platform) {
      case PLATFORM_WINDOWS:
        if(osver.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS)
          matched = FALSE;
        break;

      case PLATFORM_WINNT:
        if(osver.dwPlatformId != VER_PLATFORM_WIN32_NT)
          matched = FALSE;

      default: /* like platform == PLATFORM_DONT_CARE */
        break;
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

#endif /* WIN32 */
