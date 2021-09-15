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

#include "curl_setup.h"

#if defined(WIN32)

#include <curl/curl.h>
#include "version_win32.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

#if !defined(_WIN32_WINNT) || !defined(_WIN32_WINNT_WIN2K) || \
(_WIN32_WINNT < _WIN32_WINNT_WIN2K)
#define OLDER_THAN_WIN2K 1
#else
#define OLDER_THAN_WIN2K 0
#endif

/* Include the RtlGetVersion() regardless of the presence of
   the Windows Driver Development Kit.
*/
#if !OLDER_THAN_WIN2K
#pragma comment(lib, "ntdll.lib")

typedef LONG NTSTATUS, * PNTSTATUS;
#define STATUS_SUCCESS (0x00000000)

// Windows 2000 and newer
NTSYSAPI NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOEXW lpVersionInformation);
#endif

/*
 * curlx_verify_windows_version()
 *
 * This is used to verify if we are running on a specific windows version.
 *
 * Parameters:
 *
 * majorVersion [in] - The major version number.
 * minorVersion [in] - The minor version number.
 * buildVersion [in] - The build version number. If 0, this parameter is
 *                     ignored.
 * platform     [in] - The optional platform identifier.
 * condition    [in] - The test condition used to specifier whether we are
 *                     checking a version less then, equal to or greater than
 *                     what is specified in the major and minor version
 *                     numbers.
 *
 * Returns TRUE if matched; otherwise FALSE.
 */
bool curlx_verify_windows_version(const unsigned int majorVersion,
                                  const unsigned int minorVersion,
                                  const unsigned int buildVersion,
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
#else

#if !OLDER_THAN_WIN2K
  static RTL_OSVERSIONINFOEXW osver = { 0 };
  osver.dwOSVersionInfoSize = sizeof(osver);

  /* Find out Windows version once, cache the result */
  if (osver.dwMajorVersion == 0 && RtlGetVersion(&osver) != STATUS_SUCCESS)
      return false;
#else
  static OSVERSIONINFO osver = { 0 };
  osver.dwOSVersionInfoSize = sizeof(osver);

  /* Find out Windows version once, cache the result */
  if (osver.dwMajorVersion == 0 && !GetVersionEx(&osver))
      return false;
#endif

    /* Verify the Operating System version number */
  switch(condition) {
    case VERSION_LESS_THAN:
      if(osver.dwMajorVersion < majorVersion ||
        (osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion < minorVersion) ||
        (buildVersion == 0 ||
         (osver.dwMajorVersion == majorVersion &&
          osver.dwMinorVersion == minorVersion &&
          osver.dwBuildNumber < buildVersion)))
        matched = TRUE;
      break;

    case VERSION_LESS_THAN_EQUAL:
      if(osver.dwMajorVersion < majorVersion ||
        (osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion <= minorVersion) ||
        (buildVersion == 0 ||
         (osver.dwMajorVersion == majorVersion &&
          osver.dwMinorVersion == minorVersion &&
          osver.dwBuildNumber <= buildVersion)))
        matched = TRUE;
      break;

    case VERSION_EQUAL:
      if(osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion == minorVersion &&
        (buildVersion == 0 ||
         osver.dwBuildNumber == buildVersion))
        matched = TRUE;
      break;

    case VERSION_GREATER_THAN_EQUAL:
      if(osver.dwMajorVersion > majorVersion ||
        (osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion >= minorVersion) ||
        (buildVersion == 0 ||
         (osver.dwMajorVersion == majorVersion &&
          osver.dwMinorVersion == minorVersion &&
          osver.dwBuildNumber >= buildVersion)))
        matched = TRUE;
      break;

    case VERSION_GREATER_THAN:
      if(osver.dwMajorVersion > majorVersion ||
        (osver.dwMajorVersion == majorVersion &&
         osver.dwMinorVersion > minorVersion) ||
        (buildVersion == 0 ||
         (osver.dwMajorVersion == majorVersion &&
          osver.dwMinorVersion == minorVersion &&
          osver.dwBuildNumber > buildVersion)))
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
#endif

  return matched;
}

#endif /* WIN32 */
