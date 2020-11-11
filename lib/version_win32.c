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
#include "version_win32.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/*
 * curlx_verify_windows_version()
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
bool curlx_verify_windows_version(const unsigned int majorVersion,
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
