/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Steve Holme, <steve_holme@hotmail.com>.
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

#include "curl_setup.h"

#ifdef _WIN32

#include <curl/curl.h>
#include "version_win32.h"
#include "warnless.h"

/* The last 2 #include files should be in this order */
#ifdef BUILDING_LIBCURL
#include "curl_memory.h"
#endif
#include "memdebug.h"

/* This Unicode version struct works for VerifyVersionInfoW (OSVERSIONINFOEXW)
   and RtlVerifyVersionInfo (RTLOSVERSIONINFOEXW) */
struct OUR_OSVERSIONINFOEXW {
  ULONG  dwOSVersionInfoSize;
  ULONG  dwMajorVersion;
  ULONG  dwMinorVersion;
  ULONG  dwBuildNumber;
  ULONG  dwPlatformId;
  WCHAR  szCSDVersion[128];
  USHORT wServicePackMajor;
  USHORT wServicePackMinor;
  USHORT wSuiteMask;
  UCHAR  wProductType;
  UCHAR  wReserved;
};

/*
 * curlx_verify_windows_version()
 *
 * This is used to verify if we are running on a specific Windows version.
 *
 * Parameters:
 *
 * majorVersion [in] - The major version number.
 * minorVersion [in] - The minor version number.
 * buildVersion [in] - The build version number. If 0, this parameter is
 *                     ignored.
 * platform     [in] - The optional platform identifier.
 * condition    [in] - The test condition used to specifier whether we are
 *                     checking a version less than, equal to or greater than
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

#ifdef CURL_WINDOWS_UWP
  /* We have no way to determine the Windows version from Windows apps,
     so let's assume we are running on the target Windows version. */
  const WORD fullVersion = MAKEWORD(minorVersion, majorVersion);
  const WORD targetVersion = (WORD)_WIN32_WINNT;

  (void)buildVersion;

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
    /* we are always running on PLATFORM_WINNT */
    matched = FALSE;
  }
#elif defined(UNDER_CE)
  (void)majorVersion;
  (void)minorVersion;
  (void)buildVersion;
  (void)platform;
  (void)condition;
#else
  ULONGLONG cm = 0;
  struct OUR_OSVERSIONINFOEXW osver;
  BYTE majorCondition;
  BYTE minorCondition;
  BYTE buildCondition;
  BYTE spMajorCondition;
  BYTE spMinorCondition;
  DWORD dwTypeMask = VER_MAJORVERSION | VER_MINORVERSION |
                     VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR;

  typedef LONG (APIENTRY *RTLVERIFYVERSIONINFO_FN)
    (struct OUR_OSVERSIONINFOEXW *, ULONG, ULONGLONG);
  static RTLVERIFYVERSIONINFO_FN pRtlVerifyVersionInfo;
  static bool onetime = TRUE; /* safe because first call is during init */

  if(onetime) {
    pRtlVerifyVersionInfo = CURLX_FUNCTION_CAST(RTLVERIFYVERSIONINFO_FN,
      (GetProcAddress(GetModuleHandleA("ntdll"), "RtlVerifyVersionInfo")));
    onetime = FALSE;
  }

  switch(condition) {
  case VERSION_LESS_THAN:
    majorCondition = VER_LESS;
    minorCondition = VER_LESS;
    buildCondition = VER_LESS;
    spMajorCondition = VER_LESS_EQUAL;
    spMinorCondition = VER_LESS_EQUAL;
    break;

  case VERSION_LESS_THAN_EQUAL:
    majorCondition = VER_LESS_EQUAL;
    minorCondition = VER_LESS_EQUAL;
    buildCondition = VER_LESS_EQUAL;
    spMajorCondition = VER_LESS_EQUAL;
    spMinorCondition = VER_LESS_EQUAL;
    break;

  case VERSION_EQUAL:
    majorCondition = VER_EQUAL;
    minorCondition = VER_EQUAL;
    buildCondition = VER_EQUAL;
    spMajorCondition = VER_GREATER_EQUAL;
    spMinorCondition = VER_GREATER_EQUAL;
    break;

  case VERSION_GREATER_THAN_EQUAL:
    majorCondition = VER_GREATER_EQUAL;
    minorCondition = VER_GREATER_EQUAL;
    buildCondition = VER_GREATER_EQUAL;
    spMajorCondition = VER_GREATER_EQUAL;
    spMinorCondition = VER_GREATER_EQUAL;
    break;

  case VERSION_GREATER_THAN:
    majorCondition = VER_GREATER;
    minorCondition = VER_GREATER;
    buildCondition = VER_GREATER;
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
  osver.dwBuildNumber = buildVersion;
  if(platform == PLATFORM_WINDOWS)
    osver.dwPlatformId = VER_PLATFORM_WIN32_WINDOWS;
  else if(platform == PLATFORM_WINNT)
    osver.dwPlatformId = VER_PLATFORM_WIN32_NT;

  cm = VerSetConditionMask(cm, VER_MAJORVERSION, majorCondition);
  cm = VerSetConditionMask(cm, VER_MINORVERSION, minorCondition);
  cm = VerSetConditionMask(cm, VER_SERVICEPACKMAJOR, spMajorCondition);
  cm = VerSetConditionMask(cm, VER_SERVICEPACKMINOR, spMinorCondition);

  if(platform != PLATFORM_DONT_CARE) {
    cm = VerSetConditionMask(cm, VER_PLATFORMID, VER_EQUAL);
    dwTypeMask |= VER_PLATFORMID;
  }

  /* Later versions of Windows have version functions that may not return the
     real version of Windows unless the application is so manifested. We prefer
     the real version always, so we use the Rtl variant of the function when
     possible. Note though the function signatures have underlying fundamental
     types that are the same, the return values are different. */
  if(pRtlVerifyVersionInfo)
    matched = !pRtlVerifyVersionInfo(&osver, dwTypeMask, cm);
  else
    matched = !!VerifyVersionInfoW((OSVERSIONINFOEXW *)&osver, dwTypeMask, cm);

  /* Compare the build number separately. VerifyVersionInfo normally compares
     major.minor in hierarchical order (eg 1.9 is less than 2.0) but does not
     do the same for build (eg 1.9 build 222 is not less than 2.0 build 111).
     Build comparison is only needed when build numbers are equal (eg 1.9 is
     always less than 2.0 so build comparison is not needed). */
  if(matched && buildVersion &&
     (condition == VERSION_EQUAL ||
      ((condition == VERSION_GREATER_THAN_EQUAL ||
        condition == VERSION_LESS_THAN_EQUAL) &&
        curlx_verify_windows_version(majorVersion, minorVersion, 0,
                                     platform, VERSION_EQUAL)))) {

    cm = VerSetConditionMask(0, VER_BUILDNUMBER, buildCondition);
    dwTypeMask = VER_BUILDNUMBER;
    if(pRtlVerifyVersionInfo)
      matched = !pRtlVerifyVersionInfo(&osver, dwTypeMask, cm);
    else
      matched = !!VerifyVersionInfoW((OSVERSIONINFOEXW *)&osver,
                                      dwTypeMask, cm);
  }

#endif

  return matched;
}

#endif /* _WIN32 */
