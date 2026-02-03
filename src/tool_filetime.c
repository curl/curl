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
#include "tool_filetime.h"
#include "tool_cfgable.h"
#include "tool_msgs.h"

#ifdef HAVE_UTIME_H
#  include <utime.h>
#elif defined(HAVE_SYS_UTIME_H)
#  include <sys/utime.h>
#endif

/* Returns 0 on success, non-zero on file problems */
int getfiletime(const char *filename, curl_off_t *stamp)
{
  int rc = 1;

/* Windows stat() may attempt to adjust the Unix GMT file time by a daylight
   saving time offset and since it is GMT that is bad behavior. When we have
   access to a 64-bit type we can bypass stat and get the times directly. */
#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP)
  HANDLE hfile;
  hfile = curlx_CreateFile(filename, FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE |
                           FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
  if(hfile != INVALID_HANDLE_VALUE) {
    FILETIME ft;
    if(GetFileTime(hfile, NULL, NULL, &ft)) {
      curl_off_t converted = (curl_off_t)ft.dwLowDateTime |
        ((curl_off_t)ft.dwHighDateTime) << 32;

      if(converted < 116444736000000000)
        warnf("Failed to get filetime: underflow");
      else {
        *stamp = (converted - 116444736000000000) / 10000000;
        rc = 0;
      }
    }
    else {
      warnf("Failed to get filetime: GetFileTime failed: GetLastError 0x%08lx",
            GetLastError());
    }
    CloseHandle(hfile);
  }
  else if(GetLastError() != ERROR_FILE_NOT_FOUND) {
    warnf("Failed to get filetime: CreateFile failed: GetLastError 0x%08lx",
          GetLastError());
  }
#else
  curlx_struct_stat statbuf;
  if(curlx_stat(filename, &statbuf) != -1) {
    *stamp = (curl_off_t)statbuf.st_mtime;
    rc = 0;
  }
  else {
    char errbuf[STRERROR_LEN];
    warnf("Failed to get filetime: %s",
          curlx_strerror(errno, errbuf, sizeof(errbuf)));
  }
#endif
  return rc;
}

#if defined(HAVE_UTIME) || defined(HAVE_UTIMES) || defined(_WIN32)
void setfiletime(curl_off_t filetime, const char *filename)
{
/* Windows utime() may attempt to adjust the Unix GMT file time by a daylight
   saving time offset and since it is GMT that is bad behavior. When we have
   access to a 64-bit type we can bypass utime and set the times directly. */
#if defined(_WIN32) && !defined(CURL_WINDOWS_UWP)
  HANDLE hfile;

  /* 910670515199 is the maximum Unix filetime that can be used as a Windows
     FILETIME without overflow: 30827-12-31T23:59:59. */
  if(filetime > 910670515199) {
    filetime = 910670515199;
    warnf("Capping set filetime to max to avoid overflow");
  }
  else if(filetime < -6857222400) {
    /* dates before 14 september 1752 (pre-Gregorian calendar) are not
       accurate */
    filetime = -6857222400;
    warnf("Capping set filetime to minimum to avoid overflow");
  }

  hfile = curlx_CreateFile(filename, FILE_WRITE_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE |
                           FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
  if(hfile != INVALID_HANDLE_VALUE) {
    curl_off_t converted = ((curl_off_t)filetime * 10000000) +
      116444736000000000;
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(converted & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(converted >> 32);
    if(!SetFileTime(hfile, NULL, &ft, &ft)) {
      warnf("Failed to set filetime %" CURL_FORMAT_CURL_OFF_T
            " on outfile: SetFileTime failed: GetLastError 0x%08lx",
            filetime, GetLastError());
    }
    CloseHandle(hfile);
  }
  else {
    warnf("Failed to set filetime %" CURL_FORMAT_CURL_OFF_T
          " on outfile: CreateFile failed: GetLastError 0x%08lx",
          filetime, GetLastError());
  }

#elif defined(HAVE_UTIMES)
  struct timeval times[2];
  times[0].tv_sec = times[1].tv_sec = (time_t)filetime;
  times[0].tv_usec = times[1].tv_usec = 0;
  if(utimes(filename, times)) {
    char errbuf[STRERROR_LEN];
    warnf("Failed to set filetime %" CURL_FORMAT_CURL_OFF_T
          " on '%s': %s", filetime, filename,
          curlx_strerror(errno, errbuf, sizeof(errbuf)));
  }

#elif defined(HAVE_UTIME)
  struct utimbuf times;
  times.actime = (time_t)filetime;
  times.modtime = (time_t)filetime;
  if(utime(filename, &times)) {
    char errbuf[STRERROR_LEN];
    warnf("Failed to set filetime %" CURL_FORMAT_CURL_OFF_T
          " on '%s': %s", filetime, filename,
          curlx_strerror(errno, errbuf, sizeof(errbuf)));
  }
#endif
}
#endif /* HAVE_UTIME || HAVE_UTIMES || _WIN32 */
