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
#endif /* _WIN32 */
