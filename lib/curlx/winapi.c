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
 * Variant of curlx_strerror if the error code is definitely Windows API.
 */
#ifdef _WIN32
#include "winapi.h"
#include "snprintf.h"

/* This is a helper function for curlx_strerror that converts Windows API error
 * codes (GetLastError) to error messages.
 * Returns NULL if no error message was found for error code.
 */
const char *curlx_get_winapi_error(DWORD err, char *buf, size_t buflen)
{
  char *p;
  wchar_t wbuf[256];
  DWORD wlen;

  if(!buflen)
    return NULL;

  *buf = '\0';
  *wbuf = L'\0';

  /* We return the local codepage version of the error string because if it is
     output to the user's terminal it will likely be with functions which
     expect the local codepage (eg fprintf, failf, infof). */
  wlen = FormatMessageW((FORMAT_MESSAGE_FROM_SYSTEM |
                         FORMAT_MESSAGE_IGNORE_INSERTS), NULL, err,
                        LANG_NEUTRAL, wbuf, CURL_ARRAYSIZE(wbuf), NULL);
  if(wlen && !wcstombs_s(NULL, buf, buflen, wbuf, wlen)) {
    /* Truncate multiple lines */
    p = strchr(buf, '\n');
    if(p) {
      if(p > buf && *(p-1) == '\r')
        *(p-1) = '\0';
      else
        *p = '\0';
    }
  }

  return *buf ? buf : NULL;
}

const char *curlx_winapi_strerror(DWORD err, char *buf, size_t buflen)
{
  DWORD old_win_err = GetLastError();
  int old_errno = errno;

  if(!buflen)
    return NULL;

  *buf = '\0';

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(!curlx_get_winapi_error(err, buf, buflen)) {
#if defined(__GNUC__) && __GNUC__ >= 7
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wformat-truncation=1"
#endif
    /* some GCC compilers cause false positive warnings if we allow this
       warning */
    SNPRINTF(buf, buflen, "Unknown error %lu (0x%08lx)", err, err);
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
    errno = old_errno;

  if(old_win_err != GetLastError())
    SetLastError(old_win_err);

  return buf;
}
#endif /* _WIN32 */
