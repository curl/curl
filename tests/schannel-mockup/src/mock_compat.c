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

#include "mock_internal.h"

#include "curl/curl.h"
#include "curl_win32.h"

/*
 * curlx_verify_windows_version:
 *
 * Returns TRUE to report that the platform meets all modern Windows
 * requirements (Windows 11 / Windows Server 2022 build 20348+), enabling TLS
 * 1.3, ALPN, manual CA store validation, etc.
 */
bool curlx_verify_windows_version(unsigned int majorVersion,
                                  unsigned int minorVersion,
                                  unsigned int buildVersion,
                                  PlatformIdentifier platform,
                                  VersionCondition condition)
{
  (void)majorVersion;
  (void)minorVersion;
  (void)buildVersion;
  (void)platform;
  (void)condition;
  return TRUE;
}

const char *curlx_winapi_strerror(DWORD derr, char *buf, size_t buflen)
{
  unsigned int err = (unsigned int)derr;
  if(!buf || !buflen)
    return "";

  switch(err) {
  case ERROR_SUCCESS:
    snprintf(buf, buflen,
             "The operation completed successfully (0x%08x)", err);
    break;
  case ERROR_FILE_NOT_FOUND:
    snprintf(buf, buflen,
             "The system cannot find the file specified (0x%08x)", err);
    break;
  case ERROR_ACCESS_DENIED:
    snprintf(buf, buflen, "Access is denied (0x%08x)", err);
    break;
  case ERROR_INVALID_HANDLE:
    snprintf(buf, buflen, "The handle is invalid (0x%08x)", err);
    break;
  case ERROR_NOT_ENOUGH_MEMORY:
    snprintf(buf, buflen,
             "Not enough memory resources available (0x%08x)", err);
    break;
  case ERROR_NOT_SUPPORTED:
    snprintf(buf, buflen, "The request is not supported (0x%08x)", err);
    break;
  case ERROR_INVALID_PASSWORD:
    snprintf(buf, buflen,
             "The specified network password is not correct (0x%08x)", err);
    break;
  case ERROR_INVALID_PARAMETER:
    snprintf(buf, buflen,
             "The parameter is incorrect (0x%08x)", err);
    break;
  case ERROR_INSUFFICIENT_BUFFER:
    snprintf(buf, buflen,
             "The data area passed to a system call is too small (0x%08x)",
             err);
    break;
  case ERROR_MORE_DATA:
    snprintf(buf, buflen, "More data is available (0x%08x)", err);
    break;
  default:
    snprintf(buf, buflen, "Win32/SSPI error code 0x%08x", err);
    break;
  }

  return buf;
}

const char *curlx_get_winapi_error(DWORD err, char *buf, size_t buflen)
{
  return curlx_winapi_strerror(err, buf, buflen);
}

CURLcode curlx_win32_random(unsigned char *entropy, size_t length)
{
  if(!entropy || !length)
    return CURLE_OK;

  if(RAND_bytes(entropy, (int)length) <= 0)
    return CURLE_FAILED_INIT;

  return CURLE_OK;
}
