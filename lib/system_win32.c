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

#include "system_win32.h"
#include "curl_sspi.h"

/* Curl_win32_init() performs Win32 global initialization */
CURLcode Curl_win32_init(long flags)
{
  /* CURL_GLOBAL_WIN32 controls the *optional* part of the initialization which
     is just for Winsock at the moment. Any required Win32 initialization
     should take place after this block. */
  if(flags & CURL_GLOBAL_WIN32) {
#ifdef USE_WINSOCK
    WORD wVersionRequested;
    WSADATA wsaData;
    int res;

    wVersionRequested = MAKEWORD(2, 2);
    res = WSAStartup(wVersionRequested, &wsaData);

    if(res)
      /* Tell the user that we could not find a usable */
      /* winsock.dll.     */
      return CURLE_FAILED_INIT;

    /* Confirm that the Windows Sockets DLL supports what we need.*/
    /* Note that if the DLL supports versions greater */
    /* than wVersionRequested, it will still return */
    /* wVersionRequested in wVersion. wHighVersion contains the */
    /* highest supported version. */

    if(LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
       HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested)) {
      /* Tell the user that we could not find a usable */

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

  QueryPerformanceFrequency(&Curl_freq);
  return CURLE_OK;
}

/* Curl_win32_cleanup() is the opposite of Curl_win32_init() */
void Curl_win32_cleanup(long init_flags)
{
#ifdef USE_WINDOWS_SSPI
  Curl_sspi_global_cleanup();
#endif

  if(init_flags & CURL_GLOBAL_WIN32) {
#ifdef USE_WINSOCK
    WSACleanup();
#endif
  }
}

#endif /* _WIN32 */
