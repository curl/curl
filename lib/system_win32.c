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
#include "system_win32.h"
#include "curlx/version_win32.h"
#include "curl_sspi.h"
#include "curlx/warnless.h"

/* The last #include files should be: */
#include "curl_memory.h"
#include "memdebug.h"

/* Handle of iphlpapp.dll */
static HMODULE s_hIpHlpApiDll = NULL;

/* Pointer to the if_nametoindex function */
IF_NAMETOINDEX_FN Curl_if_nametoindex = NULL;

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
       HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested) ) {
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

  s_hIpHlpApiDll = curlx_winapi_load_library(TEXT("iphlpapi.dll"));
  if(s_hIpHlpApiDll) {
    /* Get the address of the if_nametoindex function */
#ifdef UNDER_CE
    #define CURL_TEXT(n) TEXT(n)
#else
    #define CURL_TEXT(n) (n)
#endif
    IF_NAMETOINDEX_FN pIfNameToIndex =
      CURLX_FUNCTION_CAST(IF_NAMETOINDEX_FN,
                          (GetProcAddress(s_hIpHlpApiDll,
                                          CURL_TEXT("if_nametoindex"))));

    if(pIfNameToIndex)
      Curl_if_nametoindex = pIfNameToIndex;
  }

  /* curlx_verify_windows_version must be called during init at least once
     because it has its own initialization routine. */
  if(curlx_verify_windows_version(6, 0, 0, PLATFORM_WINNT,
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

#endif /* _WIN32 */
