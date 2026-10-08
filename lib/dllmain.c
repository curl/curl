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
#include "curl_setup.h"

#ifdef USE_OPENSSL
#include <openssl/crypto.h>
#endif

/* DllMain() must only be defined for Windows DLL builds. */
#if defined(_WIN32) && !defined(CURL_STATICLIB)

#if defined(USE_OPENSSL) && \
  !defined(OPENSSL_IS_AWSLC) && !defined(OPENSSL_IS_BORINGSSL) && \
  !defined(LIBRESSL_VERSION_NUMBER)
#define PREVENT_OPENSSL_MEMLEAK  /* non-fork OpenSSL */
#endif

#if defined(_MSC_VER) && defined(DEBUGBUILD)  /* FIXME: for mingw-w64 */
#define LIBCURL_INIT_CRTDBG
#ifndef _DEBUG
#define _DEBUG  /* FIXME: is this needed */
#endif
#include <crtdbg.h> /* for _CrtSetReportFile(), _CRT* macros */
#include <stdlib.h> /* for _set_error_mode() */
#endif

#if defined(LIBCURL_INIT_CRTDBG) || defined(PREVENT_OPENSSL_MEMLEAK)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  (void)hinstDLL;
  (void)lpvReserved;

#ifdef LIBCURL_INIT_CRTDBG
  _set_error_mode(_OUT_TO_STDERR);
  _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
  _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDOUT);
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDOUT);
#endif

  switch(fdwReason) {
  case DLL_PROCESS_ATTACH:
    break;
  case DLL_PROCESS_DETACH:
    break;
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
#ifdef PREVENT_OPENSSL_MEMLEAK
    /* Call OPENSSL_thread_stop to prevent a memory leak in case OpenSSL is
       linked statically.
       https://github.com/curl/curl/issues/12327#issuecomment-1826405944 */
    OPENSSL_thread_stop();
#endif
    break;
  }
  return TRUE;
}
#endif /* LIBCURL_INIT_CRTDBG || PREVENT_OPENSSL_MEMLEAK */

#endif /* _WIN32 && !CURL_STATICLIB */
