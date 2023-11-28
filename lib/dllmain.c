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

#if (defined(_WIN32) || defined(__CYGWIN__)) && !defined(CURL_STATICLIB)

/* WARNING: Including Cygwin windows.h may define _WIN32 in old versions or
   may have unexpected behavior in unity builds (where all source files are
   bundled into a single unit). For that reason, this source file must be
   compiled separately for Cygwin unity builds. */

#ifdef __CYGWIN__
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifdef USE_OPENSSL
#include <openssl/crypto.h>
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  (void)hinstDLL;
  (void)lpvReserved;

  switch(fdwReason) {
  case DLL_PROCESS_ATTACH:
    break;
  case DLL_PROCESS_DETACH:
    break;
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
#if defined(USE_OPENSSL) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    /* Call OPENSSL_thread_stop to prevent a memory leak in case OpenSSL is
       linked statically.
       https://github.com/curl/curl/issues/12327#issuecomment-1826405944 */
    OPENSSL_thread_stop();
#endif
    break;
  }
  return TRUE;
}

#endif /* (_WIN32 || __CYGWIN__) && !CURL_STATICLIB */
