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

/* The fourth-to-last include */
#ifdef __CYGWIN__
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifdef _WIN32
#undef _WIN32
#endif
#endif

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* DllMain() must only be defined for Windows and Cygwin DLL builds. */
#if (defined(_WIN32) || defined(__CYGWIN__)) && !defined(CURL_STATICLIB)

#if defined(USE_OPENSSL) && \
    !defined(OPENSSL_IS_AWSLC) && \
    !defined(OPENSSL_IS_BORINGSSL) && \
    !defined(LIBRESSL_VERSION_NUMBER) && \
    (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define PREVENT_OPENSSL_MEMLEAK
#endif

#ifdef PREVENT_OPENSSL_MEMLEAK
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
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
    /* Call OPENSSL_thread_stop to prevent a memory leak in case OpenSSL is
       linked statically.
       https://github.com/curl/curl/issues/12327#issuecomment-1826405944 */
    OPENSSL_thread_stop();
    break;
  }
  return TRUE;
}
#endif /* OpenSSL */

#endif /* DLL build */
