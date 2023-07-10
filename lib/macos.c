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

#if defined(__APPLE__)

#if !defined(TARGET_OS_OSX) || TARGET_OS_OSX

#include <curl/curl.h>

#include "macos.h"

#if defined(ENABLE_IPV6) && defined(CURL_OSX_CALL_COPYPROXIES)
#include <SystemConfiguration/SCDynamicStoreCopySpecific.h>
#endif

CURLcode Curl_macos_init(void)
{
#if defined(ENABLE_IPV6) && defined(CURL_OSX_CALL_COPYPROXIES)
  {
    /*
     * The automagic conversion from IPv4 literals to IPv6 literals only
     * works if the SCDynamicStoreCopyProxies system function gets called
     * first. As Curl currently doesn't support system-wide HTTP proxies, we
     * therefore don't use any value this function might return.
     *
     * This function is only available on a macOS and is not needed for
     * IPv4-only builds, hence the conditions above.
     */
    CFDictionaryRef dict = SCDynamicStoreCopyProxies(NULL);
    if(dict)
      CFRelease(dict);
  }
#endif
  return CURLE_OK;
}

#endif /* TARGET_OS_OSX */

#endif /* __APPLE__ */
