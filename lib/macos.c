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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"

#ifdef FETCH_MACOS_CALL_COPYPROXIES

#include <fetch/fetch.h>

#include "macos.h"

#include <SystemConfiguration/SCDynamicStoreCopySpecific.h>

FETCHcode Curl_macos_init(void)
{
  /*
   * The automagic conversion from IPv4 literals to IPv6 literals only
   * works if the SCDynamicStoreCopyProxies system function gets called
   * first. As fetch currently does not support system-wide HTTP proxies, we
   * therefore do not use any value this function might return.
   *
   * This function is only available on macOS and is not needed for
   * IPv4-only builds, hence the conditions for defining
   * FETCH_MACOS_CALL_COPYPROXIES in fetch_setup.h.
   */
  CFDictionaryRef dict = SCDynamicStoreCopyProxies(NULL);
  if (dict)
    CFRelease(dict);
  return FETCHE_OK;
}

#endif
