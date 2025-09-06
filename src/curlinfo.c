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

/*
 * The purpose of this tool is to figure out which, if any, features that are
 * disabled which should otherwise exist and work. These are not visible in
 * regular curl -V output.
 *
 * Disabled protocols are visible in curl_version_info() and are not included
 * in this table.
 */

#include "curl_setup.h"
#include "multihandle.h" /* for ENABLE_WAKEUP */
#include "tool_xattr.h" /* for USE_XATTR */
#include "curl_sha512_256.h" /* for CURL_HAVE_SHA512_256 */
#include "asyn.h" /* for CURLRES_ARES */
#include "fake_addrinfo.h" /* for USE_FAKE_GETADDRINFO */
#include <stdio.h>

static const char *disabled[]={
  "bindlocal: "
#ifdef CURL_DISABLE_BINDLOCAL
  "OFF"
#else
  "ON"
#endif
  ,

  "cookies: "
#ifdef CURL_DISABLE_COOKIES
  "OFF"
#else
  "ON"
#endif
  ,

  "basic-auth: "
#ifdef CURL_DISABLE_BASIC_AUTH
  "OFF"
#else
  "ON"
#endif
  ,
  "bearer-auth: "
#ifdef CURL_DISABLE_BEARER_AUTH
  "OFF"
#else
  "ON"
#endif
  ,
  "digest: "
#ifdef CURL_DISABLE_DIGEST_AUTH
  "OFF"
#else
  "ON"
#endif
  ,
  "negotiate-auth: "
#ifdef CURL_DISABLE_NEGOTIATE_AUTH
  "OFF"
#else
  "ON"
#endif
  ,
  "aws: "
#ifdef CURL_DISABLE_AWS
  "OFF"
#else
  "ON"
#endif
  ,
  "DoH: "
#ifdef CURL_DISABLE_DOH
  "OFF"
#else
  "ON"
#endif
  ,
  "HTTP-auth: "
#ifdef CURL_DISABLE_HTTP_AUTH
  "OFF"
#else
  "ON"
#endif
  ,
  "Mime: "
#ifdef CURL_DISABLE_MIME
  "OFF"
#else
  "ON"
#endif
  ,

  "netrc: "
#ifdef CURL_DISABLE_NETRC
  "OFF"
#else
  "ON"
#endif
  ,
  "parsedate: "
#ifdef CURL_DISABLE_PARSEDATE
  "OFF"
#else
  "ON"
#endif
  ,
  "proxy: "
#ifdef CURL_DISABLE_PROXY
  "OFF"
#else
  "ON"
#endif
  ,
  "shuffle-dns: "
#ifdef CURL_DISABLE_SHUFFLE_DNS
  "OFF"
#else
  "ON"
#endif
  ,
  "typecheck: "
#ifdef CURL_DISABLE_TYPECHECK
  "OFF"
#else
  "ON"
#endif
  ,
  "verbose-strings: "
#ifdef CURL_DISABLE_VERBOSE_STRINGS
  "OFF"
#else
  "ON"
#endif
  ,
  "wakeup: "
#ifndef ENABLE_WAKEUP
  "OFF"
#else
  "ON"
#endif
  ,
  "headers-api: "
#ifdef CURL_DISABLE_HEADERS_API
  "OFF"
#else
  "ON"
#endif
  ,
  "xattr: "
#ifndef USE_XATTR
  "OFF"
#else
  "ON"
#endif
  ,
  "form-api: "
#ifdef CURL_DISABLE_FORM_API
  "OFF"
#else
  "ON"
#endif
  ,
  "large-time: "
#if (SIZEOF_TIME_T < 5)
  "OFF"
#else
  "ON"
#endif
  ,
  "large-size: "
#if (SIZEOF_SIZE_T < 5)
  "OFF"
#else
  "ON"
#endif
  ,
  "sha512-256: "
#ifndef CURL_HAVE_SHA512_256
  "OFF"
#else
  "ON"
#endif
  ,

  "win32-ca-searchpath: "
#if !defined(_WIN32) ||                                                 \
  (defined(CURL_WINDOWS_UWP) ||                                         \
   defined(CURL_DISABLE_CA_SEARCH) || defined(CURL_CA_SEARCH_SAFE))
  "OFF"
#else
  "ON"
#endif
  ,
  "win32-ca-search-safe: "
#if !defined(_WIN32) || !defined(CURL_CA_SEARCH_SAFE)
  "OFF"
#else
  "ON"
#endif
  ,

  "--libcurl: "
#ifdef CURL_DISABLE_LIBCURL_OPTION
  "OFF"
#else
  "ON"
#endif
  ,
  "override-dns: "
#if defined(CURLDEBUG) &&                                       \
  (defined(CURLRES_ARES) || defined(USE_FAKE_GETADDRINFO))
  "ON"
#else
  "OFF"
#endif
};

int main(int argc, char **argv)
{
  size_t i;

  (void)argc;
  (void)argv;

  for(i = 0; i < CURL_ARRAYSIZE(disabled); i++)
    printf("%s\n", disabled[i]);

  return 0;
}
