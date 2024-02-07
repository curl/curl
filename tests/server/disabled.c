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
 * disabled which should otherwise exist and work. These aren't visible in
 * regular curl -V output.
 *
 * Disabled protocols are visible in curl_version_info() and are not included
 * in this table.
 */

#include "curl_setup.h"
#include "multihandle.h" /* for ENABLE_WAKEUP */
#include "tool_xattr.h" /* for USE_XATTR */
#include "curl_sha512_256.h" /* for CURL_HAVE_SHA512_256 */
#include <stdio.h>

static const char *disabled[]={
#ifdef CURL_DISABLE_BINDLOCAL
  "bindlocal",
#endif
#ifdef CURL_DISABLE_COOKIES
  "cookies",
#endif
#ifdef CURL_DISABLE_BASIC_AUTH
  "basic-auth",
#endif
#ifdef CURL_DISABLE_BEARER_AUTH
  "bearer-auth",
#endif
#ifdef CURL_DISABLE_DIGEST_AUTH
  "digest-auth",
#endif
#ifdef CURL_DISABLE_NEGOTIATE_AUTH
  "negotiate-auth",
#endif
#ifdef CURL_DISABLE_AWS
  "aws",
#endif
#ifdef CURL_DISABLE_DOH
  "DoH",
#endif
#ifdef CURL_DISABLE_HTTP_AUTH
  "HTTP-auth",
#endif
#ifdef CURL_DISABLE_MIME
  "Mime",
#endif
#ifdef CURL_DISABLE_NETRC
  "netrc",
#endif
#ifdef CURL_DISABLE_PARSEDATE
  "parsedate",
#endif
#ifdef CURL_DISABLE_PROXY
  "proxy",
#endif
#ifdef CURL_DISABLE_SHUFFLE_DNS
  "shuffle-dns",
#endif
#ifdef CURL_DISABLE_TYPECHECK
  "typecheck",
#endif
#ifdef CURL_DISABLE_VERBOSE_STRINGS
  "verbose-strings",
#endif
#ifndef ENABLE_WAKEUP
  "wakeup",
#endif
#ifdef CURL_DISABLE_HEADERS_API
  "headers-api",
#endif
#ifndef USE_XATTR
  "xattr",
#endif
#ifdef CURL_DISABLE_FORM_API
  "form-api",
#endif
#if (SIZEOF_TIME_T < 5)
  "large-time",
#endif
#ifndef CURL_HAVE_SHA512_256
  "sha512-256",
#endif
  NULL
};

int main(int argc, char **argv)
{
  int i;

  (void) argc;
  (void) argv;

  for(i = 0; disabled[i]; i++)
    printf("%s\n", disabled[i]);

  return 0;
}
