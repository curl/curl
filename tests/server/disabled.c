/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include <stdio.h>

static const char *disabled[]={
#ifdef CURL_DISABLE_COOKIES
  "cookies",
#endif
#ifdef CURL_DISABLE_CRYPTO_AUTH
  "crypto",
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
  NULL
};

int main(void)
{
  int i;
  for(i = 0; disabled[i]; i++)
    printf("%s\n", disabled[i]);

  return 0;
}
