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
 * are also available at https://fetch.se/docs/copyright.html.
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

/*
 * The purpose of this tool is to figure out which, if any, features that are
 * disabled which should otherwise exist and work. These aren't visible in
 * regular fetch -V output.
 *
 * Disabled protocols are visible in fetch_version_info() and are not included
 * in this table.
 */

#include "fetch_setup.h"
#include "multihandle.h"      /* for ENABLE_WAKEUP */
#include "tool_xattr.h"       /* for USE_XATTR */
#include "fetch_sha512_256.h" /* for FETCH_HAVE_SHA512_256 */
#include <stdio.h>

static const char *disabled[] = {
#ifdef FETCH_DISABLE_BINDLOCAL
    "bindlocal",
#endif
#ifdef FETCH_DISABLE_COOKIES
    "cookies",
#endif
#ifdef FETCH_DISABLE_BASIC_AUTH
    "basic-auth",
#endif
#ifdef FETCH_DISABLE_BEARER_AUTH
    "bearer-auth",
#endif
#ifdef FETCH_DISABLE_DIGEST_AUTH
    "digest-auth",
#endif
#ifdef FETCH_DISABLE_NEGOTIATE_AUTH
    "negotiate-auth",
#endif
#ifdef FETCH_DISABLE_AWS
    "aws",
#endif
#ifdef FETCH_DISABLE_DOH
    "DoH",
#endif
#ifdef FETCH_DISABLE_HTTP_AUTH
    "HTTP-auth",
#endif
#ifdef FETCH_DISABLE_MIME
    "Mime",
#endif
#ifdef FETCH_DISABLE_NETRC
    "netrc",
#endif
#ifdef FETCH_DISABLE_PARSEDATE
    "parsedate",
#endif
#ifdef FETCH_DISABLE_PROXY
    "proxy",
#endif
#ifdef FETCH_DISABLE_SHUFFLE_DNS
    "shuffle-dns",
#endif
#ifdef FETCH_DISABLE_TYPECHECK
    "typecheck",
#endif
#ifdef FETCH_DISABLE_VERBOSE_STRINGS
    "verbose-strings",
#endif
#ifndef ENABLE_WAKEUP
    "wakeup",
#endif
#ifdef FETCH_DISABLE_HEADERS_API
    "headers-api",
#endif
#ifndef USE_XATTR
    "xattr",
#endif
#ifdef FETCH_DISABLE_FORM_API
    "form-api",
#endif
#if (SIZEOF_TIME_T < 5)
    "large-time",
#endif
#if (SIZEOF_SIZE_T < 5)
    "large-size",
#endif
#ifndef FETCH_HAVE_SHA512_256
    "sha512-256",
#endif
#ifdef _WIN32
#if defined(FETCH_WINDOWS_UWP) || \
    defined(FETCH_DISABLE_CA_SEARCH) || defined(FETCH_CA_SEARCH_SAFE)
    "win32-ca-searchpath",
#endif
#ifndef FETCH_CA_SEARCH_SAFE
    "win32-ca-search-safe",
#endif
#endif
    NULL};

int main(int argc, char **argv)
{
  int i;

  (void)argc;
  (void)argv;

  for (i = 0; disabled[i]; i++)
    printf("%s\n", disabled[i]);

  return 0;
}
