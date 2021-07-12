#ifndef HEADER_CURLX_GETENV_H
#define HEADER_CURLX_GETENV_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

/*
curlx getenv replacements for libcurl and curl tool.

These functions are needed to better support Windows builds.

Windows does not use or support UTF-8 as the current locale (or, not really).
The Windows Unicode builds of curl/libcurl use the current locale, but expect
Unicode UTF-8 encoded paths for internal use such as open, access and stat.

Dependencies in Windows, which may or may not be Unicode builds, may or may not
expect UTF-8 encoded Unicode for char * string pathnames. For example, libcurl
can use libssh or libssh2 as an SSH library and pathnames always need to be
passed in the local encoding AFAICS.

Basically, for Windows Unicode builds we need access to environment variables
in both UTF-8 and current locale encoding. In order to make this obvious in the
code I've banned getenv, curlx_getenv and curl_getenv (via checksrc) in favor
of Curl_getenv_local, Curl_getenv_utf8 and Curl_getenv. For Windows Unicode
builds Curl_getenv maps to Curl_getenv_utf8, and Curl_getenv_local otherwise.

Continuing the SSH example, something like CURLOPT_SSH_KNOWNHOSTS which is
passed to the SSH library and always needs the local encoding (in other words,
even if it's a Windows Unicode build) can now be retrieved in the tool by
calling homedir_local (-> Curl_getenv_local). And in contrast, a home path
for internal use like .curlrc would be retrieved by calling homedir,
which maps to homedir_utf8 (-> Curl_getenv_utf8) for Windows Unicode and
homedir_local (-> Curl_getenv_local) otherwise.
*/

/* environment variable and the returned value in current locale encoding */
char *Curl_getenv_local(const char *variable);

/* returns true if variable exists */
bool Curl_env_exist_local(const char *variable);

#if defined(WIN32) && defined(_UNICODE)
/* environment variable and the returned value in Unicode UTF-8 encoding */
char *Curl_getenv_utf8(const char *variable);
/* Windows Unicode builds of curl/libcurl always expect UTF-8 strings for
   internal file paths, regardless of current locale. For paths (or other
   values) passed to a dependency that will always expect local encoding, call
   Curl_getenv_local directly instead.*/
#define Curl_getenv(variable) Curl_getenv_utf8(variable)
/* returns true if variable exists */
bool Curl_env_exist_utf8(const char *variable);
#define Curl_env_exist(variable) Curl_env_exist_utf8(variable)
#else
#define Curl_getenv(variable) Curl_getenv_local(variable)
#define Curl_env_exist(variable) Curl_env_exist_local(variable)
#endif

#endif /* HEADER_CURLX_GETENV_H */
