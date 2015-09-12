#ifndef HEADER_CURL_VAUTH_H
#define HEADER_CURL_VAUTH_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2014 - 2015, Steve Holme, <steve_holme@hotmail.com>.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include <curl/curl.h>

/* This is used to build a SPN string */
#if !defined(USE_WINDOWS_SSPI)
char *Curl_sasl_build_spn(const char *service, const char *instance);
#else
TCHAR *Curl_sasl_build_spn(const char *service, const char *instance);
#endif

#if defined(HAVE_GSSAPI)
char *Curl_sasl_build_gssapi_spn(const char *service, const char *instance);
#endif

#endif /* HEADER_CURL_VAUTH_H */
