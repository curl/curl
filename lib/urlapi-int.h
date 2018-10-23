#ifndef HEADER_CURL_URLAPI_INT_H
#define HEADER_CURL_URLAPI_INT_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2018, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curl_setup.h"
/* scheme is not URL encoded, the longest libcurl supported ones are 6
   letters */
#define MAX_SCHEME_LEN 8

bool Curl_is_absolute_url(const char *url, char *scheme, size_t buflen);
char *Curl_concat_url(const char *base, const char *relurl);
size_t Curl_strlen_url(const char *url, bool relative);
void Curl_strcpy_url(char *output, const char *url, bool relative);
#endif /* HEADER_CURL_URLAPI_INT_H */
