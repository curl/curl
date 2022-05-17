#ifndef HEADER_CURL_CTYPE_H
#define HEADER_CURL_CTYPE_H
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

#include "curl_setup.h"

int Curl_isspace(int c);
int Curl_isdigit(int c);
int Curl_isalnum(int c);
int Curl_isxdigit(int c);
int Curl_isgraph(int c);
int Curl_isprint(int c);
int Curl_isalpha(int c);
int Curl_isupper(int c);
int Curl_islower(int c);
int Curl_iscntrl(int c);

#define ISSPACE(x)  (Curl_isspace((int)  ((unsigned char)x)))
#define ISDIGIT(x)  (Curl_isdigit((int)  ((unsigned char)x)))
#define ISALNUM(x)  (Curl_isalnum((int)  ((unsigned char)x)))
#define ISXDIGIT(x) (Curl_isxdigit((int) ((unsigned char)x)))
#define ISGRAPH(x)  (Curl_isgraph((int)  ((unsigned char)x)))
#define ISALPHA(x)  (Curl_isalpha((int)  ((unsigned char)x)))
#define ISPRINT(x)  (Curl_isprint((int)  ((unsigned char)x)))
#define ISUPPER(x)  (Curl_isupper((int)  ((unsigned char)x)))
#define ISLOWER(x)  (Curl_islower((int)  ((unsigned char)x)))
#define ISCNTRL(x)  (Curl_iscntrl((int)  ((unsigned char)x)))
#define ISASCII(x)  (((x) >= 0) && ((x) <= 0x80))

#define ISBLANK(x)  (int)((((unsigned char)x) == ' ') ||        \
                          (((unsigned char)x) == '\t'))

#endif /* HEADER_CURL_CTYPE_H */
