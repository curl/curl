#ifndef HEADER_CURL_STRPARSE_H
#define HEADER_CURL_STRPARSE_H
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

#define STRE_OK       0
#define STRE_BIG      1
#define STRE_SHORT    2
#define STRE_BEGQUOTE 3
#define STRE_ENDQUOTE 4
#define STRE_BYTE     5
#define STRE_NEWLINE  6
#define STRE_OVERFLOW 7
#define STRE_NO_NUM   8

struct Curl_str {
  const char *str;
  size_t len;
};

/* Get a word until the first space
   return non-zero on error */
int Curl_str_word(const char **linep, struct Curl_str *out, const size_t max);

/* Get a word until the first DELIM or end of string
   return non-zero on error */
int Curl_str_until(const char **linep, struct Curl_str *out, const size_t max,
                   char delim);

/* Get a "quoted" word. No escaping possible.
   return non-zero on error */
int Curl_str_quotedword(const char **linep, struct Curl_str *out,
                        const size_t max);

/* Advance over a single character.
   return non-zero on error */
int Curl_str_single(const char **linep, char byte);

/* Advance over a single space.
   return non-zero on error */
int Curl_str_singlespace(const char **linep);

/* Get an unsigned decimal number. Return non-zero on error */
int Curl_str_number(const char **linep, curl_off_t *nump, curl_off_t max);

/* Get an unsigned hexadecimal number. Return non-zero on error */
int Curl_str_hex(const char **linep, curl_off_t *nump, curl_off_t max);

/* Get an unsigned octal number. Return non-zero on error */
int Curl_str_octal(const char **linep, curl_off_t *nump, curl_off_t max);

/* Check for CR or LF
   return non-zero on error */
int Curl_str_newline(const char **linep);

/* case insensitive compare that the parsed string matches the
   given string. */
int Curl_str_casecompare(struct Curl_str *str, const char *check);

int Curl_str_nudge(struct Curl_str *str, size_t num);

#endif /* HEADER_CURL_STRPARSE_H */
