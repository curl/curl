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

#include <curl/curl.h>

#include "strcase.h"

/* Mapping table to go from lowercase to uppercase for plain ASCII.*/
static const unsigned char touppermap[256] = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 65,
66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
85, 86, 87, 88, 89, 90, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

/* Mapping table to go from uppercase to lowercase for plain ASCII.*/
static const unsigned char tolowermap[256] = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
62, 63, 64, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 91, 92, 93, 94, 95,
96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};


/* Portable, consistent toupper. Do not use toupper() because its behavior is
   altered by the current locale. */
char Curl_raw_toupper(char in)
{
  return (char)touppermap[(unsigned char) in];
}


/* Portable, consistent tolower. Do not use tolower() because its behavior is
   altered by the current locale. */
char Curl_raw_tolower(char in)
{
  return (char)tolowermap[(unsigned char) in];
}

/*
 * curl_strequal() is for doing "raw" case insensitive strings. This is meant
 * to be locale independent and only compare strings we know are safe for
 * this. See https://daniel.haxx.se/blog/2008/10/15/strcasecmp-in-turkish/ for
 * further explanations as to why this function is necessary.
 */

static int casecompare(const char *first, const char *second)
{
  while(*first && *second) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second))
      /* get out of the loop as soon as they do not match */
      return 0;
    first++;
    second++;
  }
  /* If we are here either the strings are the same or the length is different.
     We can just test if the "current" character is non-zero for one and zero
     for the other. Note that the characters may not be exactly the same even
     if they match, we only want to compare zero-ness. */
  return !*first == !*second;
}

/* --- public function --- */
int curl_strequal(const char *first, const char *second)
{
  if(first && second)
    /* both pointers point to something then compare them */
    return casecompare(first, second);

  /* if both pointers are NULL then treat them as equal */
  return NULL == first && NULL == second;
}

static int ncasecompare(const char *first, const char *second, size_t max)
{
  while(*first && *second && max) {
    if(Curl_raw_toupper(*first) != Curl_raw_toupper(*second))
      return 0;
    max--;
    first++;
    second++;
  }
  if(0 == max)
    return 1; /* they are equal this far */

  return Curl_raw_toupper(*first) == Curl_raw_toupper(*second);
}

/* --- public function --- */
int curl_strnequal(const char *first, const char *second, size_t max)
{
  if(first && second)
    /* both pointers point to something then compare them */
    return ncasecompare(first, second, max);

  /* if both pointers are NULL then treat them as equal if max is non-zero */
  return NULL == first && NULL == second && max;
}
/* Copy an upper case version of the string from src to dest. The
 * strings may overlap. No more than n characters of the string are copied
 * (including any NUL) and the destination string will NOT be
 * NUL-terminated if that limit is reached.
 */
void Curl_strntoupper(char *dest, const char *src, size_t n)
{
  if(n < 1)
    return;

  do {
    *dest++ = Curl_raw_toupper(*src);
  } while(*src++ && --n);
}

/* Copy a lower case version of the string from src to dest. The
 * strings may overlap. No more than n characters of the string are copied
 * (including any NUL) and the destination string will NOT be
 * NUL-terminated if that limit is reached.
 */
void Curl_strntolower(char *dest, const char *src, size_t n)
{
  if(n < 1)
    return;

  do {
    *dest++ = Curl_raw_tolower(*src);
  } while(*src++ && --n);
}

/* Compare case-sensitive NUL-terminated strings, taking care of possible
 * null pointers. Return true if arguments match.
 */
bool Curl_safecmp(char *a, char *b)
{
  if(a && b)
    return !strcmp(a, b);
  return !a && !b;
}

/*
 * Curl_timestrcmp() returns 0 if the two strings are identical. The time this
 * function spends is a function of the shortest string, not of the contents.
 */
int Curl_timestrcmp(const char *a, const char *b)
{
  int match = 0;
  int i = 0;

  if(a && b) {
    while(1) {
      match |= a[i]^b[i];
      if(!a[i] || !b[i])
        break;
      i++;
    }
  }
  else
    return a || b;
  return match;
}
