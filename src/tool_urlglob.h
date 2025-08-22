#ifndef HEADER_CURL_TOOL_URLGLOB_H
#define HEADER_CURL_TOOL_URLGLOB_H
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
#include "tool_setup.h"

typedef enum {
  GLOB_SET = 1,
  GLOB_ASCII,
  GLOB_NUM
} globtype;

struct URLPattern {
  globtype type;
  int globindex; /* the number of this particular glob or -1 if not used
                    within {} or [] */
  union {
    struct {
      char **elem;
      curl_off_t size;
      curl_off_t idx;
    } set;
    struct {
      int min;
      int max;
      int letter;
      unsigned char step;
    } ascii;
    struct {
      curl_off_t min;
      curl_off_t max;
      curl_off_t idx;
      curl_off_t step;
      int npad;
    } num;
  } c;
};

/* the total number of globs supported */
#define GLOB_PATTERN_NUM 30

struct URLGlob {
  struct dynbuf buf;
  struct URLPattern *pattern;
  size_t palloc; /* number of pattern entries allocated */
  size_t size;
  char beenhere;
  const char *error; /* error message */
  size_t pos;        /* column position of error or 0 */
};

CURLcode glob_url(struct URLGlob *, char *, curl_off_t *, FILE *);
CURLcode glob_next_url(char **, struct URLGlob *);
CURLcode glob_match_url(char **, const char *, struct URLGlob *);
void glob_cleanup(struct URLGlob *glob);
bool glob_inuse(struct URLGlob *glob);

#endif /* HEADER_CURL_TOOL_URLGLOB_H */
