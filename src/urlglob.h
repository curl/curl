#ifndef __URLGLOB_H
#define __URLGLOB_H
/***************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2003, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 * $Id$
 ***************************************************************************/
typedef enum {UPTSet=1,UPTCharRange,UPTNumRange} URLPatternType;

typedef struct {
  URLPatternType type;
  union {
    struct {
      char **elements;
      short size;
      short ptr_s;
    } Set;
    struct {
      char min_c, max_c;
      char ptr_c;
    } CharRange;
    struct {
      int min_n, max_n;
      short padlength;
      int ptr_n;
    } NumRange ;
  } content;
} URLPattern;

typedef struct {
  char* literal[10];
  URLPattern pattern[9];
  int size;
  int urllen;
  char *glob_buffer;
  char beenhere;
} URLGlob;

int glob_url(URLGlob**, char*, int *, FILE *);
char* glob_next_url(URLGlob*);
char* glob_match_url(char*, URLGlob *); 
void glob_cleanup(URLGlob* glob);

#endif
