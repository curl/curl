#ifndef __URLGLOB_H
#define __URLGLOB_H
/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/
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
} URLGlob;

int glob_url(URLGlob**, char*, int *);
char* next_url(URLGlob*);
char* match_url(char*, URLGlob *); 
void glob_cleanup(URLGlob* glob);

#endif
