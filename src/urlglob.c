/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 *  The contents of this file are subject to the Mozilla Public License
 *  Version 1.0 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *  http://www.mozilla.org/MPL/
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
 *  License for the specific language governing rights and limitations
 *  under the License.
 *
 *  The Original Code is Curl.
 *
 *  The Initial Developer of the Original Code is Daniel Stenberg.
 *
 *  Portions created by the Initial Developer are Copyright (C) 1998.
 *  All Rights Reserved.
 *
 * ------------------------------------------------------------
 * Main author:
 * - Daniel Stenberg <Daniel.Stenberg@haxx.nu>
 *
 * 	http://curl.haxx.nu
 *
 * $Source$
 * $Revision$
 * $Date$
 * $Author$
 * $State$
 * $Locker$
 *
 * ------------------------------------------------------------
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>
#include "urlglob.h"

char glob_buffer[URL_MAX_LENGTH];
URLGlob *glob_expand;

int glob_word(char*, int);

int glob_set(char *pattern, int pos) {
  /* processes a set expression with the point behind the opening '{'
     ','-separated elements are collected until the next closing '}'
  */
  char* buf = glob_buffer;
  URLPattern *pat;

  pat = (URLPattern*)&glob_expand->pattern[glob_expand->size / 2];
  /* patterns 0,1,2,... correspond to size=1,3,5,... */
  pat->type = UPTSet;
  pat->content.Set.size = 0;
  pat->content.Set.ptr_s = 0;
  pat->content.Set.elements = (char**)malloc(0);
  ++glob_expand->size;

  while (1) {
    switch (*pattern) {
    case '\0':				/* URL ended while set was still open */
      printf("error: unmatched brace at pos %d\n", pos);
      exit (URG_URL_MALFORMAT);
    case '{':
    case '[':				/* no nested expressions at this time */
      printf("error: nested braces not supported %d\n", pos);
      exit (URG_URL_MALFORMAT);
    case ',':
    case '}':				/* set element completed */
      *buf = '\0';
      pat->content.Set.elements = realloc(pat->content.Set.elements, (pat->content.Set.size + 1) * sizeof(char*));
      if (!pat->content.Set.elements) {
	printf("out of memory in set pattern\n");
	exit(URG_OUT_OF_MEMORY);
      }
      pat->content.Set.elements[pat->content.Set.size] = strdup(glob_buffer);
      ++pat->content.Set.size;

      if (*pattern == '}')		/* entire set pattern completed */
	/* always check for a literal (may be "") between patterns */
	return pat->content.Set.size * glob_word(++pattern, ++pos);

      buf = glob_buffer;
      ++pattern;
      ++pos;
      break;
    case ']':				/* illegal closing bracket */
      printf("error: illegal pattern at pos %d\n", pos);
      exit (URG_URL_MALFORMAT);
    case '\\':				/* escaped character, skip '\' */
      if (*(buf+1) == '\0') {		/* but no escaping of '\0'! */
	printf("error: illegal pattern at pos %d\n", pos);
	exit (URG_URL_MALFORMAT);
      }
      ++pattern;
      ++pos;				/* intentional fallthrough */
    default:
      *buf++ = *pattern++;		/* copy character to set element */
      ++pos;
    }
  }
  exit (URG_FAILED_INIT);
}

int glob_range(char *pattern, int pos) {
  /* processes a range expression with the point behind the opening '['
     - char range: e.g. "a-z]", "B-Q]"
     - num range: e.g. "0-9]", "17-2000]"
     - num range with leading zeros: e.g. "001-999]"
     expression is checked for well-formedness and collected until the next ']'
  */
  URLPattern *pat;
  char *c;
  
  pat = (URLPattern*)&glob_expand->pattern[glob_expand->size / 2];
  /* patterns 0,1,2,... correspond to size=1,3,5,... */
  ++glob_expand->size;

  if (isalpha((int)*pattern)) {		/* character range detected */
    pat->type = UPTCharRange;
    if (sscanf(pattern, "%c-%c]", &pat->content.CharRange.min_c, &pat->content.CharRange.max_c) != 2 ||
	pat->content.CharRange.min_c >= pat->content.CharRange.max_c ||
	pat->content.CharRange.max_c - pat->content.CharRange.min_c > 'z' - 'a') {
      /* the pattern is not well-formed */ 
      printf("error: illegal pattern or range specification after pos %d\n", pos);
      exit (URG_URL_MALFORMAT);
    }
    pat->content.CharRange.ptr_c = pat->content.CharRange.min_c;
    /* always check for a literal (may be "") between patterns */
    return (pat->content.CharRange.max_c - pat->content.CharRange.min_c + 1) *
      glob_word(pattern + 4, pos + 4);
  }
  if (isdigit((int)*pattern)) {		/* numeric range detected */
    pat->type = UPTNumRange;
    pat->content.NumRange.padlength = 0;
    if (sscanf(pattern, "%d-%d]", &pat->content.NumRange.min_n, &pat->content.NumRange.max_n) != 2 ||
	pat->content.NumRange.min_n >= pat->content.NumRange.max_n) {
      /* the pattern is not well-formed */ 
      printf("error: illegal pattern or range specification after pos %d\n", pos);
      exit (URG_URL_MALFORMAT);
    }
    if (*pattern == '0') {		/* leading zero specified */
      c = pattern;  
      while (isdigit((int)*c++))
	++pat->content.NumRange.padlength;	/* padding length is set for all instances
						   of this pattern */
    }
    pat->content.NumRange.ptr_n = pat->content.NumRange.min_n;
    c = (char*)(strchr(pattern, ']') + 1);	/* continue after next ']' */
    /* always check for a literal (may be "") between patterns */
    return (pat->content.NumRange.max_n - pat->content.NumRange.min_n + 1) *
      glob_word(c, pos + (c - pattern));
  }
  printf("error: illegal character in range specification at pos %d\n", pos);
  exit (URG_URL_MALFORMAT);
}

int glob_word(char *pattern, int pos) {
  /* processes a literal string component of a URL
     special characters '{' and '[' branch to set/range processing functions
   */ 
  char* buf = glob_buffer;
  int litindex;

  while (*pattern != '\0' && *pattern != '{' && *pattern != '[') {
    if (*pattern == '}' || *pattern == ']') {
      printf("illegal character at position %d\n", pos);
      exit (URG_URL_MALFORMAT);
    }
    if (*pattern == '\\') {		/* escape character, skip '\' */
      ++pattern;
      ++pos;
      if (*pattern == '\0') {		/* but no escaping of '\0'! */
	printf("illegal character at position %d\n", pos);
	exit (URG_URL_MALFORMAT);
      }
    }
    *buf++ = *pattern++;		/* copy character to literal */
    ++pos;
  }
  *buf = '\0';
  litindex = glob_expand->size / 2;
  /* literals 0,1,2,... correspond to size=0,2,4,... */
  glob_expand->literal[litindex] = strdup(glob_buffer);
  ++glob_expand->size;
  if (*pattern == '\0')
    return 1;				/* singular URL processed  */
  if (*pattern == '{') {
    return glob_set(++pattern, ++pos);	/* process set pattern */
  }
  if (*pattern == '[') {
    return glob_range(++pattern, ++pos);/* process range pattern */
  }
  printf("internal error\n");
  exit (URG_FAILED_INIT);
}

int glob_url(URLGlob** glob, char* url) {
  int urlnum;		/* counts instances of a globbed pattern */

  glob_expand = (URLGlob*)malloc(sizeof(URLGlob));
  glob_expand->size = 0;
  urlnum = glob_word(url, 1);
  *glob = glob_expand;
  return urlnum;
}

char *next_url(URLGlob *glob) {
  static int beenhere = 0;
  char *buf = glob_buffer;
  URLPattern *pat;
  char *lit;
  signed int i;
  int carry;

  if (!beenhere)
    beenhere = 1;
  else {
    carry = 1;

    /* implement a counter over the index ranges of all patterns,
       starting with the rightmost pattern */
    for (i = glob->size / 2 - 1; carry && i >= 0; --i) {
      carry = 0;
      pat = &glob->pattern[i];
      switch (pat->type) {
      case UPTSet:
	if (++pat->content.Set.ptr_s == pat->content.Set.size) {
	  pat->content.Set.ptr_s = 0;
	  carry = 1;
	}
	break;
      case UPTCharRange:
	if (++pat->content.CharRange.ptr_c > pat->content.CharRange.max_c) {
	  pat->content.CharRange.ptr_c = pat->content.CharRange.min_c;
	  carry = 1;
	}
	break;
      case UPTNumRange:
	if (++pat->content.NumRange.ptr_n > pat->content.NumRange.max_n) {
	  pat->content.NumRange.ptr_n = pat->content.NumRange.min_n;
	  carry = 1;
	}
	break;
      default:
	printf("internal error: invalid pattern type (%d)\n", pat->type);
	exit (URG_FAILED_INIT);
      }
    }
    if (carry)		/* first pattern ptr has run into overflow, done! */
      return NULL;
  }

  for (i = 0; i < glob->size; ++i) {
    if (!(i % 2)) {			/* every other term (i even) is a literal */
      lit = glob->literal[i/2];
      strcpy(buf, lit);
      buf += strlen(lit);
    }
    else {				/* the rest (i odd) are patterns */
      pat = &glob->pattern[i/2];
      switch(pat->type) {
      case UPTSet:
	strcpy(buf, pat->content.Set.elements[pat->content.Set.ptr_s]);
	buf += strlen(pat->content.Set.elements[pat->content.Set.ptr_s]);
	break;
      case UPTCharRange:
	*buf++ = pat->content.CharRange.ptr_c;
	break;
      case UPTNumRange:
	sprintf(buf, "%0*d", pat->content.NumRange.padlength, pat->content.NumRange.ptr_n); 
        buf += strlen(buf); /* make no sprint() return code assumptions */
	break;
      default:
	printf("internal error: invalid pattern type (%d)\n", pat->type);
	exit (URG_FAILED_INIT);
      }
    }
  }
  *buf = '\0';
  return strdup(glob_buffer);
}

char *match_url(char *filename, URLGlob glob) {
  char *buf = glob_buffer;
  URLPattern pat;
  int i;

  while (*filename != '\0') {
    if (*filename == '#') {
      if (!isdigit((int)*++filename) ||
	  *filename == '0') {		/* only '#1' ... '#9' allowed */
	printf("illegal matching expression\n");
	exit(URG_URL_MALFORMAT);
      }
      i = *filename - '1';
      if (i + 1 > glob.size / 2) {
	printf("match against nonexisting pattern\n");
	exit(URG_URL_MALFORMAT);
      }
      pat = glob.pattern[i];
      switch (pat.type) {
      case UPTSet:
	strcpy(buf, pat.content.Set.elements[pat.content.Set.ptr_s]);
	buf += strlen(pat.content.Set.elements[pat.content.Set.ptr_s]);
	break;
      case UPTCharRange:
	*buf++ = pat.content.CharRange.ptr_c;
	break;
      case UPTNumRange:
	sprintf(buf, "%0*d", pat.content.NumRange.padlength, pat.content.NumRange.ptr_n);
        buf += strlen(buf);
	break;
      default:
	printf("internal error: invalid pattern type (%d)\n", pat.type);
	exit (URG_FAILED_INIT);
      }
      ++filename;
    }
    else
      *buf++ = *filename++;
  }
  *buf = '\0';
  return strdup(glob_buffer);
}
