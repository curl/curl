/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

#define _MPRINTF_REPLACE /* we want curl-functions instead of native ones */
#include <curl/mprintf.h>

#include "tool_urlglob.h"
#include "tool_vms.h"

#include "memdebug.h" /* keep this as LAST include */

typedef enum {
  GLOB_OK,
  GLOB_NO_MEM,
  GLOB_ERROR
} GlobCode;

/*
 * glob_word()
 *
 * Input a full globbed string, set the forth argument to the amount of
 * strings we get out of this. Return GlobCode.
 */
static GlobCode glob_word(URLGlob *, /* object anchor */
                          char *,    /* globbed string */
                          size_t,       /* position */
                          int *);    /* returned number of strings */

static GlobCode glob_set(URLGlob *glob, char *pattern,
                         size_t pos, int *amount)
{
  /* processes a set expression with the point behind the opening '{'
     ','-separated elements are collected until the next closing '}'
  */
  URLPattern *pat;
  GlobCode res;
  bool done = FALSE;
  char* buf = glob->glob_buffer;

  pat = &glob->pattern[glob->size / 2];
  /* patterns 0,1,2,... correspond to size=1,3,5,... */
  pat->type = UPTSet;
  pat->content.Set.size = 0;
  pat->content.Set.ptr_s = 0;
  pat->content.Set.elements = NULL;

  ++glob->size;

  while(!done) {
    switch (*pattern) {
    case '\0':                  /* URL ended while set was still open */
      snprintf(glob->errormsg, sizeof(glob->errormsg),
               "unmatched brace at pos %zu\n", pos);
      return GLOB_ERROR;

    case '{':
    case '[':                   /* no nested expressions at this time */
      snprintf(glob->errormsg, sizeof(glob->errormsg),
               "nested braces not supported at pos %zu\n", pos);
      return GLOB_ERROR;

    case ',':
    case '}':                           /* set element completed */
      *buf = '\0';
      if(pat->content.Set.elements) {
        char **new_arr = realloc(pat->content.Set.elements,
                                 (pat->content.Set.size + 1) * sizeof(char*));
        if(!new_arr) {
          short elem;
          for(elem = 0; elem < pat->content.Set.size; elem++)
            Curl_safefree(pat->content.Set.elements[elem]);
          Curl_safefree(pat->content.Set.elements);
          pat->content.Set.ptr_s = 0;
          pat->content.Set.size = 0;
        }
        pat->content.Set.elements = new_arr;
      }
      else
        pat->content.Set.elements = malloc(sizeof(char*));
      if(!pat->content.Set.elements) {
        snprintf(glob->errormsg, sizeof(glob->errormsg), "out of memory\n");
        return GLOB_NO_MEM;
      }
      pat->content.Set.elements[pat->content.Set.size] =
        strdup(glob->glob_buffer);
      if(!pat->content.Set.elements[pat->content.Set.size]) {
        short elem;
        for(elem = 0; elem < pat->content.Set.size; elem++)
          Curl_safefree(pat->content.Set.elements[elem]);
        Curl_safefree(pat->content.Set.elements);
        pat->content.Set.ptr_s = 0;
        pat->content.Set.size = 0;
        snprintf(glob->errormsg, sizeof(glob->errormsg), "out of memory\n");
        return GLOB_NO_MEM;
      }
      ++pat->content.Set.size;

      if(*pattern == '}') {
        /* entire set pattern completed */
        int wordamount;

        /* always check for a literal (may be "") between patterns */
        res = glob_word(glob, ++pattern, ++pos, &wordamount);
        if(res) {
          short elem;
          for(elem = 0; elem < pat->content.Set.size; elem++)
            Curl_safefree(pat->content.Set.elements[elem]);
          Curl_safefree(pat->content.Set.elements);
          pat->content.Set.ptr_s = 0;
          pat->content.Set.size = 0;
          return res;
        }

        *amount = pat->content.Set.size * wordamount;

        done = TRUE;
        continue;
      }

      buf = glob->glob_buffer;
      ++pattern;
      ++pos;
      break;

    case ']':                           /* illegal closing bracket */
      snprintf(glob->errormsg, sizeof(glob->errormsg),
               "illegal pattern at pos %zu\n", pos);
      return GLOB_ERROR;

    case '\\':                          /* escaped character, skip '\' */
      if(pattern[1]) {
        ++pattern;
        ++pos;
      }
      /* intentional fallthrough */
    default:
      *buf++ = *pattern++;              /* copy character to set element */
      ++pos;
    }
  }
  return GLOB_OK;
}

static GlobCode glob_range(URLGlob *glob, char *pattern,
                           size_t pos, int *amount)
{
  /* processes a range expression with the point behind the opening '['
     - char range: e.g. "a-z]", "B-Q]"
     - num range: e.g. "0-9]", "17-2000]"
     - num range with leading zeros: e.g. "001-999]"
     expression is checked for well-formedness and collected until the next ']'
  */
  URLPattern *pat;
  char *c;
  char sep;
  char sep2;
  int step;
  int rc;
  GlobCode res;
  int wordamount = 1;

  pat = &glob->pattern[glob->size / 2];
  /* patterns 0,1,2,... correspond to size=1,3,5,... */
  ++glob->size;

  if(ISALPHA(*pattern)) {
    /* character range detected */
    char min_c;
    char max_c;

    pat->type = UPTCharRange;

    rc = sscanf(pattern, "%c-%c%c%d%c", &min_c, &max_c, &sep, &step, &sep2);

    if((rc < 3) || (min_c >= max_c) || ((max_c - min_c) > ('z' - 'a'))) {
      /* the pattern is not well-formed */
      snprintf(glob->errormsg, sizeof(glob->errormsg),
               "error: bad range specification after pos %zu\n", pos);
      return GLOB_ERROR;
    }

    /* check the (first) separating character */
    if((sep != ']') && (sep != ':')) {
      snprintf(glob->errormsg, sizeof(glob->errormsg),
               "error: unsupported character (%c) after range at pos %zu\n",
               sep, pos);
      return GLOB_ERROR;
    }

    /* if there was a ":[num]" thing, use that as step or else use 1 */
    pat->content.CharRange.step =
      ((sep == ':') && (rc == 5) && (sep2 == ']')) ? step : 1;

    pat->content.CharRange.ptr_c = pat->content.CharRange.min_c = min_c;
    pat->content.CharRange.max_c = max_c;
  }
  else if(ISDIGIT(*pattern)) {
    /* numeric range detected */
    int min_n;
    int max_n;

    pat->type = UPTNumRange;
    pat->content.NumRange.padlength = 0;

    rc = sscanf(pattern, "%d-%d%c%d%c", &min_n, &max_n, &sep, &step, &sep2);

    if((rc < 2) || (min_n > max_n)) {
      /* the pattern is not well-formed */
      snprintf(glob->errormsg, sizeof(glob->errormsg),
               "error: bad range specification after pos %zu\n", pos);
      return GLOB_ERROR;
    }
    pat->content.NumRange.ptr_n = pat->content.NumRange.min_n = min_n;
    pat->content.NumRange.max_n = max_n;

    /* if there was a ":[num]" thing, use that as step or else use 1 */
    pat->content.NumRange.step =
      ((sep == ':') && (rc == 5) && (sep2 == ']')) ? step : 1;

    if(*pattern == '0') {
      /* leading zero specified */
      c = pattern;
      while(ISDIGIT(*c)) {
        c++;
        ++pat->content.NumRange.padlength; /* padding length is set for all
                                              instances of this pattern */
      }
    }
  }
  else {
    snprintf(glob->errormsg, sizeof(glob->errormsg),
             "illegal character in range specification at pos %zu\n", pos);
    return GLOB_ERROR;
  }

  c = (char*)strchr(pattern, ']'); /* continue after next ']' */
  if(c)
    c++;
  else {
    snprintf(glob->errormsg, sizeof(glob->errormsg), "missing ']'");
    return GLOB_ERROR; /* missing ']' */
  }

  /* always check for a literal (may be "") between patterns */

  res = glob_word(glob, c, pos + (c - pattern), &wordamount);
  if(res == GLOB_ERROR) {
    wordamount = 1;
    res = GLOB_OK;
  }

  if(!res) {
    if(pat->type == UPTCharRange)
      *amount = wordamount * (pat->content.CharRange.max_c -
                              pat->content.CharRange.min_c + 1);
    else
      *amount = wordamount * (pat->content.NumRange.max_n -
                              pat->content.NumRange.min_n + 1);
  }

  return res; /* GLOB_OK or GLOB_NO_MEM */
}

static GlobCode glob_word(URLGlob *glob, char *pattern,
                          size_t pos, int *amount)
{
  /* processes a literal string component of a URL
     special characters '{' and '[' branch to set/range processing functions
   */
  char* buf = glob->glob_buffer;
  size_t litindex;
  GlobCode res = GLOB_OK;

  *amount = 1; /* default is one single string */

  while(*pattern != '\0' && *pattern != '{' && *pattern != '[') {
    if(*pattern == '}' || *pattern == ']') {
      snprintf(glob->errormsg, sizeof(glob->errormsg),
               "unmatched close brace/bracket at pos %zu\n", pos);
      return GLOB_ERROR;
    }

    /* only allow \ to escape known "special letters" */
    if(*pattern == '\\' &&
        (*(pattern+1) == '{' || *(pattern+1) == '[' ||
         *(pattern+1) == '}' || *(pattern+1) == ']') ) {

      /* escape character, skip '\' */
      ++pattern;
      ++pos;
    }
    *buf++ = *pattern++; /* copy character to literal */
    ++pos;
  }
  *buf = '\0';
  litindex = glob->size / 2;
  /* literals 0,1,2,... correspond to size=0,2,4,... */
  glob->literal[litindex] = strdup(glob->glob_buffer);
  if(!glob->literal[litindex]) {
    snprintf(glob->errormsg, sizeof(glob->errormsg), "out of memory\n");
    return GLOB_NO_MEM;
  }
  ++glob->size;

  switch (*pattern) {
  case '\0':
    /* singular URL processed  */
    break;

  case '{':
    /* process set pattern */
    res = glob_set(glob, ++pattern, ++pos, amount);
    break;

  case '[':
    /* process range pattern */
    res = glob_range(glob, ++pattern, ++pos, amount);
    break;
  }

  if(res)
    Curl_safefree(glob->literal[litindex]);

  return res;
}

int glob_url(URLGlob** glob, char* url, int *urlnum, FILE *error)
{
  /*
   * We can deal with any-size, just make a buffer with the same length
   * as the specified URL!
   */
  URLGlob *glob_expand;
  int amount;
  char *glob_buffer;
  GlobCode res;

  *glob = NULL;

  glob_buffer = malloc(strlen(url) + 1);
  if(!glob_buffer)
    return CURLE_OUT_OF_MEMORY;

  glob_expand = calloc(1, sizeof(URLGlob));
  if(!glob_expand) {
    Curl_safefree(glob_buffer);
    return CURLE_OUT_OF_MEMORY;
  }
  glob_expand->size = 0;
  glob_expand->urllen = strlen(url);
  glob_expand->glob_buffer = glob_buffer;
  glob_expand->beenhere = 0;

  res = glob_word(glob_expand, url, 1, &amount);
  if(!res)
    *urlnum = amount;
  else {
    if(error && glob_expand->errormsg[0]) {
      /* send error description to the error-stream */
      fprintf(error, "curl: (%d) [globbing] %s",
              (res == GLOB_NO_MEM) ? CURLE_OUT_OF_MEMORY : CURLE_URL_MALFORMAT,
              glob_expand->errormsg);
    }
    /* it failed, we cleanup */
    Curl_safefree(glob_buffer);
    Curl_safefree(glob_expand);
    *urlnum = 1;
    return (res == GLOB_NO_MEM) ? CURLE_OUT_OF_MEMORY : CURLE_URL_MALFORMAT;
  }

  *glob = glob_expand;
  return CURLE_OK;
}

void glob_cleanup(URLGlob* glob)
{
  size_t i;
  int elem;

  for(i = glob->size - 1; i < glob->size; --i) {
    if(!(i & 1)) {     /* even indexes contain literals */
      Curl_safefree(glob->literal[i/2]);
    }
    else {              /* odd indexes contain sets or ranges */
      if((glob->pattern[i/2].type == UPTSet) &&
         (glob->pattern[i/2].content.Set.elements)) {
        for(elem = glob->pattern[i/2].content.Set.size - 1;
             elem >= 0;
             --elem) {
          Curl_safefree(glob->pattern[i/2].content.Set.elements[elem]);
        }
        Curl_safefree(glob->pattern[i/2].content.Set.elements);
      }
    }
  }
  Curl_safefree(glob->glob_buffer);
  Curl_safefree(glob);
}

int glob_next_url(char **globbed, URLGlob *glob)
{
  URLPattern *pat;
  char *lit;
  size_t i;
  size_t j;
  size_t len;
  size_t buflen = glob->urllen + 1;
  char *buf = glob->glob_buffer;

  *globbed = NULL;

  if(!glob->beenhere)
    glob->beenhere = 1;
  else {
    bool carry = TRUE;

    /* implement a counter over the index ranges of all patterns,
       starting with the rightmost pattern */
    for(i = glob->size / 2 - 1; carry && (i < glob->size); --i) {
      carry = FALSE;
      pat = &glob->pattern[i];
      switch (pat->type) {
      case UPTSet:
        if((pat->content.Set.elements) &&
           (++pat->content.Set.ptr_s == pat->content.Set.size)) {
          pat->content.Set.ptr_s = 0;
          carry = TRUE;
        }
        break;
      case UPTCharRange:
        pat->content.CharRange.ptr_c = (char)(pat->content.CharRange.step +
                           (int)((unsigned char)pat->content.CharRange.ptr_c));
        if(pat->content.CharRange.ptr_c > pat->content.CharRange.max_c) {
          pat->content.CharRange.ptr_c = pat->content.CharRange.min_c;
          carry = TRUE;
        }
        break;
      case UPTNumRange:
        pat->content.NumRange.ptr_n += pat->content.NumRange.step;
        if(pat->content.NumRange.ptr_n > pat->content.NumRange.max_n) {
          pat->content.NumRange.ptr_n = pat->content.NumRange.min_n;
          carry = TRUE;
        }
        break;
      default:
        printf("internal error: invalid pattern type (%d)\n", (int)pat->type);
        return CURLE_FAILED_INIT;
      }
    }
    if(carry) {         /* first pattern ptr has run into overflow, done! */
      /* TODO: verify if this should actally return CURLE_OK. */
      return CURLE_OK; /* CURLE_OK to match previous behavior */
    }
  }

  for(j = 0; j < glob->size; ++j) {
    if(!(j&1)) {              /* every other term (j even) is a literal */
      lit = glob->literal[j/2];
      len = snprintf(buf, buflen, "%s", lit);
      buf += len;
      buflen -= len;
    }
    else {                              /* the rest (i odd) are patterns */
      pat = &glob->pattern[j/2];
      switch(pat->type) {
      case UPTSet:
        if(pat->content.Set.elements) {
          len = strlen(pat->content.Set.elements[pat->content.Set.ptr_s]);
          snprintf(buf, buflen, "%s",
                   pat->content.Set.elements[pat->content.Set.ptr_s]);
          buf += len;
          buflen -= len;
        }
        break;
      case UPTCharRange:
        *buf++ = pat->content.CharRange.ptr_c;
        break;
      case UPTNumRange:
        len = snprintf(buf, buflen, "%0*d",
                       pat->content.NumRange.padlength,
                       pat->content.NumRange.ptr_n);
        buf += len;
        buflen -= len;
        break;
      default:
        printf("internal error: invalid pattern type (%d)\n", (int)pat->type);
        return CURLE_FAILED_INIT;
      }
    }
  }
  *buf = '\0';

  *globbed = strdup(glob->glob_buffer);
  if(!*globbed)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

int glob_match_url(char **result, char *filename, URLGlob *glob)
{
  char *target;
  size_t allocsize;
  char numbuf[18];
  char *appendthis = NULL;
  size_t appendlen = 0;
  size_t stringlen = 0;

  *result = NULL;

  /* We cannot use the glob_buffer for storage here since the filename may
   * be longer than the URL we use. We allocate a good start size, then
   * we need to realloc in case of need.
   */
  allocsize = strlen(filename) + 1; /* make it at least one byte to store the
                                       trailing zero */
  target = malloc(allocsize);
  if(!target)
    return CURLE_OUT_OF_MEMORY;

  while(*filename) {
    if(*filename == '#' && ISDIGIT(filename[1])) {
      unsigned long i;
      char *ptr = filename;
      unsigned long num = strtoul(&filename[1], &filename, 10);
      i = num - 1UL;

      if(num && (i <= glob->size / 2)) {
        URLPattern pat = glob->pattern[i];
        switch (pat.type) {
        case UPTSet:
          if(pat.content.Set.elements) {
            appendthis = pat.content.Set.elements[pat.content.Set.ptr_s];
            appendlen =
              strlen(pat.content.Set.elements[pat.content.Set.ptr_s]);
          }
          break;
        case UPTCharRange:
          numbuf[0] = pat.content.CharRange.ptr_c;
          numbuf[1] = 0;
          appendthis = numbuf;
          appendlen = 1;
          break;
        case UPTNumRange:
          snprintf(numbuf, sizeof(numbuf), "%0*d",
                   pat.content.NumRange.padlength,
                   pat.content.NumRange.ptr_n);
          appendthis = numbuf;
          appendlen = strlen(numbuf);
          break;
        default:
          printf("internal error: invalid pattern type (%d)\n",
                 (int)pat.type);
          Curl_safefree(target);
          return CURLE_FAILED_INIT;
        }
      }
      else {
        /* #[num] out of range, use the #[num] in the output */
        filename = ptr;
        appendthis = filename++;
        appendlen = 1;
      }
    }
    else {
      appendthis = filename++;
      appendlen = 1;
    }
    if(appendlen + stringlen >= allocsize) {
      char *newstr;
      /* we append a single byte to allow for the trailing byte to be appended
         at the end of this function outside the while() loop */
      allocsize = (appendlen + stringlen) * 2;
      newstr = realloc(target, allocsize + 1);
      if(!newstr) {
        Curl_safefree(target);
        return CURLE_OUT_OF_MEMORY;
      }
      target = newstr;
    }
    memcpy(&target[stringlen], appendthis, appendlen);
    stringlen += appendlen;
  }
  target[stringlen]= '\0';
  *result = target;
  return CURLE_OK;
}

