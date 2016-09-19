/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"
#include "tool_cfgable.h"
#include "tool_doswin.h"
#include "tool_urlglob.h"
#include "tool_vms.h"

#include "memdebug.h" /* keep this as LAST include */

#define GLOBERROR(string, column, code) \
  glob->error = string, glob->pos = column, code

void glob_cleanup(URLGlob* glob);

static CURLcode glob_fixed(URLGlob *glob, char *fixed, size_t len)
{
  URLPattern *pat = &glob->pattern[glob->size];
  pat->type = UPTSet;
  pat->content.Set.size = 1;
  pat->content.Set.ptr_s = 0;
  pat->globindex = -1;

  pat->content.Set.elements = malloc(sizeof(char*));

  if(!pat->content.Set.elements)
    return GLOBERROR("out of memory", 0, CURLE_OUT_OF_MEMORY);

  pat->content.Set.elements[0] = malloc(len+1);
  if(!pat->content.Set.elements[0])
    return GLOBERROR("out of memory", 0, CURLE_OUT_OF_MEMORY);

  memcpy(pat->content.Set.elements[0], fixed, len);
  pat->content.Set.elements[0][len] = 0;

  return CURLE_OK;
}

/* multiply
 *
 * Multiplies and checks for overflow.
 */
static int multiply(unsigned long *amount, long with)
{
  unsigned long sum = *amount * with;
  if(sum/with != *amount)
    return 1; /* didn't fit, bail out */
  *amount = sum;
  return 0;
}

static CURLcode glob_set(URLGlob *glob, char **patternp,
                         size_t *posp, unsigned long *amount,
                         int globindex)
{
  /* processes a set expression with the point behind the opening '{'
     ','-separated elements are collected until the next closing '}'
  */
  URLPattern *pat;
  bool done = FALSE;
  char *buf = glob->glob_buffer;
  char *pattern = *patternp;
  char *opattern = pattern;
  size_t opos = *posp-1;

  pat = &glob->pattern[glob->size];
  /* patterns 0,1,2,... correspond to size=1,3,5,... */
  pat->type = UPTSet;
  pat->content.Set.size = 0;
  pat->content.Set.ptr_s = 0;
  pat->content.Set.elements = NULL;
  pat->globindex = globindex;

  while(!done) {
    switch (*pattern) {
    case '\0':                  /* URL ended while set was still open */
      return GLOBERROR("unmatched brace", opos, CURLE_URL_MALFORMAT);

    case '{':
    case '[':                   /* no nested expressions at this time */
      return GLOBERROR("nested brace", *posp, CURLE_URL_MALFORMAT);

    case '}':                           /* set element completed */
      if(opattern == pattern)
        return GLOBERROR("empty string within braces", *posp,
                         CURLE_URL_MALFORMAT);

      /* add 1 to size since it'll be incremented below */
      if(multiply(amount, pat->content.Set.size+1))
        return GLOBERROR("range overflow", 0, CURLE_URL_MALFORMAT);

      /* fall-through */
    case ',':

      *buf = '\0';
      if(pat->content.Set.elements) {
        char **new_arr = realloc(pat->content.Set.elements,
                                 (pat->content.Set.size + 1) * sizeof(char*));
        if(!new_arr)
          return GLOBERROR("out of memory", 0, CURLE_OUT_OF_MEMORY);

        pat->content.Set.elements = new_arr;
      }
      else
        pat->content.Set.elements = malloc(sizeof(char*));

      if(!pat->content.Set.elements)
        return GLOBERROR("out of memory", 0, CURLE_OUT_OF_MEMORY);

      pat->content.Set.elements[pat->content.Set.size] =
        strdup(glob->glob_buffer);
      if(!pat->content.Set.elements[pat->content.Set.size])
        return GLOBERROR("out of memory", 0, CURLE_OUT_OF_MEMORY);
      ++pat->content.Set.size;

      if(*pattern == '}') {
        pattern++; /* pass the closing brace */
        done = TRUE;
        continue;
      }

      buf = glob->glob_buffer;
      ++pattern;
      ++(*posp);
      break;

    case ']':                           /* illegal closing bracket */
      return GLOBERROR("unexpected close bracket", *posp, CURLE_URL_MALFORMAT);

    case '\\':                          /* escaped character, skip '\' */
      if(pattern[1]) {
        ++pattern;
        ++(*posp);
      }
      /* intentional fallthrough */
    default:
      *buf++ = *pattern++;              /* copy character to set element */
      ++(*posp);
    }
  }

  *patternp = pattern; /* return with the new position */
  return CURLE_OK;
}

static CURLcode glob_range(URLGlob *glob, char **patternp,
                           size_t *posp, unsigned long *amount,
                           int globindex)
{
  /* processes a range expression with the point behind the opening '['
     - char range: e.g. "a-z]", "B-Q]"
     - num range: e.g. "0-9]", "17-2000]"
     - num range with leading zeros: e.g. "001-999]"
     expression is checked for well-formedness and collected until the next ']'
  */
  URLPattern *pat;
  int rc;
  char *pattern = *patternp;
  char *c;

  pat = &glob->pattern[glob->size];
  pat->globindex = globindex;

  if(ISALPHA(*pattern)) {
    /* character range detected */
    char min_c;
    char max_c;
    int step=1;

    pat->type = UPTCharRange;

    rc = sscanf(pattern, "%c-%c", &min_c, &max_c);

    if((rc == 2) && (pattern[3] == ':')) {
      char *endp;
      unsigned long lstep;
      errno = 0;
      lstep = strtoul(&pattern[4], &endp, 10);
      if(errno || (*endp != ']'))
        step = -1;
      else {
        pattern = endp+1;
        step = (int)lstep;
        if(step > (max_c - min_c))
          step = -1;
      }
    }
    else
      pattern += 4;

    *posp += (pattern - *patternp);

    if((rc != 2) || (min_c >= max_c) || ((max_c - min_c) > ('z' - 'a')) ||
       (step <= 0) )
      /* the pattern is not well-formed */
      return GLOBERROR("bad range", *posp, CURLE_URL_MALFORMAT);

    /* if there was a ":[num]" thing, use that as step or else use 1 */
    pat->content.CharRange.step = step;
    pat->content.CharRange.ptr_c = pat->content.CharRange.min_c = min_c;
    pat->content.CharRange.max_c = max_c;

    if(multiply(amount, (pat->content.CharRange.max_c -
                          pat->content.CharRange.min_c) /
                         pat->content.CharRange.step + 1) )
      return GLOBERROR("range overflow", *posp, CURLE_URL_MALFORMAT);
  }
  else if(ISDIGIT(*pattern)) {
    /* numeric range detected */
    unsigned long min_n;
    unsigned long max_n = 0;
    unsigned long step_n = 0;
    char *endp;

    pat->type = UPTNumRange;
    pat->content.NumRange.padlength = 0;

    if(*pattern == '0') {
      /* leading zero specified, count them! */
      c = pattern;
      while(ISDIGIT(*c)) {
        c++;
        ++pat->content.NumRange.padlength; /* padding length is set for all
                                              instances of this pattern */
      }
    }

    errno = 0;
    min_n = strtoul(pattern, &endp, 10);
    if(errno || (endp == pattern))
      endp=NULL;
    else {
      if(*endp != '-')
        endp = NULL;
      else {
        pattern = endp+1;
        errno = 0;
        max_n = strtoul(pattern, &endp, 10);
        if(errno || (*endp == ':')) {
          pattern = endp+1;
          errno = 0;
          step_n = strtoul(pattern, &endp, 10);
          if(errno)
            /* over/underflow situation */
            endp = NULL;
        }
        else
          step_n = 1;
        if(endp && (*endp == ']')) {
          pattern= endp+1;
        }
        else
          endp = NULL;
      }
    }

    *posp += (pattern - *patternp);

    if(!endp || (min_n > max_n) || (step_n > (max_n - min_n)) || !step_n)
      /* the pattern is not well-formed */
      return GLOBERROR("bad range", *posp, CURLE_URL_MALFORMAT);

    /* typecasting to ints are fine here since we make sure above that we
       are within 31 bits */
    pat->content.NumRange.ptr_n = pat->content.NumRange.min_n = min_n;
    pat->content.NumRange.max_n = max_n;
    pat->content.NumRange.step = step_n;

    if(multiply(amount, (pat->content.NumRange.max_n -
                         pat->content.NumRange.min_n) /
                        pat->content.NumRange.step + 1) )
      return GLOBERROR("range overflow", *posp, CURLE_URL_MALFORMAT);
  }
  else
    return GLOBERROR("bad range specification", *posp, CURLE_URL_MALFORMAT);

  *patternp = pattern;
  return CURLE_OK;
}

static bool peek_ipv6(const char *str, size_t *skip)
{
  /*
   * Scan for a potential IPv6 literal.
   * - Valid globs contain a hyphen and <= 1 colon.
   * - IPv6 literals contain no hyphens and >= 2 colons.
   */
  size_t i = 0;
  size_t colons = 0;
  if(str[i++] != '[') {
    return FALSE;
  }
  for(;;) {
    const char c = str[i++];
    if(ISALNUM(c) || c == '.' || c == '%') {
      /* ok */
    }
    else if(c == ':') {
      colons++;
    }
    else if(c == ']') {
      *skip = i;
      return colons >= 2 ? TRUE : FALSE;
    }
    else {
      return FALSE;
    }
  }
}

static CURLcode glob_parse(URLGlob *glob, char *pattern,
                           size_t pos, unsigned long *amount)
{
  /* processes a literal string component of a URL
     special characters '{' and '[' branch to set/range processing functions
   */
  CURLcode res = CURLE_OK;
  int globindex = 0; /* count "actual" globs */

  *amount = 1;

  while(*pattern && !res) {
    char *buf = glob->glob_buffer;
    size_t sublen = 0;
    while(*pattern && *pattern != '{') {
      if(*pattern == '[') {
        /* Skip over potential IPv6 literals. */
        size_t skip;
        if(peek_ipv6(pattern, &skip)) {
          memcpy(buf, pattern, skip);
          buf += skip;
          pattern += skip;
          sublen += skip;
          continue;
        }
        break;
      }
      if(*pattern == '}' || *pattern == ']')
        return GLOBERROR("unmatched close brace/bracket", pos,
                         CURLE_URL_MALFORMAT);

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
      sublen++;
    }
    if(sublen) {
      /* we got a literal string, add it as a single-item list */
      *buf = '\0';
      res = glob_fixed(glob, glob->glob_buffer, sublen);
    }
    else {
      switch (*pattern) {
      case '\0': /* done  */
        break;

      case '{':
        /* process set pattern */
        pattern++;
        pos++;
        res = glob_set(glob, &pattern, &pos, amount, globindex++);
        break;

      case '[':
        /* process range pattern */
        pattern++;
        pos++;
        res = glob_range(glob, &pattern, &pos, amount, globindex++);
        break;
      }
    }

    if(++glob->size >= GLOB_PATTERN_NUM)
      return GLOBERROR("too many globs", pos, CURLE_URL_MALFORMAT);
  }
  return res;
}

CURLcode glob_url(URLGlob** glob, char* url, unsigned long *urlnum,
                  FILE *error)
{
  /*
   * We can deal with any-size, just make a buffer with the same length
   * as the specified URL!
   */
  URLGlob *glob_expand;
  unsigned long amount = 0;
  char *glob_buffer;
  CURLcode res;

  *glob = NULL;

  glob_buffer = malloc(strlen(url) + 1);
  if(!glob_buffer)
    return CURLE_OUT_OF_MEMORY;

  glob_expand = calloc(1, sizeof(URLGlob));
  if(!glob_expand) {
    Curl_safefree(glob_buffer);
    return CURLE_OUT_OF_MEMORY;
  }
  glob_expand->urllen = strlen(url);
  glob_expand->glob_buffer = glob_buffer;

  res = glob_parse(glob_expand, url, 1, &amount);
  if(!res)
    *urlnum = amount;
  else {
    if(error && glob_expand->error) {
      char text[128];
      const char *t;
      if(glob_expand->pos) {
        snprintf(text, sizeof(text), "%s in column %zu", glob_expand->error,
                 glob_expand->pos);
        t = text;
      }
      else
        t = glob_expand->error;

      /* send error description to the error-stream */
      fprintf(error, "curl: (%d) [globbing] %s\n", res, t);
    }
    /* it failed, we cleanup */
    glob_cleanup(glob_expand);
    *urlnum = 1;
    return res;
  }

  *glob = glob_expand;
  return CURLE_OK;
}

void glob_cleanup(URLGlob* glob)
{
  size_t i;
  int elem;

  for(i = 0; i < glob->size; i++) {
    if((glob->pattern[i].type == UPTSet) &&
       (glob->pattern[i].content.Set.elements)) {
      for(elem = glob->pattern[i].content.Set.size - 1;
          elem >= 0;
          --elem) {
        Curl_safefree(glob->pattern[i].content.Set.elements[elem]);
      }
      Curl_safefree(glob->pattern[i].content.Set.elements);
    }
  }
  Curl_safefree(glob->glob_buffer);
  Curl_safefree(glob);
}

CURLcode glob_next_url(char **globbed, URLGlob *glob)
{
  URLPattern *pat;
  size_t i;
  size_t len;
  size_t buflen = glob->urllen + 1;
  char *buf = glob->glob_buffer;

  *globbed = NULL;

  if(!glob->beenhere)
    glob->beenhere = 1;
  else {
    bool carry = TRUE;

    /* implement a counter over the index ranges of all patterns, starting
       with the rightmost pattern */
    for(i = 0; carry && (i < glob->size); i++) {
      carry = FALSE;
      pat = &glob->pattern[glob->size - 1 - i];
      switch (pat->type) {
      case UPTSet:
        if((pat->content.Set.elements) &&
           (++pat->content.Set.ptr_s == pat->content.Set.size)) {
          pat->content.Set.ptr_s = 0;
          carry = TRUE;
        }
        break;
      case UPTCharRange:
        pat->content.CharRange.ptr_c =
          (char)(pat->content.CharRange.step +
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

  for(i = 0; i < glob->size; ++i) {
    pat = &glob->pattern[i];
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
      len = snprintf(buf, buflen, "%0*ld",
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
  *buf = '\0';

  *globbed = strdup(glob->glob_buffer);
  if(!*globbed)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

CURLcode glob_match_url(char **result, char *filename, URLGlob *glob)
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
      URLPattern *pat =NULL;

      if(num < glob->size) {
        num--; /* make it zero based */
        /* find the correct glob entry */
        for(i=0; i<glob->size; i++) {
          if(glob->pattern[i].globindex == (int)num) {
            pat = &glob->pattern[i];
            break;
          }
        }
      }

      if(pat) {
        switch (pat->type) {
        case UPTSet:
          if(pat->content.Set.elements) {
            appendthis = pat->content.Set.elements[pat->content.Set.ptr_s];
            appendlen =
              strlen(pat->content.Set.elements[pat->content.Set.ptr_s]);
          }
          break;
        case UPTCharRange:
          numbuf[0] = pat->content.CharRange.ptr_c;
          numbuf[1] = 0;
          appendthis = numbuf;
          appendlen = 1;
          break;
        case UPTNumRange:
          snprintf(numbuf, sizeof(numbuf), "%0*d",
                   pat->content.NumRange.padlength,
                   pat->content.NumRange.ptr_n);
          appendthis = numbuf;
          appendlen = strlen(numbuf);
          break;
        default:
          fprintf(stderr, "internal error: invalid pattern type (%d)\n",
                  (int)pat->type);
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

#if defined(MSDOS) || defined(WIN32)
  {
    char *sanitized;
    SANITIZEcode sc = sanitize_file_name(&sanitized, target,
                                         (SANITIZE_ALLOW_PATH |
                                          SANITIZE_ALLOW_RESERVED));
    Curl_safefree(target);
    if(sc)
      return CURLE_URL_MALFORMAT;
    target = sanitized;
  }
#endif /* MSDOS || WIN32 */

  *result = target;
  return CURLE_OK;
}
