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

#include "curlx.h"
#include "tool_cfgable.h"
#include "tool_doswin.h"
#include "tool_urlglob.h"
#include "tool_vms.h"
#include "dynbuf.h"

#include "memdebug.h" /* keep this as LAST include */

#define GLOBERROR(string, column, code) \
  glob->error = string, glob->pos = column, code

static CURLcode glob_fixed(struct URLGlob *glob, char *fixed, size_t len)
{
  struct URLPattern *pat = &glob->pattern[glob->size];
  pat->type = UPTSet;
  pat->content.Set.size = 1;
  pat->content.Set.ptr_s = 0;
  pat->globindex = -1;

  pat->content.Set.elements = MALLOC(sizeof(char *));

  if(!pat->content.Set.elements)
    return GLOBERROR("out of memory", 0, CURLE_OUT_OF_MEMORY);

  pat->content.Set.elements[0] = MALLOC(len + 1);
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
static int multiply(curl_off_t *amount, curl_off_t with)
{
  curl_off_t sum;
  DEBUGASSERT(*amount >= 0);
  DEBUGASSERT(with >= 0);
  if((with <= 0) || (*amount <= 0)) {
    sum = 0;
  }
  else {
#if defined(__GNUC__) && \
  ((__GNUC__ > 5) || ((__GNUC__ == 5) && (__GNUC_MINOR__ >= 1)))
    if(__builtin_mul_overflow(*amount, with, &sum))
      return 1;
#else
    sum = *amount * with;
    if(sum/with != *amount)
      return 1; /* did not fit, bail out */
#endif
  }
  *amount = sum;
  return 0;
}

static CURLcode glob_set(struct URLGlob *glob, const char **patternp,
                         size_t *posp, curl_off_t *amount,
                         int globindex)
{
  /* processes a set expression with the point behind the opening '{'
     ','-separated elements are collected until the next closing '}'
  */
  struct URLPattern *pat;
  bool done = FALSE;
  char *buf = glob->glob_buffer;
  const char *pattern = *patternp;
  const char *opattern = pattern;
  size_t opos = *posp-1;

  pat = &glob->pattern[glob->size];
  /* patterns 0,1,2,... correspond to size=1,3,5,... */
  pat->type = UPTSet;
  pat->content.Set.size = 0;
  pat->content.Set.ptr_s = 0;
  pat->content.Set.elements = NULL;
  pat->globindex = globindex;

  while(!done) {
    switch(*pattern) {
    case '\0':                  /* URL ended while set was still open */
      return GLOBERROR("unmatched brace", opos, CURLE_URL_MALFORMAT);

    case '{':
    case '[':                   /* no nested expressions at this time */
      return GLOBERROR("nested brace", *posp, CURLE_URL_MALFORMAT);

    case '}':                           /* set element completed */
      if(opattern == pattern)
        return GLOBERROR("empty string within braces", *posp,
                         CURLE_URL_MALFORMAT);

      /* add 1 to size since it will be incremented below */
      if(multiply(amount, pat->content.Set.size + 1))
        return GLOBERROR("range overflow", 0, CURLE_URL_MALFORMAT);

      FALLTHROUGH();
    case ',':

      *buf = '\0';
      if(pat->content.Set.elements) {
        char **new_arr = REALLOC(pat->content.Set.elements,
                                 (size_t)(pat->content.Set.size + 1) *
                                 sizeof(char *));
        if(!new_arr)
          return GLOBERROR("out of memory", 0, CURLE_OUT_OF_MEMORY);

        pat->content.Set.elements = new_arr;
      }
      else
        pat->content.Set.elements = MALLOC(sizeof(char *));

      if(!pat->content.Set.elements)
        return GLOBERROR("out of memory", 0, CURLE_OUT_OF_MEMORY);

      pat->content.Set.elements[pat->content.Set.size] =
        STRDUP(glob->glob_buffer);
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
      FALLTHROUGH();
    default:
      *buf++ = *pattern++;              /* copy character to set element */
      ++(*posp);
    }
  }

  *patternp = pattern; /* return with the new position */
  return CURLE_OK;
}

static CURLcode glob_range(struct URLGlob *glob, const char **patternp,
                           size_t *posp, curl_off_t *amount,
                           int globindex)
{
  /* processes a range expression with the point behind the opening '['
     - char range: e.g. "a-z]", "B-Q]"
     - num range: e.g. "0-9]", "17-2000]"
     - num range with leading zeros: e.g. "001-999]"
     expression is checked for well-formedness and collected until the next ']'
  */
  struct URLPattern *pat;
  const char *pattern = *patternp;
  const char *c;

  pat = &glob->pattern[glob->size];
  pat->globindex = globindex;

  if(ISALPHA(*pattern)) {
    /* character range detected */
    bool pmatch = FALSE;
    char min_c = 0;
    char max_c = 0;
    char end_c = 0;
    unsigned long step = 1;

    pat->type = UPTCharRange;

    if((pattern[1] == '-') && pattern[2] && pattern[3]) {
      min_c = pattern[0];
      max_c = pattern[2];
      end_c = pattern[3];
      pmatch = TRUE;

      if(end_c == ':') {
        curl_off_t num;
        const char *p = &pattern[4];
        if(curlx_str_number(&p, &num, 256) || curlx_str_single(&p, ']'))
          step = 0;
        else
          step = (unsigned long)num;
        pattern = p;
      }
      else if(end_c != ']')
        /* then this is wrong */
        pmatch = FALSE;
      else
        /* end_c == ']' */
        pattern += 4;
    }

    *posp += (pattern - *patternp);

    if(!pmatch || !step ||
       (min_c == max_c && step != 1) ||
       (min_c != max_c && (min_c > max_c || step > (unsigned)(max_c - min_c) ||
                           (max_c - min_c) > ('z' - 'a'))))
      /* the pattern is not well-formed */
      return GLOBERROR("bad range", *posp, CURLE_URL_MALFORMAT);

    /* if there was a ":[num]" thing, use that as step or else use 1 */
    pat->content.CharRange.step = (int)step;
    pat->content.CharRange.ptr_c = pat->content.CharRange.min_c = min_c;
    pat->content.CharRange.max_c = max_c;

    if(multiply(amount, ((pat->content.CharRange.max_c -
                          pat->content.CharRange.min_c) /
                         pat->content.CharRange.step + 1)))
      return GLOBERROR("range overflow", *posp, CURLE_URL_MALFORMAT);
  }
  else if(ISDIGIT(*pattern)) {
    /* numeric range detected */
    unsigned long min_n = 0;
    unsigned long max_n = 0;
    unsigned long step_n = 0;
    curl_off_t num;

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

    if(!curlx_str_number(&pattern, &num, CURL_OFF_T_MAX)) {
      min_n = (unsigned long)num;
      if(!curlx_str_single(&pattern, '-')) {
        curlx_str_passblanks(&pattern);
        if(!curlx_str_number(&pattern, &num, CURL_OFF_T_MAX)) {
          max_n = (unsigned long)num;
          if(!curlx_str_single(&pattern, ']'))
            step_n = 1;
          else if(!curlx_str_single(&pattern, ':') &&
                  !curlx_str_number(&pattern, &num, CURL_OFF_T_MAX) &&
                  !curlx_str_single(&pattern, ']')) {
            step_n = (unsigned long)num;
          }
          /* else bad syntax */
        }
      }
    }

    *posp += (pattern - *patternp);

    if(!step_n ||
       (min_n == max_n && step_n != 1) ||
       (min_n != max_n && (min_n > max_n || step_n > (max_n - min_n))))
      /* the pattern is not well-formed */
      return GLOBERROR("bad range", *posp, CURLE_URL_MALFORMAT);

    /* typecasting to ints are fine here since we make sure above that we
       are within 31 bits */
    pat->content.NumRange.ptr_n = pat->content.NumRange.min_n = min_n;
    pat->content.NumRange.max_n = max_n;
    pat->content.NumRange.step = step_n;

    if(multiply(amount, ((pat->content.NumRange.max_n -
                          pat->content.NumRange.min_n) /
                         pat->content.NumRange.step + 1)))
      return GLOBERROR("range overflow", *posp, CURLE_URL_MALFORMAT);
  }
  else
    return GLOBERROR("bad range specification", *posp, CURLE_URL_MALFORMAT);

  *patternp = pattern;
  return CURLE_OK;
}

#define MAX_IP6LEN 128

static bool peek_ipv6(const char *str, size_t *skip)
{
  /*
   * Scan for a potential IPv6 literal.
   * - Valid globs contain a hyphen and <= 1 colon.
   * - IPv6 literals contain no hyphens and >= 2 colons.
   */
  char hostname[MAX_IP6LEN];
  CURLU *u;
  char *endbr = strchr(str, ']');
  size_t hlen;
  CURLUcode rc;
  if(!endbr)
    return FALSE;

  hlen = endbr - str + 1;
  if(hlen >= MAX_IP6LEN)
    return FALSE;

  u = curl_url();
  if(!u)
    return FALSE;

  memcpy(hostname, str, hlen);
  hostname[hlen] = 0;

  /* ask to "guess scheme" as then it works without an https:// prefix */
  rc = curl_url_set(u, CURLUPART_URL, hostname, CURLU_GUESS_SCHEME);

  curl_url_cleanup(u);
  if(!rc)
    *skip = hlen;
  return rc ? FALSE : TRUE;
}

static CURLcode glob_parse(struct URLGlob *glob, const char *pattern,
                           size_t pos, curl_off_t *amount)
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
        /* skip over IPv6 literals and [] */
        size_t skip = 0;
        if(!peek_ipv6(pattern, &skip) && (pattern[1] == ']'))
          skip = 2;
        if(skip) {
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
         (*(pattern + 1) == '{' || *(pattern + 1) == '[' ||
          *(pattern + 1) == '}' || *(pattern + 1) == ']') ) {

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
      switch(*pattern) {
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

CURLcode glob_url(struct URLGlob **glob, char *url, curl_off_t *urlnum,
                  FILE *error)
{
  /*
   * We can deal with any-size, just make a buffer with the same length
   * as the specified URL!
   */
  struct URLGlob *glob_expand;
  curl_off_t amount = 0;
  char *glob_buffer;
  CURLcode res;

  *glob = NULL;

  glob_buffer = MALLOC(strlen(url) + 1);
  if(!glob_buffer)
    return CURLE_OUT_OF_MEMORY;
  glob_buffer[0] = 0;

  glob_expand = CALLOC(1, sizeof(struct URLGlob));
  if(!glob_expand) {
    curlx_safefree(glob_buffer);
    return CURLE_OUT_OF_MEMORY;
  }
  glob_expand->urllen = strlen(url);
  glob_expand->glob_buffer = glob_buffer;

  res = glob_parse(glob_expand, url, 1, &amount);
  if(!res)
    *urlnum = amount;
  else {
    if(error && glob_expand->error) {
      char text[512];
      const char *t;
      if(glob_expand->pos) {
        msnprintf(text, sizeof(text), "%s in URL position %zu:\n%s\n%*s^",
                  glob_expand->error,
                  glob_expand->pos, url, (int)glob_expand->pos - 1, " ");
        t = text;
      }
      else
        t = glob_expand->error;

      /* send error description to the error-stream */
      fprintf(error, "curl: (%d) %s\n", res, t);
    }
    /* it failed, we cleanup */
    glob_cleanup(&glob_expand);
    *urlnum = 1;
    return res;
  }

  *glob = glob_expand;
  return CURLE_OK;
}

void glob_cleanup(struct URLGlob **globp)
{
  size_t i;
  curl_off_t elem;
  struct URLGlob *glob = *globp;

  if(!glob)
    return;

  for(i = 0; i < glob->size; i++) {
    if((glob->pattern[i].type == UPTSet) &&
       (glob->pattern[i].content.Set.elements)) {
      for(elem = glob->pattern[i].content.Set.size - 1;
          elem >= 0;
          --elem) {
        curlx_safefree(glob->pattern[i].content.Set.elements[elem]);
      }
      curlx_safefree(glob->pattern[i].content.Set.elements);
    }
  }
  curlx_safefree(glob->glob_buffer);
  curlx_safefree(glob);
  *globp = NULL;
}

CURLcode glob_next_url(char **globbed, struct URLGlob *glob)
{
  struct URLPattern *pat;
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
      switch(pat->type) {
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
      return CURLE_OK;
    }
  }

  for(i = 0; i < glob->size; ++i) {
    pat = &glob->pattern[i];
    switch(pat->type) {
    case UPTSet:
      if(pat->content.Set.elements) {
        msnprintf(buf, buflen, "%s",
                  pat->content.Set.elements[pat->content.Set.ptr_s]);
        len = strlen(buf);
        buf += len;
        buflen -= len;
      }
      break;
    case UPTCharRange:
      if(buflen) {
        *buf++ = pat->content.CharRange.ptr_c;
        *buf = '\0';
        buflen--;
      }
      break;
    case UPTNumRange:
      msnprintf(buf, buflen, "%0*" CURL_FORMAT_CURL_OFF_T,
                pat->content.NumRange.padlength,
                pat->content.NumRange.ptr_n);
      len = strlen(buf);
      buf += len;
      buflen -= len;
      break;
    default:
      printf("internal error: invalid pattern type (%d)\n", (int)pat->type);
      return CURLE_FAILED_INIT;
    }
  }

  *globbed = STRDUP(glob->glob_buffer);
  if(!*globbed)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

#define MAX_OUTPUT_GLOB_LENGTH (10*1024)

CURLcode glob_match_url(char **result, const char *filename,
                        struct URLGlob *glob)
{
  char numbuf[18];
  const char *appendthis = "";
  size_t appendlen = 0;
  struct curlx_dynbuf dyn;

  *result = NULL;

  /* We cannot use the glob_buffer for storage since the filename may be
   * longer than the URL we use.
   */
  curlx_dyn_init(&dyn, MAX_OUTPUT_GLOB_LENGTH);

  while(*filename) {
    if(*filename == '#' && ISDIGIT(filename[1])) {
      const char *ptr = filename;
      curl_off_t num;
      struct URLPattern *pat = NULL;
      filename++;
      if(!curlx_str_number(&filename, &num, glob->size) && num) {
        unsigned long i;
        num--; /* make it zero based */
        /* find the correct glob entry */
        for(i = 0; i < glob->size; i++) {
          if(glob->pattern[i].globindex == (int)num) {
            pat = &glob->pattern[i];
            break;
          }
        }
      }

      if(pat) {
        switch(pat->type) {
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
          msnprintf(numbuf, sizeof(numbuf), "%0*" CURL_FORMAT_CURL_OFF_T,
                    pat->content.NumRange.padlength,
                    pat->content.NumRange.ptr_n);
          appendthis = numbuf;
          appendlen = strlen(numbuf);
          break;
        default:
          fprintf(tool_stderr, "internal error: invalid pattern type (%d)\n",
                  (int)pat->type);
          curlx_dyn_free(&dyn);
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
    if(curlx_dyn_addn(&dyn, appendthis, appendlen))
      return CURLE_OUT_OF_MEMORY;
  }

  if(curlx_dyn_addn(&dyn, "", 0))
    return CURLE_OUT_OF_MEMORY;

#if defined(_WIN32) || defined(MSDOS)
  {
    char *sanitized;
    SANITIZEcode sc = sanitize_file_name(&sanitized, curlx_dyn_ptr(&dyn),
                                         (SANITIZE_ALLOW_PATH |
                                          SANITIZE_ALLOW_RESERVED));
    curlx_dyn_free(&dyn);
    if(sc)
      return CURLE_URL_MALFORMAT;
    *result = sanitized;
    return CURLE_OK;
  }
#else
  *result = curlx_dyn_ptr(&dyn);
  return CURLE_OK;
#endif /* _WIN32 || MSDOS */
}
