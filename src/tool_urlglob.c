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

#include "tool_cfgable.h"
#include "tool_doswin.h"
#include "tool_urlglob.h"
#include "tool_vms.h"
#include "tool_strdup.h"

static CURLcode globerror(struct URLGlob *glob, const char *err,
                          size_t pos, CURLcode error)
{
  glob->error = err;
  glob->pos = pos;
  return error;
}

static CURLcode glob_fixed(struct URLGlob *glob, char *fixed, size_t len)
{
  struct URLPattern *pat = &glob->pattern[glob->pnum];
  pat->type = GLOB_SET;
  pat->globindex = -1;
  pat->c.set.size = 0;
  pat->c.set.idx = 0;
  pat->c.set.elem = curlx_malloc(sizeof(char *));

  if(!pat->c.set.elem)
    return globerror(glob, NULL, 0, CURLE_OUT_OF_MEMORY);

  pat->c.set.elem[0] = memdup0(fixed, len);
  if(!pat->c.set.elem[0]) {
    tool_safefree(pat->c.set.elem);
    return globerror(glob, NULL, 0, CURLE_OUT_OF_MEMORY);
  }

  pat->c.set.palloc = 1;
  pat->c.set.size = 1;
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
#if (defined(__GNUC__) && \
  ((__GNUC__ > 5) || ((__GNUC__ == 5) && (__GNUC_MINOR__ >= 1)))) || \
  (defined(__clang__) && __clang_major__ >= 8)
    if(__builtin_mul_overflow(*amount, with, &sum))
      return 1;
#else
    sum = *amount * with;
    if(sum / with != *amount)
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
  const char *pattern = *patternp;
  const char *opattern = pattern;
  size_t opos = *posp - 1;
  CURLcode result = CURLE_OK;
  size_t size = 0;
  char **elem = NULL;
  size_t palloc = 0; /* start with this */

  while(!done) {
    switch(*pattern) {
    case '\0':                  /* URL ended while set was still open */
      result = globerror(glob, "unmatched brace", opos, CURLE_URL_MALFORMAT);
      goto error;

    case '{':
    case '[':                   /* no nested expressions at this time */
      result = globerror(glob, "nested brace", *posp, CURLE_URL_MALFORMAT);
      goto error;

    case '}':                           /* set element completed */
      if(opattern == pattern) {
        result = globerror(glob, "empty string within braces", *posp,
                           CURLE_URL_MALFORMAT);
        goto error;
      }

      /* add 1 to size since it will be incremented below */
      if(multiply(amount, size + 1)) {
        result = globerror(glob, "range overflow", 0, CURLE_URL_MALFORMAT);
        goto error;
      }
      done = TRUE;
      FALLTHROUGH();
    case ',':
      if(size >= 100000)
        return globerror(glob, "range overflow", 0, CURLE_URL_MALFORMAT);

      if(!palloc) {
        palloc = 5; /* a reasonable default */
        elem = curlx_malloc(palloc * sizeof(char *));
      }
      else if(size >= palloc) {
        char **arr = curlx_realloc(elem, palloc * 2 * sizeof(char *));
        if(!arr) {
          result = globerror(glob, NULL, 0, CURLE_OUT_OF_MEMORY);
          goto error;
        }
        elem = arr;
        palloc *= 2;
      }

      if(!elem) {
        result = globerror(glob, NULL, 0, CURLE_OUT_OF_MEMORY);
        goto error;
      }

      elem[size] = curlx_strdup(curlx_dyn_ptr(&glob->buf) ?
                                curlx_dyn_ptr(&glob->buf) : "");
      if(!elem[size]) {
        result = globerror(glob, NULL, 0, CURLE_OUT_OF_MEMORY);
        goto error;
      }
      ++size;
      curlx_dyn_reset(&glob->buf);

      ++pattern;
      if(!done)
        ++(*posp);
      break;

    case ']':                           /* illegal closing bracket */
      result = globerror(glob, "unexpected close bracket", *posp,
                         CURLE_URL_MALFORMAT);
      goto error;

    case '\\':                          /* escaped character, skip '\' */
      if(pattern[1]) {
        ++pattern;
        ++(*posp);
      }
      FALLTHROUGH();
    default:
      /* copy character to set element */
      if(curlx_dyn_addn(&glob->buf, pattern++, 1)) {
        result = CURLE_OUT_OF_MEMORY;
        goto error;
      }
      ++(*posp);
    }
  }

  *patternp = pattern; /* return with the new position */

  pat = &glob->pattern[glob->pnum];
  pat->type = GLOB_SET;
  pat->globindex = globindex;
  pat->c.set.elem = elem;
  pat->c.set.size = size;
  pat->c.set.idx = 0;
  pat->c.set.palloc = palloc;

  return CURLE_OK;
error:
  {
    size_t i;
    for(i = 0; i < size; i++)
      tool_safefree(elem[i]);
  }
  curlx_free(elem);
  return result;
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

  pat = &glob->pattern[glob->pnum];
  pat->globindex = globindex;

  if(ISALPHA(*pattern)) {
    /* character range detected */
    bool pmatch = FALSE;
    char min_c = 0;
    char max_c = 0;
    char end_c = 0;
    unsigned char step = 1;

    pat->type = GLOB_ASCII;

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
          step = (unsigned char)num;
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
      return globerror(glob, "bad range", *posp, CURLE_URL_MALFORMAT);

    /* if there was a ":[num]" thing, use that as step or else use 1 */
    pat->c.ascii.step = step;
    pat->c.ascii.letter = pat->c.ascii.min = min_c;
    pat->c.ascii.max = max_c;

    if(multiply(amount, ((pat->c.ascii.max - pat->c.ascii.min) /
                         pat->c.ascii.step + 1)))
      return globerror(glob, "range overflow", *posp, CURLE_URL_MALFORMAT);
  }
  else if(ISDIGIT(*pattern)) {
    /* numeric range detected */
    curl_off_t min_n = 0;
    curl_off_t max_n = 0;
    curl_off_t step_n = 0;
    curl_off_t num;

    pat->type = GLOB_NUM;
    pat->c.num.npad = 0;

    if(*pattern == '0') {
      /* leading zero specified, count them! */
      c = pattern;
      while(ISDIGIT(*c)) {
        c++;
        ++pat->c.num.npad; /* padding length is set for all instances of this
                              pattern */
      }
    }

    if(!curlx_str_number(&pattern, &num, CURL_OFF_T_MAX)) {
      min_n = num;
      if(!curlx_str_single(&pattern, '-')) {
        curlx_str_passblanks(&pattern);
        if(!curlx_str_number(&pattern, &num, CURL_OFF_T_MAX)) {
          max_n = num;
          if(!curlx_str_single(&pattern, ']'))
            step_n = 1;
          else if(!curlx_str_single(&pattern, ':') &&
                  !curlx_str_number(&pattern, &num, CURL_OFF_T_MAX) &&
                  !curlx_str_single(&pattern, ']')) {
            step_n = num;
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
      return globerror(glob, "bad range", *posp, CURLE_URL_MALFORMAT);

    /* typecasting to ints are fine here since we make sure above that we
       are within 31 bits */
    pat->c.num.idx = pat->c.num.min = min_n;
    pat->c.num.max = max_n;
    pat->c.num.step = step_n;

    if(multiply(amount, ((pat->c.num.max - pat->c.num.min) /
                         pat->c.num.step + 1)))
      return globerror(glob, "range overflow", *posp, CURLE_URL_MALFORMAT);
  }
  else
    return globerror(glob, "bad range specification", *posp,
                     CURLE_URL_MALFORMAT);

  *patternp = pattern;
  return CURLE_OK;
}

#define MAX_IP6LEN 128

static CURLcode peek_ipv6(const char *str, size_t *skip, bool *ipv6p)
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
  CURLcode result = CURLE_OK;
  *ipv6p = FALSE; /* default to nope */
  *skip = 0;
  if(!endbr)
    return CURLE_OK;

  hlen = endbr - str + 1;
  if(hlen >= MAX_IP6LEN)
    return CURLE_OK;

  u = curl_url();
  if(!u)
    return CURLE_OUT_OF_MEMORY;

  memcpy(hostname, str, hlen);
  hostname[hlen] = 0;

  /* ask to "guess scheme" as then it works without an https:// prefix */
  rc = curl_url_set(u, CURLUPART_URL, hostname, CURLU_GUESS_SCHEME);
  curl_url_cleanup(u);
  if(rc == CURLUE_OUT_OF_MEMORY)
    return CURLE_OUT_OF_MEMORY;
  if(!rc) {
    *skip = hlen;
    *ipv6p = TRUE;
  }
  return result;
}

static CURLcode add_glob(struct URLGlob *glob, size_t pos)
{
  DEBUGASSERT(glob->pattern[glob->pnum].type);

  if(++glob->pnum >= glob->palloc) {
    struct URLPattern *np = NULL;
    glob->palloc *= 2;
    if(glob->pnum < 255) { /* avoid ridiculous amounts */
      np = curlx_realloc(glob->pattern,
                         glob->palloc * sizeof(struct URLPattern));
      if(!np)
        return globerror(glob, NULL, pos, CURLE_OUT_OF_MEMORY);
    }
    else
      return globerror(glob, "too many {} sets", pos, CURLE_URL_MALFORMAT);
    glob->pattern = np;
  }
  return CURLE_OK;
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
    while(*pattern && *pattern != '{') {
      if(*pattern == '[') {
        /* skip over IPv6 literals and [] */
        size_t skip = 0;
        bool ipv6;
        res = peek_ipv6(pattern, &skip, &ipv6);
        if(res)
          return res;
        if(!ipv6 && (pattern[1] == ']'))
          skip = 2;
        if(skip) {
          if(curlx_dyn_addn(&glob->buf, pattern, skip))
            return CURLE_OUT_OF_MEMORY;
          pattern += skip;
          continue;
        }
        break;
      }
      if(*pattern == '}' || *pattern == ']')
        return globerror(glob, "unmatched close brace/bracket", pos,
                         CURLE_URL_MALFORMAT);

      /* only allow \ to escape known "special letters" */
      if(*pattern == '\\' &&
         (pattern[1] == '{' || pattern[1] == '[' ||
          pattern[1] == '}' || pattern[1] == ']')) {

        /* escape character, skip '\' */
        ++pattern;
        ++pos;
      }
      /* copy character to literal */
      if(curlx_dyn_addn(&glob->buf, pattern++, 1))
        return CURLE_OUT_OF_MEMORY;
      ++pos;
    }
    if(curlx_dyn_len(&glob->buf)) {
      /* we got a literal string, add it as a single-item list */
      res = glob_fixed(glob, curlx_dyn_ptr(&glob->buf),
                       curlx_dyn_len(&glob->buf));
      if(!res)
        res = add_glob(glob, pos);
      curlx_dyn_reset(&glob->buf);
    }
    else {
      if(!*pattern) /* done  */
        break;
      else if(*pattern == '{') {
        /* process set pattern */
        pattern++;
        pos++;
        res = glob_set(glob, &pattern, &pos, amount, globindex++);
        if(!res)
          res = add_glob(glob, pos);
      }
      else if(*pattern == '[') {
        /* process range pattern */
        pattern++;
        pos++;
        res = glob_range(glob, &pattern, &pos, amount, globindex++);
        if(!res)
          res = add_glob(glob, pos);
      }
    }
  }
  return res;
}

bool glob_inuse(struct URLGlob *glob)
{
  return glob->palloc ? TRUE : FALSE;
}

CURLcode glob_url(struct URLGlob *glob, const char *url, curl_off_t *urlnum,
                  FILE *error)
{
  /*
   * We can deal with any-size, just make a buffer with the same length
   * as the specified URL!
   */
  curl_off_t amount = 0;
  CURLcode res;

  memset(glob, 0, sizeof(struct URLGlob));
  curlx_dyn_init(&glob->buf, MAX_CONFIG_LINE_LENGTH);
  glob->pattern = curlx_malloc(2 * sizeof(struct URLPattern));
  if(!glob->pattern)
    return CURLE_OUT_OF_MEMORY;
  glob->palloc = 2;

  res = glob_parse(glob, url, 1, &amount);
  if(res) {
    if(error && glob->error) {
      char text[512];
      const char *t;
      if(glob->pos) {
        curl_msnprintf(text, sizeof(text), "%s in URL position %zu:\n%s\n%*s^",
                       glob->error,
                       glob->pos, url, (int)glob->pos - 1, " ");
        t = text;
      }
      else
        t = glob->error;

      /* send error description to the error-stream */
      curl_mfprintf(error, "curl: (%d) %s\n", res, t);
    }
    *urlnum = 1;
    return res;
  }
  *urlnum = amount;
  return CURLE_OK;
}

void glob_cleanup(struct URLGlob *glob)
{
  size_t i;

  if(glob->pattern) {
    for(i = 0; i < glob->pnum; i++) {
      DEBUGASSERT(glob->pattern[i].type);
      if((glob->pattern[i].type == GLOB_SET) &&
         (glob->pattern[i].c.set.elem)) {
        curl_off_t elem;
        for(elem = 0; elem < glob->pattern[i].c.set.size; elem++)
          tool_safefree(glob->pattern[i].c.set.elem[elem]);
        tool_safefree(glob->pattern[i].c.set.elem);
      }
    }
    tool_safefree(glob->pattern);
    glob->palloc = 0;
    curlx_dyn_free(&glob->buf);
  }
}

CURLcode glob_next_url(char **globbed, struct URLGlob *glob)
{
  struct URLPattern *pat;
  size_t i;

  *globbed = NULL;
  curlx_dyn_reset(&glob->buf);

  if(!glob->beenhere)
    glob->beenhere = 1;
  else {
    bool carry = TRUE;

    /* implement a counter over the index ranges of all patterns, starting
       with the rightmost pattern */
    for(i = 0; carry && (i < glob->pnum); i++) {
      carry = FALSE;
      pat = &glob->pattern[glob->pnum - 1 - i];
      switch(pat->type) {
      case GLOB_SET:
        if((pat->c.set.elem) && (++pat->c.set.idx == pat->c.set.size)) {
          pat->c.set.idx = 0;
          carry = TRUE;
        }
        break;
      case GLOB_ASCII:
        pat->c.ascii.letter += pat->c.ascii.step;
        if(pat->c.ascii.letter > pat->c.ascii.max) {
          pat->c.ascii.letter = pat->c.ascii.min;
          carry = TRUE;
        }
        break;
      case GLOB_NUM:
        pat->c.num.idx += pat->c.num.step;
        if(pat->c.num.idx > pat->c.num.max) {
          pat->c.num.idx = pat->c.num.min;
          carry = TRUE;
        }
        break;
      default:
        DEBUGASSERT(0);
        return CURLE_FAILED_INIT;
      }
    }
    if(carry) {         /* first pattern ptr has run into overflow, done! */
      return CURLE_OK;
    }
  }

  for(i = 0; i < glob->pnum; ++i) {
    pat = &glob->pattern[i];
    switch(pat->type) {
    case GLOB_SET:
      if(pat->c.set.elem) {
        if(curlx_dyn_add(&glob->buf, pat->c.set.elem[pat->c.set.idx]))
          return CURLE_OUT_OF_MEMORY;
      }
      break;
    case GLOB_ASCII: {
      char letter = (char)pat->c.ascii.letter;
      if(curlx_dyn_addn(&glob->buf, &letter, 1))
        return CURLE_OUT_OF_MEMORY;
      break;
    }
    case GLOB_NUM:
      if(curlx_dyn_addf(&glob->buf, "%0*" CURL_FORMAT_CURL_OFF_T,
                        pat->c.num.npad, pat->c.num.idx))
        return CURLE_OUT_OF_MEMORY;
      break;
    default:
      DEBUGASSERT(0);
      return CURLE_FAILED_INIT;
    }
  }

  *globbed =
    curlx_strdup(curlx_dyn_ptr(&glob->buf) ? curlx_dyn_ptr(&glob->buf) : "");
  if(!*globbed)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

#define MAX_OUTPUT_GLOB_LENGTH (1024 * 1024)

CURLcode glob_match_url(char **output, const char *filename,
                        struct URLGlob *glob)
{
  struct dynbuf dyn;
  *output = NULL;

  curlx_dyn_init(&dyn, MAX_OUTPUT_GLOB_LENGTH);

  while(*filename) {
    CURLcode result = CURLE_OK;
    if(*filename == '#' && ISDIGIT(filename[1])) {
      const char *ptr = filename;
      curl_off_t num;
      struct URLPattern *pat = NULL;
      filename++;
      if(!curlx_str_number(&filename, &num, glob->pnum) && num) {
        size_t i;
        num--; /* make it zero based */
        /* find the correct glob entry */
        for(i = 0; i < glob->pnum; i++) {
          if(glob->pattern[i].globindex == (int)num) {
            pat = &glob->pattern[i];
            break;
          }
        }
      }

      if(pat) {
        switch(pat->type) {
        case GLOB_SET:
          if(pat->c.set.elem)
            result = curlx_dyn_add(&dyn, pat->c.set.elem[pat->c.set.idx]);
          break;
        case GLOB_ASCII: {
          char letter = (char)pat->c.ascii.letter;
          result = curlx_dyn_addn(&dyn, &letter, 1);
          break;
        }
        case GLOB_NUM:
          result = curlx_dyn_addf(&dyn, "%0*" CURL_FORMAT_CURL_OFF_T,
                                  pat->c.num.npad, pat->c.num.idx);
          break;
        default:
          DEBUGASSERT(0);
          curlx_dyn_free(&dyn);
          return CURLE_FAILED_INIT;
        }
      }
      else
        /* #[num] out of range, use the #[num] in the output */
        result = curlx_dyn_addn(&dyn, ptr, filename - ptr);
    }
    else
      result = curlx_dyn_addn(&dyn, filename++, 1);
    if(result)
      return result;
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
    *output = sanitized;
    return CURLE_OK;
  }
#else
  *output = curlx_dyn_ptr(&dyn);
  return CURLE_OK;
#endif /* _WIN32 || MSDOS */
}
