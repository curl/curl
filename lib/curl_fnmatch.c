/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "curl_setup.h"

#include <curl/curl.h>

#include "curl_fnmatch.h"
#include "curl_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

#define CURLFNM_CHARSET_LEN (sizeof(char) * 256)
#define CURLFNM_CHSET_SIZE (CURLFNM_CHARSET_LEN + 15)

#define CURLFNM_NEGATE  CURLFNM_CHARSET_LEN

#define CURLFNM_ALNUM   (CURLFNM_CHARSET_LEN + 1)
#define CURLFNM_DIGIT   (CURLFNM_CHARSET_LEN + 2)
#define CURLFNM_XDIGIT  (CURLFNM_CHARSET_LEN + 3)
#define CURLFNM_ALPHA   (CURLFNM_CHARSET_LEN + 4)
#define CURLFNM_PRINT   (CURLFNM_CHARSET_LEN + 5)
#define CURLFNM_BLANK   (CURLFNM_CHARSET_LEN + 6)
#define CURLFNM_LOWER   (CURLFNM_CHARSET_LEN + 7)
#define CURLFNM_GRAPH   (CURLFNM_CHARSET_LEN + 8)
#define CURLFNM_SPACE   (CURLFNM_CHARSET_LEN + 9)
#define CURLFNM_UPPER   (CURLFNM_CHARSET_LEN + 10)

typedef enum {
  CURLFNM_LOOP_DEFAULT = 0,
  CURLFNM_LOOP_BACKSLASH
} loop_state;

typedef enum {
  CURLFNM_SCHS_DEFAULT = 0,
  CURLFNM_SCHS_MAYRANGE,
  CURLFNM_SCHS_MAYRANGE2,
  CURLFNM_SCHS_RIGHTBR,
  CURLFNM_SCHS_RIGHTBRLEFTBR
} setcharset_state;

typedef enum {
  CURLFNM_PKW_INIT = 0,
  CURLFNM_PKW_DDOT
} parsekey_state;

#define SETCHARSET_OK     1
#define SETCHARSET_FAIL   0

static int parsekeyword(unsigned char **pattern, unsigned char *charset)
{
  parsekey_state state = CURLFNM_PKW_INIT;
#define KEYLEN 10
  char keyword[KEYLEN] = { 0 };
  int found = FALSE;
  int i;
  unsigned char *p = *pattern;
  for(i = 0; !found; i++) {
    char c = *p++;
    if(i >= KEYLEN)
      return SETCHARSET_FAIL;
    switch(state) {
    case CURLFNM_PKW_INIT:
      if(ISALPHA(c) && ISLOWER(c))
        keyword[i] = c;
      else if(c == ':')
        state = CURLFNM_PKW_DDOT;
      else
        return 0;
      break;
    case CURLFNM_PKW_DDOT:
      if(c == ']')
        found = TRUE;
      else
        return SETCHARSET_FAIL;
    }
  }
#undef KEYLEN

  *pattern = p; /* move caller's pattern pointer */
  if(strcmp(keyword, "digit") == 0)
    charset[CURLFNM_DIGIT] = 1;
  else if(strcmp(keyword, "alnum") == 0)
    charset[CURLFNM_ALNUM] = 1;
  else if(strcmp(keyword, "alpha") == 0)
    charset[CURLFNM_ALPHA] = 1;
  else if(strcmp(keyword, "xdigit") == 0)
    charset[CURLFNM_XDIGIT] = 1;
  else if(strcmp(keyword, "print") == 0)
    charset[CURLFNM_PRINT] = 1;
  else if(strcmp(keyword, "graph") == 0)
    charset[CURLFNM_GRAPH] = 1;
  else if(strcmp(keyword, "space") == 0)
    charset[CURLFNM_SPACE] = 1;
  else if(strcmp(keyword, "blank") == 0)
    charset[CURLFNM_BLANK] = 1;
  else if(strcmp(keyword, "upper") == 0)
    charset[CURLFNM_UPPER] = 1;
  else if(strcmp(keyword, "lower") == 0)
    charset[CURLFNM_LOWER] = 1;
  else
    return SETCHARSET_FAIL;
  return SETCHARSET_OK;
}

/* returns 1 (true) if pattern is OK, 0 if is bad ("p" is pattern pointer) */
static int setcharset(unsigned char **p, unsigned char *charset)
{
  setcharset_state state = CURLFNM_SCHS_DEFAULT;
  unsigned char rangestart = 0;
  unsigned char lastchar   = 0;
  bool something_found = FALSE;
  unsigned char c;
  for(;;) {
    c = **p;
    if(!c)
      return SETCHARSET_FAIL;

    switch(state) {
    case CURLFNM_SCHS_DEFAULT:
      if(ISALNUM(c)) { /* ASCII value */
        rangestart = c;
        charset[c] = 1;
        (*p)++;
        state = CURLFNM_SCHS_MAYRANGE;
        something_found = TRUE;
      }
      else if(c == ']') {
        if(something_found)
          return SETCHARSET_OK;
        something_found = TRUE;
        state = CURLFNM_SCHS_RIGHTBR;
        charset[c] = 1;
        (*p)++;
      }
      else if(c == '[') {
        char c2 = *((*p) + 1);
        if(c2 == ':') { /* there has to be a keyword */
          (*p) += 2;
          if(parsekeyword(p, charset)) {
            state = CURLFNM_SCHS_DEFAULT;
          }
          else
            return SETCHARSET_FAIL;
        }
        else {
          charset[c] = 1;
          (*p)++;
        }
        something_found = TRUE;
      }
      else if(c == '?' || c == '*') {
        something_found = TRUE;
        charset[c] = 1;
        (*p)++;
      }
      else if(c == '^' || c == '!') {
        if(!something_found) {
          if(charset[CURLFNM_NEGATE]) {
            charset[c] = 1;
            something_found = TRUE;
          }
          else
            charset[CURLFNM_NEGATE] = 1; /* negate charset */
        }
        else
          charset[c] = 1;
        (*p)++;
      }
      else if(c == '\\') {
        c = *(++(*p));
        if(ISPRINT((c))) {
          something_found = TRUE;
          state = CURLFNM_SCHS_MAYRANGE;
          charset[c] = 1;
          rangestart = c;
          (*p)++;
        }
        else
          return SETCHARSET_FAIL;
      }
      else {
        charset[c] = 1;
        (*p)++;
        something_found = TRUE;
      }
      break;
    case CURLFNM_SCHS_MAYRANGE:
      if(c == '-') {
        charset[c] = 1;
        (*p)++;
        lastchar = '-';
        state = CURLFNM_SCHS_MAYRANGE2;
      }
      else if(c == '[') {
        state = CURLFNM_SCHS_DEFAULT;
      }
      else if(ISALNUM(c)) {
        charset[c] = 1;
        (*p)++;
      }
      else if(c == '\\') {
        c = *(++(*p));
        if(ISPRINT(c)) {
          charset[c] = 1;
          (*p)++;
        }
        else
          return SETCHARSET_FAIL;
      }
      else if(c == ']') {
        return SETCHARSET_OK;
      }
      else
        return SETCHARSET_FAIL;
      break;
    case CURLFNM_SCHS_MAYRANGE2:
      if(c == ']') {
        return SETCHARSET_OK;
      }
      else if(c == '\\') {
        c = *(++(*p));
        if(ISPRINT(c)) {
          charset[c] = 1;
          state = CURLFNM_SCHS_DEFAULT;
          (*p)++;
        }
        else
          return SETCHARSET_FAIL;
      }
      else if(c >= rangestart) {
        if((ISLOWER(c) && ISLOWER(rangestart)) ||
           (ISDIGIT(c) && ISDIGIT(rangestart)) ||
           (ISUPPER(c) && ISUPPER(rangestart))) {
          charset[lastchar] = 0;
          rangestart++;
          while(rangestart++ <= c)
            charset[rangestart-1] = 1;
          (*p)++;
          state = CURLFNM_SCHS_DEFAULT;
        }
        else
          return SETCHARSET_FAIL;
      }
      else
        return SETCHARSET_FAIL;
      break;
    case CURLFNM_SCHS_RIGHTBR:
      if(c == '[') {
        state = CURLFNM_SCHS_RIGHTBRLEFTBR;
        charset[c] = 1;
        (*p)++;
      }
      else if(c == ']') {
        return SETCHARSET_OK;
      }
      else if(ISPRINT(c)) {
        charset[c] = 1;
        (*p)++;
        state = CURLFNM_SCHS_DEFAULT;
      }
      else
        /* used 'goto fail' instead of 'return SETCHARSET_FAIL' to avoid a
         * nonsense warning 'statement not reached' at end of the fnc when
         * compiling on Solaris */
        goto fail;
      break;
    case CURLFNM_SCHS_RIGHTBRLEFTBR:
      if(c == ']') {
        return SETCHARSET_OK;
      }
      else {
        state  = CURLFNM_SCHS_DEFAULT;
        charset[c] = 1;
        (*p)++;
      }
      break;
    }
  }
fail:
  return SETCHARSET_FAIL;
}

static int loop(const unsigned char *pattern, const unsigned char *string)
{
  loop_state state = CURLFNM_LOOP_DEFAULT;
  unsigned char *p = (unsigned char *)pattern;
  unsigned char *s = (unsigned char *)string;
  unsigned char charset[CURLFNM_CHSET_SIZE] = { 0 };
  int rc = 0;

  for(;;) {
    switch(state) {
    case CURLFNM_LOOP_DEFAULT:
      if(*p == '*') {
        while(*(p + 1) == '*') /* eliminate multiple stars */
          p++;
        if(*s == '\0' && *(p + 1) == '\0')
          return CURL_FNMATCH_MATCH;
        rc = loop(p + 1, s); /* *.txt matches .txt <=> .txt matches .txt */
        if(rc == CURL_FNMATCH_MATCH)
          return CURL_FNMATCH_MATCH;
        if(*s) /* let the star eat up one character */
          s++;
        else
          return CURL_FNMATCH_NOMATCH;
      }
      else if(*p == '?') {
        if(ISPRINT(*s)) {
          s++;
          p++;
        }
        else if(*s == '\0')
          return CURL_FNMATCH_NOMATCH;
        else
          return CURL_FNMATCH_FAIL; /* cannot deal with other character */
      }
      else if(*p == '\0') {
        if(*s == '\0')
          return CURL_FNMATCH_MATCH;
        return CURL_FNMATCH_NOMATCH;
      }
      else if(*p == '\\') {
        state = CURLFNM_LOOP_BACKSLASH;
        p++;
      }
      else if(*p == '[') {
        unsigned char *pp = p + 1; /* cannot handle with pointer to register */
        if(setcharset(&pp, charset)) {
          int found = FALSE;
          if(charset[(unsigned int)*s])
            found = TRUE;
          else if(charset[CURLFNM_ALNUM])
            found = ISALNUM(*s);
          else if(charset[CURLFNM_ALPHA])
            found = ISALPHA(*s);
          else if(charset[CURLFNM_DIGIT])
            found = ISDIGIT(*s);
          else if(charset[CURLFNM_XDIGIT])
            found = ISXDIGIT(*s);
          else if(charset[CURLFNM_PRINT])
            found = ISPRINT(*s);
          else if(charset[CURLFNM_SPACE])
            found = ISSPACE(*s);
          else if(charset[CURLFNM_UPPER])
            found = ISUPPER(*s);
          else if(charset[CURLFNM_LOWER])
            found = ISLOWER(*s);
          else if(charset[CURLFNM_BLANK])
            found = ISBLANK(*s);
          else if(charset[CURLFNM_GRAPH])
            found = ISGRAPH(*s);

          if(charset[CURLFNM_NEGATE])
            found = !found;

          if(found) {
            p = pp + 1;
            s++;
            memset(charset, 0, CURLFNM_CHSET_SIZE);
          }
          else
            return CURL_FNMATCH_NOMATCH;
        }
        else
          return CURL_FNMATCH_FAIL;
      }
      else {
        if(*p++ != *s++)
          return CURL_FNMATCH_NOMATCH;
      }
      break;
    case CURLFNM_LOOP_BACKSLASH:
      if(ISPRINT(*p)) {
        if(*p++ == *s++)
          state = CURLFNM_LOOP_DEFAULT;
        else
          return CURL_FNMATCH_NOMATCH;
      }
      else
        return CURL_FNMATCH_FAIL;
      break;
    }
  }
}

/*
 * @unittest: 1307
 */
int Curl_fnmatch(void *ptr, const char *pattern, const char *string)
{
  (void)ptr; /* the argument is specified by the curl_fnmatch_callback
                prototype, but not used by Curl_fnmatch() */
  if(!pattern || !string) {
    return CURL_FNMATCH_FAIL;
  }
  return loop((unsigned char *)pattern, (unsigned char *)string);
}
