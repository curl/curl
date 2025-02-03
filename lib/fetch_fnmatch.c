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
 * are also available at https://fetch.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/

#include "fetch_setup.h"
#ifndef FETCH_DISABLE_FTP
#include <fetch/fetch.h>

#include "fetch_fnmatch.h"
#include "fetch_memory.h"

/* The last #include file should be: */
#include "memdebug.h"

#ifndef HAVE_FNMATCH

#define FETCHFNM_CHARSET_LEN (sizeof(char) * 256)
#define FETCHFNM_CHSET_SIZE (FETCHFNM_CHARSET_LEN + 15)

#define FETCHFNM_NEGATE FETCHFNM_CHARSET_LEN

#define FETCHFNM_ALNUM (FETCHFNM_CHARSET_LEN + 1)
#define FETCHFNM_DIGIT (FETCHFNM_CHARSET_LEN + 2)
#define FETCHFNM_XDIGIT (FETCHFNM_CHARSET_LEN + 3)
#define FETCHFNM_ALPHA (FETCHFNM_CHARSET_LEN + 4)
#define FETCHFNM_PRINT (FETCHFNM_CHARSET_LEN + 5)
#define FETCHFNM_BLANK (FETCHFNM_CHARSET_LEN + 6)
#define FETCHFNM_LOWER (FETCHFNM_CHARSET_LEN + 7)
#define FETCHFNM_GRAPH (FETCHFNM_CHARSET_LEN + 8)
#define FETCHFNM_SPACE (FETCHFNM_CHARSET_LEN + 9)
#define FETCHFNM_UPPER (FETCHFNM_CHARSET_LEN + 10)

typedef enum
{
  FETCHFNM_SCHS_DEFAULT = 0,
  FETCHFNM_SCHS_RIGHTBR,
  FETCHFNM_SCHS_RIGHTBRLEFTBR
} setcharset_state;

typedef enum
{
  FETCHFNM_PKW_INIT = 0,
  FETCHFNM_PKW_DDOT
} parsekey_state;

typedef enum
{
  CCLASS_OTHER = 0,
  CCLASS_DIGIT,
  CCLASS_UPPER,
  CCLASS_LOWER
} char_class;

#define SETCHARSET_OK 1
#define SETCHARSET_FAIL 0

static int parsekeyword(unsigned char **pattern, unsigned char *charset)
{
  parsekey_state state = FETCHFNM_PKW_INIT;
#define KEYLEN 10
  char keyword[KEYLEN] = {0};
  int i;
  unsigned char *p = *pattern;
  bool found = FALSE;
  for (i = 0; !found; i++)
  {
    char c = (char)*p++;
    if (i >= KEYLEN)
      return SETCHARSET_FAIL;
    switch (state)
    {
    case FETCHFNM_PKW_INIT:
      if (ISLOWER(c))
        keyword[i] = c;
      else if (c == ':')
        state = FETCHFNM_PKW_DDOT;
      else
        return SETCHARSET_FAIL;
      break;
    case FETCHFNM_PKW_DDOT:
      if (c == ']')
        found = TRUE;
      else
        return SETCHARSET_FAIL;
    }
  }
#undef KEYLEN

  *pattern = p; /* move caller's pattern pointer */
  if (strcmp(keyword, "digit") == 0)
    charset[FETCHFNM_DIGIT] = 1;
  else if (strcmp(keyword, "alnum") == 0)
    charset[FETCHFNM_ALNUM] = 1;
  else if (strcmp(keyword, "alpha") == 0)
    charset[FETCHFNM_ALPHA] = 1;
  else if (strcmp(keyword, "xdigit") == 0)
    charset[FETCHFNM_XDIGIT] = 1;
  else if (strcmp(keyword, "print") == 0)
    charset[FETCHFNM_PRINT] = 1;
  else if (strcmp(keyword, "graph") == 0)
    charset[FETCHFNM_GRAPH] = 1;
  else if (strcmp(keyword, "space") == 0)
    charset[FETCHFNM_SPACE] = 1;
  else if (strcmp(keyword, "blank") == 0)
    charset[FETCHFNM_BLANK] = 1;
  else if (strcmp(keyword, "upper") == 0)
    charset[FETCHFNM_UPPER] = 1;
  else if (strcmp(keyword, "lower") == 0)
    charset[FETCHFNM_LOWER] = 1;
  else
    return SETCHARSET_FAIL;
  return SETCHARSET_OK;
}

/* Return the character class. */
static char_class charclass(unsigned char c)
{
  if (ISUPPER(c))
    return CCLASS_UPPER;
  if (ISLOWER(c))
    return CCLASS_LOWER;
  if (ISDIGIT(c))
    return CCLASS_DIGIT;
  return CCLASS_OTHER;
}

/* Include a character or a range in set. */
static void setcharorrange(unsigned char **pp, unsigned char *charset)
{
  unsigned char *p = (*pp)++;
  unsigned char c = *p++;

  charset[c] = 1;
  if (ISALNUM(c) && *p++ == '-')
  {
    char_class cc = charclass(c);
    unsigned char endrange = *p++;

    if (endrange == '\\')
      endrange = *p++;
    if (endrange >= c && charclass(endrange) == cc)
    {
      while (c++ != endrange)
        if (charclass(c) == cc) /* Chars in class may be not consecutive. */
          charset[c] = 1;
      *pp = p;
    }
  }
}

/* returns 1 (TRUE) if pattern is OK, 0 if is bad ("p" is pattern pointer) */
static int setcharset(unsigned char **p, unsigned char *charset)
{
  setcharset_state state = FETCHFNM_SCHS_DEFAULT;
  bool something_found = FALSE;
  unsigned char c;

  memset(charset, 0, FETCHFNM_CHSET_SIZE);
  for (;;)
  {
    c = **p;
    if (!c)
      return SETCHARSET_FAIL;

    switch (state)
    {
    case FETCHFNM_SCHS_DEFAULT:
      if (c == ']')
      {
        if (something_found)
          return SETCHARSET_OK;
        something_found = TRUE;
        state = FETCHFNM_SCHS_RIGHTBR;
        charset[c] = 1;
        (*p)++;
      }
      else if (c == '[')
      {
        unsigned char *pp = *p + 1;

        if (*pp++ == ':' && parsekeyword(&pp, charset))
          *p = pp;
        else
        {
          charset[c] = 1;
          (*p)++;
        }
        something_found = TRUE;
      }
      else if (c == '^' || c == '!')
      {
        if (!something_found)
        {
          if (charset[FETCHFNM_NEGATE])
          {
            charset[c] = 1;
            something_found = TRUE;
          }
          else
            charset[FETCHFNM_NEGATE] = 1; /* negate charset */
        }
        else
          charset[c] = 1;
        (*p)++;
      }
      else if (c == '\\')
      {
        c = *(++(*p));
        if (c)
          setcharorrange(p, charset);
        else
          charset['\\'] = 1;
        something_found = TRUE;
      }
      else
      {
        setcharorrange(p, charset);
        something_found = TRUE;
      }
      break;
    case FETCHFNM_SCHS_RIGHTBR:
      if (c == '[')
      {
        state = FETCHFNM_SCHS_RIGHTBRLEFTBR;
        charset[c] = 1;
        (*p)++;
      }
      else if (c == ']')
      {
        return SETCHARSET_OK;
      }
      else if (ISPRINT(c))
      {
        charset[c] = 1;
        (*p)++;
        state = FETCHFNM_SCHS_DEFAULT;
      }
      else
        /* used 'goto fail' instead of 'return SETCHARSET_FAIL' to avoid a
         * nonsense warning 'statement not reached' at end of the fnc when
         * compiling on Solaris */
        goto fail;
      break;
    case FETCHFNM_SCHS_RIGHTBRLEFTBR:
      if (c == ']')
        return SETCHARSET_OK;
      state = FETCHFNM_SCHS_DEFAULT;
      charset[c] = 1;
      (*p)++;
      break;
    }
  }
fail:
  return SETCHARSET_FAIL;
}

static int loop(const unsigned char *pattern, const unsigned char *string,
                int maxstars)
{
  unsigned char *p = (unsigned char *)pattern;
  unsigned char *s = (unsigned char *)string;
  unsigned char charset[FETCHFNM_CHSET_SIZE] = {0};

  for (;;)
  {
    unsigned char *pp;

    switch (*p)
    {
    case '*':
      if (!maxstars)
        return FETCH_FNMATCH_NOMATCH;
      /* Regroup consecutive stars and question marks. This can be done because
         '*?*?*' can be expressed as '??*'. */
      for (;;)
      {
        if (*++p == '\0')
          return FETCH_FNMATCH_MATCH;
        if (*p == '?')
        {
          if (!*s++)
            return FETCH_FNMATCH_NOMATCH;
        }
        else if (*p != '*')
          break;
      }
      /* Skip string characters until we find a match with pattern suffix. */
      for (maxstars--; *s; s++)
      {
        if (loop(p, s, maxstars) == FETCH_FNMATCH_MATCH)
          return FETCH_FNMATCH_MATCH;
      }
      return FETCH_FNMATCH_NOMATCH;
    case '?':
      if (!*s)
        return FETCH_FNMATCH_NOMATCH;
      s++;
      p++;
      break;
    case '\0':
      return *s ? FETCH_FNMATCH_NOMATCH : FETCH_FNMATCH_MATCH;
    case '\\':
      if (p[1])
        p++;
      if (*s++ != *p++)
        return FETCH_FNMATCH_NOMATCH;
      break;
    case '[':
      pp = p + 1; /* Copy in case of syntax error in set. */
      if (setcharset(&pp, charset))
      {
        bool found = FALSE;
        if (!*s)
          return FETCH_FNMATCH_NOMATCH;
        if (charset[(unsigned int)*s])
          found = TRUE;
        else if (charset[FETCHFNM_ALNUM])
          found = ISALNUM(*s);
        else if (charset[FETCHFNM_ALPHA])
          found = ISALPHA(*s);
        else if (charset[FETCHFNM_DIGIT])
          found = ISDIGIT(*s);
        else if (charset[FETCHFNM_XDIGIT])
          found = ISXDIGIT(*s);
        else if (charset[FETCHFNM_PRINT])
          found = ISPRINT(*s);
        else if (charset[FETCHFNM_SPACE])
          found = ISSPACE(*s);
        else if (charset[FETCHFNM_UPPER])
          found = ISUPPER(*s);
        else if (charset[FETCHFNM_LOWER])
          found = ISLOWER(*s);
        else if (charset[FETCHFNM_BLANK])
          found = ISBLANK(*s);
        else if (charset[FETCHFNM_GRAPH])
          found = ISGRAPH(*s);

        if (charset[FETCHFNM_NEGATE])
          found = !found;

        if (!found)
          return FETCH_FNMATCH_NOMATCH;
        p = pp + 1;
        s++;
        break;
      }
      /* Syntax error in set; mismatch! */
      return FETCH_FNMATCH_NOMATCH;

    default:
      if (*p++ != *s++)
        return FETCH_FNMATCH_NOMATCH;
      break;
    }
  }
}

/*
 * @unittest: 1307
 */
int Fetch_fnmatch(void *ptr, const char *pattern, const char *string)
{
  (void)ptr; /* the argument is specified by the fetch_fnmatch_callback
                prototype, but not used by Fetch_fnmatch() */
  if (!pattern || !string)
  {
    return FETCH_FNMATCH_FAIL;
  }
  return loop((unsigned char *)pattern, (unsigned char *)string, 2);
}
#else
#include <fnmatch.h>
/*
 * @unittest: 1307
 */
int Fetch_fnmatch(void *ptr, const char *pattern, const char *string)
{
  (void)ptr; /* the argument is specified by the fetch_fnmatch_callback
                prototype, but not used by Fetch_fnmatch() */
  if (!pattern || !string)
  {
    return FETCH_FNMATCH_FAIL;
  }

  switch (fnmatch(pattern, string, 0))
  {
  case 0:
    return FETCH_FNMATCH_MATCH;
  case FNM_NOMATCH:
    return FETCH_FNMATCH_NOMATCH;
  default:
    return FETCH_FNMATCH_FAIL;
  }
  /* not reached */
}

#endif

#endif /* if FTP is disabled */
