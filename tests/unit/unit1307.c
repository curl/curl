/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "curlcheck.h"

#include "curl_fnmatch.h"

#define MATCH   CURL_FNMATCH_MATCH
#define NOMATCH CURL_FNMATCH_NOMATCH
#define RE_ERR  CURL_FNMATCH_FAIL

#define MAX_PATTERN_L 100
#define MAX_STRING_L  100

struct testcase {
  char pattern[MAX_PATTERN_L];
  char string[MAX_STRING_L];
  int  result;
};

static const struct testcase tests[] = {
  /* brackets syntax */
  { "\\[",                      "[",                      MATCH },
  { "[",                        "[",                      RE_ERR },
  { "[]",                       "[]",                     RE_ERR },
  { "[][]",                     "[",                      MATCH },
  { "[][]",                     "]",                      MATCH },
  { "[[]",                      "[",                      MATCH },
  { "[[[]",                     "[",                      MATCH },
  { "[[[[]",                    "[",                      MATCH },
  { "[[[[]",                    "[",                      MATCH },

  { "[][[]",                    "]",                      MATCH },
  { "[][[[]",                   "[",                      MATCH },
  { "[[]",                      "]",                      NOMATCH },

  { "[a-z]",                    "a",                      MATCH },
  { "[a-z]",                    "A",                      NOMATCH },
  { "?[a-z]",                   "?Z",                     NOMATCH },
  { "[A-Z]",                    "C",                      MATCH },
  { "[A-Z]",                    "c",                      NOMATCH },
  { "[0-9]",                    "7",                      MATCH },
  { "[7-8]",                    "7",                      MATCH },
  { "[7-]",                     "7",                      MATCH },
  { "[7-]",                     "-",                      MATCH },
  { "[7-]",                     "[",                      NOMATCH },
  { "[a-bA-F]",                 "F",                      MATCH },
  { "[a-bA-B9]",                "9",                      MATCH },
  { "[a-bA-B98]",               "8",                      MATCH },
  { "[a-bA-B98]",               "C",                      NOMATCH },
  { "[a-bA-Z9]",                "F",                      MATCH },
  { "[a-bA-Z9]ero*",            "Zero chance.",           MATCH },
  { "S[a-][x]opho*",            "Saxophone",              MATCH },
  { "S[a-][x]opho*",            "SaXophone",              NOMATCH },
  { "S[a-][x]*.txt",            "S-x.txt",                MATCH },
  { "[\\a-\\b]",                "a",                      MATCH },
  { "[\\a-\\b]",                "b",                      MATCH },
  { "[?*[][?*[][?*[]",          "?*[",                    MATCH },
  { "[][?*-]",                  "]",                      MATCH },
  { "[][?*-]",                  "[",                      MATCH },
  { "[][?*-]",                  "?",                      MATCH },
  { "[][?*-]",                  "*",                      MATCH },
  { "[][?*-]",                  "-",                      MATCH },
  { "[]?*-]",                   "-",                      MATCH },
  { "?/b/c",                    "a/b/c",                  MATCH },
  { "^_{}~",                    "^_{}~",                  MATCH },
  { "!#%+,-./01234567889",      "!#%+,-./01234567889",    MATCH },
  { "PQRSTUVWXYZ]abcdefg",      "PQRSTUVWXYZ]abcdefg",    MATCH },
  { ":;=@ABCDEFGHIJKLMNO",      ":;=@ABCDEFGHIJKLMNO",    MATCH },

  /* negate */
  { "[!a]",                     "b",                      MATCH },
  { "[!a]",                     "a",                      NOMATCH },
  { "[^a]",                     "b",                      MATCH },
  { "[^a]",                     "a",                      NOMATCH },
  { "[^a-z0-9A-Z]",             "a",                      NOMATCH },
  { "[^a-z0-9A-Z]",             "-",                      MATCH },
  { "curl[!a-z]lib",            "curl lib",               MATCH },
  { "curl[! ]lib",              "curl lib",               NOMATCH },
  { "[! ][ ]",                  "  ",                     NOMATCH },
  { "[! ][ ]",                  "a ",                     MATCH },
  { "*[^a].t?t",                "a.txt",                  NOMATCH },
  { "*[^a].t?t",                "ba.txt",                 NOMATCH },
  { "*[^a].t?t",                "ab.txt",                 MATCH },
  { "[!?*[]",                   "?",                      NOMATCH },
  { "[!!]",                     "!",                      NOMATCH },
  { "[!!]",                     "x",                      MATCH },

  { "[[:alpha:]]",              "a",                      MATCH },
  { "[[:alpha:]]",              "9",                      NOMATCH },
  { "[[:alnum:]]",              "a",                      MATCH },
  { "[[:alnum:]]",              "[",                      NOMATCH },
  { "[[:alnum:]]",              "]",                      NOMATCH },
  { "[[:alnum:]]",              "9",                      MATCH },
  { "[[:digit:]]",              "9",                      MATCH },
  { "[[:xdigit:]]",             "9",                      MATCH },
  { "[[:xdigit:]]",             "F",                      MATCH },
  { "[[:xdigit:]]",             "G",                      NOMATCH },
  { "[[:upper:]]",              "U",                      MATCH },
  { "[[:upper:]]",              "u",                      NOMATCH },
  { "[[:lower:]]",              "l",                      MATCH },
  { "[[:lower:]]",              "L",                      NOMATCH },
  { "[[:print:]]",              "L",                      MATCH },
  { "[[:print:]]",              {'\10'},                  NOMATCH },
  { "[[:print:]]",              {'\10'},                  NOMATCH },
  { "[[:space:]]",              " ",                      MATCH },
  { "[[:space:]]",              "x",                      NOMATCH },
  { "[[:graph:]]",              " ",                      NOMATCH },
  { "[[:graph:]]",              "x",                      MATCH },
  { "[[:blank:]]",              {'\t'},                   MATCH },
  { "[[:blank:]]",              {' '},                    MATCH },
  { "[[:blank:]]",              {'\r'},                   NOMATCH },
  { "[^[:blank:]]",             {'\t'},                   NOMATCH },
  { "[^[:print:]]",             {'\10'},                  MATCH },
  { "[[:lower:]][[:lower:]]",   "ll",                     MATCH },

  { "Curl[[:blank:]];-)",       "Curl ;-)",               MATCH },
  { "*[[:blank:]]*",            " ",                      MATCH },
  { "*[[:blank:]]*",            "",                       NOMATCH },
  { "*[[:blank:]]*",            "hi, im_Pavel",           MATCH },

  /* common using */
  { "filename.dat",             "filename.dat",           MATCH },
  { "*curl*",                   "lets use curl!!",        MATCH },
  { "filename.txt",             "filename.dat",           NOMATCH },
  { "*.txt",                    "text.txt",               MATCH },
  { "*.txt",                    "a.txt",                  MATCH },
  { "*.txt",                    ".txt",                   MATCH },
  { "*.txt",                    "txt",                    NOMATCH },
  { "??.txt",                   "99.txt",                 MATCH },
  { "??.txt",                   "a99.txt",                NOMATCH },
  { "?.???",                    "a.txt",                  MATCH },
  { "*.???",                    "somefile.dat",           MATCH },
  { "*.???",                    "photo.jpeg",             NOMATCH },
  { ".*",                       ".htaccess",              MATCH },
  { ".*",                       ".",                      MATCH },
  { ".*",                       "..",                     MATCH },

  /* many stars => one star */
  { "**.txt",                   "text.txt",               MATCH },
  { "***.txt",                  "t.txt",                  MATCH },
  { "****.txt",                 ".txt",                   MATCH },

  /* empty string or pattern */
  { "",                         "",                       MATCH } ,
  { "",                         "hello",                  NOMATCH },
  { "file",                     "",                       NOMATCH  },
  { "?",                        "",                       NOMATCH },
  { "*",                        "",                       MATCH },
  { "x",                        "",                       NOMATCH },

  /* backslash */
  { "\\",                       "\\",                     RE_ERR },
  { "\\\\",                     "\\",                     MATCH },
  { "\\\\",                     "\\\\",                   NOMATCH },
  { "\\?",                      "?",                      MATCH },
  { "\\*",                      "*",                      MATCH },
  { "?.txt",                    "?.txt",                  MATCH },
  { "*.txt",                    "*.txt",                  MATCH },
  { "\\?.txt",                  "?.txt",                  MATCH },
  { "\\*.txt",                  "*.txt",                  MATCH },
  { "\\?.txt",                  "x.txt",                  NOMATCH },
  { "\\*.txt",                  "x.txt",                  NOMATCH },
  { "\\*\\\\.txt",              "*\\.txt",                MATCH },
  { "*\\**\\?*\\\\*",           "cc*cc?cc\\cc*cc",        MATCH },
  { "*\\**\\?*\\\\*",           "cc*cc?cccc",             NOMATCH },
  { "*\\**\\?*\\\\*",           "cc*cc?cc\\cc*cc",        MATCH },
  { "*\\?*\\**",                "cc?c*c",                 MATCH },
  { "*\\?*\\**curl*",           "cc?c*curl",              MATCH },
  { "*\\?*\\**",                "cc?cc",                  NOMATCH },
  { "\\\"\\$\\&\\'\\(\\)",      "\"$&'()",                MATCH },
  { "\\*\\?\\[\\\\\\`\\|",      "*?[\\`|",                MATCH },
  { "[\\a\\b]c",                "ac",                     MATCH },
  { "[\\a\\b]c",                "bc",                     MATCH },
  { "[\\a\\b]d",                "bc",                     NOMATCH },
  { "[a-bA-B\\?]",              "?",                      MATCH },
  { "cu[a-ab-b\\r]l",           "curl",                   MATCH },
  { "[\\a-z]",                  "c",                      MATCH },

  { "?*?*?.*?*",                "abc.c",                  MATCH },
  { "?*?*?.*?*",                "abcc",                   NOMATCH },
  { "?*?*?.*?*",                "abc.",                   NOMATCH },
  { "?*?*?.*?*",                "abc.c++",                MATCH },
  { "?*?*?.*?*",                "abcdef.c++",             MATCH },
  { "?*?*?.?",                  "abcdef.c",               MATCH },
  { "?*?*?.?",                  "abcdef.cd",              NOMATCH },

  { "Lindmätarv",               "Lindmätarv",             MATCH },

  { "",                         "",                       MATCH }
};

static CURLcode unit_setup( void )
{
  return CURLE_OK;
}

static void unit_stop( void )
{
}

UNITTEST_START

  int testnum = sizeof(tests) / sizeof(struct testcase);
  int i, rc;

  for(i = 0; i < testnum; i++) {
    rc = Curl_fnmatch(NULL, tests[i].pattern, tests[i].string);
    if(rc != tests[i].result) {
      printf("Curl_fnmatch(\"%s\", \"%s\") should return %d (returns %d)\n",
             tests[i].pattern, tests[i].string, tests[i].result, rc);
      fail("pattern mismatch");
    }
  }

UNITTEST_STOP
