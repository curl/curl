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
#include "unitcheck.h"
#include "tool_sdecls.h"
#include "tool_urlglob.h"

/* Structure for glob expansion tests */
struct glob_expand_case {
  const char *pattern;
  curl_off_t expected_num;
  const char * const *expected_urls;
};

/* Structure for glob error tests */
struct glob_error_case {
  const char *pattern;
  CURLcode expected_result;
  const char *expected_substr;
  size_t expected_pos;
};

/* Structure for glob_match_url tests */
struct glob_match_case {
  const char *url_glob;
  const char *second_glob;
  const char *match_template;
  const char *expected_output;
  CURLcode expected_result;
};

/* Expected URL lists for expansion tests */
static const char * const exp_set_single[] = {
  "http://example.com/alpha", NULL
};
static const char * const exp_set_basic[] = {
  "http://example.com/a",
  "http://example.com/b",
  "http://example.com/c",
  NULL
};
static const char * const exp_set_words[] = {
  "http://example.com/apple",
  "http://example.com/banana",
  "http://example.com/cherry",
  NULL
};
static const char * const exp_set_empty_tail[] = {
  "http://example.com/a",
  "http://example.com/",
  NULL
};
static const char * const exp_set_empty_head[] = {
  "http://example.com/",
  "http://example.com/b",
  NULL
};
static const char * const exp_set_empty_mid[] = {
  "http://example.com/a",
  "http://example.com/",
  "http://example.com/c",
  NULL
};
static const char * const exp_set_escaped_comma[] = {
  "http://example.com/a,b",
  "http://example.com/c",
  NULL
};
static const char * const exp_set_escaped_brace[] = {
  "http://example.com/a}b",
  "http://example.com/c",
  NULL
};
static const char * const exp_set_escaped_brackets[] = {
  "http://example.com/a[b",
  "http://example.com/c]d",
  NULL
};
static const char * const exp_set_escaped_bs[] = {
  "http://example.com/a\\b",
  "http://example.com/c",
  NULL
};
static const char * const exp_set_named[] = {
  "http://example.com/first",
  "http://example.com/second",
  NULL
};
static const char * const exp_set_adjacent[] = {
  "a1", "a2", "b1", "b2", NULL
};
static const char * const exp_set_triple[] = {
  "ace", "acf", "ade", "adf", "bce", "bcf", "bde", "bdf", NULL
};
static const char * const exp_set_query[] = {
  "http://example.com/test?a=1&b=3",
  "http://example.com/test?a=1&b=4",
  "http://example.com/test?a=2&b=3",
  "http://example.com/test?a=2&b=4",
  NULL
};

static const char * const exp_char_basic[] = {
  "http://example.com/a",
  "http://example.com/b",
  "http://example.com/c",
  NULL
};
static const char * const exp_char_end[] = {
  "http://example.com/x",
  "http://example.com/y",
  "http://example.com/z",
  NULL
};
static const char * const exp_char_single[] = {
  "http://example.com/m",
  NULL
};
static const char * const exp_char_upper[] = {
  "http://example.com/X",
  "http://example.com/Y",
  "http://example.com/Z",
  NULL
};
static const char * const exp_char_step_div[] = {
  "http://example.com/a",
  "http://example.com/c",
  "http://example.com/e",
  "http://example.com/g",
  NULL
};
static const char * const exp_char_step_nondiv[] = {
  "http://example.com/a",
  "http://example.com/c",
  "http://example.com/e",
  NULL
};
static const char * const exp_char_step_span[] = {
  "http://example.com/a",
  "http://example.com/d",
  NULL
};
static const char * const exp_char_named[] = {
  "http://example.com/p",
  "http://example.com/q",
  "http://example.com/r",
  NULL
};
static const char * const exp_char_adjacent[] = {
  "ac", "ad", "bc", "bd", NULL
};

static const char * const exp_num_basic[] = {
  "http://example.com/0",
  "http://example.com/1",
  "http://example.com/2",
  "http://example.com/3",
  NULL
};
static const char * const exp_num_span_digits[] = {
  "http://example.com/8",
  "http://example.com/9",
  "http://example.com/10",
  NULL
};
static const char * const exp_num_span_hundred[] = {
  "http://example.com/99",
  "http://example.com/100",
  "http://example.com/101",
  NULL
};
static const char * const exp_num_single[] = {
  "http://example.com/5",
  NULL
};
static const char * const exp_num_step_div[] = {
  "http://example.com/1",
  "http://example.com/3",
  "http://example.com/5",
  "http://example.com/7",
  "http://example.com/9",
  NULL
};
static const char * const exp_num_step_nondiv[] = {
  "http://example.com/1",
  "http://example.com/3",
  "http://example.com/5",
  "http://example.com/7",
  NULL
};
static const char * const exp_num_step_span[] = {
  "http://example.com/1",
  "http://example.com/5",
  NULL
};
static const char * const exp_num_pad2[] = {
  "http://example.com/01",
  "http://example.com/02",
  "http://example.com/03",
  "http://example.com/04",
  NULL
};
static const char * const exp_num_pad3[] = {
  "http://example.com/001",
  "http://example.com/002",
  "http://example.com/003",
  NULL
};
static const char * const exp_num_pad3_zero[] = {
  "http://example.com/000",
  "http://example.com/001",
  "http://example.com/002",
  NULL
};
static const char * const exp_num_pad_span[] = {
  "http://example.com/08",
  "http://example.com/09",
  "http://example.com/10",
  "http://example.com/11",
  NULL
};
static const char * const exp_num_pad_step[] = {
  "http://example.com/001",
  "http://example.com/004",
  "http://example.com/007",
  NULL
};
static const char * const exp_num_named[] = {
  "http://example.com/01",
  "http://example.com/02",
  NULL
};
static const char * const exp_num_large[] = {
  "http://example.com/10000000000",
  "http://example.com/10000000001",
  "http://example.com/10000000002",
  NULL
};

static const char * const exp_combo_proto_num[] = {
  "http://example.com/1",
  "http://example.com/2",
  "https://example.com/1",
  "https://example.com/2",
  NULL
};
static const char * const exp_combo_set_char_num[] = {
  "http://example.com/cat/a/1.txt",
  "http://example.com/cat/a/2.txt",
  "http://example.com/cat/b/1.txt",
  "http://example.com/cat/b/2.txt",
  "http://example.com/dog/a/1.txt",
  "http://example.com/dog/a/2.txt",
  "http://example.com/dog/b/1.txt",
  "http://example.com/dog/b/2.txt",
  NULL
};
static const char * const exp_combo_no_sep[] = {
  "a1x", "a1y", "a2x", "a2y",
  "b1x", "b1y", "b2x", "b2y",
  NULL
};

static const char * const exp_lit_simple[] = {
  "http://example.com/index.html", NULL
};
static const char * const exp_lit_symbols[] = {
  "http://example.com/foo_bar-123.html", NULL
};
static const char * const exp_lit_ipv6[] = {
  "http://[::1]:8080/path", NULL
};
static const char * const exp_lit_ipv6_full[] = {
  "http://[2001:db8::1]:80/index.html", NULL
};
static const char * const exp_lit_ipv6_glob[] = {
  "http://[::1]/1",
  "http://[::1]/2",
  NULL
};
static const char * const exp_lit_ipv6_set[] = {
  "http://[::1]/a",
  "http://[::1]/b",
  NULL
};
static const char * const exp_lit_empty_brackets[] = {
  "http://example.com/path[]", NULL
};
static const char * const exp_lit_empty_brackets_glob[] = {
  "http://example.com/[]/1",
  "http://example.com/[]/2",
  NULL
};
static const char * const exp_lit_escaped_brackets[] = {
  "http://example.com/[1-2]", NULL
};
static const char * const exp_lit_escaped_braces[] = {
  "http://example.com/{foo,bar}", NULL
};

/* Expansion test cases table */
static const struct glob_expand_case expand_cases[] = {
  /* Sets */
  { "http://example.com/{alpha}", 1, exp_set_single },
  { "http://example.com/{a,b,c}", 3, exp_set_basic },
  { "http://example.com/{apple,banana,cherry}", 3, exp_set_words },
  { "http://example.com/{a,}", 2, exp_set_empty_tail },
  { "http://example.com/{,b}", 2, exp_set_empty_head },
  { "http://example.com/{a,,c}", 3, exp_set_empty_mid },
  { "http://example.com/{a\\,b,c}", 2, exp_set_escaped_comma },
  { "http://example.com/{a\\}b,c}", 2, exp_set_escaped_brace },
  { "http://example.com/{a\\[b,c\\]d}", 2, exp_set_escaped_brackets },
  { "http://example.com/{a\\\\b,c}", 2, exp_set_escaped_bs },
  { "http://example.com/{<name>first,second}", 2, exp_set_named },
  { "{a,b}{1,2}", 4, exp_set_adjacent },
  { "{a,b}{c,d}{e,f}", 8, exp_set_triple },
  { "http://example.com/test?a={1,2}&b={3,4}", 4, exp_set_query },

  /* Character ranges */
  { "http://example.com/[a-c]", 3, exp_char_basic },
  { "http://example.com/[x-z]", 3, exp_char_end },
  { "http://example.com/[m-m]", 1, exp_char_single },
  { "http://example.com/[X-Z]", 3, exp_char_upper },
  { "http://example.com/[a-g:2]", 4, exp_char_step_div },
  { "http://example.com/[a-f:2]", 3, exp_char_step_nondiv },
  { "http://example.com/[a-d:3]", 2, exp_char_step_span },
  { "http://example.com/[<letter>p-r]", 3, exp_char_named },
  { "[a-b][c-d]", 4, exp_char_adjacent },

  /* Numeric ranges */
  { "http://example.com/[0-3]", 4, exp_num_basic },
  { "http://example.com/[8-10]", 3, exp_num_span_digits },
  { "http://example.com/[99-101]", 3, exp_num_span_hundred },
  { "http://example.com/[5-5]", 1, exp_num_single },
  { "http://example.com/[1-9:2]", 5, exp_num_step_div },
  { "http://example.com/[1-8:2]", 4, exp_num_step_nondiv },
  { "http://example.com/[1-5:4]", 2, exp_num_step_span },
  { "http://example.com/[01-04]", 4, exp_num_pad2 },
  { "http://example.com/[001-003]", 3, exp_num_pad3 },
  { "http://example.com/[000-002]", 3, exp_num_pad3_zero },
  { "http://example.com/[08-11]", 4, exp_num_pad_span },
  { "http://example.com/[001-007:3]", 3, exp_num_pad_step },
  { "http://example.com/[<num>01-02]", 2, exp_num_named },
  { "http://example.com/[10000000000-10000000002]", 3, exp_num_large },

  /* Combinations */
  { "{http,https}://example.com/[1-2]", 4, exp_combo_proto_num },
  { "http://example.com/{cat,dog}/[a-b]/[1-2].txt", 8,
    exp_combo_set_char_num },
  { "{a,b}[1-2]{x,y}", 8, exp_combo_no_sep },

  /* Literals, IPv6, Escaped characters */
  { "http://example.com/index.html", 1, exp_lit_simple },
  { "http://example.com/foo_bar-123.html", 1, exp_lit_symbols },
  { "http://[::1]:8080/path", 1, exp_lit_ipv6 },
  { "http://[2001:db8::1]:80/index.html", 1, exp_lit_ipv6_full },
  { "http://[::1]/[1-2]", 2, exp_lit_ipv6_glob },
  { "http://[::1]/{a,b}", 2, exp_lit_ipv6_set },
  { "http://example.com/path[]", 1, exp_lit_empty_brackets },
  { "http://example.com/[]/[1-2]", 2, exp_lit_empty_brackets_glob },
  { "http://example.com/\\[1-2\\]", 1, exp_lit_escaped_brackets },
  { "http://example.com/\\{foo,bar\\}", 1, exp_lit_escaped_braces }
};

/* Error test cases table */
static const struct glob_error_case error_cases[] = {
  /* Set errors */
  { "http://example.com/{a,b", CURLE_URL_MALFORMAT, "unmatched brace", 24 },
  { "http://example.com/{}", CURLE_URL_MALFORMAT,
    "empty string within braces", 21 },
  { "http://example.com/{a,{b,c}}", CURLE_URL_MALFORMAT, "nested brace", 23 },
  { "http://example.com/{a,[1-2]}", CURLE_URL_MALFORMAT, "nested brace", 23 },
  { "http://example.com/{a,b]}", CURLE_URL_MALFORMAT,
    "unexpected close bracket", 24 },
  { "http://example.com/a}b", CURLE_URL_MALFORMAT,
    "unmatched close brace/bracket", 21 },
  { "http://example.com/a]b", CURLE_URL_MALFORMAT,
    "unmatched close brace/bracket", 21 },

  /* Character range errors */
  { "http://example.com/[1-10", CURLE_URL_MALFORMAT, "bad range", 25 },
  { "http://example.com/[a-", CURLE_URL_MALFORMAT, "bad range", 21 },
  { "http://example.com/[a-c", CURLE_URL_MALFORMAT, "bad range", 21 },
  { "http://example.com/[z-a]", CURLE_URL_MALFORMAT, "bad range", 25 },
  { "http://example.com/[a-Z]", CURLE_URL_MALFORMAT, "bad range", 25 },
  { "http://example.com/[A-z]", CURLE_URL_MALFORMAT, "bad range", 25 },
  { "http://example.com/[a-z:0]", CURLE_URL_MALFORMAT, "bad range", 27 },
  { "http://example.com/[a-c:5]", CURLE_URL_MALFORMAT, "bad range", 27 },
  { "http://example.com/[b-b:2]", CURLE_URL_MALFORMAT, "bad range", 27 },

  /* Numeric range errors */
  { "http://example.com/[10-1]", CURLE_URL_MALFORMAT, "bad range", 26 },
  { "http://example.com/[1-10:0]", CURLE_URL_MALFORMAT, "bad range", 28 },
  { "http://example.com/[1-5:10]", CURLE_URL_MALFORMAT, "bad range", 28 },
  { "http://example.com/[3-3:2]", CURLE_URL_MALFORMAT, "bad range", 27 },
  { "http://example.com/[!-~]", CURLE_URL_MALFORMAT,
    "bad range specification", 21 },
  { "http://example.com/[#-&]", CURLE_URL_MALFORMAT,
    "bad range specification", 21 },

  /* Named glob errors */
  { "http://example.com/{<id>a,b}/[<id>1-2]", CURLE_URL_MALFORMAT,
    "Duplicate glob name", 34 },
  { "http://example.com/{<x>a,b}/{<x>c,d}", CURLE_URL_MALFORMAT,
    "Duplicate glob name", 32 },
  { "http://example.com/[<n>1-2]/[<n>3-4]", CURLE_URL_MALFORMAT,
    "Duplicate glob name", 32 }
};

/* glob_match_url test cases table */
static const struct glob_match_case match_cases[] = {
  /* Numbered references */
  { "http://example.com/{alpha,beta}", NULL,
    "out_#1.txt", "out_alpha.txt", CURLE_OK },
  { "http://example.com/{first,second}/[01-02]", NULL,
    "#1-#2.log", "first-01.log", CURLE_OK },
  { "http://example.com/{a,b}/[1-2]/[x-y]", NULL,
    "#1_#2_#3", "a_1_x", CURLE_OK },
  { "http://example.com/{foo,bar}", NULL,
    "file_#2.txt", "file_#2.txt", CURLE_OK },
  { "http://example.com/{foo,bar}", NULL,
    "file_#99.txt", "file_#99.txt", CURLE_OK },
  { "http://example.com/{foo,bar}", NULL,
    "file_#0.txt", "file_#0.txt", CURLE_OK },
  { "http://example.com/{alpha,beta}", NULL,
    "file##1", "file#alpha", CURLE_OK },
  { "http://example.com/{alpha,beta}", NULL,
    "file#_#1", "file#_alpha", CURLE_OK },
  { "http://example.com/{alpha,beta}", NULL,
    "file#", "file#", CURLE_OK },

  /* Named references */
  { "http://example.com/{<animal>cat,dog}", NULL,
    "pet_#<animal>.png", "pet_cat.png", CURLE_OK },
  { "http://example.com/{<user>alice,bob}/[<id>10-11]", NULL,
    "user_#<user>_id_#<id>.json", "user_alice_id_10.json", CURLE_OK },
  { "http://example.com/{<name>a,b}", NULL,
    "file_#<nonexistent>.txt", NULL, CURLE_BAD_FUNCTION_ARGUMENT },
  { "http://example.com/{<name>a,b}", NULL,
#if defined(_WIN32) || defined(MSDOS)
    /* On Windows and MS-DOS, glob_match_url() passes successful output
       through sanitize_file_name(), which replaces < with _. */
    "#<unclosed", "#_unclosed", CURLE_OK },
#else
    "#<unclosed", "#<unclosed", CURLE_OK },
#endif
  /* Two globs */
  { "http://example.com/{<site>siteA,siteB}", "[<part>1-2]",
    "dump_#<site>_#<part>.tar", "dump_siteA_1.tar", CURLE_OK },
  { "http://example.com/{<site>siteA,siteB}", "[<part>1-2]",
    "part_#<part>.bin", "part_1.bin", CURLE_OK },

  /* Literal URL without globbing */
  { "http://example.com/page.html", NULL,
    "saved_#1.html", "saved_#1.html", CURLE_OK }
};

static CURLcode test_tool2155(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  size_t i;

  /* Part 1: Test valid expansions and next_url enumeration */
  for(i = 0; i < CURL_ARRAYSIZE(expand_cases); i++) {
    const struct glob_expand_case *tc = &expand_cases[i];
    struct URLGlob glob;
    curl_off_t num = 0;
    CURLcode result = glob_url(&glob, tc->pattern, &num, NULL);

    if(result) {
      curl_mprintf("glob_url failed for '%s' with result %d\n",
                   tc->pattern, (int)result);
      fail("glob_url unexpectedly failed");
      glob_cleanup(&glob);
      continue;
    }

    if(num != tc->expected_num) {
      curl_mprintf("Expected %" FMT_OFF_T " urls, got %" FMT_OFF_T
                   " for '%s'\n", tc->expected_num, num, tc->pattern);
      fail("Incorrect expansion count");
    }

    if(glob_is_literal(&glob)) {
      if(tc->expected_num != 1 ||
         strcmp(tc->expected_urls[0], tc->pattern) != 0) {
        curl_mprintf("Literal URL mismatch: expected '%s', pattern '%s'\n",
                     tc->expected_urls[0], tc->pattern);
        fail("Literal URL content mismatch");
      }
    }
    else {
      curl_off_t count = 0;
      char *url = NULL;

      do {
        result = glob_next_url(&url, &glob);
        if(result || !url)
          break;
        if(!tc->expected_urls[count]) {
          curl_mprintf("Unexpected extra URL '%s' at index %" FMT_OFF_T
                       " for '%s'\n", url, count, tc->pattern);
          fail("Extra URL generated");
          curlx_safefree(url);
          break;
        }

        if(strcmp(url, tc->expected_urls[count]) != 0) {
          curl_mprintf("URL mismatch at index %" FMT_OFF_T
                       " for '%s': expected '%s', got '%s'\n",
                       count, tc->pattern, tc->expected_urls[count], url);
          fail("URL string mismatch");
        }

        curlx_safefree(url);
        count++;
      } while(1);

      if(result) {
        curl_mprintf("glob_next_url failed for '%s' with %d\n",
                     tc->pattern, (int)result);
        fail("glob_next_url failed");
      }

      if(count != tc->expected_num) {
        curl_mprintf("Generated %" FMT_OFF_T " URLs, expected %" FMT_OFF_T
                     " for '%s'\n", count, tc->expected_num, tc->pattern);
        fail("Generated URL count mismatch");
      }
    }

    /* Verification of state flags */
    if(!glob_inuse(&glob))
      fail("glob_inuse should be true before cleanup");

    glob_cleanup(&glob);

    if(glob_inuse(&glob))
      fail("glob_inuse should be false after cleanup");
    if(glob_is_literal(&glob))
      fail("glob_is_literal should be false after cleanup");
  }

  /* Part 2: Test malformed syntax and error reporting */
  for(i = 0; i < CURL_ARRAYSIZE(error_cases); i++) {
    const struct glob_error_case *tc = &error_cases[i];
    struct URLGlob glob;
    curl_off_t num = 0;
    CURLcode result = glob_url(&glob, tc->pattern, &num, NULL);

    if(result != tc->expected_result) {
      curl_mprintf("Expected error %d, got %d for '%s'\n",
                   (int)tc->expected_result, (int)result, tc->pattern);
      fail("Did not get expected error code");
    }

    if(glob.error) {
      if(!strstr(glob.error, tc->expected_substr)) {
        curl_mprintf("Expected error message containing '%s', got '%s'"
                     " for '%s'\n",
                     tc->expected_substr, glob.error, tc->pattern);
        fail("Error message substring mismatch");
      }
    }
    else {
      curl_mprintf("glob.error is NULL for '%s'\n", tc->pattern);
      fail("Expected non-NULL glob.error");
    }

    if(tc->expected_pos && (glob.pos != tc->expected_pos)) {
      curl_mprintf("Expected error pos %zu, got %zu for '%s'\n",
                   tc->expected_pos, glob.pos, tc->pattern);
      fail("Error position mismatch");
    }

    glob_cleanup(&glob);
  }

  /* Part 3: Test glob_match_url output pattern replacement */
  for(i = 0; i < CURL_ARRAYSIZE(match_cases); i++) {
    const struct glob_match_case *tc = &match_cases[i];
    struct URLGlob glob;
    struct URLGlob glob2;
    struct URLGlob *g2_ptr = NULL;
    curl_off_t num = 0;
    char *output = NULL;
    SANITIZEcode sc;
    CURLcode result;

    result = glob_url(&glob, tc->url_glob, &num, NULL);
    if(result) {
      curl_mprintf("glob_url failed for match test url_glob '%s'\n",
                   tc->url_glob);
      fail("match_test glob_url failed");
      glob_cleanup(&glob);
      continue;
    }

    if(tc->second_glob) {
      result = glob_url(&glob2, tc->second_glob, &num, NULL);
      if(result) {
        curl_mprintf("glob_url failed for match test second_glob '%s'\n",
                     tc->second_glob);
        fail("match_test second_glob glob_url failed");
        glob_cleanup(&glob);
        glob_cleanup(&glob2);
        continue;
      }
      g2_ptr = &glob2;
    }

    result = glob_match_url(&output, tc->match_template, &glob, g2_ptr, &sc);

    if(result != tc->expected_result) {
      curl_mprintf("glob_match_url returned %d, expected %d for '%s'\n",
                   (int)result, (int)tc->expected_result, tc->match_template);
      fail("glob_match_url result mismatch");
    }

    if(!result && tc->expected_output) {
      if(!output || (strcmp(output, tc->expected_output) != 0)) {
        curl_mprintf("glob_match_url output mismatch for '%s':"
                     " expected '%s', got '%s'\n",
                     tc->match_template, tc->expected_output,
                     output ? output : "(null)");
        fail("glob_match_url output string mismatch");
      }
    }

    curlx_safefree(output);
    glob_cleanup(&glob);
    if(g2_ptr)
      glob_cleanup(&glob2);
  }

  /* Part 4: Test glob_match_url across iterations of glob_next_url */
  {
    struct URLGlob glob;
    curl_off_t num = 0;
    static const char * const expected_matches[] = {
      "first-01.log",
      "first-02.log",
      "second-01.log",
      "second-02.log"
    };
    size_t step = 0;
    char *url = NULL;

    CURLcode result =
      glob_url(&glob, "http://example.com/{first,second}/[01-02]", &num, NULL);
    fail_unless(!result, "glob_url failed for step matching");
    fail_unless(num == 4, "step matching count should be 4");

    do {
      char *output = NULL;
      SANITIZEcode sc;
      CURLcode mres;

      result = glob_next_url(&url, &glob);
      if(result || !url)
        break;

      mres = glob_match_url(&output, "#1-#2.log", &glob, NULL, &sc);

      fail_unless(!mres, "glob_match_url failed in loop");
      if(output && (step < CURL_ARRAYSIZE(expected_matches))) {
        if(strcmp(output, expected_matches[step]) != 0) {
          curl_mprintf("Iterative match step %zu: expected '%s', got '%s'\n",
                       step, expected_matches[step], output);
          fail("Iterative match mismatch");
        }
      }
      else {
        fail("Iterative match output NULL or out of bounds");
      }

      curlx_safefree(output);
      curlx_safefree(url);
      step++;
    } while(1);

    fail_unless(step == 4, "Should have stepped exactly 4 times");
    glob_cleanup(&glob);
  }

  /* Part 5: Test glob_cleanup idempotency and initial state */
  {
    struct URLGlob glob;
    memset(&glob, 0, sizeof(glob));

    fail_unless(!glob_inuse(&glob), "zeroed glob should not be in use");
    fail_unless(!glob_is_literal(&glob),
                "zeroed glob should not be literal");

    /* Multiple cleanups on uninitialized/zeroed struct must not crash */
    glob_cleanup(&glob);
    glob_cleanup(&glob);

    fail_unless(!glob_inuse(&glob), "glob should not be in use after cleanup");
  }

  UNITTEST_END_SIMPLE
}
