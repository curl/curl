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

#include "urldata.h"
#include "url.h" /* for Curl_safefree */
#include "memdebug.h" /* LAST include file */

struct etest {
  const char *input;
  size_t ilen;
  const char *output;
  size_t olen;
};

static CURLcode test_unit1302(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  CURLcode rc;
  unsigned int i;

  /* common base64 encoding */
  struct etest encode[] = {
    {"iiiiii", 1, "aQ==", 4 },
    {"iiiiii", 2, "aWk=", 4 },
    {"iiiiii", 3, "aWlp", 4 },
    {"iiiiii", 4, "aWlpaQ==", 8 },
    {"iiiiii", 5, "aWlpaWk=", 8 },
    {"iiiiii", 6, "aWlpaWlp", 8 },
    {"iiiiiii", 7, "aWlpaWlpaQ==", 12 },
    {"iiiiiiii", 8, "aWlpaWlpaWk=", 12 },
    {"iiiiiiiii", 9, "aWlpaWlpaWlp", 12 },
    {"iiiiiiiiii", 10, "aWlpaWlpaWlpaQ==", 16 },
    {"iiiiiiiiiii", 11, "aWlpaWlpaWlpaWk=", 16 },
    {"iiiiiiiiiiii", 12, "aWlpaWlpaWlpaWlp", 16 },
    {"\xff\x01\xfe\x02", 4, "/wH+Ag==", 8 },
    {"\xff\xff\xff\xff", 4, "/////w==", 8 },
    {"\x00\x00\x00\x00", 4, "AAAAAA==", 8 },
    {"\x00\x00\x00\x00", 1, "AA==", 4 },
  };

  /* base64 URL encoding */
  struct etest url[] = {
    {"", 0, "", 0 },
    {"iiiiiiiiiii", 1, "aQ", 2 },
    {"iiiiiiiiiii", 2, "aWk", 3 },
    {"iiiiiiiiiii", 3, "aWlp", 4 },
    {"iiiiiiiiiii", 4, "aWlpaQ", 6 },
    {"iiiiiiiiiii", 5, "aWlpaWk", 7 },
    {"iiiiiiiiiii", 6, "aWlpaWlp", 8 },
    {"iiiiiiiiiii", 7, "aWlpaWlpaQ", 10 },
    {"iiiiiiiiiii", 8, "aWlpaWlpaWk", 11 },
    {"iiiiiiiiiii", 9, "aWlpaWlpaWlp", 12 },
    {"iiiiiiiiiii", 10, "aWlpaWlpaWlpaQ", 14 },
    {"iiiiiiiiiii", 11, "aWlpaWlpaWlpaWk", 15 },
    {"iiiiiiiiiiii", 12, "aWlpaWlpaWlpaWlp", 16 },
    {"\xff\x01\xfe\x02", 4, "_wH-Ag", 6 },
    {"\xff\xff\xff\xff", 4, "_____w", 6 },
    {"\xff\x00\xff\x00", 4, "_wD_AA", 6 },
    {"\x00\xff\x00\xff", 4, "AP8A_w", 6 },
    {"\x00\x00\x00\x00", 4, "AAAAAA", 6 },
    {"\x00", 1, "AA", 2 },
    {"\x01", 1, "AQ", 2 },
    {"\x02", 1, "Ag", 2 },
    {"\x03", 1, "Aw", 2 },
    {"\x04", 1, "BA", 2 }, /* spellchecker:disable-line */
    {"\x05", 1, "BQ", 2 },
    {"\x06", 1, "Bg", 2 },
    {"\x07", 1, "Bw", 2 },
    {"\x08", 1, "CA", 2 },
    {"\x09", 1, "CQ", 2 },
    {"\x0a", 1, "Cg", 2 },
    {"\x0b", 1, "Cw", 2 },
    {"\x0c", 1, "DA", 2 },
    {"\x0d", 1, "DQ", 2 },
    {"\x0e", 1, "Dg", 2 },
    {"\x0f", 1, "Dw", 2 },
    {"\x10", 1, "EA", 2 },
  };

  /* bad decode inputs */
  struct etest badecode[] = {
    {"", 0, "", 0 }, /* no dats means error */
    {"", 0, "a", 1 }, /* data is too short */
    {"", 0, "aQ", 2 }, /* data is too short */
    {"", 0, "aQ=", 3 }, /* data is too short */
    {"", 0, "====", 1 }, /* data is only padding characters */
    {"", 0, "====", 2 }, /* data is only padding characters */
    {"", 0, "====", 3 }, /* data is only padding characters */
    {"", 0, "====", 4 }, /* data is only padding characters */
    {"", 0, "a===", 4 }, /* contains three padding characters */
    {"", 0, "a=Q=", 4 }, /* contains a padding character mid input */
    {"", 0, "aWlpa=Q=", 8 }, /* contains a padding character mid input */
    {"", 0, "a\x1f==", 4 }, /* contains illegal base64 character */
    {"", 0, "abcd ", 5 }, /* contains illegal base64 character */
    {"", 0, "abcd  ", 6 }, /* contains illegal base64 character */
    {"", 0, " abcd", 5 }, /* contains illegal base64 character */
    {"", 0, "_abcd", 5 }, /* contains illegal base64 character */
    {"", 0, "abcd-", 5 }, /* contains illegal base64 character */
    {"", 0, "abcd_", 5 }, /* contains illegal base64 character */
    {"", 0, "aWlpaWlpaQ==-", 17}, /* bad character after padding */
    {"", 0, "aWlpaWlpaQ==_", 17}, /* bad character after padding */
    {"", 0, "aWlpaWlpaQ== ", 17}, /* bad character after padding */
    {"", 0, "aWlpaWlpaQ=", 15} /* unaligned size, missing a padding char */
  };

  for(i = 0 ; i < CURL_ARRAYSIZE(encode); i++) {
    struct etest *e = &encode[i];
    char *out;
    unsigned char *decoded;
    size_t olen;
    size_t dlen;

    /* first encode */
    rc = curlx_base64_encode(e->input, e->ilen, &out, &olen);
    abort_unless(rc == CURLE_OK, "return code should be CURLE_OK");
    abort_unless(olen == e->olen, "wrong output size");
    if(memcmp(out, e->output, e->olen)) {
      fprintf(stderr, "Test %u encoded badly\n", i);
      unitfail++;
    }
    Curl_safefree(out);

    /* then verify decode */
    rc = curlx_base64_decode(e->output, &decoded, &dlen);
    if(rc != CURLE_OK) {
      fprintf(stderr, "Test %u URL decode returned %d\n", i, (int)rc);
      unitfail++;
    }
    if(dlen != e->ilen) {
      fprintf(stderr, "Test %u URL decode output length %d instead of %d\n",
              i, (int)dlen, (int)e->ilen);
      unitfail++;
    }
    if(memcmp(decoded, e->input, dlen)) {
      fprintf(stderr, "Test %u URL decoded badly. Got '%s', expected '%s'\n",
              i, decoded, e->input);
      unitfail++;
    }

    Curl_safefree(decoded);
  }

  for(i = 0 ; i < CURL_ARRAYSIZE(url); i++) {
    struct etest *e = &url[i];
    char *out;
    size_t olen;
    rc = curlx_base64url_encode(e->input, e->ilen, &out, &olen);
    abort_unless(rc == CURLE_OK, "return code should be CURLE_OK");
    if(olen != e->olen) {
      fprintf(stderr, "Test %u URL encoded output length %d instead of %d\n",
              i, (int)olen, (int)e->olen);
    }
    if(memcmp(out, e->output, e->olen)) {
      fprintf(stderr, "Test %u URL encoded badly. Got '%s', expected '%s'\n",
              i, out, e->output);
      unitfail++;
    }
    Curl_safefree(out);
  }

  for(i = 0 ; i < CURL_ARRAYSIZE(badecode); i++) {
    struct etest *e = &badecode[i];
    unsigned char *decoded;
    size_t dlen;

    /* then verify decode with illegal inputs */
    rc = curlx_base64_decode(e->output, &decoded, &dlen);
    if(rc != CURLE_BAD_CONTENT_ENCODING) {
      fprintf(stderr, "Test %u URL bad decoded badly. "
              "Returned '%d', expected '%d'\n",
              i, (int)rc, CURLE_BAD_CONTENT_ENCODING);
      unitfail++;
    }
  }

  UNITTEST_END_SIMPLE
}
