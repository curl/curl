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

#ifndef CURL_DISABLE_HTTP

#include "urldata.h"
#include "url.h"

struct check1626 {
  const char *in; /* send this in */
  const char *out; /* expect this out */
};

static CURLcode test_unit1626(const char *arg)
{
  size_t i;
  static const struct check1626 list[] = {
    /* basic */
    { "Header: value", "value" },
    /* no space */
    { "Header:value", "value" },
    /* multiple spaces */
    { "Header:    value", "value" },
    /* tabs */
    { "Header: \tvalue", "value" },
    /* trailing space */
    { "Header: value  ", "value" },
    /* leading and trailing spaces */
    { "Header:    value   ", "value" },
    /* nothing after colon */
    { "Header:", "" },
    /* spaces-only after colon */
    { "Header:  ", "" },
    /* spaces and tabs after colon */
    { "Header: \t ", "" },
    /* spaces in the value */
    { "Header: one two", "one two" },
    /* multiple spaces in the value */
    { "Header: one two a b c ", "one two a b c" },
    /* realistic */
    { "Header: text/html", "text/html" },
    /* ending with CR */
    { "Header: value\r", "value" },
    /* ending with LF */
    { "Header: value\n", "value" },
    /* quoted value */
    { "Header: \"value\"\n", "\"value\"" },
    /* quoted value with trailing space */
    { "Header: \"value\"  ", "\"value\"" },
    /* leading whitespace before header name */
    { " Header: value", "value" },
    /* tab before colon */
    { "Header\t: value", "value" },
    /* mixed whitespace after colon */
    { "Header:\t  value", "value" },
    /* value containing colon */
    { "Header: foo:bar", "foo:bar" },
    /* multiple colons */
    { "Header: foo:bar:baz", "foo:bar:baz" },
    /* tab-only value */
    { "Header:\t\t", "" },
    /* CRLF ending */
    { "Header: value\r\n", "value" },
    /* value with internal tabs */
    { "Header: foo\tbar", "foo\tbar" },
    /* value with leading tab trimmed */
    { "Header:\tfoo", "foo" },
    /* colon with spaces before it */
    { "Header : value", "value" },
    /* multiple spaces before colon */
    { "Header    : value", "value" },
    /* spaces around colon */
    { "Header :    value", "value" },
  };

  (void)arg;

  for(i = 0; i < CURL_ARRAYSIZE(list); i++) {
    bool ok;
    char *get = Curl_copy_header_value(list[i].in);

    ok = get && !strcmp(list[i].out, get);
    if(!ok) {
      curl_mprintf("Input: %s\n"
                   "Got: %s\n"
                   "Expected: %s\n",
                   list[i].in, get, list[i].out);
    }
    curlx_free(get);
    if(!ok)
      break;
  }

  curl_mprintf("%zu invokes\n", i);

  if(i != CURL_ARRAYSIZE(list))
    return CURLE_FAILED_INIT;

  return CURLE_OK;
}
#else
/* for HTTP-disabled builds */
static CURLcode test_unit1626(const char *arg)
{
  (void)arg;
  return CURLE_OK;
}
#endif
