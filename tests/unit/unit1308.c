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
#include "fetchcheck.h"

#include <fetch/fetch.h>

static FETCHcode unit_setup(void)
{
  return FETCHE_OK;
}

static void unit_stop(void)
{
}

static size_t print_httppost_callback(void *arg, const char *buf, size_t len)
{
  fwrite(buf, len, 1, stdout);
  (*(size_t *)arg) += len;
  return len;
}

UNITTEST_START
FETCHFORMcode rc;
int res;
struct fetch_httppost *post = NULL;
struct fetch_httppost *last = NULL;
size_t total_size = 0;
char buffer[] = "test buffer";

FETCH_IGNORE_DEPRECATION(
    rc = fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "name",
                       FETCHFORM_COPYCONTENTS, "content", FETCHFORM_END);)
fail_unless(rc == 0, "fetch_formadd returned error");

/* after the first fetch_formadd when there's a single entry, both pointers
   should point to the same struct */
fail_unless(post == last, "post and last weren't the same");

FETCH_IGNORE_DEPRECATION(
    rc = fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "htmlcode",
                       FETCHFORM_COPYCONTENTS, "<HTML></HTML>",
                       FETCHFORM_CONTENTTYPE, "text/html", FETCHFORM_END);)
fail_unless(rc == 0, "fetch_formadd returned error");

FETCH_IGNORE_DEPRECATION(
    rc = fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "name_for_ptrcontent",
                       FETCHFORM_PTRCONTENTS, buffer, FETCHFORM_END);)
fail_unless(rc == 0, "fetch_formadd returned error");

FETCH_IGNORE_DEPRECATION(
    res = fetch_formget(post, &total_size, print_httppost_callback);)
fail_unless(res == 0, "fetch_formget returned error");

fail_unless(total_size == 518, "fetch_formget got wrong size back");

FETCH_IGNORE_DEPRECATION(
    fetch_formfree(post);)

/* start a new formpost with a file upload and formget */
post = last = NULL;

FETCH_IGNORE_DEPRECATION(
    rc = fetch_formadd(&post, &last,
                       FETCHFORM_PTRNAME, "name of file field",
                       FETCHFORM_FILE, arg,
                       FETCHFORM_FILENAME, "custom named file",
                       FETCHFORM_END);)
fail_unless(rc == 0, "fetch_formadd returned error");

FETCH_IGNORE_DEPRECATION(
    res = fetch_formget(post, &total_size, print_httppost_callback);)
fail_unless(res == 0, "fetch_formget returned error");
fail_unless(total_size == 899, "fetch_formget got wrong size back");

FETCH_IGNORE_DEPRECATION(
    fetch_formfree(post);)

UNITTEST_STOP
