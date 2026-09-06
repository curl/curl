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

#if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_ALTSVC) || \
  !defined(CURL_DISABLE_HSTS)

#include "urldata.h"
#include "curl_fopen.h"

#define ORIGCONTENT "ORIGINAL CONTENT, DO NOT TOUCH\n"

static bool checkcontent(const char *file, const char *expect)
{
  char buf[128];
  size_t n;
  FILE *f = curlx_fopen(file, FOPEN_READTEXT);
  if(!f)
    return FALSE;
  n = fread(buf, 1, sizeof(buf) - 1, f);
  curlx_fclose(f);
  buf[n] = '\0';
  return !strcmp(buf, expect);
}

static CURLcode test_unit1696(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  CURL *easy;
  FILE *fh;
  char *tempname;
  CURLcode result;
  FILE *f;

  curl_global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  abort_unless(easy, "curl_easy_init() failed");

  /* Case 1: an existing regular file must never be modified by the mere
     act of calling Curl_fopen(), before the caller has written new
     content and renamed a temp file into its place. This is a
     regression test for curl issue #21610: commit 0c667188e0 made
     Curl_fopen() open the destination with "w" purely to probe its
     type, which truncated it immediately no matter what happened
     afterwards (e.g. the temp file creation or the rename failing). */
  f = curlx_fopen(arg, FOPEN_WRITETEXT);
  abort_unless(f, "failed to create the pre-existing test file");
  fputs(ORIGCONTENT, f);
  curlx_fclose(f);

  tempname = NULL;
  fh = NULL;
  result = Curl_fopen(easy, arg, &fh, &tempname);
  fail_unless(result == CURLE_OK, "Curl_fopen() failed on an existing file");
  fail_unless(tempname != NULL,
              "an existing regular file must go through the "
              "temp-file-plus-rename path");
  fail_unless(checkcontent(arg, ORIGCONTENT),
              "Curl_fopen() modified the pre-existing file");
  if(fh)
    curlx_fclose(fh);
  if(tempname) {
    unlink(tempname);
    curlx_free(tempname);
  }

#ifndef _WIN32
  /* Case 2: same invariant, but the destination path is a symlink
     pointing at a regular file elsewhere. The symlink's target must
     not be truncated either (the second half of #21610: fopen()
     follows symlinks, so probing the type by opening the path for
     writing truncated the linked-to file, not just the link). */
  {
    char linkname[256];
    curl_msnprintf(linkname, sizeof(linkname), "%s.link", arg);
    unlink(linkname);
    if(symlink(arg, linkname))
      fail("symlink() setup failed");
    else {
      tempname = NULL;
      fh = NULL;
      result = Curl_fopen(easy, linkname, &fh, &tempname);
      fail_unless(result == CURLE_OK,
                  "Curl_fopen() failed on a symlink to an existing file");
      fail_unless(tempname != NULL,
                  "a symlink to an existing regular file must go "
                  "through the temp-file-plus-rename path");
      fail_unless(checkcontent(arg, ORIGCONTENT),
                  "Curl_fopen() truncated the symlink target file");
      if(fh)
        curlx_fclose(fh);
      if(tempname) {
        unlink(tempname);
        curlx_free(tempname);
      }
      unlink(linkname);
    }
  }

#ifdef HAVE_GETEUID
  /* Case 3: a write-protected (but otherwise ordinary) existing regular
     file cannot be opened directly to probe its type, yet must still be
     recognized as an existing regular file (via a stat() fallback) so
     the rename dance -- which only needs permission on the directory,
     not the file -- can still replace it, matching the pre-#0c667188e0
     behavior. Skipped when running as root, since permission bits are
     not enforced against the file owner in that case. */
  if(geteuid()) {
    char ro[256];
    curl_msnprintf(ro, sizeof(ro), "%s.ro", arg);
    f = curlx_fopen(ro, FOPEN_WRITETEXT);
    abort_unless(f, "failed to create the read-only test file");
    fputs(ORIGCONTENT, f);
    curlx_fclose(f);
    fail_unless(!chmod(ro, 0400), "chmod 0400 failed");

    tempname = NULL;
    fh = NULL;
    result = Curl_fopen(easy, ro, &fh, &tempname);
    fail_unless(result == CURLE_OK,
                "Curl_fopen() failed on a write-protected existing file");
    fail_unless(tempname != NULL,
                "a write-protected existing regular file must still go "
                "through the temp-file-plus-rename path");
    fail_unless(checkcontent(ro, ORIGCONTENT),
                "Curl_fopen() modified the write-protected file");
    if(fh)
      curlx_fclose(fh);
    if(tempname) {
      unlink(tempname);
      curlx_free(tempname);
    }
    chmod(ro, 0600);
    unlink(ro);
  }
#endif
#endif /* !_WIN32 */

  curl_easy_cleanup(easy);
  if(!unitfail)
    curl_mprintf("OK\n");

  UNITTEST_END(curl_global_cleanup())
}
#else
static CURLcode test_unit1696(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  (void)arg;
  puts("nothing to do when cookies, alt-svc and HSTS are all disabled");
  UNITTEST_END_SIMPLE
}
#endif
