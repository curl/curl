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

static void write_unit1679(const char *file, const char *content)
{
  FILE *f = curlx_fopen(file, FOPEN_WRITETEXT);
  if(f) {
    fputs(content, f);
    curlx_fclose(f);
  }
}

/* return TRUE if the file holds exactly the given content */
static bool check_unit1679(const char *file, const char *content)
{
  char buf[80];
  size_t nread;
  FILE *f = curlx_fopen(file, FOPEN_READTEXT);
  if(!f)
    return FALSE;
  nread = fread(buf, 1, sizeof(buf) - 1, f);
  curlx_fclose(f);
  buf[nread] = '\0';
  return !strcmp(buf, content);
}

/* Curl_fopen() writes to a temp file, so an existing file at the target
   name keeps its content until the temp file is renamed into place. */
static CURLcode test_unit1679(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  CURL *easy;
  FILE *fh = NULL;
  char *tempname = NULL;
  CURLcode result;
  char file[256];
  static const char before[] = "original file content\n";
  static const char after[] = "new file content\n";

  curl_global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  abort_unless(easy, "curl_easy_init()");

  curl_msnprintf(file, sizeof(file), "%s.txt", arg);

  /* write to an existing file: it must keep its content until the temp
     file replaces it in the rename */
  write_unit1679(file, before);
  result = Curl_fopen(easy, file, &fh, &tempname);
  fail_unless(!result && fh, "Curl_fopen() on an existing file");
  if(!result && fh) {
    fail_unless(check_unit1679(file, before), "original file was clobbered");
    fputs(after, fh);
    curlx_fclose(fh);
    fh = NULL;
    fail_unless(tempname, "no temp file name was returned");
    if(tempname) {
      fail_unless(!curlx_rename(tempname, file), "rename to target failed");
      fail_unless(check_unit1679(file, after), "bad content after rename");
      curlx_safefree(tempname);
    }
  }

#ifndef _WIN32
  {
    /* writing via a symlink must not touch the link target, the rename
       replaces the symlink itself */
    char slink[256];
    const char *base = strrchr(file, '/');
    base = base ? base + 1 : file;
    curl_msnprintf(slink, sizeof(slink), "%s.link", arg);
    write_unit1679(file, before);
    unlink(slink);
    /* the link sits in the same directory as the target file */
    if(!symlink(base, slink)) {
      result = Curl_fopen(easy, slink, &fh, &tempname);
      fail_unless(!result && fh, "Curl_fopen() on a symlink");
      if(!result && fh) {
        fail_unless(check_unit1679(file, before),
                    "symlink target was clobbered");
        fputs(after, fh);
        curlx_fclose(fh);
        fh = NULL;
        if(tempname) {
          fail_unless(!curlx_rename(tempname, slink),
                      "rename to symlink failed");
          fail_unless(check_unit1679(file, before),
                      "symlink target was overwritten");
          fail_unless(check_unit1679(slink, after),
                      "bad content after rename");
          curlx_safefree(tempname);
        }
      }
    }
  }
  {
    /* failing to create the temp file must not hurt the original file */
    char dir[256];
    char rofile[512];
    int dfd;
    curl_msnprintf(dir, sizeof(dir), "%s.dir", arg);
    if(!mkdir(dir, 0700)) {
      dfd = curlx_open(dir, O_RDONLY);
      curl_msnprintf(rofile, sizeof(rofile), "%s/target.txt", dir);
      write_unit1679(rofile, before);
      if(dfd != -1 && !fchmod(dfd, 0500)) {
        /* the open fails unless running privileged, but either way the
           original file content must remain untouched */
        result = Curl_fopen(easy, rofile, &fh, &tempname);
        fail_unless(check_unit1679(rofile, before),
                    "original file was clobbered in the failure path");
        if(!result && fh) {
          curlx_fclose(fh);
          fh = NULL;
          if(tempname)
            unlink(tempname);
          curlx_safefree(tempname);
        }
        fchmod(dfd, 0700);
      }
      if(dfd != -1)
        curlx_close(dfd);
    }
  }
  {
    /* a missing file gets created and written to directly */
    char newf[256];
    curl_msnprintf(newf, sizeof(newf), "%s.new", arg);
    unlink(newf);
    result = Curl_fopen(easy, newf, &fh, &tempname);
    fail_unless(!result && fh, "Curl_fopen() creating a missing file");
    if(!result && fh) {
      fputs(after, fh);
      curlx_fclose(fh);
      fh = NULL;
      if(tempname)
        fail_unless(!curlx_rename(tempname, newf), "rename failed");
      curlx_safefree(tempname);
      fail_unless(check_unit1679(newf, after), "bad content in new file");
    }
  }
  {
    /* a file lacking write permission is still replaced via the temp
       file, as long as the directory allows it */
    int ffd;
    write_unit1679(file, before);
    ffd = curlx_open(file, O_RDONLY);
    if(ffd != -1) {
      if(!fchmod(ffd, 0400)) {
        result = Curl_fopen(easy, file, &fh, &tempname);
        fail_unless(!result && fh, "Curl_fopen() on a write-protected file");
        if(!result && fh) {
          fputs(after, fh);
          curlx_fclose(fh);
          fh = NULL;
          if(tempname)
            fail_unless(!curlx_rename(tempname, file), "rename failed");
          curlx_safefree(tempname);
          fail_unless(check_unit1679(file, after),
                      "bad content after replacing a write-protected file");
        }
      }
      curlx_close(ffd);
    }
  }
#endif /* !_WIN32 */

  curl_easy_cleanup(easy);

  UNITTEST_END(curl_global_cleanup())
}
#else
static CURLcode test_unit1679(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("nothing to do without cookies, alt-svc or hsts support");
  UNITTEST_END_SIMPLE
}
#endif
