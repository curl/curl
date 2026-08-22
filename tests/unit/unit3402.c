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
#include "curl_fopen.h"

#ifndef _WIN32
static char filename[512];
static char linkname[512];
static char targetname[512];

static void cleanup_file(const char *path)
{
  if(path)
    unlink(path);
}

static CURLcode t3402_setup(void)
{
  long pid = (long)getpid();

  curl_msnprintf(filename, sizeof(filename), "unit3402-file-%ld.tmp", pid);
  curl_msnprintf(linkname, sizeof(linkname), "unit3402-link-%ld.tmp", pid);
  curl_msnprintf(targetname, sizeof(targetname), "unit3402-target-%ld.tmp",
                 pid);

  cleanup_file(filename);
  cleanup_file(linkname);
  cleanup_file(targetname);

  return CURLE_OK;
}

static void t3402_stop(void)
{
  cleanup_file(filename);
  cleanup_file(linkname);
  cleanup_file(targetname);
}

static bool write_text(const char *path, const char *text)
{
  FILE *fp = curlx_fopen(path, "wb");
  if(!fp)
    return FALSE;
  if(fputs(text, fp) < 0) {
    curlx_fclose(fp);
    return FALSE;
  }
  return !curlx_fclose(fp);
}

static bool read_text(const char *path, char *buf, size_t buflen)
{
  FILE *fp = curlx_fopen(path, "rb");
  size_t nread;

  if(!fp)
    return FALSE;
  nread = fread(buf, 1, buflen - 1, fp);
  if(ferror(fp)) {
    curlx_fclose(fp);
    return FALSE;
  }
  buf[nread] = '\0';
  return !curlx_fclose(fp);
}

static void write_replacement(const char *path, FILE *fp, char *tempname)
{
  fputs("replacement\n", fp);
  curlx_fclose(fp);
  fail_unless(curlx_rename(tempname, path) == 0, "rename failed");
  curlx_free(tempname);
}
#endif

static CURLcode test_unit3402(const char *arg)
{
#ifndef _WIN32
  UNITTEST_BEGIN(t3402_setup())

  CURLcode result;
  FILE *fp = NULL;
  char *tempname = NULL;
  char buf[64];

  abort_unless(write_text(filename, "original\n"), "create file failed");
  result = Curl_fopen(NULL, filename, &fp, &tempname);
  abort_unless(result == CURLE_OK, "Curl_fopen failed");
  abort_unless(fp && tempname, "expected temp file for existing file");
  abort_unless(read_text(filename, buf, sizeof(buf)), "read file failed");
  fail_unless(!strcmp(buf, "original\n"), "destination was truncated");
  write_replacement(filename, fp, tempname);
  abort_unless(read_text(filename, buf, sizeof(buf)), "read replaced failed");
  fail_unless(!strcmp(buf, "replacement\n"), "replacement failed");

  abort_unless(write_text(targetname, "symlink target\n"),
               "create symlink target failed");
  abort_unless(symlink(targetname, linkname) == 0, "symlink failed");
  result = Curl_fopen(NULL, linkname, &fp, &tempname);
  abort_unless(result == CURLE_OK, "Curl_fopen symlink failed");
  abort_unless(fp && tempname, "expected temp file for symlink");
  abort_unless(read_text(targetname, buf, sizeof(buf)),
               "read symlink target failed");
  fail_unless(!strcmp(buf, "symlink target\n"),
              "symlink target was truncated");
  write_replacement(linkname, fp, tempname);
  abort_unless(read_text(linkname, buf, sizeof(buf)), "read link failed");
  fail_unless(!strcmp(buf, "replacement\n"), "link replacement failed");
  abort_unless(read_text(targetname, buf, sizeof(buf)),
               "read original symlink target failed");
  fail_unless(!strcmp(buf, "symlink target\n"),
              "original symlink target changed");

  UNITTEST_END(t3402_stop())
#else
  UNITTEST_BEGIN_SIMPLE
  UNITTEST_END_SIMPLE
#endif
}
