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
#include "tool_setup.h"

#include "tool_xattr.h"

#ifdef USE_XATTR

/* returns a new URL that needs to be freed */
/* @unittest: 1621 */
UNITTEST char *stripcredentials(const char *url)
{
  CURLU *u;
  CURLUcode uc;
  char *nurl;
  u = curl_url();
  if(u) {
    uc = curl_url_set(u, CURLUPART_URL, url, CURLU_GUESS_SCHEME);
    if(uc)
      goto error;

    uc = curl_url_set(u, CURLUPART_USER, NULL, 0);
    if(uc)
      goto error;

    uc = curl_url_set(u, CURLUPART_PASSWORD, NULL, 0);
    if(uc)
      goto error;

    uc = curl_url_get(u, CURLUPART_URL, &nurl, 0);
    if(uc)
      goto error;

    curl_url_cleanup(u);

    return nurl;
  }
error:
  curl_url_cleanup(u);
  return NULL;
}

#ifndef _WIN32
/* mapping table of curl metadata to extended attribute names */
static const struct xattr_mapping {
  const char *attr; /* name of the xattr */
  CURLINFO info;
} mappings[] = {
  /* mappings proposed by
   * https://freedesktop.org/wiki/CommonExtendedAttributes/
   */
  { "user.xdg.referrer.url", CURLINFO_REFERER },
  { "user.mime_type",        CURLINFO_CONTENT_TYPE },
  { NULL,                    CURLINFO_NONE } /* last element, abort here */
};

static int xattr(int fd,
                 const char *attr, /* name of the xattr */
                 const char *value)
{
  int err = 0;
  if(value) {
#ifdef DEBUGBUILD
    if(getenv("CURL_FAKE_XATTR")) {
      curl_mprintf("%s => %s\n", attr, value);
      return 0;
    }
#endif
#ifdef HAVE_FSETXATTR_6
    err = fsetxattr(fd, attr, value, strlen(value), 0, 0);
#elif defined(HAVE_FSETXATTR_5)
    err = fsetxattr(fd, attr, value, strlen(value), 0);
#elif defined(__FreeBSD_version) || defined(__MidnightBSD_version)
    {
      ssize_t rc = extattr_set_fd(fd, EXTATTR_NAMESPACE_USER,
                                  attr, value, strlen(value));
      /* FreeBSD's extattr_set_fd returns the length of the extended
         attribute */
      err = (rc < 0 ? -1 : 0);
    }
#endif
  }
  return err;
}
#else
static int win32_file_stream(CURL *curl, FILE *fs, const char *url)
{
  int err = 1;
  char *value = NULL;
  char *nurl = stripcredentials(url);
  CURLcode result = curl_easy_getinfo(curl, CURLINFO_REFERER, &value);

  if(nurl && !result) {
    err = 0;
    err |= (fputs("[ZoneTransfer]\n", fs) == EOF);
    if(value) {
      err |= (fputs("ReferrerUrl=", fs) == EOF);
      err |= (fputs(value, fs) == EOF);
      err |= (fputs("\n", fs) == EOF);
    }
    err |= (fputs("HostUrl=", fs) == EOF);
    err |= (fputs(nurl, fs) == EOF);
    err |= (fputs("\n", fs) == EOF);
  }
  curl_free(nurl);
  return err;
}
#endif /* !_WIN32 */

/* store metadata from the curl request alongside the downloaded
 * file using extended attributes
 */
int fwrite_xattr(CURL *curl, const char *url, int fd, const char *filename)
{
  int err;
#ifdef _WIN32
  char *fn_abs, *fn_stream;
  FILE *fs;
  (void)fd;

  /* convert to absolute path to prevent Windows interpreting a 'X:<stream>'
     filename as 'drive-letter:<filename>'. */
  fn_abs = _fullpath(NULL, filename, 0);
  if(!fn_abs)
    return 1;

  fn_stream = curl_maprintf("%s:%s", fn_abs, "Zone.Identifier");
  /* !checksrc! disable BANNEDFUNC 1 */
  free(fn_abs); /* allocated by CRT, use system free() */
  if(!fn_stream)
    return 1;

  fs = curlx_fopen(fn_stream, FOPEN_WRITETEXT);
  curl_free(fn_stream);
  if(!fs)
    return 1;

#ifdef DEBUGBUILD
  if(getenv("CURL_FAKE_XATTR"))
    win32_file_stream(curl, stdout, url);
#endif
  err = win32_file_stream(curl, fs, url);
  curlx_fclose(fs);
#else
  int i = 0;
  (void)filename;

  err = xattr(fd, "user.creator", "curl");

  /* loop through all xattr-curlinfo pairs and abort on a set error */
  while(!err && mappings[i].attr) {
    char *value = NULL;
    CURLcode result = curl_easy_getinfo(curl, mappings[i].info, &value);
    if(!result && value)
      err = xattr(fd, mappings[i].attr, value);
    i++;
  }
  if(!err) {
    char *nurl = stripcredentials(url);
    if(!nurl)
      return 1;
    err = xattr(fd, "user.xdg.origin.url", nurl);
    curl_free(nurl);
  }
#endif
  return err;
}
#endif
