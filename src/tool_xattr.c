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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
#include "tool_setup.h"
#include "tool_xattr.h"

#include "memdebug.h" /* keep this as LAST include */

#ifdef USE_XATTR

/* mapping table of fetch metadata to extended attribute names */
static const struct xattr_mapping
{
  const char *attr; /* name of the xattr */
  FETCHINFO info;
} mappings[] = {
    /* mappings proposed by
     * https://freedesktop.org/wiki/CommonExtendedAttributes/
     */
    {"user.xdg.referrer.url", FETCHINFO_REFERER},
    {"user.mime_type", FETCHINFO_CONTENT_TYPE},
    {NULL, FETCHINFO_NONE} /* last element, abort here */
};

/* returns a new URL that needs to be freed */
/* @unittest: 1621 */
#ifdef UNITTESTS
char *stripcredentials(const char *url);
#else
static
#endif
char *stripcredentials(const char *url)
{
  FETCHU *u;
  FETCHUcode uc;
  char *nurl;
  u = fetch_url();
  if (u)
  {
    uc = fetch_url_set(u, FETCHUPART_URL, url, FETCHU_GUESS_SCHEME);
    if (uc)
      goto error;

    uc = fetch_url_set(u, FETCHUPART_USER, NULL, 0);
    if (uc)
      goto error;

    uc = fetch_url_set(u, FETCHUPART_PASSWORD, NULL, 0);
    if (uc)
      goto error;

    uc = fetch_url_get(u, FETCHUPART_URL, &nurl, 0);
    if (uc)
      goto error;

    fetch_url_cleanup(u);

    return nurl;
  }
error:
  fetch_url_cleanup(u);
  return NULL;
}

static int xattr(int fd,
                 const char *attr, /* name of the xattr */
                 const char *value)
{
  int err = 0;
  if (value)
  {
#ifdef DEBUGBUILD
    if (getenv("FETCH_FAKE_XATTR"))
    {
      printf("%s => %s\n", attr, value);
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
/* store metadata from the fetch request alongside the downloaded
 * file using extended attributes
 */
int fwrite_xattr(FETCH *fetch, const char *url, int fd)
{
  int i = 0;
  int err = xattr(fd, "user.creator", "fetch");

  /* loop through all xattr-fetchinfo pairs and abort on a set error */
  while (!err && mappings[i].attr)
  {
    char *value = NULL;
    FETCHcode result = fetch_easy_getinfo(fetch, mappings[i].info, &value);
    if (!result && value)
      err = xattr(fd, mappings[i].attr, value);
    i++;
  }
  if (!err)
  {
    char *nurl = stripcredentials(url);
    if (!nurl)
      return 1;
    err = xattr(fd, "user.xdg.origin.url", nurl);
    fetch_free(nurl);
  }
  return err;
}
#endif
