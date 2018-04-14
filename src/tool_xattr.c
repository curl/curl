/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "tool_setup.h"

#ifdef HAVE_FSETXATTR
#  include <sys/xattr.h> /* header from libc, not from libattr */
#  define USE_XATTR
#elif defined(__FreeBSD_version) && (__FreeBSD_version > 500000)
#  include <sys/types.h>
#  include <sys/extattr.h>
#  define USE_XATTR
#endif

#include "tool_xattr.h"

#include "memdebug.h" /* keep this as LAST include */

#ifdef USE_XATTR

/* mapping table of curl metadata to extended attribute names */
static const struct xattr_mapping {
  const char *attr; /* name of the xattr */
  CURLINFO info;
} mappings[] = {
  /* mappings proposed by
   * https://freedesktop.org/wiki/CommonExtendedAttributes/
   */
  { "user.xdg.origin.url", CURLINFO_EFFECTIVE_URL },
  { "user.mime_type",      CURLINFO_CONTENT_TYPE },
  { NULL,                  CURLINFO_NONE } /* last element, abort loop here */
};

/* store metadata from the curl request alongside the downloaded
 * file using extended attributes
 */
int fwrite_xattr(CURL *curl, int fd)
{
  int i = 0;
  int err = 0;

  /* loop through all xattr-curlinfo pairs and abort on a set error */
  while(err == 0 && mappings[i].attr != NULL) {
    char *value = NULL;
    CURLcode result = curl_easy_getinfo(curl, mappings[i].info, &value);
    if(!result && value) {
#ifdef HAVE_FSETXATTR_6
      err = fsetxattr(fd, mappings[i].attr, value, strlen(value), 0, 0);
#elif defined(HAVE_FSETXATTR_5)
      err = fsetxattr(fd, mappings[i].attr, value, strlen(value), 0);
#elif defined(__FreeBSD_version)
      err = extattr_set_fd(fd, EXTATTR_NAMESPACE_USER, mappings[i].attr, value,
                           strlen(value));
      /* FreeBSD's extattr_set_fd returns the length of the extended attribute
       */
      err = err < 0 ? err : 0;
#endif
    }
    i++;
  }

  return err;
}
#else
int fwrite_xattr(CURL *curl, int fd)
{
  (void)curl;
  (void)fd;

  return 0;
}
#endif
