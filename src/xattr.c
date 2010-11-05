/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/* client-local setup.h */
#include "setup.h"
#include <curl/curl.h>
#include "xattr.h"

#ifdef HAVE_SETXATTR
#include <sys/types.h>
#include <string.h>
#include <sys/xattr.h> /* include header from libc, not from libattr */

/* mapping table of curl metadata to extended attribute names */
static struct xattr_mapping {
  char *attr; /* name of the xattr */
  CURLINFO info;
} mappings[] = {
  /* mappings proposed by
   * http://freedesktop.org/wiki/CommonExtendedAttributes
   */
  { "user.xdg.origin.url", CURLINFO_EFFECTIVE_URL },
  { "user.mime_type", CURLINFO_CONTENT_TYPE },
  { NULL, 0 } /* last element, abort loop here */
};

/* store metadata from the curl request alongside the downloaded
 * file using extended attributes
 */
int write_xattr(CURL *curl, const char *filename)
{
  int i = 0;
  int err = 0;
  /* loop through all xattr-curlinfo pairs and abort on error */
  while ( err == 0 && mappings[i].attr != NULL ) {
    char *value = NULL;
    curl_easy_getinfo(curl, mappings[i].info, &value);
    if (value) {
      err = setxattr( filename, mappings[i].attr, value, strlen(value), 0 );
    }
    i++;
  }
  return err;
}
#else
int write_xattr(CURL *curl, const char *filename)
{
  (void)curl;
  (void)filename;
  return 0;
}
#endif
