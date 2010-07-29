/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "setup.h"
#include "curl_gethostname.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define GETHOSTNAME_ENV_VAR "CURL_GETHOSTNAME"

int Curl_gethostname(char *name, size_t namelen) {
#ifdef HAVE_GETHOSTNAME

#ifdef CURLDEBUG
  /* we check the environment variable only in case of debug build */
  const char *force_hostname = getenv(GETHOSTNAME_ENV_VAR);
  if(force_hostname) {
    strncpy(name, force_hostname, namelen);
    return 0;
  }
#endif
  /* no override requested */
  return gethostname(name, namelen);

#else
  /* no gethostname() available on system, we should always fail */
  (void) name;
  (void) namelen;
  return -1;
#endif
}
