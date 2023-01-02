#ifndef HEADER_CURL_TOOL_XATTR_H
#define HEADER_CURL_TOOL_XATTR_H
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

#ifdef HAVE_FSETXATTR
#  include <sys/xattr.h> /* header from libc, not from libattr */
#  define USE_XATTR
#elif (defined(__FreeBSD_version) && (__FreeBSD_version > 500000)) || \
      defined(__MidnightBSD_version)
#  include <sys/types.h>
#  include <sys/extattr.h>
#  define USE_XATTR
#endif

#ifdef USE_XATTR
int fwrite_xattr(CURL *curl, const char *url, int fd);

#else
#define fwrite_xattr(a,b,c) 0
#endif

#endif /* HEADER_CURL_TOOL_XATTR_H */
