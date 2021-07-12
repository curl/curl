#ifndef HEADER_CURL_TOOL_HOMEDIR_H
#define HEADER_CURL_TOOL_HOMEDIR_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "tool_setup.h"

/* returns home directory in current locale encoding.
   windows unicode builds expect filename param 'fname' in UTF-8 encoding. */
char *homedir_local(const char *fname);

#if defined(WIN32) && defined(_UNICODE)
/* returns home directory in unicode utf-8 encoding */
char *homedir_utf8(const char *fname);
/* Windows Unicode builds of curl/libcurl always expect UTF-8 strings for
   internal file paths, regardless of current locale. For paths passed to a
   dependency that always expects local encoding, call homedir_local directly
   instead. */
#define homedir(variable) homedir_utf8(variable)
#else
#define homedir(variable) homedir_local(variable)
#endif

#endif /* HEADER_CURL_TOOL_HOMEDIR_H */
