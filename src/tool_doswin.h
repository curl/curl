#ifndef HEADER_CURL_TOOL_DOSWIN_H
#define HEADER_CURL_TOOL_DOSWIN_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#if defined(MSDOS) || defined(WIN32)

char *sanitize_dos_name(char *file_name);

#if defined(MSDOS) && (defined(__DJGPP__) || defined(__GO32__))

char **__crt0_glob_function(char *arg);

#endif /* MSDOS && (__DJGPP__ || __GO32__) */

#ifdef WIN32

CURLcode FindWin32CACert(struct Configurable *config, const char *bundle_file);

#endif /* WIN32 */

#endif /* MSDOS || WIN32 */

#endif /* HEADER_CURL_TOOL_DOSWIN_H */

