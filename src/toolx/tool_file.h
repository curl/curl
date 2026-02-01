#ifndef HEADER_TOOLX_TOOL_FILE_H
#define HEADER_TOOLX_TOOL_FILE_H
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
#include "curl_setup.h"

#ifdef _WIN32
int toolx_win32_mkdir(const char *path);
#define toolx_mkdir(x, y) toolx_win32_mkdir(x)
#elif defined(MSDOS) && !defined(__DJGPP__)
#define toolx_mkdir(x, y) mkdir(x)
#else
#define toolx_mkdir       mkdir
#endif

#endif /* HEADER_TOOLS_TOOL_FILE_H */
