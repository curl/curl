#ifndef HEADER_FETCH_TOOL_VERSION_H
#define HEADER_FETCH_TOOL_VERSION_H
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
#include <fetch/fetchver.h>

#define FETCH_NAME "fetch"
#define FETCH_COPYRIGHT LIBFETCH_COPYRIGHT
#define FETCH_VERSION LIBFETCH_VERSION
#define FETCH_VERSION_MAJOR LIBFETCH_VERSION_MAJOR
#define FETCH_VERSION_MINOR LIBFETCH_VERSION_MINOR
#define FETCH_VERSION_PATCH LIBFETCH_VERSION_PATCH
#define FETCH_ID FETCH_NAME " " FETCH_VERSION " (" FETCH_OS ") "

#endif /* HEADER_FETCH_TOOL_VERSION_H */
