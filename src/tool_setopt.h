#ifndef HEADER_CURL_TOOL_SETOPT_H
#define HEADER_CURL_TOOL_SETOPT_H
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

CURLcode tool_setopt(CURL *curl, bool str, struct Configurable *config,
                     const char *name, CURLoption tag, ...);

/*
 * Macros used in operate()
 */

#define my_setopt(x,y,z)  do { \
  res = tool_setopt(x, FALSE, config, #y, y, z); \
  if(res) \
    goto quit_curl; \
} WHILE_FALSE

#define my_setopt_str(x,y,z)  do { \
  res = tool_setopt(x, TRUE, config, #y, y, z); \
  if(res) \
    goto quit_curl; \
} WHILE_FALSE

#define res_setopt(x,y,z) tool_setopt(x, FALSE, config, #y, y, z)

#define res_setopt_str(x,y,z) tool_setopt(x, TRUE, config, #y, y, z)

#endif /* HEADER_CURL_TOOL_SETOPT_H */

