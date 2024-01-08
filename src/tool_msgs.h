#ifndef HEADER_CURL_TOOL_MSGS_H
#define HEADER_CURL_TOOL_MSGS_H
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
#include "tool_cfgable.h"

void warnf(struct GlobalConfig *config, const char *fmt, ...)
  CURL_PRINTF(2, 3);
void notef(struct GlobalConfig *config, const char *fmt, ...)
  CURL_PRINTF(2, 3);
void helpf(FILE *errors, const char *fmt, ...)
  CURL_PRINTF(2, 3);
void errorf(struct GlobalConfig *config, const char *fmt, ...)
  CURL_PRINTF(2, 3);

#endif /* HEADER_CURL_TOOL_MSGS_H */
