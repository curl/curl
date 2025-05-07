#ifndef HEADER_CURL_VAR_H
#define HEADER_CURL_VAR_H
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

#include "tool_getparam.h"
#include <curlx.h>

struct tool_var {
  struct tool_var *next;
  const char *content;
  size_t clen; /* content length */
  char name[1]; /* allocated as part of the struct */
};

struct GlobalConfig;

ParameterError setvariable(struct GlobalConfig *global, const char *input);
ParameterError varexpand(struct GlobalConfig *global,
                         const char *line, struct dynbuf *out,
                         bool *replaced);

/* free everything */
void varcleanup(struct GlobalConfig *global);

#endif /* HEADER_CURL_VAR_H */
