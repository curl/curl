#ifndef HEADER_CURL_TOOL_WRITEOUT_JSON_H
#define HEADER_CURL_TOOL_WRITEOUT_JSON_H
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
#include "tool_writeout.h"

int jsonquoted(const char *in, size_t len,
               struct dynbuf *out, bool lowercase);

void ourWriteOutJSON(FILE *stream, const struct writeoutvar mappings[],
                     size_t nentries,
                     struct per_transfer *per, CURLcode per_result);
void headerJSON(FILE *stream, struct per_transfer *per);
void jsonWriteString(FILE *stream, const char *in, bool lowercase);

#endif /* HEADER_CURL_TOOL_WRITEOUT_H */
