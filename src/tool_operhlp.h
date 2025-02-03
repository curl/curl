#ifndef HEADER_FETCH_TOOL_OPERHLP_H
#define HEADER_FETCH_TOOL_OPERHLP_H
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
 * are also available at https://fetch.se/docs/copyright.html.
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
#include "tool_setup.h"

struct OperationConfig;

void clean_getout(struct OperationConfig *config);

bool output_expected(const char *url, const char *uploadfile);

bool stdin_upload(const char *uploadfile);

FETCHcode add_file_name_to_url(FETCH *fetch, char **inurlp, const char *filename);

FETCHcode get_url_file_name(struct GlobalConfig *global,
                            char **filename, const char *url);

FETCHcode urlerr_cvt(FETCHUcode ucode);

#endif /* HEADER_FETCH_TOOL_OPERHLP_H */
