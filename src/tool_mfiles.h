#ifndef HEADER_CURL_TOOL_MFILES_H
#define HEADER_CURL_TOOL_MFILES_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

/*
 * Structure for storing the information needed to build
 * a multiple files section.
 */

struct multi_files {
  struct curl_forms   form;
  struct multi_files *next;
};

struct multi_files *AddMultiFiles(const char *file_name,
                                  const char *type_name,
                                  const char *show_filename,
                                  struct multi_files **multi_first,
                                  struct multi_files **multi_last);

void FreeMultiInfo(struct multi_files **multi_first,
                   struct multi_files **multi_last);

#endif /* HEADER_CURL_TOOL_MFILES_H */

