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
#include <stdio.h>
#include <string.h>
#include "first.h"

int main(int argc, char **argv)
{
  entry_func_t entry_func;
  char *entry_name;

  if(argc < 2) {
    fprintf(stderr, "Pass servername as first argument\n");
    return 1;
  }

  entry_name = argv[1];
  entry_func = NULL;
  {
    size_t tmp;
    for(tmp = 0; tmp < CURL_ARRAYSIZE(s_entries); ++tmp) {
      if(strcmp(entry_name, s_entries[tmp].name) == 0) {
        entry_func = s_entries[tmp].ptr;
        break;
      }
    }
  }

  if(!entry_func) {
    fprintf(stderr, "Test '%s' not found.\n", entry_name);
    return 99;
  }

  --argc;
  ++argv;

  return entry_func(argc, argv);
}
