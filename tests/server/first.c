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
  main_func_t main_func;
  char *main_name;

  if(argc < 2) {
    fprintf(stderr, "Pass servername as first argument\n");
    return 1;
  }

  main_name = argv[1];
  main_func = NULL;
  {
    size_t tmp;
    for(tmp = 0; s_mains[tmp].ptr; ++tmp) {
      if(strcmp(main_name, s_mains[tmp].name) == 0) {
        main_func = s_mains[tmp].ptr;
        break;
      }
    }
  }

  if(!main_func) {
    fprintf(stderr, "Test '%s' not found.\n", main_name);
    return 99;
  }

  --argc;
  ++argv;

  return main_func(argc, argv);
}
