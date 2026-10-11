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
#include "first.h"

int main(int argc, const char *argv[])
{
  const char *URL = "";
  CURLcode result;
  entry_func_t entry_func;
  const char *entry_name;
  size_t tmp;

#ifdef _WIN32
  if(argc == 2 && !strcmp(argv[1], "--dump-module-paths")) {
    return 0;
  }
#endif

  CURL_BINMODE(stdout);

  if(argc < 2) {
    fprintf(stderr, "Pass testname "
            "(and URL as argument for numbered tests) please\n");
    return 1;
  }

  entry_name = argv[1];
  entry_func = NULL;
  for(tmp = 0; s_entries[tmp].ptr; ++tmp) {
    if(!strcmp(entry_name, s_entries[tmp].name)) {
      entry_func = s_entries[tmp].ptr;
      break;
    }
  }

  if(!entry_func) {
    fprintf(stderr, "Test '%s' not found.\n", entry_name);
    return 1;
  }

  if(argc > 2) {
    URL = argv[2];
    fprintf(stderr, "URL: %s\n", URL);
  }

  result = entry_func(URL);
  fprintf("Test ended with result %d\n", (int)result);

  /* Regular program status codes are limited to 0..127 and 126 and 127 have
   * special meanings by the shell, so limit a normal return code to 125 */
  return result <= 125 ? result : 125;
}
