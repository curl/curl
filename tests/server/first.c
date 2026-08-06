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

#include <stdio.h>

int main(int argc, const char **argv)
{
  entry_func_t entry_func;
  const char *entry_name;
  int result;
  size_t tmp;

  if(argc < 2) {
    fprintf(stderr, "Pass servername as first argument\n");
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
    return 99;
  }

#ifdef _WIN32
  if(win32_init())
    return 2;
#endif

  result = entry_func(argc - 1, argv + 1);

  if(got_exit_signal) {
    logmsg("========> %s %s (port: %d pid: %ld) exits with signal (%d)",
           socket_type, entry_name + CURL_CSTRLEN("test_"),
           location_str, (long)our_getpid(), exit_signal);
    /*
     * To properly set the return status of the process we
     * must raise the same signal SIGINT or SIGTERM that we
     * caught and let the old handler take care of it.
     */
    raise(exit_signal);
  }

  logmsg("========> %s quits", entry_name + CURL_CSTRLEN("test_"));

  return result;
}
