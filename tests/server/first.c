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
#include <string.h>

#ifdef _WIN32
static void win32_cleanup(void)
{
#ifdef USE_WINSOCK
  WSACleanup();
#endif

  /* flush buffers of all streams regardless of their mode */
  _flushall();
}

static int win32_init(void)
{
  curlx_now_init();
#ifdef USE_WINSOCK
  {
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);

    if(err) {
      win32_perror("Winsock init failed");
      logmsg("Error initialising Winsock -- aborting");
      return 1;
    }

    if(LOBYTE(wsaData.wVersion) != LOBYTE(wVersionRequested) ||
       HIBYTE(wsaData.wVersion) != HIBYTE(wVersionRequested)) {
      WSACleanup();
      win32_perror("Winsock init failed");
      logmsg("No suitable winsock.dll found -- aborting");
      return 1;
    }
  }
#endif /* USE_WINSOCK */
  atexit(win32_cleanup);
  return 0;
}
#endif /* _WIN32 */

int main(int argc, char **argv)
{
  entry_func_t entry_func;
  char *entry_name;
  size_t tmp;

  if(argc < 2) {
    fprintf(stderr, "Pass servername as first argument\n");
    return 1;
  }

  entry_name = argv[1];
  entry_func = NULL;
  for(tmp = 0; s_entries[tmp].ptr; ++tmp) {
    if(strcmp(entry_name, s_entries[tmp].name) == 0) {
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

  return entry_func(argc - 1, argv + 1);
}
