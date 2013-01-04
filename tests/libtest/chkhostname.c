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
#include "setup.h"

#include "curl_gethostname.h"

#define HOSTNAME_MAX 1024

int main(int argc, char *argv[])
{
  char buff[HOSTNAME_MAX];
  if (argc != 2) {
    printf("Usage: %s EXPECTED_HOSTNAME\n", argv[0]);
    return 1;
  }

  if (Curl_gethostname(buff, HOSTNAME_MAX)) {
    printf("Curl_gethostname() failed\n");
    return 1;
  }

  /* compare the name returned by Curl_gethostname() with the expected one */
  if(strncmp(buff, argv[1], HOSTNAME_MAX)) {
    printf("got unexpected host name back, LD_PRELOAD failed\n");
    return 1;
  }
  return 0;
}
