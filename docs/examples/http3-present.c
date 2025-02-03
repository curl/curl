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
 * SPDX-License-Identifier: fetch
 *
 ***************************************************************************/
/* <DESC>
 * Checks if HTTP/3 support is present in libfetch.
 * </DESC>
 */
#include <stdio.h>
#include <fetch/fetch.h>

int main(void)
{
  fetch_version_info_data *ver;

  fetch_global_init(FETCH_GLOBAL_ALL);

  ver = fetch_version_info(FETCHVERSION_NOW);
  if (ver->features & FETCH_VERSION_HTTP2)
    printf("HTTP/2 support is present\n");

  if (ver->features & FETCH_VERSION_HTTP3)
    printf("HTTP/3 support is present\n");

  if (ver->features & FETCH_VERSION_ALTSVC)
    printf("Alt-svc support is present\n");

  fetch_global_cleanup();
  return 0;
}
