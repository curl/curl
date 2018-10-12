/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "test.h"

#include <fcntl.h>

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

int test(char *URL)
{
  CURL *handle = NULL;
  CURLM *mhandle = NULL;
  int res = 0;
  int still_running = 0;
  CURLU* urlp = curl_url();

  global_init(CURL_GLOBAL_ALL);

  easy_init(handle);

  /* Set URL in Curl URL API urlp. */
  curl_url_set(urlp, CURLUPART_URL, URL, 0);

  /* Set easy option CURLOPT_CURLU with urlp. */
  easy_setopt(handle, CURLOPT_CURLU, urlp);
  easy_setopt(handle, CURLOPT_VERBOSE, 1L);

  multi_init(mhandle);
  multi_add_handle(mhandle, handle);
  multi_perform(mhandle, &still_running);

test_cleanup:

  /* undocumented cleanup sequence - type UA */

  curl_multi_cleanup(mhandle);
  curl_easy_cleanup(handle);
  curl_global_cleanup();
  curl_url_cleanup(urlp);

  return res;
}
