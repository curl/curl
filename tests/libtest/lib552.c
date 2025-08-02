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
/* argv1 = URL
 * argv2 = proxy with embedded user+password
 */

#include "first.h"

#include "testtrace.h"
#include "memdebug.h"

static size_t current_offset = 0;
static char databuf[70000]; /* MUST be more than 64k OR
                               MAX_INITIAL_POST_SIZE */

static size_t t552_read_cb(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t  amount = nmemb * size; /* Total bytes curl wants */
  size_t  available = sizeof(databuf) - current_offset; /* What we have to
                                                           give */
  size_t  given = amount < available ? amount : available; /* What is given */
  (void)stream;
  memcpy(ptr, databuf + current_offset, given);
  current_offset += given;
  return given;
}

static size_t t552_write_cb(char *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t amount = size * nmemb;
  curl_mprintf("%.*s", (int)amount, ptr);
  (void)stream;
  return amount;
}

static curlioerr ioctl_callback(CURL *handle, int cmd, void *clientp)
{
  (void)clientp;
  if(cmd == CURLIOCMD_RESTARTREAD) {
    curl_mprintf("APPLICATION received a CURLIOCMD_RESTARTREAD request\n");
    curl_mprintf("APPLICATION ** REWINDING! **\n");
    current_offset = 0;
    return CURLIOE_OK;
  }
  (void)handle;
  return CURLIOE_UNKNOWNCMD;
}

static CURLcode test_lib552(const char *URL)
{
  CURL *curl;
  CURLcode res = CURLE_OK;
  size_t i;
  static const char fill[] = "test data";

  debug_config.nohex = TRUE;
  debug_config.tracetime = FALSE;

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  test_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  test_setopt(curl, CURLOPT_DEBUGDATA, &debug_config);
  /* the DEBUGFUNCTION has no effect until we enable VERBOSE */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  /* setup repeated data string */
  for(i = 0; i < sizeof(databuf); ++i)
    databuf[i] = fill[i % sizeof(fill)];

  /* Post */
  test_setopt(curl, CURLOPT_POST, 1L);

  /* Setup read callback */
  test_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)sizeof(databuf));
  test_setopt(curl, CURLOPT_READFUNCTION, t552_read_cb);

  /* Write callback */
  test_setopt(curl, CURLOPT_WRITEFUNCTION, t552_write_cb);

  /* Ioctl function */
  test_setopt(curl, CURLOPT_IOCTLFUNCTION, ioctl_callback);

  test_setopt(curl, CURLOPT_PROXY, libtest_arg2);

  test_setopt(curl, CURLOPT_URL, URL);

  /* Accept any auth. But for this bug configure proxy with DIGEST, basic
     might work too, not NTLM */
  test_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_ANY);

  res = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return res;
}
