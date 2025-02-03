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
 * are also available at https://fetch.se/docs/copyright.html.
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
#include "test.h"

/* test case and code based on https://github.com/fetch/fetch/issues/2847 */

#include "testtrace.h"
#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

static char g_Data[40 * 1024]; /* POST 40KB */

static int sockopt_callback(void *clientp, fetch_socket_t fetchfd,
                            fetchsocktype purpose)
{
#if defined(SOL_SOCKET) && defined(SO_SNDBUF)
  int sndbufsize = 4 * 1024; /* 4KB send buffer */
  (void)clientp;
  (void)purpose;
  setsockopt(fetchfd, SOL_SOCKET, SO_SNDBUF,
             (char *)&sndbufsize, sizeof(sndbufsize));
#else
  (void)clientp;
  (void)fetchfd;
  (void)purpose;
#endif
  return FETCH_SOCKOPT_OK;
}

FETCHcode test(char *URL)
{
  FETCHcode code = TEST_ERR_MAJOR_BAD;
  FETCHcode res;
  struct fetch_slist *pHeaderList = NULL;
  FETCH *fetch = fetch_easy_init();
  memset(g_Data, 'A', sizeof(g_Data)); /* send As! */

  fetch_easy_setopt(fetch, FETCHOPT_SOCKOPTFUNCTION, sockopt_callback);
  fetch_easy_setopt(fetch, FETCHOPT_URL, URL);
  fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, g_Data);
  fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long)sizeof(g_Data));

  libtest_debug_config.nohex = 1;
  libtest_debug_config.tracetime = 1;
  test_setopt(fetch, FETCHOPT_DEBUGDATA, &libtest_debug_config);
  test_setopt(fetch, FETCHOPT_DEBUGFUNCTION, libtest_debug_cb);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  /* Remove "Expect: 100-continue" */
  pHeaderList = fetch_slist_append(pHeaderList, "Expect:");

  fetch_easy_setopt(fetch, FETCHOPT_HTTPHEADER, pHeaderList);

  code = fetch_easy_perform(fetch);

  if (code == FETCHE_OK)
  {
    fetch_off_t uploadSize;
    fetch_easy_getinfo(fetch, FETCHINFO_SIZE_UPLOAD_T, &uploadSize);

    printf("uploadSize = %ld\n", (long)uploadSize);

    if ((size_t)uploadSize == sizeof(g_Data))
    {
      printf("!!!!!!!!!! PASS\n");
    }
    else
    {
      printf("sent %d, libfetch says %d\n",
             (int)sizeof(g_Data), (int)uploadSize);
    }
  }
  else
  {
    printf("fetch_easy_perform() failed. e = %d\n", code);
  }
test_cleanup:
  fetch_slist_free_all(pHeaderList);
  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return code;
}
