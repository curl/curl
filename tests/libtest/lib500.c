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
#include "test.h"

#include "testtrace.h"
#include "memdebug.h"

#ifdef LIB585

static int testcounter;

static fetch_socket_t tst_opensocket(void *clientp,
                                     fetchsocktype purpose,
                                     struct fetch_sockaddr *addr)
{
  (void)clientp;
  (void)purpose;
  printf("[OPEN] counter: %d\n", ++testcounter);
  return socket(addr->family, addr->socktype, addr->protocol);
}

static int tst_closesocket(void *clientp, fetch_socket_t sock)
{
  (void)clientp;
  printf("[CLOSE] counter: %d\n", testcounter--);
  return sclose(sock);
}

static void setupcallbacks(FETCH *fetch)
{
  fetch_easy_setopt(fetch, FETCHOPT_OPENSOCKETFUNCTION, tst_opensocket);
  fetch_easy_setopt(fetch, FETCHOPT_CLOSESOCKETFUNCTION, tst_closesocket);
  testcounter = 0;
}

#else
#define setupcallbacks(x) Curl_nop_stmt
#endif

FETCHcode test(char *URL)
{
  FETCHcode res;
  FETCH *fetch;
  char *ipstr = NULL;

  if (fetch_global_init(FETCH_GLOBAL_ALL) != FETCHE_OK)
  {
    fprintf(stderr, "fetch_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  fetch = fetch_easy_init();
  if (!fetch)
  {
    fprintf(stderr, "fetch_easy_init() failed\n");
    fetch_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(fetch, FETCHOPT_URL, URL);
  test_setopt(fetch, FETCHOPT_HEADER, 1L);

  libtest_debug_config.nohex = 1;
  libtest_debug_config.tracetime = 1;
  test_setopt(fetch, FETCHOPT_DEBUGDATA, &libtest_debug_config);
  test_setopt(fetch, FETCHOPT_DEBUGFUNCTION, libtest_debug_cb);
  test_setopt(fetch, FETCHOPT_VERBOSE, 1L);

  if (libtest_arg3 && !strcmp(libtest_arg3, "activeftp"))
    test_setopt(fetch, FETCHOPT_FTPPORT, "-");

  setupcallbacks(fetch);

  res = fetch_easy_perform(fetch);

  if (!res)
  {
    res = fetch_easy_getinfo(fetch, FETCHINFO_PRIMARY_IP, &ipstr);
    if (libtest_arg2)
    {
      FILE *moo = fopen(libtest_arg2, "wb");
      if (moo)
      {
        fetch_off_t time_namelookup;
        fetch_off_t time_connect;
        fetch_off_t time_pretransfer;
        fetch_off_t time_posttransfer;
        fetch_off_t time_starttransfer;
        fetch_off_t time_total;
        fprintf(moo, "IP %s\n", ipstr);
        fetch_easy_getinfo(fetch, FETCHINFO_NAMELOOKUP_TIME_T, &time_namelookup);
        fetch_easy_getinfo(fetch, FETCHINFO_CONNECT_TIME_T, &time_connect);
        fetch_easy_getinfo(fetch, FETCHINFO_PRETRANSFER_TIME_T,
                           &time_pretransfer);
        fetch_easy_getinfo(fetch, FETCHINFO_POSTTRANSFER_TIME_T,
                           &time_posttransfer);
        fetch_easy_getinfo(fetch, FETCHINFO_STARTTRANSFER_TIME_T,
                           &time_starttransfer);
        fetch_easy_getinfo(fetch, FETCHINFO_TOTAL_TIME_T, &time_total);

        /* since the timing will always vary we only compare relative
           differences between these 5 times */
        if (time_namelookup > time_connect)
        {
          fprintf(moo, "namelookup vs connect: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld %" FETCH_FORMAT_FETCH_OFF_T ".%06ld\n",
                  (time_namelookup / 1000000),
                  (long)(time_namelookup % 1000000),
                  (time_connect / 1000000), (long)(time_connect % 1000000));
        }
        if (time_connect > time_pretransfer)
        {
          fprintf(moo, "connect vs pretransfer: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld %" FETCH_FORMAT_FETCH_OFF_T ".%06ld\n",
                  (time_connect / 1000000), (long)(time_connect % 1000000),
                  (time_pretransfer / 1000000),
                  (long)(time_pretransfer % 1000000));
        }
        if (time_pretransfer > time_posttransfer)
        {
          fprintf(moo, "pretransfer vs posttransfer: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld %" FETCH_FORMAT_FETCH_OFF_T ".%06ld\n",
                  (time_pretransfer / 1000000),
                  (long)(time_pretransfer % 1000000),
                  (time_posttransfer / 1000000),
                  (long)(time_posttransfer % 1000000));
        }
        if (time_pretransfer > time_starttransfer)
        {
          fprintf(moo, "pretransfer vs starttransfer: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld %" FETCH_FORMAT_FETCH_OFF_T ".%06ld\n",
                  (time_pretransfer / 1000000),
                  (long)(time_pretransfer % 1000000),
                  (time_starttransfer / 1000000),
                  (long)(time_starttransfer % 1000000));
        }
        if (time_starttransfer > time_total)
        {
          fprintf(moo, "starttransfer vs total: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld %" FETCH_FORMAT_FETCH_OFF_T ".%06ld\n",
                  (time_starttransfer / 1000000),
                  (long)(time_starttransfer % 1000000),
                  (time_total / 1000000), (long)(time_total % 1000000));
        }
        if (time_posttransfer > time_total)
        {
          fprintf(moo, "posttransfer vs total: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld %" FETCH_FORMAT_FETCH_OFF_T ".%06ld\n",
                  (time_posttransfer / 1000000),
                  (long)(time_posttransfer % 1000000),
                  (time_total / 1000000), (long)(time_total % 1000000));
        }

        fclose(moo);
      }
    }
  }

test_cleanup:

  fetch_easy_cleanup(fetch);
  fetch_global_cleanup();

  return res;
}

#undef setupcallbacks
