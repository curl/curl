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

#include "testtrace.h"
#include "memdebug.h"

static int testcounter;

static curl_socket_t tst_opensocket(void *clientp,
                                    curlsocktype purpose,
                                    struct curl_sockaddr *addr)
{
  (void)clientp;
  (void)purpose;
  curl_mprintf("[OPEN] counter: %d\n", ++testcounter);
  return socket(addr->family, addr->socktype, addr->protocol);
}

static int tst_closesocket(void *clientp, curl_socket_t sock)
{
  (void)clientp;
  curl_mprintf("[CLOSE] counter: %d\n", testcounter--);
  return sclose(sock);
}

static void setupcallbacks(CURL *curl)
{
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, tst_opensocket);
  curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, tst_closesocket);
  testcounter = 0;
}

static CURLcode test_lib500(const char *URL)
{
  CURLcode res;
  CURL *curl;
  char *ipstr = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  test_setopt(curl, CURLOPT_URL, URL);
  test_setopt(curl, CURLOPT_HEADER, 1L);

  debug_config.nohex = TRUE;
  debug_config.tracetime = TRUE;
  test_setopt(curl, CURLOPT_DEBUGDATA, &debug_config);
  test_setopt(curl, CURLOPT_DEBUGFUNCTION, libtest_debug_cb);
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  if(libtest_arg3 && !strcmp(libtest_arg3, "activeftp"))
    test_setopt(curl, CURLOPT_FTPPORT, "-");

  if(testnum == 585 || testnum == 586 || testnum == 595 || testnum == 596)
    setupcallbacks(curl);

  res = curl_easy_perform(curl);

  if(!res) {
    res = curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &ipstr);
    if(libtest_arg2) {
      FILE *moo = fopen(libtest_arg2, "wb");
      if(moo) {
        curl_off_t time_namelookup;
        curl_off_t time_connect;
        curl_off_t time_pretransfer;
        curl_off_t time_posttransfer;
        curl_off_t time_starttransfer;
        curl_off_t time_total;
        curl_mfprintf(moo, "IP %s\n", ipstr);
        curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME_T, &time_namelookup);
        curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME_T, &time_connect);
        curl_easy_getinfo(curl, CURLINFO_PRETRANSFER_TIME_T,
                          &time_pretransfer);
        curl_easy_getinfo(curl, CURLINFO_POSTTRANSFER_TIME_T,
                          &time_posttransfer);
        curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME_T,
                          &time_starttransfer);
        curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &time_total);

        /* since the timing will always vary we only compare relative
           differences between these 5 times */
        if(time_namelookup > time_connect) {
          curl_mfprintf(moo, "namelookup vs connect: %" CURL_FORMAT_CURL_OFF_T
                        ".%06ld %" CURL_FORMAT_CURL_OFF_T ".%06ld\n",
                        (time_namelookup / 1000000),
                        (long)(time_namelookup % 1000000),
                        (time_connect / 1000000),
                        (long)(time_connect % 1000000));
        }
        if(time_connect > time_pretransfer) {
          curl_mfprintf(moo, "connect vs pretransfer: %"
                        CURL_FORMAT_CURL_OFF_T
                        ".%06ld %" CURL_FORMAT_CURL_OFF_T ".%06ld\n",
                        (time_connect / 1000000),
                        (long)(time_connect % 1000000),
                        (time_pretransfer / 1000000),
                        (long)(time_pretransfer % 1000000));
        }
        if(time_pretransfer > time_posttransfer) {
          curl_mfprintf(moo, "pretransfer vs posttransfer: %"
                        CURL_FORMAT_CURL_OFF_T
                        ".%06ld %" CURL_FORMAT_CURL_OFF_T ".%06ld\n",
                        (time_pretransfer / 1000000),
                        (long)(time_pretransfer % 1000000),
                        (time_posttransfer / 1000000),
                        (long)(time_posttransfer % 1000000));
        }
        if(time_pretransfer > time_starttransfer) {
          curl_mfprintf(moo, "pretransfer vs starttransfer: %"
                        CURL_FORMAT_CURL_OFF_T
                        ".%06ld %" CURL_FORMAT_CURL_OFF_T ".%06ld\n",
                        (time_pretransfer / 1000000),
                        (long)(time_pretransfer % 1000000),
                        (time_starttransfer / 1000000),
                        (long)(time_starttransfer % 1000000));
        }
        if(time_starttransfer > time_total) {
          curl_mfprintf(moo, "starttransfer vs total: %" CURL_FORMAT_CURL_OFF_T
                        ".%06ld %" CURL_FORMAT_CURL_OFF_T ".%06ld\n",
                        (time_starttransfer / 1000000),
                        (long)(time_starttransfer % 1000000),
                        (time_total / 1000000),
                        (long)(time_total % 1000000));
        }
        if(time_posttransfer > time_total) {
          curl_mfprintf(moo, "posttransfer vs total: %" CURL_FORMAT_CURL_OFF_T
                        ".%06ld %" CURL_FORMAT_CURL_OFF_T ".%06ld\n",
                        (time_posttransfer / 1000000),
                        (long)(time_posttransfer % 1000000),
                        (time_total / 1000000),
                        (long)(time_total % 1000000));
        }

        fclose(moo);
      }
    }
  }

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return res;
}
