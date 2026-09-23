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

/*
 * Verify that when CURLOPT_RESOLVER_START_FUNCTION vetoes the HTTPS RR
 * side-query for a host, the overall connection attempt is aborted with
 * CURLE_ABORTED_BY_CALLBACK instead of silently ignoring the veto and
 * continuing on to the regular A/AAAA resolve and connect.
 */

#include "first.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

static int t465_cb_count = 0;
static int t465_https_seen = 0;

static int t465_resolver_start_cb(void *resolver_state, void *reserved,
                                  void *userdata)
{
  (void)reserved;
  (void)userdata;
  t465_cb_count++;
  if(resolver_state) {
    /* This is the HTTPS RR side-channel announce: veto it. */
    t465_https_seen = 1;
    return 1;
  }
  /* This is the regular A/AAAA announce: let it proceed. Should not
     happen once the HTTPS RR veto correctly aborts the connection. */
  return 0;
}

static CURLcode test_lib465(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  curl_socket_t dnssock = CURL_SOCKET_BAD;
  struct sockaddr_in sa;
  curl_socklen_t salen = sizeof(sa);
  char envbuf[64];
  int port;
  bool global_inited = FALSE;

  (void)URL;

  dnssock = CURL_SOCKET(AF_INET, SOCK_DGRAM, 0);
  if(dnssock == CURL_SOCKET_BAD) {
    curl_mfprintf(stderr, "socket creation error\n");
    return TEST_ERR_MAJOR_BAD;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;

  if(bind(dnssock, (struct sockaddr *)&sa, sizeof(sa))) {
    curl_mfprintf(stderr, "bind() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  if(getsockname(dnssock, (struct sockaddr *)&sa, &salen)) {
    curl_mfprintf(stderr, "getsockname() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  port = ntohs(sa.sin_port);
  curl_msnprintf(envbuf, sizeof(envbuf), "127.0.0.1:%d", port);
#ifdef _WIN32
  _putenv_s("CURL_DNS_SERVER", envbuf);
#else
  setenv("CURL_DNS_SERVER", envbuf, 1);
#endif

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  global_inited = TRUE;
  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    result = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }

  easy_setopt(curl, CURLOPT_URL, "https://localhost/465");
  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_RESOLVER_START_FUNCTION, t465_resolver_start_cb);

  /* Vetoing the HTTPS RR side-query is an explicit application abort of
   * that resolve and must fail the whole connection attempt before the
   * regular A/AAAA resolve is ever started. */
  result = curl_easy_perform(curl);
  if(result != CURLE_ABORTED_BY_CALLBACK) {
    curl_mfprintf(stderr, "curl_easy_perform should have returned "
                  "CURLE_ABORTED_BY_CALLBACK but instead returned error %d\n",
                  (int)result);
    if(result == CURLE_OK)
      result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  result = CURLE_OK;

  if(!t465_https_seen) {
    curl_mfprintf(stderr, "the HTTPS RR resolver-start announce never "
                  "happened, this test needs asyn-rr support\n");
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }
  if(t465_cb_count != 1) {
    curl_mfprintf(stderr, "Unexpected number of callbacks: %d, "
                  "the regular A/AAAA resolve should not have been "
                  "attempted after the HTTPS RR veto\n", t465_cb_count);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

test_cleanup:
  curl_easy_cleanup(curl);
  if(global_inited)
    curl_global_cleanup();
  if(dnssock != CURL_SOCKET_BAD)
    sclose(dnssock);

  return result;
}
