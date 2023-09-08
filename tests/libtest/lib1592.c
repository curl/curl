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
 * See https://github.com/curl/curl/issues/3371
 *
 * This test case checks whether curl_multi_remove_handle() cancels
 * asynchronous DNS resolvers without blocking where possible.  Obviously, it
 * only tests whichever resolver cURL is actually built with.
 */

/* We're willing to wait a very generous two seconds for the removal.  This is
   as low as we can go while still easily supporting SIGALRM timing for the
   non-threaded blocking resolver.  It doesn't matter that much because when
   the test passes, we never wait this long. We set it much higher to avoid
   issues when running on overloaded CI machines. */
#define TEST_HANG_TIMEOUT 60 * 1000

#include "test.h"
#include "testutil.h"

#include <sys/stat.h>

int test(char *URL)
{
  int stillRunning;
  CURLM *multiHandle = NULL;
  CURL *curl = NULL;
  CURLcode res = CURLE_OK;
  CURLMcode mres;
  int timeout;

  global_init(CURL_GLOBAL_ALL);

  multi_init(multiHandle);

  easy_init(curl);

  easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  easy_setopt(curl, CURLOPT_URL, URL);

  /* Set a DNS server that hopefully will not respond when using c-ares. */
  if(curl_easy_setopt(curl, CURLOPT_DNS_SERVERS, "0.0.0.0") == CURLE_OK)
    /* Since we could set the DNS server, presume we are working with a
       resolver that can be cancelled (i.e. c-ares).  Thus,
       curl_multi_remove_handle() should not block even when the resolver
       request is outstanding.  So, set a request timeout _longer_ than the
       test hang timeout so we will fail if the handle removal call incorrectly
       blocks. */
    timeout = TEST_HANG_TIMEOUT * 2;
  else {
    /* If we can't set the DNS server, presume that we are configured to use a
       resolver that can't be cancelled (i.e. the threaded resolver or the
       non-threaded blocking resolver).  So, we just test that the
       curl_multi_remove_handle() call does finish well within our test
       timeout.

       But, it is very unlikely that the resolver request will take any time at
       all because we haven't been able to configure the resolver to use an
       non-responsive DNS server.  At least we exercise the flow.
       */
    fprintf(stderr,
            "CURLOPT_DNS_SERVERS not supported; "
            "assuming curl_multi_remove_handle() will block\n");
    timeout = TEST_HANG_TIMEOUT / 2;
  }

  /* Setting a timeout on the request should ensure that even if we have to
     wait for the resolver during curl_multi_remove_handle(), it won't take
     longer than this, because the resolver request inherits its timeout from
     this. */
  easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);

  multi_add_handle(multiHandle, curl);

  /* This should move the handle from INIT => CONNECT => WAITRESOLVE. */
  fprintf(stderr, "curl_multi_perform()...\n");
  multi_perform(multiHandle, &stillRunning);
  fprintf(stderr, "curl_multi_perform() succeeded\n");

  /* Start measuring how long it takes to remove the handle. */
  fprintf(stderr, "curl_multi_remove_handle()...\n");
  start_test_timing();
  mres = curl_multi_remove_handle(multiHandle, curl);
  if(mres) {
    fprintf(stderr, "curl_multi_remove_handle() failed, "
            "with code %d\n", (int)res);
    res = TEST_ERR_MULTI;
    goto test_cleanup;
  }
  fprintf(stderr, "curl_multi_remove_handle() succeeded\n");

  /* Fail the test if it took too long to remove.  This happens after the fact,
     and says "it seems that it would have run forever", which isn't true, but
     it's close enough, and simple to do. */
  abort_on_test_timeout();

test_cleanup:
  curl_easy_cleanup(curl);
  curl_multi_cleanup(multiHandle);
  curl_global_cleanup();

  return (int)res;
}
