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
#include "unitcheck.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#include "cf-socket.h"

#include "memdebug.h" /* LAST include file */

static CURLcode t1663_setup(void)
{
  CURLcode res = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return res;
}

static void t1663_parse(
  const char *input_data,
  const char *exp_dev,
  const char *exp_iface,
  const char *exp_host,
  CURLcode exp_rc)
{
  char *dev = NULL;
  char *iface = NULL;
  char *host = NULL;
  CURLcode rc = Curl_parse_interface(input_data, &dev, &iface, &host);
  fail_unless(rc == exp_rc, "Curl_parse_interface() failed");

  fail_unless(!!exp_dev == !!dev, "dev expectation failed.");
  fail_unless(!!exp_iface == !!iface, "iface expectation failed");
  fail_unless(!!exp_host == !!host, "host expectation failed");

  if(!unitfail) {
    fail_unless(!dev || !exp_dev || strcmp(dev, exp_dev) == 0,
                "dev should be equal to exp_dev");
    fail_unless(!iface || !exp_iface || strcmp(iface, exp_iface) == 0,
                "iface should be equal to exp_iface");
    fail_unless(!host || !exp_host || strcmp(host, exp_host) == 0,
                "host should be equal to exp_host");
  }

  free(dev);
  free(iface);
  free(host);
}

static CURLcode test_unit1663(const char *arg)
{
  UNITTEST_BEGIN(t1663_setup())

  t1663_parse("dev", "dev", NULL, NULL, CURLE_OK);
  t1663_parse("if!eth0", NULL, "eth0", NULL, CURLE_OK);
  t1663_parse("host!myname", NULL, NULL, "myname", CURLE_OK);
  t1663_parse("ifhost!eth0!myname", NULL, "eth0", "myname", CURLE_OK);
  t1663_parse("", NULL, NULL, NULL, CURLE_BAD_FUNCTION_ARGUMENT);
  t1663_parse("!", "!", NULL, NULL, CURLE_OK);
  t1663_parse("if!", NULL, NULL, NULL, CURLE_BAD_FUNCTION_ARGUMENT);
  t1663_parse("if!eth0!blubb", NULL, "eth0!blubb", NULL, CURLE_OK);
  t1663_parse("host!", NULL, NULL, NULL, CURLE_BAD_FUNCTION_ARGUMENT);
  t1663_parse("ifhost!", NULL, NULL, NULL, CURLE_BAD_FUNCTION_ARGUMENT);
  t1663_parse("ifhost!eth0", NULL, NULL, NULL, CURLE_BAD_FUNCTION_ARGUMENT);
  t1663_parse("ifhost!eth0!", NULL, NULL, NULL, CURLE_BAD_FUNCTION_ARGUMENT);

  UNITTEST_END(curl_global_cleanup())
}
