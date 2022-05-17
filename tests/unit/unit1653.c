/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "curlcheck.h"

#include "urldata.h"
#include "curl/urlapi.h"
#include "urlapi-int.h"


static CURLU *u;

static CURLcode
unit_setup(void)
{
  return CURLE_OK;
}

static void
unit_stop(void)
{
  curl_global_cleanup();
}

#define free_and_clear(x) free(x); x = NULL

UNITTEST_START
{
  CURLUcode ret;
  char *ipv6port = NULL;
  char *portnum;

  /* Valid IPv6 */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15]");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret == CURLUE_OK, "Curl_parse_port returned error");
  ret = curl_url_get(u, CURLUPART_PORT, &portnum, CURLU_NO_DEFAULT_PORT);
  fail_unless(ret != CURLUE_OK, "curl_url_get portnum returned something");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* Invalid IPv6 */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15|");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret != CURLUE_OK, "Curl_parse_port true on error");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff;fea7:da15]:80");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret != CURLUE_OK, "Curl_parse_port true on error");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* Valid IPv6 with zone index and port number */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15%25eth3]:80");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret == CURLUE_OK, "Curl_parse_port returned error");
  ret = curl_url_get(u, CURLUPART_PORT, &portnum, 0);
  fail_unless(ret == CURLUE_OK, "curl_url_get portnum returned error");
  fail_unless(portnum && !strcmp(portnum, "80"), "Check portnumber");
  curl_free(portnum);
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* Valid IPv6 with zone index without port number */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15%25eth3]");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret == CURLUE_OK, "Curl_parse_port returned error");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* Valid IPv6 with port number */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15]:81");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret == CURLUE_OK, "Curl_parse_port returned error");
  ret = curl_url_get(u, CURLUPART_PORT, &portnum, 0);
  fail_unless(ret == CURLUE_OK, "curl_url_get portnum returned error");
  fail_unless(portnum && !strcmp(portnum, "81"), "Check portnumber");
  curl_free(portnum);
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* Valid IPv6 with syntax error in the port number */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15];81");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret != CURLUE_OK, "Curl_parse_port true on error");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15]80");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret != CURLUE_OK, "Curl_parse_port true on error");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* Valid IPv6 with no port after the colon, should use default if a scheme
     was used in the URL */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15]:");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, TRUE);
  fail_unless(ret == CURLUE_OK, "Curl_parse_port returned error");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* Incorrect zone index syntax */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15!25eth3]:80");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret != CURLUE_OK, "Curl_parse_port returned non-error");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* Non percent-encoded zone index */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15%eth3]:80");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret == CURLUE_OK, "Curl_parse_port returned error");
  free_and_clear(ipv6port);
  curl_url_cleanup(u);

  /* No scheme and no digits following the colon - not accepted. Because that
     makes (a*50):// that looks like a scheme be an acceptable input. */
  u = curl_url();
  if(!u)
    goto fail;
  ipv6port = strdup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    "aaaaaaaaaaaaaaaaaaaaaa:");
  if(!ipv6port)
    goto fail;
  ret = Curl_parse_port(u, ipv6port, FALSE);
  fail_unless(ret == CURLUE_BAD_PORT_NUMBER, "Curl_parse_port did wrong");
  fail:
  free(ipv6port);
  curl_url_cleanup(u);

}
UNITTEST_STOP
