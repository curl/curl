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
#include "fetchcheck.h"

#include "urldata.h"
#include "fetch/urlapi.h"
#include "urlapi-int.h"

static FETCHU *u;

static FETCHcode
unit_setup(void)
{
  return FETCHE_OK;
}

static void
unit_stop(void)
{
  fetch_global_cleanup();
}

#define free_and_clear(x) \
  free(x);                \
  x = NULL

static FETCHUcode parse_port(FETCHU *url,
                             char *h, bool has_scheme)
{
  struct dynbuf host;
  FETCHUcode ret;
  Curl_dyn_init(&host, 10000);
  if (Curl_dyn_add(&host, h))
    return FETCHUE_OUT_OF_MEMORY;
  ret = Curl_parse_port(url, &host, has_scheme);
  Curl_dyn_free(&host);
  return ret;
}

UNITTEST_START
{
  FETCHUcode ret;
  char *ipv6port = NULL;
  char *portnum;

  /* Valid IPv6 */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15]");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret == FETCHUE_OK, "parse_port returned error");
  ret = fetch_url_get(u, FETCHUPART_PORT, &portnum, FETCHU_NO_DEFAULT_PORT);
  fail_unless(ret != FETCHUE_OK, "fetch_url_get portnum returned something");
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* Invalid IPv6 */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15|");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret != FETCHUE_OK, "parse_port true on error");
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff;fea7:da15]:808");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret == FETCHUE_OK, "parse_port returned error");
  ret = fetch_url_get(u, FETCHUPART_PORT, &portnum, 0);
  fail_unless(ret == FETCHUE_OK, "fetch_url_get portnum returned error");
  fail_unless(portnum && !strcmp(portnum, "808"), "Check portnumber");

  fetch_free(portnum);
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* Valid IPv6 with zone index and port number */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15%25eth3]:80");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret == FETCHUE_OK, "parse_port returned error");
  ret = fetch_url_get(u, FETCHUPART_PORT, &portnum, 0);
  fail_unless(ret == FETCHUE_OK, "fetch_url_get portnum returned error");
  fail_unless(portnum && !strcmp(portnum, "80"), "Check portnumber");
  fetch_free(portnum);
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* Valid IPv6 with zone index without port number */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15%25eth3]");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret == FETCHUE_OK, "parse_port returned error");
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* Valid IPv6 with port number */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15]:81");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret == FETCHUE_OK, "parse_port returned error");
  ret = fetch_url_get(u, FETCHUPART_PORT, &portnum, 0);
  fail_unless(ret == FETCHUE_OK, "fetch_url_get portnum returned error");
  fail_unless(portnum && !strcmp(portnum, "81"), "Check portnumber");
  fetch_free(portnum);
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* Valid IPv6 with syntax error in the port number */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15];81");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret != FETCHUE_OK, "parse_port true on error");
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15]80");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret != FETCHUE_OK, "parse_port true on error");
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* Valid IPv6 with no port after the colon, should use default if a scheme
     was used in the URL */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15]:");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, TRUE);
  fail_unless(ret == FETCHUE_OK, "parse_port returned error");
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* Incorrect zone index syntax, but the port extractor doesn't care */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15!25eth3]:180");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret == FETCHUE_OK, "parse_port returned error");
  ret = fetch_url_get(u, FETCHUPART_PORT, &portnum, 0);
  fail_unless(ret == FETCHUE_OK, "fetch_url_get portnum returned error");
  fail_unless(portnum && !strcmp(portnum, "180"), "Check portnumber");
  fetch_free(portnum);
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* Non percent-encoded zone index */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("[fe80::250:56ff:fea7:da15%eth3]:80");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret == FETCHUE_OK, "parse_port returned error");
  free_and_clear(ipv6port);
  fetch_url_cleanup(u);

  /* No scheme and no digits following the colon - not accepted. Because that
     makes (a*50):// that looks like a scheme be an acceptable input. */
  u = fetch_url();
  if (!u)
    goto fail;
  ipv6port = strdup("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    "aaaaaaaaaaaaaaaaaaaaaa:");
  if (!ipv6port)
    goto fail;
  ret = parse_port(u, ipv6port, FALSE);
  fail_unless(ret == FETCHUE_BAD_PORT_NUMBER, "parse_port did wrong");
fail:
  free(ipv6port);
  fetch_url_cleanup(u);
}
UNITTEST_STOP
