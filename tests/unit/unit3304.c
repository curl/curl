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

/* Unit tests for TLS session cache peer key discrimination on mTLS fields.
 * Verifies that Curl_ssl_peer_key_build() produces distinct keys when two
 * handles differ only on key, key_type or cert_type.  key_passwd is NOT
 * embedded in the peer key; it is compared separately at session lookup via
 * cf_ssl_scache_match_auth(), following the same pattern as SRP
 * credentials. */

#include "unitcheck.h"
#include "urldata.h"
#include "peer.h"

#ifdef USE_SSL
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#endif

static CURLcode test_unit3304(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef USE_SSL
  struct Curl_peer dest;
  struct ssl_peer peer;
  struct ssl_primary_config ssl;
  char *key1 = NULL;
  char *key2 = NULL;
  static char base_hostname[] = "example.com";
  static char base_cert[]     = "client.pem";
  static char base_key[]      = "client.key";
  static char base_passwd[]   = "secret";
  static char base_ctype[]    = "PEM";
  static char base_ktype[]    = "PEM";
  static char alt_key[]       = "other.key";
  static char alt_ktype[]     = "DER";
  static char alt_ctype[]     = "P12";
  static char lc_ctype[]      = "pem";
  static char lc_ktype[]      = "pem";

  memset(&dest, 0, sizeof(dest));
  dest.hostname = base_hostname;
  dest.port = 443;

  memset(&peer, 0, sizeof(peer));
  peer.dest = &dest;
  peer.transport = TRNSPRT_TCP;

  memset(&ssl, 0, sizeof(ssl));
  ssl.verifypeer = TRUE;
  ssl.verifyhost = TRUE;
  ssl.clientcert = base_cert;
  ssl.key        = base_key;
  ssl.key_passwd = base_passwd;
  ssl.cert_type  = base_ctype;
  ssl.key_type   = base_ktype;

  /* Baseline: same config produces same key. */
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key1),
              "peer key build failed");
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && !strcmp(key1, key2),
              "identical config should produce identical peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);

  /* key_passwd is NOT in the peer key: lookup uses timing-safe comparison
   * via cf_ssl_scache_match_auth(), same as SRP credentials. */
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key1),
              "peer key build failed");
  ssl.key_passwd = NULL;
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && !strcmp(key1, key2),
              "key_passwd must not affect the peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.key_passwd = base_passwd;

  /* Different key path must produce a different peer key. */
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key1),
              "peer key build failed");
  ssl.key = alt_key;
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "different key must produce different peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.key = base_key;

  /* Different key_type must produce a different peer key. */
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key1),
              "peer key build failed");
  ssl.key_type = alt_ktype;
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "different key_type must produce different peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.key_type = base_ktype;

  /* Different cert_type must produce a different peer key. */
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key1),
              "peer key build failed");
  ssl.cert_type = alt_ctype;
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "different cert_type must produce different peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.cert_type = base_ctype;

  /* cert_type is case-insensitive: "PEM" and "pem" must produce the
   * same peer key, consistent with the conn-reuse comparison. */
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key1),
              "peer key build failed");
  ssl.cert_type = lc_ctype;
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && !strcmp(key1, key2),
              "cert_type case must not affect peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.cert_type = base_ctype;

  /* key_type is case-insensitive: "PEM" and "pem" must produce the
   * same peer key. */
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key1),
              "peer key build failed");
  ssl.key_type = lc_ktype;
  fail_unless(!Curl_ssl_peer_key_build(&ssl, &peer, NULL, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && !strcmp(key1, key2),
              "key_type case must not affect peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
#endif /* USE_SSL */

  UNITTEST_END_SIMPLE
}
