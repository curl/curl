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
 * cf_ssl_scache_match_auth().
 */

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
  struct Curl_peer origin;
  struct ssl_peer peer;
  struct ssl_filter_config ssl;
  struct Curl_scheme scheme;
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
  static char cafile_fields[] = "/root:CApath-/certs";
  static char cafile[]        = "/root";
  static char capath[]        = "/certs";
  static char cipher_fields[] = "DEFAULT:CIPHER13-TLS_AES_128_GCM_SHA256";
  static char cipher_list[]   = "DEFAULT";
  static char cipher_list13[] = "TLS_AES_128_GCM_SHA256";

  memset(&scheme, 0, sizeof(scheme));
  scheme.name = "https";

  memset(&origin, 0, sizeof(origin));
  origin.hostname = base_hostname;
  origin.port = 443;
  origin.scheme = &scheme;

  memset(&peer, 0, sizeof(peer));
  peer.origin = &origin;
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
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && !strcmp(key1, key2),
              "identical config should produce identical peer key");
  /* Keep legacy serialized keys separate from this key format. */
  fail_unless(key1 && !strncmp(key1, "https:example.com:443:KEY-V3:",
                               sizeof("https:example.com:443:KEY-V3:") - 1),
              "peer key must carry the V3 format marker after the port");
  curlx_safefree(key1);
  curlx_safefree(key2);

  /* The effective native CA-store policy is not necessarily represented in
   * ssl_options: a build can enable it by default. It must still separate
   * sessions authenticated with native roots from file-only sessions. */
  ssl.native_ca_store = TRUE;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.native_ca_store = FALSE;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "native CA-store policy must affect the peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);

  /* A delimiter in a CA path must not create a second trust field. */
  ssl.CAfile = cafile_fields;
  ssl.CApath = NULL;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.CAfile = cafile;
  ssl.CApath = capath;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "CA file and path must not alias another CA file");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.CAfile = NULL;
  ssl.CApath = NULL;

  /* Non-path fields must not inject a following field either. */
  ssl.cipher_list = cipher_fields;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.cipher_list = cipher_list;
  ssl.cipher_list13 = cipher_list13;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "cipher fields must have unambiguous boundaries");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.cipher_list = NULL;
  ssl.cipher_list13 = NULL;

  /* key_passwd is NOT in the peer key: lookup uses timing-safe comparison
   * via cf_ssl_scache_match_auth(). */
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.key_passwd = NULL;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && !strcmp(key1, key2),
              "key_passwd must not affect the peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.key_passwd = base_passwd;

  /* Different key path must produce a different peer key. */
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.key = alt_key;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "different key must produce different peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.key = base_key;

  /* Different key_type must produce a different peer key. */
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.key_type = alt_ktype;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "different key_type must produce different peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.key_type = base_ktype;

  /* Different cert_type must produce a different peer key. */
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.cert_type = alt_ctype;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && strcmp(key1, key2),
              "different cert_type must produce different peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.cert_type = base_ctype;

  /* cert_type is case-insensitive: "PEM" and "pem" must produce the
   * same peer key, consistent with the conn-reuse comparison. */
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.cert_type = lc_ctype;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && !strcmp(key1, key2),
              "cert_type case must not affect peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
  ssl.cert_type = base_ctype;

  /* key_type is case-insensitive: "PEM" and "pem" must produce the
   * same peer key. */
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key1),
              "peer key build failed");
  ssl.key_type = lc_ktype;
  fail_unless(!Curl_ssl_peer_key_make(&peer, &ssl, "test", &key2),
              "peer key build failed");
  fail_unless(key1 && key2 && !strcmp(key1, key2),
              "key_type case must not affect peer key");
  curlx_safefree(key1);
  curlx_safefree(key2);
#endif /* USE_SSL */

  UNITTEST_END_SIMPLE
}
