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
#include "urldata.h"

#ifdef USE_SSL
#include "vtls/vtls.h"
#endif

static CURLcode test_unit3303(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef USE_SSL
  CURL *curl;
  struct Curl_easy *data = NULL;
  struct connectdata *conn;
  char *saved;
  static char alt_passwd[] = "wrong";
  static char alt_key[]    = "other.key";
  static char alt_ktype[]  = "DER";
  static char alt_ctype[]  = "P12";
  struct Curl_peer *origin = NULL;
  struct ssl_filter_config ssl_config;
  struct ssl_filter_config proxy_ssl_config;
  CURLcode result;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    goto unit_test_abort;
  }
  data = (struct Curl_easy *)curl;

  result = Curl_peer_create(data, &Curl_scheme_https,
                            "test.curl.se", 1234, &origin);
  if(result) {
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    goto unit_test_abort;
  }
  Curl_peer_link(&data->state.initial_origin, origin);

  curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
  curl_easy_setopt(curl, CURLOPT_SSLKEY, "client.key");
  curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "secret");
  curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
  curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");

  memset(&ssl_config, 0, sizeof(ssl_config));
  memset(&proxy_ssl_config, 0, sizeof(proxy_ssl_config));
  if(Curl_ssl_filter_config_tmp_init(data, origin, &ssl_config,
                                     &proxy_ssl_config)) {
    Curl_peer_unlink(&origin);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    goto unit_test_abort;
  }

  conn = curlx_calloc(1, sizeof(*conn));
  if(!conn ||
    Curl_ssl_conn_config_clone(&ssl_config, NULL, conn)) {
    if(conn)
      Curl_ssl_conn_config_cleanup(conn);
    curlx_free(conn);
    Curl_peer_unlink(&origin);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    goto unit_test_abort;
  }

  /* Baseline: identical config must match. */
  fail_unless(Curl_ssl_conn_config_match(data, &ssl_config, conn, FALSE),
              "identical mTLS config should match");

  /* Different key_passwd must not match. */
  saved = ssl_config.key_passwd;
  ssl_config.key_passwd = alt_passwd;
  fail_unless(!Curl_ssl_conn_config_match(data, &ssl_config, conn, FALSE),
              "different key_passwd must not reuse conn");
  ssl_config.key_passwd = saved;

  /* Different key path must not match. */
  saved = ssl_config.key;
  ssl_config.key = alt_key;
  fail_unless(!Curl_ssl_conn_config_match(data, &ssl_config, conn, FALSE),
              "different key must not reuse conn");
  ssl_config.key = saved;

  /* Different key type must not match. */
  saved = ssl_config.key_type;
  ssl_config.key_type = alt_ktype;
  fail_unless(!Curl_ssl_conn_config_match(data, &ssl_config, conn, FALSE),
              "different key_type must not reuse conn");
  ssl_config.key_type = saved;

  /* Different cert type must not match. */
  saved = ssl_config.cert_type;
  ssl_config.cert_type = alt_ctype;
  fail_unless(!Curl_ssl_conn_config_match(data, &ssl_config, conn, FALSE),
              "different cert_type must not reuse conn");
  ssl_config.cert_type = saved;

  /* All fields restored: must match again. */
  fail_unless(Curl_ssl_conn_config_match(data, &ssl_config, conn, FALSE),
              "restored mTLS config should match");

  Curl_ssl_config_cleanup(&ssl_config);
  Curl_ssl_conn_config_cleanup(conn);
  curlx_free(conn);
  curl_easy_cleanup(curl);
  Curl_peer_unlink(&origin);
  curl_global_cleanup();
#endif /* USE_SSL */

  UNITTEST_END_SIMPLE
}
