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
  struct connectdata *conn;
  struct ssl_primary_config *primary;
  char *saved;
  static char alt_passwd[] = "wrong";
  static char alt_key[]    = "other.key";
  static char alt_ktype[]  = "DER";
  static char alt_ctype[]  = "P12";
  struct Curl_peer *origin = NULL;
  CURLcode result;

  curl_global_init(CURL_GLOBAL_ALL);
  curl = curl_easy_init();
  if(!curl) {
    curl_global_cleanup();
    goto unit_test_abort;
  }

  result = Curl_peer_create((struct Curl_easy *)curl,
                            &Curl_scheme_https,
                            "test.curl.se", 1234, &origin);
  if(result) {
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    goto unit_test_abort;
  }
  Curl_peer_link(&((struct Curl_easy *)curl)->state.initial_origin, origin);

  curl_easy_setopt(curl, CURLOPT_SSLCERT, "client.pem");
  curl_easy_setopt(curl, CURLOPT_SSLKEY, "client.key");
  curl_easy_setopt(curl, CURLOPT_KEYPASSWD, "secret");
  curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
  curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");

  if(Curl_ssl_easy_config_complete((struct Curl_easy *)curl, origin)) {
    Curl_peer_unlink(&origin);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    goto unit_test_abort;
  }

  conn = curlx_calloc(1, sizeof(*conn));
  if(!conn || Curl_ssl_conn_config_init((struct Curl_easy *)curl, conn)) {
    if(conn)
      Curl_ssl_conn_config_cleanup(conn);
    curlx_free(conn);
    Curl_peer_unlink(&origin);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    goto unit_test_abort;
  }

  /* Baseline: identical config must match. */
  fail_unless(Curl_ssl_conn_config_match((struct Curl_easy *)curl, conn,
                                         FALSE),
              "identical mTLS config should match");

  primary = &((struct Curl_easy *)curl)->set.ssl.primary;

  /* Different key_passwd must not match. */
  saved = primary->key_passwd;
  primary->key_passwd = alt_passwd;
  fail_unless(!Curl_ssl_conn_config_match((struct Curl_easy *)curl, conn,
                                          FALSE),
              "different key_passwd must not reuse conn");
  primary->key_passwd = saved;

  /* Different key path must not match. */
  saved = primary->key;
  primary->key = alt_key;
  fail_unless(!Curl_ssl_conn_config_match((struct Curl_easy *)curl, conn,
                                          FALSE),
              "different key must not reuse conn");
  primary->key = saved;

  /* Different key type must not match. */
  saved = primary->key_type;
  primary->key_type = alt_ktype;
  fail_unless(!Curl_ssl_conn_config_match((struct Curl_easy *)curl, conn,
                                          FALSE),
              "different key_type must not reuse conn");
  primary->key_type = saved;

  /* Different cert type must not match. */
  saved = primary->cert_type;
  primary->cert_type = alt_ctype;
  fail_unless(!Curl_ssl_conn_config_match((struct Curl_easy *)curl, conn,
                                          FALSE),
              "different cert_type must not reuse conn");
  primary->cert_type = saved;

  /* All fields restored: must match again. */
  fail_unless(Curl_ssl_conn_config_match((struct Curl_easy *)curl, conn,
                                         FALSE),
              "restored mTLS config should match");

  Curl_ssl_conn_config_cleanup(conn);
  curlx_free(conn);
  curl_easy_cleanup(curl);
  Curl_peer_unlink(&origin);
  curl_global_cleanup();
#endif /* USE_SSL */

  UNITTEST_END_SIMPLE
}
