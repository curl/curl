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
#include "vtls/x509asn1.h"
#include "vtls/vtls.h"

static CURLcode test_unit1676(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if defined(USE_GNUTLS) || defined(USE_MBEDTLS) || defined(USE_RUSTLS) || \
  defined(USE_SCHANNEL)

  /*
   * Minimal DER-encoded X.509 certificate with a DH public key.
   * Hand-crafted to exercise the do_pubkey() dhpublicnumber branch.
   *
   * The DH parameters contain two distinct INTEGER values:
   *   p = 0x11 (renders as "17" via int2str decimal format)
   *   g = 0x22 (renders as "34")
   * The public key value is:
   *   pub_key = 0x33 (renders as "51")
   *
   * OID 1.2.840.10046.2.1 = dhpublicnumber
   */
  static const unsigned char cert[] = {
    0x30, 0x81, 0x85, 0x30, 0x72, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01,
    0x01, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x01, 0x0B, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1E, 0x17, 0x0D, 0x32,
    0x35, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
    0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x5A, 0x30, 0x0F, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0C, 0x04, 0x74, 0x65, 0x73, 0x74, 0x30, 0x19, 0x30, 0x11,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01, 0x30, 0x06, 0x02,
    0x01, 0x11, 0x02, 0x01, 0x22, 0x03, 0x04, 0x00, 0x02, 0x01, 0x33, 0x30,
    0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
    0x03, 0x02, 0x00, 0xFF
  };

  CURLcode result;
  const char *beg = (const char *)&cert[0];
  const char *end = (const char *)&cert[sizeof(cert)];
  struct Curl_easy *data;
  struct curl_slist *slist;
  const char *dhp_value = NULL;
  const char *dhg_value = NULL;
  const char *dhpk_value = NULL;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  data = curl_easy_init();
  if(!data) {
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  data->set.ssl.certinfo = 1;
  result = Curl_ssl_init_certinfo(data, 1);
  if(result) {
    curl_easy_cleanup(data);
    curl_global_cleanup();
    return TEST_ERR_MAJOR_BAD;
  }

  result = Curl_extract_certinfo(data, 0, beg, end);
  fail_unless(result == CURLE_OK, "Curl_extract_certinfo returned error");
  if(result == CURLE_OK) {
    /* Walk certinfo entries to find dh(p), dh(g), and dh(pub_key) */
    for(slist = data->info.certs.certinfo[0]; slist; slist = slist->next) {
      if(strncmp(slist->data, "dh(p):", 6) == 0)
        dhp_value = slist->data + 6;
      else if(strncmp(slist->data, "dh(g):", 6) == 0)
        dhg_value = slist->data + 6;
      else if(strncmp(slist->data, "dh(pub_key):", 12) == 0)
        dhpk_value = slist->data + 12;
    }

    abort_unless(dhp_value != NULL, "dh(p) not found in certinfo");
    abort_unless(dhg_value != NULL, "dh(g) not found in certinfo");
    abort_unless(dhpk_value != NULL, "dh(pub_key) not found in certinfo");
    fail_if(strcmp(dhp_value, dhg_value) == 0,
            "dh(p) and dh(g) have the same value (bug: g re-reads p)");
    fail_unless(strcmp(dhp_value, "17") == 0, "dh(p) expected 17 (0x11)");
    fail_unless(strcmp(dhg_value, "34") == 0, "dh(g) expected 34 (0x22)");
    fail_unless(strcmp(dhpk_value, "51") == 0,
                "dh(pub_key) expected 51 (0x33)");
  }

  curl_easy_cleanup(data);
  curl_global_cleanup();
#else
  puts("not tested since Curl_extract_certinfo() is not built in");
#endif
  UNITTEST_END_SIMPLE
}
