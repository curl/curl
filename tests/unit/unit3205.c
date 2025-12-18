/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Jan Venekamp, <jan@venekamp.net>
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

#include "vtls/cipher_suite.h"

static CURLcode test_unit3205(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#if defined(USE_MBEDTLS) || defined(USE_RUSTLS)

  struct test_cs_entry {
    uint16_t id;
    const char *rfc;
    const char *openssl;
  };

  static const struct test_cs_entry test_cs_list[] = {
    { 0x1301, "TLS_AES_128_GCM_SHA256",
              NULL },
    { 0x1302, "TLS_AES_256_GCM_SHA384",
              NULL },
    { 0x1303, "TLS_CHACHA20_POLY1305_SHA256",
              NULL },
    { 0x1304, "TLS_AES_128_CCM_SHA256",
              NULL },
    { 0x1305, "TLS_AES_128_CCM_8_SHA256",
              NULL },
    { 0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
              "ECDHE-ECDSA-AES128-GCM-SHA256" },
    { 0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
              "ECDHE-ECDSA-AES256-GCM-SHA384" },
    { 0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
              "ECDHE-RSA-AES128-GCM-SHA256" },
    { 0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
              "ECDHE-RSA-AES256-GCM-SHA384" },
    { 0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
              "ECDHE-RSA-CHACHA20-POLY1305" },
    { 0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
              "ECDHE-ECDSA-CHACHA20-POLY1305" },
#ifdef USE_MBEDTLS
    { 0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA",
              "AES128-SHA" },
    { 0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA",
              "AES256-SHA" },
    { 0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256",
              "AES128-SHA256" },
    { 0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256",
              "AES256-SHA256" },
    { 0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256",
              "AES128-GCM-SHA256" },
    { 0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384",
              "AES256-GCM-SHA384" },
    { 0xC004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
              "ECDH-ECDSA-AES128-SHA" },
    { 0xC005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
              "ECDH-ECDSA-AES256-SHA" },
    { 0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
              "ECDHE-ECDSA-AES128-SHA" },
    { 0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
              "ECDHE-ECDSA-AES256-SHA" },
    { 0xC00E, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
              "ECDH-RSA-AES128-SHA" },
    { 0xC00F, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
              "ECDH-RSA-AES256-SHA" },
    { 0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
              "ECDHE-RSA-AES128-SHA" },
    { 0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
              "ECDHE-RSA-AES256-SHA" },
    { 0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
              "ECDHE-ECDSA-AES128-SHA256" },
    { 0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
              "ECDHE-ECDSA-AES256-SHA384" },
    { 0xC025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
              "ECDH-ECDSA-AES128-SHA256" },
    { 0xC026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
              "ECDH-ECDSA-AES256-SHA384" },
    { 0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
              "ECDHE-RSA-AES128-SHA256" },
    { 0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
              "ECDHE-RSA-AES256-SHA384" },
    { 0xC029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
              "ECDH-RSA-AES128-SHA256" },
    { 0xC02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
              "ECDH-RSA-AES256-SHA384" },
    { 0xC02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
              "ECDH-ECDSA-AES128-GCM-SHA256" },
    { 0xC02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
              "ECDH-ECDSA-AES256-GCM-SHA384" },
    { 0xC031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
              "ECDH-RSA-AES128-GCM-SHA256" },
    { 0xC032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
              "ECDH-RSA-AES256-GCM-SHA384" },
    { 0x0001, "TLS_RSA_WITH_NULL_MD5",
              "NULL-MD5" },
    { 0x0002, "TLS_RSA_WITH_NULL_SHA",
              "NULL-SHA" },
    { 0x002C, "TLS_PSK_WITH_NULL_SHA",
              "PSK-NULL-SHA" },
    { 0x002D, "TLS_DHE_PSK_WITH_NULL_SHA",
              "DHE-PSK-NULL-SHA" },
    { 0x002E, "TLS_RSA_PSK_WITH_NULL_SHA",
              "RSA-PSK-NULL-SHA" },
    { 0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
              "DHE-RSA-AES128-SHA" },
    { 0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
              "DHE-RSA-AES256-SHA" },
    { 0x003B, "TLS_RSA_WITH_NULL_SHA256",
              "NULL-SHA256" },
    { 0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
              "DHE-RSA-AES128-SHA256" },
    { 0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
              "DHE-RSA-AES256-SHA256" },
    { 0x008C, "TLS_PSK_WITH_AES_128_CBC_SHA",
              "PSK-AES128-CBC-SHA" },
    { 0x008D, "TLS_PSK_WITH_AES_256_CBC_SHA",
              "PSK-AES256-CBC-SHA" },
    { 0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
              "DHE-PSK-AES128-CBC-SHA" },
    { 0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
              "DHE-PSK-AES256-CBC-SHA" },
    { 0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
              "RSA-PSK-AES128-CBC-SHA" },
    { 0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
              "RSA-PSK-AES256-CBC-SHA" },
    { 0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
              "DHE-RSA-AES128-GCM-SHA256" },
    { 0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
              "DHE-RSA-AES256-GCM-SHA384" },
    { 0x00A8, "TLS_PSK_WITH_AES_128_GCM_SHA256",
              "PSK-AES128-GCM-SHA256" },
    { 0x00A9, "TLS_PSK_WITH_AES_256_GCM_SHA384",
              "PSK-AES256-GCM-SHA384" },
    { 0x00AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
              "DHE-PSK-AES128-GCM-SHA256" },
    { 0x00AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
              "DHE-PSK-AES256-GCM-SHA384" },
    { 0x00AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
              "RSA-PSK-AES128-GCM-SHA256" },
    { 0x00AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
              "RSA-PSK-AES256-GCM-SHA384" },
    { 0x00AE, "TLS_PSK_WITH_AES_128_CBC_SHA256",
              "PSK-AES128-CBC-SHA256" },
    { 0x00AF, "TLS_PSK_WITH_AES_256_CBC_SHA384",
              "PSK-AES256-CBC-SHA384" },
    { 0x00B0, "TLS_PSK_WITH_NULL_SHA256",
              "PSK-NULL-SHA256" },
    { 0x00B1, "TLS_PSK_WITH_NULL_SHA384",
              "PSK-NULL-SHA384" },
    { 0x00B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
              "DHE-PSK-AES128-CBC-SHA256" },
    { 0x00B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
              "DHE-PSK-AES256-CBC-SHA384" },
    { 0x00B4, "TLS_DHE_PSK_WITH_NULL_SHA256",
              "DHE-PSK-NULL-SHA256" },
    { 0x00B5, "TLS_DHE_PSK_WITH_NULL_SHA384",
              "DHE-PSK-NULL-SHA384" },
    { 0x00B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
              "RSA-PSK-AES128-CBC-SHA256" },
    { 0x00B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
              "RSA-PSK-AES256-CBC-SHA384" },
    { 0x00B8, "TLS_RSA_PSK_WITH_NULL_SHA256",
              "RSA-PSK-NULL-SHA256" },
    { 0x00B9, "TLS_RSA_PSK_WITH_NULL_SHA384",
              "RSA-PSK-NULL-SHA384" },
    { 0xC001, "TLS_ECDH_ECDSA_WITH_NULL_SHA",
              "ECDH-ECDSA-NULL-SHA" },
    { 0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
              "ECDHE-ECDSA-NULL-SHA" },
    { 0xC00B, "TLS_ECDH_RSA_WITH_NULL_SHA",
              "ECDH-RSA-NULL-SHA" },
    { 0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA",
              "ECDHE-RSA-NULL-SHA" },
    { 0xC035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
              "ECDHE-PSK-AES128-CBC-SHA" },
    { 0xC036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
              "ECDHE-PSK-AES256-CBC-SHA" },
    { 0xCCAB, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
              "PSK-CHACHA20-POLY1305" },
    { 0xC09C, "TLS_RSA_WITH_AES_128_CCM",
              "AES128-CCM" },
    { 0xC09D, "TLS_RSA_WITH_AES_256_CCM",
              "AES256-CCM" },
    { 0xC0A0, "TLS_RSA_WITH_AES_128_CCM_8",
              "AES128-CCM8" },
    { 0xC0A1, "TLS_RSA_WITH_AES_256_CCM_8",
              "AES256-CCM8" },
    { 0xC0AC, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
              "ECDHE-ECDSA-AES128-CCM" },
    { 0xC0AD, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
              "ECDHE-ECDSA-AES256-CCM" },
    { 0xC0AE, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
              "ECDHE-ECDSA-AES128-CCM8" },
    { 0xC0AF, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
              "ECDHE-ECDSA-AES256-CCM8" },
    /* entries marked ns are non-"standard", they are not in OpenSSL */
    { 0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
              "CAMELLIA128-SHA" },
    { 0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
              "DHE-RSA-CAMELLIA128-SHA" },
    { 0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
              "CAMELLIA256-SHA" },
    { 0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
              "DHE-RSA-CAMELLIA256-SHA" },
    { 0x00BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
              "CAMELLIA128-SHA256" },
    { 0x00BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
              "DHE-RSA-CAMELLIA128-SHA256" },
    { 0x00C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
              "CAMELLIA256-SHA256" },
    { 0x00C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
              "DHE-RSA-CAMELLIA256-SHA256" },
    { 0xC037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
              "ECDHE-PSK-AES128-CBC-SHA256" },
    { 0xC038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
              "ECDHE-PSK-AES256-CBC-SHA384" },
    { 0xC039, "TLS_ECDHE_PSK_WITH_NULL_SHA",
              "ECDHE-PSK-NULL-SHA" },
    { 0xC03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256",
              "ECDHE-PSK-NULL-SHA256" },
    { 0xC03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384",
              "ECDHE-PSK-NULL-SHA384" },
    { 0xC03C, "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
              "ARIA128-SHA256" /* ns */ },
    { 0xC03D, "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
              "ARIA256-SHA384" /* ns */ },
    { 0xC044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
              "DHE-RSA-ARIA128-SHA256" /* ns */ },
    { 0xC045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
              "DHE-RSA-ARIA256-SHA384" /* ns */ },
    { 0xC048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
              "ECDHE-ECDSA-ARIA128-SHA256" /* ns */ },
    { 0xC049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
              "ECDHE-ECDSA-ARIA256-SHA384" /* ns */ },
    { 0xC04A, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
              "ECDH-ECDSA-ARIA128-SHA256" /* ns */ },
    { 0xC04B, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
              "ECDH-ECDSA-ARIA256-SHA384" /* ns */ },
    { 0xC04C, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
              "ECDHE-ARIA128-SHA256" /* ns */ },
    { 0xC04D, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
              "ECDHE-ARIA256-SHA384" /* ns */ },
    { 0xC04E, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
              "ECDH-ARIA128-SHA256" /* ns */ },
    { 0xC04F, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
              "ECDH-ARIA256-SHA384" /* ns */ },
    { 0xC050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
              "ARIA128-GCM-SHA256" },
    { 0xC051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
              "ARIA256-GCM-SHA384" },
    { 0xC052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
              "DHE-RSA-ARIA128-GCM-SHA256" },
    { 0xC053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
              "DHE-RSA-ARIA256-GCM-SHA384" },
    { 0xC05C, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
              "ECDHE-ECDSA-ARIA128-GCM-SHA256" },
    { 0xC05D, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
              "ECDHE-ECDSA-ARIA256-GCM-SHA384" },
    { 0xC05E, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
              "ECDH-ECDSA-ARIA128-GCM-SHA256" /* ns */ },
    { 0xC05F, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
              "ECDH-ECDSA-ARIA256-GCM-SHA384" /* ns */ },
    { 0xC060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
              "ECDHE-ARIA128-GCM-SHA256" },
    { 0xC061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
              "ECDHE-ARIA256-GCM-SHA384" },
    { 0xC062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
              "ECDH-ARIA128-GCM-SHA256" /* ns */ },
    { 0xC063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
              "ECDH-ARIA256-GCM-SHA384" /* ns */ },
    { 0xC064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
              "PSK-ARIA128-SHA256" /* ns */ },
    { 0xC065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
              "PSK-ARIA256-SHA384" /* ns */ },
    { 0xC066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
              "DHE-PSK-ARIA128-SHA256" /* ns */ },
    { 0xC067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
              "DHE-PSK-ARIA256-SHA384" /* ns */ },
    { 0xC068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
              "RSA-PSK-ARIA128-SHA256" /* ns */ },
    { 0xC069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
              "RSA-PSK-ARIA256-SHA384" /* ns */ },
    { 0xC06A, "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
              "PSK-ARIA128-GCM-SHA256" },
    { 0xC06B, "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
              "PSK-ARIA256-GCM-SHA384" },
    { 0xC06C, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
              "DHE-PSK-ARIA128-GCM-SHA256" },
    { 0xC06D, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
              "DHE-PSK-ARIA256-GCM-SHA384" },
    { 0xC06E, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
              "RSA-PSK-ARIA128-GCM-SHA256" },
    { 0xC06F, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
              "RSA-PSK-ARIA256-GCM-SHA384" },
    { 0xC070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
              "ECDHE-PSK-ARIA128-SHA256" /* ns */ },
    { 0xC071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
              "ECDHE-PSK-ARIA256-SHA384" /* ns */ },
    { 0xC072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
              "ECDHE-ECDSA-CAMELLIA128-SHA256" },
    { 0xC073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
              "ECDHE-ECDSA-CAMELLIA256-SHA384" },
    { 0xC074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
              "ECDH-ECDSA-CAMELLIA128-SHA256" /* ns */ },
    { 0xC075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
              "ECDH-ECDSA-CAMELLIA256-SHA384" /* ns */ },
    { 0xC076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
              "ECDHE-RSA-CAMELLIA128-SHA256" },
    { 0xC077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
              "ECDHE-RSA-CAMELLIA256-SHA384" },
    { 0xC078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
              "ECDH-CAMELLIA128-SHA256" /* ns */ },
    { 0xC079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
              "ECDH-CAMELLIA256-SHA384" /* ns */ },
    { 0xC07A, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
              "CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC07B, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
              "CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC07C, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
              "DHE-RSA-CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC07D, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
              "DHE-RSA-CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
              "ECDHE-ECDSA-CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
              "ECDHE-ECDSA-CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
              "ECDH-ECDSA-CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
              "ECDH-ECDSA-CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC08A, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
              "ECDHE-CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC08B, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
              "ECDHE-CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC08C, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
              "ECDH-CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC08D, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
              "ECDH-CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC08E, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
              "PSK-CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC08F, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
              "PSK-CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
              "DHE-PSK-CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
              "DHE-PSK-CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
              "RSA-PSK-CAMELLIA128-GCM-SHA256" /* ns */ },
    { 0xC093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
              "RSA-PSK-CAMELLIA256-GCM-SHA384" /* ns */ },
    { 0xC094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
              "PSK-CAMELLIA128-SHA256" },
    { 0xC095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
              "PSK-CAMELLIA256-SHA384" },
    { 0xC096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
              "DHE-PSK-CAMELLIA128-SHA256" },
    { 0xC097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
              "DHE-PSK-CAMELLIA256-SHA384" },
    { 0xC098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
              "RSA-PSK-CAMELLIA128-SHA256" },
    { 0xC099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
              "RSA-PSK-CAMELLIA256-SHA384" },
    { 0xC09A, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
              "ECDHE-PSK-CAMELLIA128-SHA256" },
    { 0xC09B, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
              "ECDHE-PSK-CAMELLIA256-SHA384" },
    { 0xC09E, "TLS_DHE_RSA_WITH_AES_128_CCM",
              "DHE-RSA-AES128-CCM" },
    { 0xC09F, "TLS_DHE_RSA_WITH_AES_256_CCM",
              "DHE-RSA-AES256-CCM" },
    { 0xC0A2, "TLS_DHE_RSA_WITH_AES_128_CCM_8",
              "DHE-RSA-AES128-CCM8" },
    { 0xC0A3, "TLS_DHE_RSA_WITH_AES_256_CCM_8",
              "DHE-RSA-AES256-CCM8" },
    { 0xC0A4, "TLS_PSK_WITH_AES_128_CCM",
              "PSK-AES128-CCM" },
    { 0xC0A5, "TLS_PSK_WITH_AES_256_CCM",
              "PSK-AES256-CCM" },
    { 0xC0A6, "TLS_DHE_PSK_WITH_AES_128_CCM",
              "DHE-PSK-AES128-CCM" },
    { 0xC0A7, "TLS_DHE_PSK_WITH_AES_256_CCM",
              "DHE-PSK-AES256-CCM" },
    { 0xC0A8, "TLS_PSK_WITH_AES_128_CCM_8",
              "PSK-AES128-CCM8" },
    { 0xC0A9, "TLS_PSK_WITH_AES_256_CCM_8",
              "PSK-AES256-CCM8" },
    { 0xC0AA, "TLS_PSK_DHE_WITH_AES_128_CCM_8",
              "DHE-PSK-AES128-CCM8" },
    { 0xC0AB, "TLS_PSK_DHE_WITH_AES_256_CCM_8",
              "DHE-PSK-AES256-CCM8" },
    { 0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
              "DHE-RSA-CHACHA20-POLY1305" },
    { 0xCCAC, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
              "ECDHE-PSK-CHACHA20-POLY1305" },
    { 0xCCAD, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
              "DHE-PSK-CHACHA20-POLY1305" },
    { 0xCCAE, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
              "RSA-PSK-CHACHA20-POLY1305" },
#endif
  };

  static const char *cs_test_string =
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:"
    "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:"
    "ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:"
    "DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:"
    "DES-CBC3-SHA:"
    ":: GIBBERISH ::"
  ;

  struct test_str_entry {
    uint16_t id;
    const char *str;
  };
  static const struct test_str_entry test_str_list[] = {
    { 0x1301, "TLS_AES_128_GCM_SHA256"},
    { 0x1302, "TLS_AES_256_GCM_SHA384"},
    { 0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
    { 0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"},
    { 0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"},
    { 0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"},
    { 0xC030, "ECDHE-RSA-AES256-GCM-SHA384"},
    { 0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305"},
    { 0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305"},
#ifdef USE_MBEDTLS
    { 0x009E, "DHE-RSA-AES128-GCM-SHA256"},
    { 0x009F, "DHE-RSA-AES256-GCM-SHA384"},
#else
    { 0x0000, "DHE-RSA-AES128-GCM-SHA256"},
    { 0x0000, "DHE-RSA-AES256-GCM-SHA384"},
#endif
#ifdef USE_MBEDTLS
    { 0xCCAA, "DHE-RSA-CHACHA20-POLY1305"},
#else
    { 0x0000, "DHE-RSA-CHACHA20-POLY1305"},
#endif
#ifdef USE_MBEDTLS
    { 0xC023, "ECDHE-ECDSA-AES128-SHA256" },
    { 0xC027, "ECDHE-RSA-AES128-SHA256" },
    { 0xC009, "ECDHE-ECDSA-AES128-SHA" },
    { 0xC013, "ECDHE-RSA-AES128-SHA" },
    { 0xC024, "ECDHE-ECDSA-AES256-SHA384" },
    { 0xC028, "ECDHE-RSA-AES256-SHA384" },
    { 0xC00A, "ECDHE-ECDSA-AES256-SHA" },
    { 0xC014, "ECDHE-RSA-AES256-SHA" },
#else
    { 0x0000, "ECDHE-ECDSA-AES128-SHA256" },
    { 0x0000, "ECDHE-RSA-AES128-SHA256" },
    { 0x0000, "ECDHE-ECDSA-AES128-SHA" },
    { 0x0000, "ECDHE-RSA-AES128-SHA" },
    { 0x0000, "ECDHE-ECDSA-AES256-SHA384" },
    { 0x0000, "ECDHE-RSA-AES256-SHA384" },
    { 0x0000, "ECDHE-ECDSA-AES256-SHA" },
    { 0x0000, "ECDHE-RSA-AES256-SHA" },
#endif
#ifdef USE_MBEDTLS
    { 0x0067, "DHE-RSA-AES128-SHA256" },
    { 0x006B, "DHE-RSA-AES256-SHA256" },
#else
    { 0x0000, "DHE-RSA-AES128-SHA256" },
    { 0x0000, "DHE-RSA-AES256-SHA256" },
#endif
#ifdef USE_MBEDTLS
    { 0x009C, "AES128-GCM-SHA256" },
    { 0x009D, "AES256-GCM-SHA384" },
    { 0x003C, "AES128-SHA256" },
    { 0x003D, "AES256-SHA256" },
    { 0x002F, "AES128-SHA" },
    { 0x0035, "AES256-SHA" },
#else
    { 0x0000, "AES128-GCM-SHA256" },
    { 0x0000, "AES256-GCM-SHA384" },
    { 0x0000, "AES128-SHA256" },
    { 0x0000, "AES256-SHA256" },
    { 0x0000, "AES128-SHA" },
    { 0x0000, "AES256-SHA" },
#endif
    { 0x0000, "DES-CBC3-SHA" },
    { 0x0000, "GIBBERISH" },
    { 0x0000, "" },
  };

  size_t i;
  for(i = 0; i < CURL_ARRAYSIZE(test_cs_list); i++) {
    const struct test_cs_entry *test = &test_cs_list[i];
    const char *expect;
    char buf[64] = "";
    char alt[64] = "";
    uint16_t id;

    /* test Curl_cipher_suite_lookup_id() for rfc name */
    if(test->rfc) {
      id = Curl_cipher_suite_lookup_id(test->rfc, strlen(test->rfc));
      if(id != test->id) {
        curl_mfprintf(stderr, "Curl_cipher_suite_lookup_id FAILED for \"%s\", "
                      "result = 0x%04x, expected = 0x%04x\n",
                      test->rfc, id, test->id);
        unitfail++;
      }
    }

    /* test Curl_cipher_suite_lookup_id() for OpenSSL name */
    if(test->openssl) {
      id = Curl_cipher_suite_lookup_id(test->openssl, strlen(test->openssl));
      if(id != test->id) {
        curl_mfprintf(stderr, "Curl_cipher_suite_lookup_id FAILED for \"%s\", "
                      "result = 0x%04x, expected = 0x%04x\n",
                      test->openssl, id, test->id);
        unitfail++;
      }
    }

    /* test Curl_cipher_suite_get_str() prefer rfc name */
    buf[0] = '\0';
    expect = test->rfc ? test->rfc : test->openssl;

    Curl_cipher_suite_get_str(test->id, buf, sizeof(buf), true);

    if(expect && strcmp(buf, expect) != 0) {
      curl_mfprintf(stderr, "Curl_cipher_suite_get_str FAILED for 0x%04x, "
                    "result = \"%s\", expected = \"%s\"\n",
                    test->id, buf, expect);
      unitfail++;
    }

    /* test Curl_cipher_suite_get_str() prefer OpenSSL name */
    buf[0] = '\0';
    expect = test->openssl ? test->openssl : test->rfc;

    Curl_cipher_suite_get_str(test->id, buf, sizeof(buf), false);

    /* suites matched by EDH alias will return the DHE name */
    if(test->id >= 0x0011 && test->id < 0x0017) {
      if(expect && memcmp(expect, "EDH-", 4) == 0)
        expect = (char *) memcpy(strcpy(alt, expect), "DHE-", 4);
      if(expect && memcmp(expect + 4, "EDH-", 4) == 0)
        expect = (char *) memcpy(strcpy(alt, expect) + 4, "DHE-", 4) - 4;
    }

    if(expect && strcmp(buf, expect) != 0) {
      curl_mfprintf(stderr, "Curl_cipher_suite_get_str FAILED for 0x%04x, "
                    "result = \"%s\", expected = \"%s\"\n",
                    test->id, buf, expect);
      unitfail++;
    }
  }

  /* test Curl_cipher_suite_walk_str() */
  {
    const char *ptr, *end = cs_test_string;
    int j = 0;
    uint16_t id;
    size_t len;

    for(ptr = cs_test_string; ptr[0] != '\0'; ptr = end) {
      const struct test_str_entry *test = &test_str_list[j];
      abort_if(j == CURL_ARRAYSIZE(test_str_list), "should have been done");

      id = Curl_cipher_suite_walk_str(&ptr, &end);
      len = end - ptr;

      if(id != test->id) {
        curl_mfprintf(stderr, "Curl_cipher_suite_walk_str FAILED for \"%s\" "
                      "unexpected cipher, "
                      "result = 0x%04x, expected = 0x%04x\n",
                      test->str, id, test->id);
        unitfail++;
      }
      if(len > 64 || strncmp(ptr, test->str, len) != 0) {
        curl_mfprintf(stderr, "Curl_cipher_suite_walk_str ABORT for \"%s\" "
                      "unexpected pointers\n",
                      test->str);
        unitfail++;
        goto unit_test_abort;
      }
      j++;
    }
  }
#endif /* USE_MBEDTLS || USE_RUSTLS */

  UNITTEST_END_SIMPLE
}
