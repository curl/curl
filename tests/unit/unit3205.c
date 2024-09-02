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
#include "curlcheck.h"

#include "vtls/cipher_suite.h"

static CURLcode unit_setup(void)
{
  return CURLE_OK;
}

static void unit_stop(void)
{
}

#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS) || \
    defined(USE_BEARSSL) || defined(USE_RUSTLS)

struct test_cs_entry {
  uint16_t id;
  const char *rfc;
  const char *openssl;
};
static const struct test_cs_entry test_cs_list[] = {
#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS) || defined(USE_RUSTLS)
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
#endif
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
#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS) || defined(USE_BEARSSL)
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
#endif
#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS)
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
#endif
#if defined(USE_SECTRANSP)  || defined(USE_BEARSSL)
  { 0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "DES-CBC3-SHA" },
  { 0xC003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "ECDH-ECDSA-DES-CBC3-SHA" },
  { 0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            "ECDHE-ECDSA-DES-CBC3-SHA" },
  { 0xC00D, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
            "ECDH-RSA-DES-CBC3-SHA" },
  { 0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "ECDHE-RSA-DES-CBC3-SHA" },
#endif
#if defined(USE_MBEDTLS) || defined(USE_BEARSSL)
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
#endif
#if defined(USE_SECTRANSP)
  { 0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
            "EXP-RC4-MD5" },
  { 0x0004, "TLS_RSA_WITH_RC4_128_MD5",
            "RC4-MD5" },
  { 0x0005, "TLS_RSA_WITH_RC4_128_SHA",
            "RC4-SHA" },
  { 0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
            "EXP-RC2-CBC-MD5" },
  { 0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA",
            "IDEA-CBC-SHA" },
  { 0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "EXP-DES-CBC-SHA" },
  { 0x0009, "TLS_RSA_WITH_DES_CBC_SHA",
            "DES-CBC-SHA" },
  { 0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
            "EXP-DH-DSS-DES-CBC-SHA" },
  { 0x000C, "TLS_DH_DSS_WITH_DES_CBC_SHA",
            "DH-DSS-DES-CBC-SHA" },
  { 0x000D, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
            "DH-DSS-DES-CBC3-SHA" },
  { 0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "EXP-DH-RSA-DES-CBC-SHA" },
  { 0x000F, "TLS_DH_RSA_WITH_DES_CBC_SHA",
            "DH-RSA-DES-CBC-SHA" },
  { 0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
            "DH-RSA-DES-CBC3-SHA" },
  { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            "EXP-DHE-DSS-DES-CBC-SHA" },
  { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA",
            "DHE-DSS-DES-CBC-SHA" },
  { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            "DHE-DSS-DES-CBC3-SHA" },
  { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "EXP-DHE-RSA-DES-CBC-SHA" },
  { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA",
            "DHE-RSA-DES-CBC-SHA" },
  { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "DHE-RSA-DES-CBC3-SHA" },
  { 0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
            "EXP-ADH-RC4-MD5" },
  { 0x0018, "TLS_DH_anon_WITH_RC4_128_MD5",
            "ADH-RC4-MD5" },
  { 0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
            "EXP-ADH-DES-CBC-SHA" },
  { 0x001A, "TLS_DH_anon_WITH_DES_CBC_SHA",
            "ADH-DES-CBC-SHA" },
  { 0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
            "ADH-DES-CBC3-SHA" },
  { 0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
            "DH-DSS-AES128-SHA" },
  { 0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
            "DH-RSA-AES128-SHA" },
  { 0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            "DHE-DSS-AES128-SHA" },
  { 0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA",
            "ADH-AES128-SHA" },
  { 0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
            "DH-DSS-AES256-SHA" },
  { 0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
            "DH-RSA-AES256-SHA" },
  { 0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
            "DHE-DSS-AES256-SHA" },
  { 0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA",
            "ADH-AES256-SHA" },
  { 0x003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
            "DH-DSS-AES128-SHA256" },
  { 0x003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
            "DH-RSA-AES128-SHA256" },
  { 0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            "DHE-DSS-AES128-SHA256" },
  { 0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
            "DH-DSS-AES256-SHA256" },
  { 0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
            "DH-RSA-AES256-SHA256" },
  { 0x006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            "DHE-DSS-AES256-SHA256" },
  { 0x006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
            "ADH-AES128-SHA256" },
  { 0x006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
            "ADH-AES256-SHA256" },
  { 0x008A, "TLS_PSK_WITH_RC4_128_SHA",
            "PSK-RC4-SHA" },
  { 0x008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
            "PSK-3DES-EDE-CBC-SHA" },
  { 0x008E, "TLS_DHE_PSK_WITH_RC4_128_SHA",
            "DHE-PSK-RC4-SHA" },
  { 0x008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
            "DHE-PSK-3DES-EDE-CBC-SHA" },
  { 0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA",
            "RSA-PSK-RC4-SHA" },
  { 0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
            "RSA-PSK-3DES-EDE-CBC-SHA" },
  { 0x00A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
            "DH-RSA-AES128-GCM-SHA256" },
  { 0x00A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
            "DH-RSA-AES256-GCM-SHA384" },
  { 0x00A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
            "DHE-DSS-AES128-GCM-SHA256" },
  { 0x00A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            "DHE-DSS-AES256-GCM-SHA384" },
  { 0x00A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
            "DH-DSS-AES128-GCM-SHA256" },
  { 0x00A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
            "DH-DSS-AES256-GCM-SHA384" },
  { 0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
            "ADH-AES128-GCM-SHA256" },
  { 0x00A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
            "ADH-AES256-GCM-SHA384" },
  { 0xC002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
            "ECDH-ECDSA-RC4-SHA" },
  { 0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
            "ECDHE-ECDSA-RC4-SHA" },
  { 0xC00C, "TLS_ECDH_RSA_WITH_RC4_128_SHA",
            "ECDH-RSA-RC4-SHA" },
  { 0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
            "ECDHE-RSA-RC4-SHA" },
  { 0xC015, "TLS_ECDH_anon_WITH_NULL_SHA",
            "AECDH-NULL-SHA" },
  { 0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA",
            "AECDH-RC4-SHA" },
  { 0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
            "AECDH-DES-CBC3-SHA" },
  { 0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
            "AECDH-AES128-SHA" },
  { 0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
            "AECDH-AES256-SHA" },
  /* Backward compatible aliases (EDH vs DHE) */
  { 0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            "EXP-EDH-DSS-DES-CBC-SHA" },
  { 0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA",
            "EDH-DSS-DES-CBC-SHA" },
  { 0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            "EDH-DSS-DES-CBC3-SHA" },
  { 0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            "EXP-EDH-RSA-DES-CBC-SHA" },
  { 0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA",
            "EDH-RSA-DES-CBC-SHA" },
  { 0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            "EDH-RSA-DES-CBC3-SHA" },
#endif
#if defined(USE_MBEDTLS)
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
#define TEST_CS_LIST_LEN (sizeof(test_cs_list) / sizeof(test_cs_list[0]))

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
#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS) || defined(USE_RUSTLS)
  { 0x1301, "TLS_AES_128_GCM_SHA256"},
  { 0x1302, "TLS_AES_256_GCM_SHA384"},
  { 0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
#else
  { 0x0000, "TLS_AES_128_GCM_SHA256"},
  { 0x0000, "TLS_AES_256_GCM_SHA384"},
  { 0x0000, "TLS_CHACHA20_POLY1305_SHA256"},
#endif
  { 0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"},
  { 0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"},
  { 0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"},
  { 0xC030, "ECDHE-RSA-AES256-GCM-SHA384"},
  { 0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305"},
  { 0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305"},
#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS)
  { 0x009E, "DHE-RSA-AES128-GCM-SHA256"},
  { 0x009F, "DHE-RSA-AES256-GCM-SHA384"},
#else
  { 0x0000, "DHE-RSA-AES128-GCM-SHA256"},
  { 0x0000, "DHE-RSA-AES256-GCM-SHA384"},
#endif
#if defined(USE_MBEDTLS)
  { 0xCCAA, "DHE-RSA-CHACHA20-POLY1305"},
#else
  { 0x0000, "DHE-RSA-CHACHA20-POLY1305"},
#endif
#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS) || defined(USE_BEARSSL)
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
#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS)
  { 0x0067, "DHE-RSA-AES128-SHA256" },
  { 0x006B, "DHE-RSA-AES256-SHA256" },
#else
  { 0x0000, "DHE-RSA-AES128-SHA256" },
  { 0x0000, "DHE-RSA-AES256-SHA256" },
#endif
#if defined(USE_SECTRANSP) || defined(USE_MBEDTLS) || defined(USE_BEARSSL)
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
#if defined(USE_SECTRANSP) || defined(USE_BEARSSL)
  { 0x000A, "DES-CBC3-SHA" },
#else
  { 0x0000, "DES-CBC3-SHA" },
#endif
  { 0x0000, "GIBBERISH" },
  { 0x0000, "" },
};
#define TEST_STR_LIST_LEN (sizeof(test_str_list) / sizeof(test_str_list[0]))

UNITTEST_START
{
  for(size_t i = 0; i < TEST_CS_LIST_LEN; i++) {
    const struct test_cs_entry *test = &test_cs_list[i];
    const char *expect;
    char buf[64] = "";
    char alt[64] = "";
    uint16_t id;

    /* test Curl_cipher_suite_lookup_id() for rfc name */
    if(test->rfc) {
      id = Curl_cipher_suite_lookup_id(test->rfc, strlen(test->rfc));
      if(id != test->id) {
        fprintf(stderr, "Curl_cipher_suite_lookup_id FAILED for \"%s\", "
                        "result = 0x%04x, expected = 0x%04x\n",
                        test->rfc, id, test->id);
        unitfail++;
      }
    }

    /* test Curl_cipher_suite_lookup_id() for OpenSSL name */
    if(test->openssl) {
      id = Curl_cipher_suite_lookup_id(test->openssl, strlen(test->openssl));
      if(id != test->id) {
        fprintf(stderr, "Curl_cipher_suite_lookup_id FAILED for \"%s\", "
                        "result = 0x%04x, expected = 0x%04x\n",
                        test->openssl, id, test->id);
        unitfail++;
      }
    }

    /* test Curl_cipher_suite_get_str() prefer rfc name */
    buf[0] = '\0';
    expect = test->rfc ? test->rfc : test->openssl;

    Curl_cipher_suite_get_str(test->id, buf, sizeof(buf), true);

    if(strcmp(buf, expect) != 0) {
      fprintf(stderr, "Curl_cipher_suite_get_str FAILED for 0x%04x, "
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
      if(memcmp(expect, "EDH-", 4) == 0)
        expect = (char *) memcpy(strcpy(alt, expect), "DHE-", 4);
      if(memcmp(expect + 4, "EDH-", 4) == 0)
        expect = (char *) memcpy(strcpy(alt, expect) + 4, "DHE-", 4) - 4;
    }

    if(strcmp(buf, expect) != 0) {
      fprintf(stderr, "Curl_cipher_suite_get_str FAILED for 0x%04x, "
                      "result = \"%s\", expected = \"%s\"\n",
                      test->id, buf, expect);
      unitfail++;
    }
  }

  /* test Curl_cipher_suite_walk_str() */
  {
    const char *ptr, *end = cs_test_string;
    int i = 0;
    uint16_t id;
    size_t len;

    for(ptr = cs_test_string; ptr[0] != '\0'; ptr = end) {
      const struct test_str_entry *test = &test_str_list[i];
      abort_if(i == TEST_STR_LIST_LEN, "should have been done");

      id = Curl_cipher_suite_walk_str(&ptr, &end);
      len = end - ptr;

      if(id != test->id) {
        fprintf(stderr, "Curl_cipher_suite_walk_str FAILED for \"%s\" "
                        "unexpected cipher, "
                        "result = 0x%04x, expected = 0x%04x\n",
                        test->str, id, test->id);
        unitfail++;
      }
      if(len > 64 || strncmp(ptr, test->str, len) != 0) {
        fprintf(stderr, "Curl_cipher_suite_walk_str ABORT for \"%s\" "
                        "unexpected pointers\n",
                        test->str);
        unitfail++;
        goto unit_test_abort;
      }
      i++;
    }
  }
}
UNITTEST_STOP

#else /* defined(USE_SECTRANSP) || defined(USE_MBEDTLS) || \
          defined(USE_BEARSSL) */

UNITTEST_START
UNITTEST_STOP

#endif /* defined(USE_SECTRANSP) || defined(USE_MBEDTLS) || \
          defined(USE_BEARSSL) || defined(USE_RUSTLS) */
