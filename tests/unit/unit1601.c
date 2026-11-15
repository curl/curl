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
#include "curl_md5.h"
#include "curl_sha256.h"
#include "curl_sha512_256.h"

static CURLcode t1601_setup(void)
{
  CURLcode result = CURLE_OK;
  global_init(CURL_GLOBAL_ALL);
  return result;
}

static CURLcode test_unit1601(const char *arg)
{
  UNITTEST_BEGIN(t1601_setup())

#ifdef CURL_HAVE_MD5
  {
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    uint8_t output[CURL_MD5_DIGEST_LEN];

    Curl_md5it(output, string1, strlen(string1));

    verify_memory(output, "\xc4\xca\x42\x38\xa0\xb9\x23\x82\x0d\xcc\x50\x9a"
                  "\x6f\x75\x84\x9b", CURL_MD5_DIGEST_LEN);

    Curl_md5it(output, string2, strlen(string2));

    verify_memory(output, "\x88\x67\x0b\x6d\x5d\x74\x2f\xad\xa5\xcd\xf9\xb6"
                  "\x82\x87\x5f\x22", CURL_MD5_DIGEST_LEN);
  }
#endif
#ifdef CURL_HAVE_SHA256
  {
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    uint8_t output[CURL_SHA256_DIGEST_LENGTH];

    Curl_sha256it(output, string1, strlen(string1));

    verify_memory(output, "\x6b\x86\xb2\x73\xff\x34\xfc\xe1\x9d\x6b\x80\x4e"
                  "\xff\x5a\x3f\x57\x47\xad\xa4\xea\xa2\x2f\x1d\x49\xc0\x1e"
                  "\x52\xdd\xb7\x87\x5b\x4b", CURL_SHA256_DIGEST_LENGTH);

    Curl_sha256it(output, string2, strlen(string2));

    verify_memory(output, "\xcb\xb1\x6a\x8a\xb9\xcb\xb9\x35\xa8\xcb\xa0\x2e"
                  "\x28\xc0\x26\x30\xd1\x19\x9c\x1f\x02\x17\xf4\x7c\x96\x20"
                  "\xf3\xef\xe8\x27\x15\xae", CURL_SHA256_DIGEST_LENGTH);
  }
#endif
#ifdef CURL_HAVE_SHA512_256
  static const char test_str1[] = "1";
  static const uint8_t precomp_hash1[CURL_SHA512_256_DIGEST_LENGTH] = {
    0x18, 0xd2, 0x75, 0x66, 0xbd, 0x1a, 0xc6, 0x6b, 0x23, 0x32, 0xd8,
    0xc5, 0x4a, 0xd4, 0x3f, 0x7b, 0xb2, 0x20, 0x79, 0xc9, 0x06, 0xd0,
    0x5f, 0x49, 0x1f, 0x3f, 0x07, 0xa2, 0x8d, 0x5c, 0x69, 0x90
  };
  static const char test_str2[] = "hello-you-fool";
  static const uint8_t precomp_hash2[CURL_SHA512_256_DIGEST_LENGTH] = {
    0xaf, 0x6f, 0xb4, 0xb0, 0x13, 0x9b, 0xee, 0x13, 0xd1, 0x95, 0x3c,
    0xb8, 0xc7, 0xcd, 0x5b, 0x19, 0xf9, 0xcd, 0xcd, 0x21, 0xef, 0xdf,
    0xa7, 0x42, 0x5c, 0x07, 0x13, 0xea, 0xcc, 0x1a, 0x39, 0x76
  };
  static const char test_str3[] = "abc";
  static const uint8_t precomp_hash3[CURL_SHA512_256_DIGEST_LENGTH] = {
    0x53, 0x04, 0x8E, 0x26, 0x81, 0x94, 0x1E, 0xF9, 0x9B, 0x2E, 0x29,
    0xB7, 0x6B, 0x4C, 0x7D, 0xAB, 0xE4, 0xC2, 0xD0, 0xC6, 0x34, 0xFC,
    0x6D, 0x46, 0xE0, 0xE2, 0xF1, 0x31, 0x07, 0xE7, 0xAF, 0x23
  };
  static const char test_str4[] = ""; /* empty, zero size input */
  static const uint8_t precomp_hash4[CURL_SHA512_256_DIGEST_LENGTH] = {
    0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3,
    0x62, 0x2c, 0x51, 0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9,
    0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a
  };
  static const char test_str5[] =
    "abcdefghijklmnopqrstuvwxyzzyxwvutsrqponMLKJIHGFEDCBA"
    "abcdefghijklmnopqrstuvwxyzzyxwvutsrqponMLKJIHGFEDCBA";
  static const uint8_t precomp_hash5[CURL_SHA512_256_DIGEST_LENGTH] = {
    0xad, 0xe9, 0x5d, 0x55, 0x3b, 0x9e, 0x45, 0x69, 0xdb, 0x53, 0xa4,
    0x04, 0x92, 0xe7, 0x87, 0x94, 0xff, 0xc9, 0x98, 0x5f, 0x93, 0x03,
    0x86, 0x45, 0xe1, 0x97, 0x17, 0x72, 0x7c, 0xbc, 0x31, 0x15
  };
  static const char test_str6[] =
    "/long/long/long/long/long/long/long/long/long/long/long"
    "/long/long/long/long/long/long/long/long/long/long/long"
    "/long/long/long/long/long/long/long/long/long/long/long"
    "/long/long/long/long/long/long/long/long/long/long/long"
    "/long/long/long/long/long/long/long/long/long/long/long"
    "/long/long/long/long/long/long/long/long/long/long/long"
    "/long/long/long/long/path?with%20some=parameters";
  static const uint8_t precomp_hash6[CURL_SHA512_256_DIGEST_LENGTH] = {
    0xbc, 0xab, 0xc6, 0x2c, 0x0a, 0x22, 0xd5, 0xcb, 0xac, 0xac, 0xe9,
    0x25, 0xcf, 0xce, 0xaa, 0xaf, 0x0e, 0xa1, 0xed, 0x42, 0x46, 0x8a,
    0xe2, 0x01, 0xee, 0x2f, 0xdb, 0x39, 0x75, 0x47, 0x73, 0xf1
  };
  static const char test_str7[] = "Simple string.";
  static const uint8_t precomp_hash7[CURL_SHA512_256_DIGEST_LENGTH] = {
    0xde, 0xcb, 0x3c, 0x81, 0x65, 0x4b, 0xa0, 0xf5, 0xf0, 0x45, 0x6b,
    0x7e, 0x61, 0xf5, 0x0d, 0xf5, 0x38, 0xa4, 0xfc, 0xb1, 0x8a, 0x95,
    0xff, 0x59, 0xbc, 0x04, 0x82, 0xcf, 0x23, 0xb2, 0x32, 0x56
  };
  static const uint8_t test_seq8[] = {
    255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241,
    240, 239, 238, 237, 236, 235, 234, 233, 232, 231, 230, 229, 228, 227, 226,
    225, 224, 223, 222, 221, 220, 219, 218, 217, 216, 215, 214, 213, 212, 211,
    210, 209, 208, 207, 206, 205, 204, 203, 202, 201, 200, 199, 198, 197, 196,
    195, 194, 193, 192, 191, 190, 189, 188, 187, 186, 185, 184, 183, 182, 181,
    180, 179, 178, 177, 176, 175, 174, 173, 172, 171, 170, 169, 168, 167, 166,
    165, 164, 163, 162, 161, 160, 159, 158, 157, 156, 155, 154, 153, 152, 151,
    150, 149, 148, 147, 146, 145, 144, 143, 142, 141, 140, 139, 138, 137, 136,
    135, 134, 133, 132, 131, 130, 129, 128, 127, 126, 125, 124, 123, 122, 121,
    120, 119, 118, 117, 116, 115, 114, 113, 112, 111, 110, 109, 108, 107, 106,
    105, 104, 103, 102, 101, 100, 99,  98,  97,  96,  95,  94,  93,  92,  91,
    90,  89,  88,  87,  86,  85,  84,  83,  82,  81,  80,  79,  78,  77,  76,
    75,  74,  73,  72,  71,  70,  69,  68,  67,  66,  65,  64,  63,  62,  61,
    60,  59,  58,  57,  56,  55,  54,  53,  52,  51,  50,  49,  48,  47,  46,
    45,  44,  43,  42,  41,  40,  39,  38,  37,  36,  35,  34,  33,  32,  31,
    30,  29,  28,  27,  26,  25,  24,  23,  22,  21,  20,  19,  18,  17,  16,
    15,  14,  13,  12,  11,  10,  9,   8,   7,   6,   5,   4,   3,   2,   1
  }; /* 255..1 sequence */
  static const uint8_t precomp_hash8[CURL_SHA512_256_DIGEST_LENGTH] = {
    0x22, 0x31, 0xf2, 0xa1, 0xb4, 0x89, 0xb2, 0x44, 0xf7, 0x66, 0xa0,
    0xb8, 0x31, 0xed, 0xb7, 0x73, 0x8a, 0x34, 0xdc, 0x11, 0xc8, 0x2c,
    0xf2, 0xb5, 0x88, 0x60, 0x39, 0x6b, 0x5c, 0x06, 0x70, 0x37
  };

  uint8_t output_buf[CURL_SHA512_256_DIGEST_LENGTH];

  Curl_sha512_256it(output_buf, test_str1, CURL_ARRAYSIZE(test_str1) - 1);
  verify_memory(output_buf, precomp_hash1, CURL_SHA512_256_DIGEST_LENGTH);

  Curl_sha512_256it(output_buf, test_str2, CURL_ARRAYSIZE(test_str2) - 1);
  verify_memory(output_buf, precomp_hash2, CURL_SHA512_256_DIGEST_LENGTH);

  Curl_sha512_256it(output_buf, test_str3, CURL_ARRAYSIZE(test_str3) - 1);
  verify_memory(output_buf, precomp_hash3, CURL_SHA512_256_DIGEST_LENGTH);

  Curl_sha512_256it(output_buf, test_str4, CURL_ARRAYSIZE(test_str4) - 1);
  verify_memory(output_buf, precomp_hash4, CURL_SHA512_256_DIGEST_LENGTH);

  Curl_sha512_256it(output_buf, test_str5, CURL_ARRAYSIZE(test_str5) - 1);
  verify_memory(output_buf, precomp_hash5, CURL_SHA512_256_DIGEST_LENGTH);

  Curl_sha512_256it(output_buf, test_str6, CURL_ARRAYSIZE(test_str6) - 1);
  verify_memory(output_buf, precomp_hash6, CURL_SHA512_256_DIGEST_LENGTH);

  Curl_sha512_256it(output_buf, test_str7, CURL_ARRAYSIZE(test_str7) - 1);
  verify_memory(output_buf, precomp_hash7, CURL_SHA512_256_DIGEST_LENGTH);

  Curl_sha512_256it(output_buf, test_seq8,
                    CURL_ARRAYSIZE(test_seq8));
  verify_memory(output_buf, precomp_hash8, CURL_SHA512_256_DIGEST_LENGTH);
#endif /* CURL_HAVE_SHA512_256 */

#if !defined(CURL_DISABLE_AWS) || !defined(CURL_DISABLE_HTTPSIG) || \
  !defined(CURL_DISABLE_DIGEST_AUTH) ||                             \
  defined(USE_LIBSSH2) || defined(USE_SSL)

#ifdef CURL_HAVE_MD5
  {
    static const char password[] = "Pa55worD";
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    uint8_t output[CURL_MD5_DIGEST_LEN];

    Curl_hmacit(&Curl_HMAC_MD5,
                password, strlen(password), string1, strlen(string1), output);

    verify_memory(output, "\xd1\x29\x75\x43\x58\xdc\xab\x78\xdf\xcd\x7f\x2b"
                  "\x29\x31\x13\x37", CURL_MD5_DIGEST_LEN);

    Curl_hmacit(&Curl_HMAC_MD5,
                password, strlen(password), string2, strlen(string2), output);

    verify_memory(output, "\x75\xf1\xa7\xb9\xf5\x40\xe5\xa4\x98\x83\x9f\x64"
                  "\x5a\x27\x6d\xd0", CURL_MD5_DIGEST_LEN);
  }
#endif
#ifdef CURL_HAVE_SHA256
  {
    static const char password[] = "Pa55worD";
    static const char string1[] = "1";
    static const char string2[] = "hello-you-fool";
    uint8_t output[CURL_SHA256_DIGEST_LENGTH];

    Curl_hmacit(&Curl_HMAC_SHA256,
                password, strlen(password), string1, strlen(string1), output);

    verify_memory(output, "\x8c\x9d\x74\x0f\x32\xf7\xbb\xb7\xec\xe0\x07\x7e"
                  "\xc1\x8e\x1f\xdb\x17\x02\x6e\xaf\x9c\xcf\x76\x3d\x26\x88"
                  "\x56\x6d\xc8\x07\xbf\x59", CURL_SHA256_DIGEST_LENGTH);

    Curl_hmacit(&Curl_HMAC_SHA256,
                password, strlen(password), string2, strlen(string2), output);

    verify_memory(output, "\xe4\x81\x63\x53\xab\xc6\x8c\x34\xd4\xa8\xe5\xc8"
                  "\xf3\x1d\x12\xbd\xaf\xd6\x58\x73\x11\xe9\xe6\xf9\x93\x2e"
                  "\x0a\xba\x69\x49\x63\x8c", CURL_SHA256_DIGEST_LENGTH);
  }
#endif
#endif /* feature using HMAC */

  UNITTEST_END(curl_global_cleanup())
}
