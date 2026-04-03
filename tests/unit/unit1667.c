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

#if defined(USE_GNUTLS) || defined(USE_SCHANNEL) || defined(USE_MBEDTLS) || \
  defined(USE_RUSTLS)

#include "vtls/x509asn1.h"
#include "vtls/vtls.h"

struct test_1667 {
  unsigned char tag;
  const char *asn1;
  const size_t size;
  const char *out;
  CURLcode result_exp;
};

/* the size of the object needs to deduct the null terminator */
#define OID(x) x, sizeof(x) - 1

static bool test1667(const struct test_1667 *spec, size_t i,
                     struct dynbuf *dbuf)
{
  CURLcode result;
  bool ok = TRUE;
  struct Curl_asn1Element elem;

  curlx_dyn_reset(dbuf);

  /* setup private struct for this invoke */
  elem.tag = spec->tag;
  elem.header = NULL;
  elem.beg = spec->asn1;
  elem.end = elem.beg + spec->size;
  elem.eclass = 0;
  elem.constructed = 0;

  result = ASN1tostr(dbuf, &elem);
  if(result != spec->result_exp) {
    curl_mfprintf(stderr, "test %zu (type %u): expect result %d, got %d\n",
                  i, spec->tag, spec->result_exp, result);
    if(!spec->result_exp) {
      curl_mfprintf(stderr, "test %zu: expected output '%s'\n",
                    i, spec->out);
    }
    ok = FALSE;
  }
  else if(!result) {
    /* use strlen on the pointer instead of curlx_dyn_len() because for some
       of these type, the code explicitly adds a null terminator which is then
       counted as buffer size. */
    size_t actual_len = strlen(curlx_dyn_ptr(dbuf));
    if(strlen(spec->out) != actual_len) {
      curl_mfprintf(stderr,
                    "test %zu (type %u): "
                    "unexpected length. Got %zu, expected %zu)\n",
                    i, spec->tag, actual_len, strlen(spec->out));
      ok = FALSE;
    }
    if(strcmp(spec->out, curlx_dyn_ptr(dbuf))) {
      size_t loop;
      const uint8_t *data = curlx_dyn_uptr(dbuf);
      const size_t len = curlx_dyn_len(dbuf);
      curl_mfprintf(stderr,
                    "test %zu (type %u): "
                    "expected output '%s', got '%s' (length %zu)\n",
                    i, spec->tag, spec->out, data, len);
      for(loop = 0; loop < len; loop++)
        curl_mfprintf(stderr, "test %zu: index %zu byte %02x\n",
                      i, loop, data[loop]);
      ok = FALSE;
    }
  }

  return ok;
}

static CURLcode test_unit1667(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

  static const struct test_1667 test_specs[] = {
    /* unsupported type > CURL_ASN1_BMP_STRING (30) */
    { 31, "abcde", 5, "", CURLE_BAD_FUNCTION_ARGUMENT },
    { 99, "abcde", 5, "", CURLE_BAD_FUNCTION_ARGUMENT },

    /*
      (many different) strings:

      CURL_ASN1_UTF8_STRING
      CURL_ASN1_NUMERIC_STRING
      CURL_ASN1_PRINTABLE_STRING
      CURL_ASN1_TELETEX_STRING
      CURL_ASN1_IA5_STRING
      CURL_ASN1_VISIBLE_STRING
      CURL_ASN1_UNIVERSAL_STRING
      CURL_ASN1_BMP_STRING
    */
    { CURL_ASN1_UTF8_STRING, "abcde", 5, "abcde", CURLE_OK },
    /* a with ring, a with umlaut, o with umlaut in UTF-8 encoding */
    { CURL_ASN1_UTF8_STRING, "\xc3\xa5\xc3\xa4\xc3\xb6", 6,
      "\xc3\xa5\xc3\xa4\xc3\xb6", CURLE_OK },
    { CURL_ASN1_NUMERIC_STRING, "abcde", 5, "abcde", CURLE_OK },
    { CURL_ASN1_PRINTABLE_STRING, "abcde", 5, "abcde", CURLE_OK },
    { CURL_ASN1_TELETEX_STRING, "abcde", 5, "abcde", CURLE_OK },
    { CURL_ASN1_IA5_STRING, "abcde", 5, "abcde", CURLE_OK },
    { CURL_ASN1_VISIBLE_STRING, "abcde", 5, "abcde", CURLE_OK },
    { CURL_ASN1_UNIVERSAL_STRING, "abcde", 5, "abcde",
      CURLE_BAD_FUNCTION_ARGUMENT },
    { CURL_ASN1_UNIVERSAL_STRING, "abcd", 4, "abcd",
      CURLE_WEIRD_SERVER_REPLY },
    { CURL_ASN1_UNIVERSAL_STRING, "\x00\x00\x12\x34", 4, "\xe1\x88\xb4",
      CURLE_OK },
    { CURL_ASN1_BMP_STRING, "abcde", 5, "abcde", CURLE_BAD_FUNCTION_ARGUMENT },

    /* Generalized Time */
    /* GTime2str() is tested separately in unit test 1656 */
    { CURL_ASN1_GENERALIZED_TIME, "19851106210627.3", 16,
      "1985-11-06 21:06:27.3", CURLE_OK },
    { CURL_ASN1_GENERALIZED_TIME, "19851106210627.3Z", 17,
      "1985-11-06 21:06:27.3 GMT", CURLE_OK },
    { CURL_ASN1_GENERALIZED_TIME, "19851106210627.3-0500", 21,
      "1985-11-06 21:06:27.3 UTC-0500", CURLE_OK },
    /* Generalized Time: Invalid month (13). Still fine! */
    { CURL_ASN1_GENERALIZED_TIME, "20231301000000Z", 15,
      "2023-13-01 00:00:00 GMT", CURLE_OK },
    /* Generalized Time: Valid millisecond precision */
    { CURL_ASN1_GENERALIZED_TIME, "20230101000000.123Z", 19,
      "2023-01-01 00:00:00.123 GMT", CURLE_OK },

    /* UTC Time */
    { CURL_ASN1_UTC_TIME, "991231235959Z", 13, "1999-12-31 23:59:59 GMT",
      CURLE_OK },
    { CURL_ASN1_UTC_TIME, "991231235959+0200", 17, "1999-12-31 23:59:59 +0200",
      CURLE_OK },
    { CURL_ASN1_UTC_TIME, "991231235959-0200", 17, "1999-12-31 23:59:59 -0200",
      CURLE_OK },
    { CURL_ASN1_UTC_TIME, "991231235959+999", 16, "1999-12-31 23:59:59 +999",
      CURLE_OK },
    /* Leap year check (Feb 29, 2024) */
    { CURL_ASN1_UTC_TIME, "240229120000Z", 13, "2024-02-29 12:00:00 GMT",
      CURLE_OK },
    /* Century roll-over (00-49 is 20xx, 50-99 is 19xx) */
    { CURL_ASN1_UTC_TIME, "491231235959Z", 13, "2049-12-31 23:59:59 GMT",
      CURLE_OK },
    { CURL_ASN1_UTC_TIME, "500101000000Z", 13, "1950-01-01 00:00:00 GMT",
      CURLE_OK },

    /* Object Identifier (encodeOID() is tested in unit test 1666) */

    /* 1.2.840.10040.4.1 */
    { CURL_ASN1_OBJECT_IDENTIFIER, "\x2A\x86\x48\xCE\x38\x04\x01", 7,
      "dsa", CURLE_OK },
    /* 1.2.840.113549.1.1.13 */
    { CURL_ASN1_OBJECT_IDENTIFIER, "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0D", 9,
      "sha512WithRSAEncryption", CURLE_OK },
    /* 1.2.840.10040.4.2 */
    { CURL_ASN1_OBJECT_IDENTIFIER, "\x2A\x86\x48\xCE\x38\x04\x02", 7,
      "1.2.840.10040.4.2", CURLE_OK },
    /* 2.16.840.1.101.3.4.2.3 */
    { CURL_ASN1_OBJECT_IDENTIFIER, "\x60\x86\x48\x01\x65\x03\x04\x02\x03", 9,
      "sha512", CURLE_OK },
    /* 2.999 -> (2*40) + 999 = 1079. 1079 in VLQ is 0x88 0x37 */
    { CURL_ASN1_OBJECT_IDENTIFIER, "\x88\x37\x03", 3, "2.999.3",
      CURLE_OK },
    /* 1.0 (Minimum possible OID length/value)
       (1*40) + 0 = 40 (0x28) */
    { CURL_ASN1_OBJECT_IDENTIFIER, "\x28", 1, "1.0", CURLE_OK },
    /* Malformed (Incomplete multi-byte SID, MSB set but no following byte) */
    { CURL_ASN1_OBJECT_IDENTIFIER, "\x88", 1, "",
      CURLE_BAD_FUNCTION_ARGUMENT },

    /* NULL */
    { CURL_ASN1_NULL, "", 0, "", CURLE_OK },
    { CURL_ASN1_NULL, "a", 1, "", CURLE_OK },
    { CURL_ASN1_NULL, "aa", 2, "", CURLE_OK },

    /* Octet string */
    { CURL_ASN1_OCTET_STRING, "\x00\x00\x00\x04\x05", 5, "00:00:00:04:05:",
      CURLE_OK },
    { CURL_ASN1_OCTET_STRING, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff", 14, "", CURLE_TOO_LARGE},

    /* Bit string. The first byte is number of unused bits. */
    { CURL_ASN1_BIT_STRING, "\x00\x55", 2, "55:", CURLE_OK },
    /* Invalid number of unused bits (> 7) */
    { CURL_ASN1_BIT_STRING, "\x08\x55", 2, "", CURLE_BAD_FUNCTION_ARGUMENT },
    { CURL_ASN1_BIT_STRING, "\x00\xaa\x55", 3, "aa:55:", CURLE_OK },
    { CURL_ASN1_BIT_STRING, "\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff", 15, "", CURLE_TOO_LARGE},
    /* 3 unused bits, data 0xF0 (11110000)
       The '0' at the end of 11110... are the unused bits. */
    { CURL_ASN1_BIT_STRING, "\x03\xf0", 2, "f0:", CURLE_OK },

    /* Integer */
    { CURL_ASN1_INTEGER, "\x00", 1, "0", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x01", 1, "1", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x09", 1, "9", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x0a", 1, "10", CURLE_OK },
    { CURL_ASN1_INTEGER, "\xb", 1, "11", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x11", 1, "17", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x7f", 1, "127", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x80", 1, "-128", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x81", 1, "-127", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x82", 1, "-126", CURLE_OK },
    { CURL_ASN1_INTEGER, "\xff", 1, "-1", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x27\x0f", 2, "9999", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x27\x10", 2, "0x2710", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x7f\x81", 2, "0x7f81", CURLE_OK },

    /* sign-extended, would be -32385 in decimal */
    { CURL_ASN1_INTEGER, "\x81\x7f", 2, "0xffff817f", CURLE_OK },
    { CURL_ASN1_INTEGER, "\xff\xff", 2, "-1", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x00\x00", 2, "0", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x01\x02\x03", 3, "0x10203", CURLE_OK },
    { CURL_ASN1_INTEGER, "\xff\x02\xff", 3, "0xffff02ff", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x00\xff\x00", 3, "0xff00", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x01\x02\x03\x04", 4, "0x1020304", CURLE_OK },
    { CURL_ASN1_INTEGER, "\xff\x02\x03\x04", 4, "0xff020304", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x00\x00\x00\x04", 4, "4", CURLE_OK },
    { CURL_ASN1_INTEGER, "\x00\x00\x00\x04\x05", 5, "00:00:00:04:05:",
      CURLE_OK },
    { CURL_ASN1_INTEGER, "\xff\x00\x00\x04\x05", 5, "ff:00:00:04:05:",
      CURLE_OK },
    { CURL_ASN1_INTEGER, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
      11, "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:", CURLE_OK },
    { CURL_ASN1_INTEGER, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff", 12, "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:", CURLE_OK },
    { CURL_ASN1_INTEGER, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff", 14, "", CURLE_TOO_LARGE},
    { CURL_ASN1_INTEGER, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff\xff", 15, "", CURLE_TOO_LARGE },
    { CURL_ASN1_INTEGER, "", 0, "", CURLE_BAD_FUNCTION_ARGUMENT },
    /* Leading zero required if the MSB of the next byte is 1 (to keep it
       positive) */
    { CURL_ASN1_INTEGER, "\x00\x80", 2, "128", CURLE_OK },

    /* Enumerated works the same as Integer */
    { CURL_ASN1_ENUMERATED, "\x00", 1, "0", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x01", 1, "1", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x09", 1, "9", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x0a", 1, "10", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xb", 1, "11", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x11", 1, "17", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x7f", 1, "127", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x80", 1, "-128", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xff", 1, "-1", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x7f\x81", 2, "0x7f81", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xff\xff", 2, "-1", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x00\x00", 2, "0", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x01\x02\x03", 3, "0x10203", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xff\x02\xff", 3, "0xffff02ff", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x00\xff\x00", 3, "0xff00", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x01\x02\x03\x04", 4, "0x1020304", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xff\x02\x03\x04", 4, "0xff020304", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x00\x00\x00\x04", 4, "4", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\x00\x00\x00\x04\x05", 5, "00:00:00:04:05:",
      CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xff\x00\x00\x04\x05", 5, "ff:00:00:04:05:",
      CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
      11, "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff", 12, "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:", CURLE_OK },
    { CURL_ASN1_ENUMERATED, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff", 14, "", CURLE_TOO_LARGE},
    { CURL_ASN1_ENUMERATED, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff\xff", 15, "", CURLE_TOO_LARGE },
    { CURL_ASN1_ENUMERATED, "", 0, "", CURLE_BAD_FUNCTION_ARGUMENT },

    /* Boolean */
    { CURL_ASN1_BOOLEAN, "\xff", 1, "TRUE", CURLE_OK },
    { CURL_ASN1_BOOLEAN, "\x01", 1, "", CURLE_BAD_FUNCTION_ARGUMENT },
    { CURL_ASN1_BOOLEAN, "\x02", 1, "", CURLE_BAD_FUNCTION_ARGUMENT },
    { CURL_ASN1_BOOLEAN, "\x00", 1, "FALSE", CURLE_OK },
    { CURL_ASN1_BOOLEAN, "\x01\x01", 2, "", CURLE_BAD_FUNCTION_ARGUMENT },
    { CURL_ASN1_BOOLEAN, "\x00\x01", 2, "", CURLE_BAD_FUNCTION_ARGUMENT },
    { CURL_ASN1_BOOLEAN, "", 0, "", CURLE_BAD_FUNCTION_ARGUMENT },
  };

  size_t i;
  struct dynbuf dbuf;
  bool all_ok = TRUE;

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* the real code uses CURL_X509_STR_MAX for maximum size, but we set a
     smaller one here so that we can test running into the limit a little
     easier */
  curlx_dyn_init(&dbuf, 40);
  for(i = 0; i < CURL_ARRAYSIZE(test_specs); ++i) {
    if(!test1667(&test_specs[i], i, &dbuf))
      all_ok = FALSE;
  }
  fail_unless(all_ok, "some tests of ASN1tostr() failed");

  curlx_dyn_free(&dbuf);
  curl_global_cleanup();

  UNITTEST_END_SIMPLE
}

#undef OID

#else

static CURLcode test_unit1667(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  puts("not tested since ASN1tostr() is not built in");
  UNITTEST_END_SIMPLE
}

#endif
