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
#include "url.h" /* for curlx_safefree */

struct etest {
  const char *input;
  size_t ilen;
  const char *output;
  size_t olen;
};

static CURLcode test_unit1302(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE
  CURLcode result;
  unsigned int i;

  /* common base64 encoding */
  struct etest encode[] = {
    { "iiiiii", 1, "aQ==", 4 },
    { "iiiiii", 2, "aWk=", 4 },
    { "iiiiii", 3, "aWlp", 4 },
    { "iiiiii", 4, "aWlpaQ==", 8 },
    { "iiiiii", 5, "aWlpaWk=", 8 },
    { "iiiiii", 6, "aWlpaWlp", 8 },
    { "iiiiiii", 7, "aWlpaWlpaQ==", 12 },
    { "iiiiiiii", 8, "aWlpaWlpaWk=", 12 },
    { "iiiiiiiii", 9, "aWlpaWlpaWlp", 12 },
    { "iiiiiiiiii", 10, "aWlpaWlpaWlpaQ==", 16 },
    { "iiiiiiiiiii", 11, "aWlpaWlpaWlpaWk=", 16 },
    { "iiiiiiiiiiii", 12, "aWlpaWlpaWlpaWlp", 16 },
    { "\xff\x01\xfe\x02", 4, "/wH+Ag==", 8 },
    { "\xff\xff\xff\xff", 4, "/////w==", 8 },
    { "\x00\x00\x00\x00", 4, "AAAAAA==", 8 },
    { "\x00\x00\x00\x00", 1, "AA==", 4 },
  };

  /* base64 URL encoding */
  struct etest url[] = {
    { "", 0, "", 0 },
    { "iiiiiiiiiii", 1, "aQ", 2 },
    { "iiiiiiiiiii", 2, "aWk", 3 },
    { "iiiiiiiiiii", 3, "aWlp", 4 },
    { "iiiiiiiiiii", 4, "aWlpaQ", 6 },
    { "iiiiiiiiiii", 5, "aWlpaWk", 7 },
    { "iiiiiiiiiii", 6, "aWlpaWlp", 8 },
    { "iiiiiiiiiii", 7, "aWlpaWlpaQ", 10 },
    { "iiiiiiiiiii", 8, "aWlpaWlpaWk", 11 },
    { "iiiiiiiiiii", 9, "aWlpaWlpaWlp", 12 },
    { "iiiiiiiiiii", 10, "aWlpaWlpaWlpaQ", 14 },
    { "iiiiiiiiiii", 11, "aWlpaWlpaWlpaWk", 15 },
    { "iiiiiiiiiiii", 12, "aWlpaWlpaWlpaWlp", 16 },
    { "\xff\x01\xfe\x02", 4, "_wH-Ag", 6 },
    { "\xff\xff\xff\xff", 4, "_____w", 6 },
    { "\xff\x00\xff\x00", 4, "_wD_AA", 6 },
    { "\x00\xff\x00\xff", 4, "AP8A_w", 6 },
    { "\x00\x00\x00\x00", 4, "AAAAAA", 6 },
    { "\x00", 1, "AA", 2 },
    { "\x01", 1, "AQ", 2 },
    { "\x02", 1, "Ag", 2 },
    { "\x03", 1, "Aw", 2 },
    { "\x04", 1, "BA", 2 }, /* spellchecker:disable-line */
    { "\x05", 1, "BQ", 2 },
    { "\x06", 1, "Bg", 2 },
    { "\x07", 1, "Bw", 2 },
    { "\x08", 1, "CA", 2 },
    { "\x09", 1, "CQ", 2 },
    { "\x0a", 1, "Cg", 2 },
    { "\x0b", 1, "Cw", 2 },
    { "\x0c", 1, "DA", 2 },
    { "\x0d", 1, "DQ", 2 },
    { "\x0e", 1, "Dg", 2 },
    { "\x0f", 1, "Dw", 2 },
    { "\x10", 1, "EA", 2 },
  };

  /* bad decode inputs */
  struct etest badecode[] = {
    { "", 0, "", 0 },         /* no data means error */
    { "", 0, "a", 1 },        /* data is too short */
    { "", 0, "aQ", 2 },       /* data is too short */
    { "", 0, "aQ=", 3 },      /* data is too short */
    { "", 0, "====", 1 },     /* data is only padding characters */
    { "", 0, "====", 2 },     /* data is only padding characters */
    { "", 0, "====", 3 },     /* data is only padding characters */
    { "", 0, "====", 4 },     /* data is only padding characters */
    { "", 0, "a===", 4 },     /* contains three padding characters */
    { "", 0, "a=Q=", 4 },     /* contains a padding character mid input */
    { "", 0, "aWlpa=Q=", 8 }, /* contains a padding character mid input */
    { "", 0, "a\x1f==", 4 },  /* contains illegal base64 character */
    { "", 0, "abcd ", 5 },    /* contains illegal base64 character */
    { "", 0, "abcd  ", 6 },   /* contains illegal base64 character */
    { "", 0, " abcd", 5 },    /* contains illegal base64 character */
    { "", 0, "_abcd", 5 },    /* contains illegal base64 character */
    { "", 0, "abcd-", 5 },    /* contains illegal base64 character */
    { "", 0, "abcd_", 5 },    /* contains illegal base64 character */
    { "", 0, "aWlpaWlpaQ==-", 17 }, /* bad character after padding */
    { "", 0, "aWlpaWlpaQ==_", 17 }, /* bad character after padding */
    { "", 0, "aWlpaWlpaQ== ", 17 }, /* bad character after padding */
    { "", 0, "aWlpaWlpaQ=", 15 }, /* unaligned size, missing padding */
    { "", 0, "AA A", 4 },     /* whitespace is not ignored */
    { "", 0, "AA\tA", 4 },
    { "", 0, "AA\nA", 4 },
    { "", 0, "AA\rA", 4 },
    { "", 0, "AA\fA", 4 },
    { "", 0, "AA\vA", 4 },
    { "", 0, "AAAA    AAAA", 12 }, /* valid if whitespace were skipped */
    { "", 0, "AAAA\t\t\t\tAAAA", 12 },
    { "", 0, "AAAA\n\n\n\nAAAA", 12 },
    { "", 0, "AAAA\r\r\r\rAAAA", 12 },
    { "", 0, "AAAA\f\f\f\fAAAA", 12 },
    { "", 0, "AAAA\v\v\v\vAAAA", 12 },
    { "", 0, "-w==", 4 },     /* URL alphabet is not accepted */
    { "", 0, "_w==", 4 },
    { "", 0, "AAA-", 4 },
    { "", 0, "AAA_", 4 },
    { "", 0, "AA\x80" "A", 4 }, /* high bytes are invalid */
    { "", 0, "AA\xff" "A", 4 },
    { "", 0, "aQ==AAAA", 8 }, /* padding is only valid at the end */
    { "", 0, "aQ==aQ==", 8 }
  };

  /* Unused bits in the last quantum have historically been ignored. */
  struct etest noncanonical[] = {
    { "f", 1, "Zh==", 4 },
    { "fo", 2, "Zm9=", 4 }, /* spellchecker:disable-line */
    { "\xff", 1, "/x==", 4 },
    { "\xff\xff", 2, "//9=", 4 }
  };

  for(i = 0; i < CURL_ARRAYSIZE(encode); i++) {
    const struct etest *e = &encode[i];
    char *out;
    unsigned char *decoded;
    size_t olen;
    size_t dlen;

    /* first encode */
    result = curlx_base64_encode((const uint8_t *)e->input, e->ilen,
                                 &out, &olen);
    abort_unless(result == CURLE_OK, "return code should be CURLE_OK");
    abort_unless(olen == e->olen, "wrong output size");
    if(memcmp(out, e->output, e->olen)) {
      curl_mfprintf(stderr, "Test %u encoded badly\n", i);
      unitfail++;
    }
    curlx_safefree(out);

    /* then verify decode */
    result = curlx_base64_decode(e->output, &decoded, &dlen);
    if(result != CURLE_OK) {
      curl_mfprintf(stderr, "Test %u URL decode returned %d\n", i,
                    (int)result);
      unitfail++;
    }
    if(dlen != e->ilen) {
      curl_mfprintf(stderr, "Test %u URL decode output length %zu "
                    "instead of %zu\n", i, dlen, e->ilen);
      unitfail++;
    }
    if(memcmp(decoded, e->input, dlen)) {
      curl_mfprintf(stderr, "Test %u URL decoded badly. Got '%s', "
                    "expected '%s'\n", i, decoded, e->input);
      unitfail++;
    }

    curlx_safefree(decoded);
  }

  {
    /* Known encodings of bytes 0..255: shared encoder/decoder mistakes must
       not be hidden by a successful roundtrip. Prefixes cover vector widths
       and their tails, including binary NULs and both alphabet differences. */
    static const char binary_encoded[] =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"
      "MDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"
      "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6P"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/"
      "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v"
      "8PHy8/T19vf4+fr7/P3+/w==";
    static const char binary_url[] =
      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v"
      "MDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"
      "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn-AgYKDhIWGh4iJiouMjY6P"
      "kJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq-wsbKztLW2t7i5uru8vb6_"
      "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v"
      "8PHy8_T19vf4-fr7_P3-_w";
    unsigned char binary[256];
    size_t length;
    for(i = 0; i < sizeof(binary); i++)
      binary[i] = (unsigned char)i;
    for(length = 1; length <= sizeof(binary); length++) {
      char *encoded;
      unsigned char *decoded;
      size_t enclen;
      size_t declen;
      result = curlx_base64_encode(binary, length, &encoded, &enclen);
      abort_unless(result == CURLE_OK, "binary encoding failed");
      abort_unless(enclen == (length + 2) / 3 * 4, "wrong encoded size");
      fail_unless(!encoded[enclen], "encoded data is not terminated");
      fail_unless(!memcmp(encoded, binary_encoded, length / 3 * 4),
                  "wrong encoded data");
      if(length == sizeof(binary))
        fail_unless(!strcmp(encoded, binary_encoded),
                    "wrong encoded final quantum");
      /* The longest decode uses the fixed reference, independently of the
         encoder's output. Shorter decodes exercise every possible tail. */
      result = curlx_base64_decode(length == sizeof(binary) ?
                                  binary_encoded : encoded, &decoded, &declen);
      curlx_free(encoded);
      abort_unless(result == CURLE_OK, "binary decoding failed");
      abort_unless(declen == length, "wrong decoded size");
      fail_unless(!memcmp(decoded, binary, length), "wrong decoded data");
      fail_unless(!decoded[declen], "decoded data is not terminated");
      curlx_free(decoded);

      result = curlx_base64url_encode(binary, length, &encoded, &enclen);
      abort_unless(result == CURLE_OK, "binary URL encoding failed");
      abort_unless(enclen == (length * 4 + 2) / 3,
                   "wrong URL encoded size");
      fail_unless(!encoded[enclen], "URL encoded data is not terminated");
      fail_unless(!memcmp(encoded, binary_url, length / 3 * 4),
                  "wrong URL encoded data");
      fail_unless(!strchr(encoded, '='), "URL encoded data has padding");
      if(length == sizeof(binary))
        fail_unless(!strcmp(encoded, binary_url),
                    "wrong URL encoded final quantum");
      curlx_free(encoded);
    }

    {
      static const size_t positions[] = { 0, 31, 32, 63, 64, 127, 128, 340 };
      static const char * const invalid[] = {
        "    ", "\t\t\t\t", "\n\n\n\n", "\r\r\r\r", "\f\f\f\f", "\v\v\v\v",
        "-", "_", "=", "\x80", "\xff"
      };
      char damaged[sizeof(binary_encoded)];
      size_t p;
      size_t b;
      /* Reject bad bytes in vector blocks and in the final scalar tail.
         Whitespace replaces a whole quantum, so skipping it would otherwise
         leave valid base64 and conceal an overly permissive decoder. */
      for(p = 0; p < CURL_ARRAYSIZE(positions); p++) {
        for(b = 0; b < CURL_ARRAYSIZE(invalid); b++) {
          unsigned char *decoded;
          size_t dlen;
          memcpy(damaged, binary_encoded, sizeof(damaged));
          memcpy(damaged + positions[p], invalid[b], strlen(invalid[b]));
          result = curlx_base64_decode(damaged, &decoded, &dlen);
          fail_unless(result == CURLE_BAD_CONTENT_ENCODING,
                      "invalid byte in long input should be rejected");
          fail_unless(!decoded, "failed decode should not return data");
          fail_unless(!dlen, "failed decode should return zero length");
          curlx_safefree(decoded);
        }
      }
    }
  }

  for(i = 0; i < CURL_ARRAYSIZE(noncanonical); i++) {
    const struct etest *e = &noncanonical[i];
    unsigned char *decoded;
    size_t dlen;
    result = curlx_base64_decode(e->output, &decoded, &dlen);
    abort_unless(result == CURLE_OK, "nonzero pad bits should be accepted");
    abort_unless(dlen == e->ilen, "wrong size with nonzero pad bits");
    fail_unless(!memcmp(decoded, e->input, dlen),
                "wrong data with nonzero pad bits");
    fail_unless(!decoded[dlen], "decoded data is not terminated");
    curlx_free(decoded);
  }

  for(i = 0; i < CURL_ARRAYSIZE(url); i++) {
    const struct etest *e = &url[i];
    char *out;
    size_t olen;
    result = curlx_base64url_encode((const uint8_t *)e->input, e->ilen,
                                    &out, &olen);
    abort_unless(result == CURLE_OK, "return code should be CURLE_OK");
    if(olen != e->olen) {
      curl_mfprintf(stderr, "Test %u URL encoded output length %zu "
                    "instead of %zu\n", i, olen, e->olen);
    }
    if(out && memcmp(out, e->output, e->olen)) {
      curl_mfprintf(stderr, "Test %u URL encoded badly. Got '%s', "
                    "expected '%s'\n", i, out, e->output);
      unitfail++;
    }
    curlx_safefree(out);
  }

  for(i = 0; i < CURL_ARRAYSIZE(badecode); i++) {
    struct etest *e = &badecode[i];
    unsigned char *decoded;
    size_t dlen;

    /* then verify decode with illegal inputs */
    result = curlx_base64_decode(e->output, &decoded, &dlen);
    if(result != CURLE_BAD_CONTENT_ENCODING) {
      curl_mfprintf(stderr, "Test %u URL bad decoded badly. "
                    "Returned '%d', expected '%d'\n",
                    i, (int)result, CURLE_BAD_CONTENT_ENCODING);
      unitfail++;
    }
    fail_unless(!decoded, "failed decode should not return data");
    fail_unless(!dlen, "failed decode should return zero length");
    curlx_safefree(decoded);
  }

  UNITTEST_END_SIMPLE
}
