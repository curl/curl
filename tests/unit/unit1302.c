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
#include "curlcheck.h"

#include "urldata.h"
#include "url.h" /* for Curl_safefree */
#include "curlx/base64.h"
#include "memdebug.h" /* LAST include file */

static struct Curl_easy *testdata;

static CURLcode unit_setup(void)
{
  CURLcode res = CURLE_OK;

  global_init(CURL_GLOBAL_ALL);
  testdata = curl_easy_init();
  if(!testdata) {
    curl_global_cleanup();
    return CURLE_OUT_OF_MEMORY;
  }
  return res;
}

static void unit_stop(void)
{
  curl_easy_cleanup(testdata);
  curl_global_cleanup();
}

UNITTEST_START

char *output;
unsigned char *decoded;
size_t size = 0;
unsigned char anychar = 'x';
CURLcode rc;

rc = curlx_base64_encode("i", 1, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 4, "size should be 4");
verify_memory(output, "aQ==", 4);
Curl_safefree(output);

rc = curlx_base64_encode("ii", 2, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 4, "size should be 4");
verify_memory(output, "aWk=", 4);
Curl_safefree(output);

rc = curlx_base64_encode("iii", 3, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 4, "size should be 4");
verify_memory(output, "aWlp", 4);
Curl_safefree(output);

rc = curlx_base64_encode("iiii", 4, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 8, "size should be 8");
verify_memory(output, "aWlpaQ==", 8);
Curl_safefree(output);

rc = curlx_base64_encode("\xff\x01\xfe\x02", 4, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 8, "size should be 8");
verify_memory(output, "/wH+Ag==", 8);
Curl_safefree(output);

rc = curlx_base64url_encode("\xff\x01\xfe\x02", 4, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 6, "size should be 6");
verify_memory(output, "_wH-Ag", 6);
Curl_safefree(output);

rc = curlx_base64url_encode("iiii", 4, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 6, "size should be 6");
verify_memory(output, "aWlpaQ", 6);
Curl_safefree(output);

/* 0 length makes it do strlen() */
rc = curlx_base64_encode("iiii", 0, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 8, "size should be 8");
verify_memory(output, "aWlpaQ==", 8);
Curl_safefree(output);

rc = curlx_base64_encode("", 0, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 0, "size should be 0");
fail_unless(output && !output[0], "output should be a zero-length string");
Curl_safefree(output);

rc = curlx_base64url_encode("", 0, &output, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 0, "size should be 0");
fail_unless(output && !output[0], "output should be a zero-length string");
Curl_safefree(output);

rc = curlx_base64_decode("aWlpaQ==", &decoded, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 4, "size should be 4");
verify_memory(decoded, "iiii", 4);
Curl_safefree(decoded);

rc = curlx_base64_decode("aWlp", &decoded, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 3, "size should be 3");
verify_memory(decoded, "iii", 3);
Curl_safefree(decoded);

rc = curlx_base64_decode("aWk=", &decoded, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 2, "size should be 2");
verify_memory(decoded, "ii", 2);
Curl_safefree(decoded);

rc = curlx_base64_decode("aQ==", &decoded, &size);
fail_unless(rc == CURLE_OK, "return code should be CURLE_OK");
fail_unless(size == 1, "size should be 1");
verify_memory(decoded, "i", 2);
Curl_safefree(decoded);

/* This is illegal input as the data is too short */
size = 1; /* not zero */
decoded = &anychar; /* not NULL */
rc = curlx_base64_decode("aQ", &decoded, &size);
fail_unless(rc == CURLE_BAD_CONTENT_ENCODING,
            "return code should be CURLE_BAD_CONTENT_ENCODING");
fail_unless(size == 0, "size should be 0");
fail_if(decoded, "returned pointer should be NULL");

/* This is illegal input as it contains three padding characters */
size = 1; /* not zero */
decoded = &anychar; /* not NULL */
rc = curlx_base64_decode("a===", &decoded, &size);
fail_unless(rc == CURLE_BAD_CONTENT_ENCODING,
            "return code should be CURLE_BAD_CONTENT_ENCODING");
fail_unless(size == 0, "size should be 0");
fail_if(decoded, "returned pointer should be NULL");

/* This is illegal input as it contains a padding character mid input */
size = 1; /* not zero */
decoded = &anychar; /* not NULL */
rc = curlx_base64_decode("a=Q=", &decoded, &size);
fail_unless(rc == CURLE_BAD_CONTENT_ENCODING,
            "return code should be CURLE_BAD_CONTENT_ENCODING");
fail_unless(size == 0, "size should be 0");
fail_if(decoded, "returned pointer should be NULL");

/* This is also illegal input as it contains a padding character mid input */
size = 1; /* not zero */
decoded = &anychar; /* not NULL */
rc = curlx_base64_decode("aWlpa=Q=", &decoded, &size);
fail_unless(rc == CURLE_BAD_CONTENT_ENCODING,
            "return code should be CURLE_BAD_CONTENT_ENCODING");
fail_unless(size == 0, "size should be 0");
fail_if(decoded, "returned pointer should be NULL");

/* This is garbage input as it contains an illegal base64 character */
size = 1; /* not zero */
decoded = &anychar; /* not NULL */
rc = curlx_base64_decode("a\x1f==", &decoded, &size);
fail_unless(rc == CURLE_BAD_CONTENT_ENCODING,
            "return code should be CURLE_BAD_CONTENT_ENCODING");
fail_unless(size == 0, "size should be 0");
fail_if(decoded, "returned pointer should be NULL");


UNITTEST_STOP
