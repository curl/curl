/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2011, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
#include "curlcheck.h"

#include "urldata.h"
#include "url.h" /* for Curl_safefree */
#include "curl_base64.h"
#include "memdebug.h" /* LAST include file */

static struct SessionHandle *data;

static CURLcode unit_setup( void )
{
  data = curl_easy_init();
  if (!data)
    return CURLE_OUT_OF_MEMORY;
  return CURLE_OK;
}

static void unit_stop( void )
{
  curl_easy_cleanup(data);
}

UNITTEST_START

char *output;
unsigned char *decoded;
size_t rc;

rc = Curl_base64_encode(data, "i", 1, &output);
fail_unless( rc == 4 , "return code should be 4" );
verify_memory( output, "aQ==", 4);
Curl_safefree(output);

rc = Curl_base64_encode(data, "ii", 2, &output);
fail_unless( rc == 4 , "return code should be 4" );
verify_memory( output, "aWk=", 4);
Curl_safefree(output);

rc = Curl_base64_encode(data, "iii", 3, &output);
fail_unless( rc == 4 , "return code should be 4" );
verify_memory( output, "aWlp", 4);
Curl_safefree(output);

rc = Curl_base64_encode(data, "iiii", 4, &output);
fail_unless( rc == 8 , "return code should be 8" );
verify_memory( output, "aWlpaQ==", 8);
Curl_safefree(output);

/* 0 length makes it do strlen() */
rc = Curl_base64_encode(data, "iiii", 0, &output);
fail_unless( rc == 8 , "return code should be 8" );
verify_memory( output, "aWlpaQ==", 8);
Curl_safefree(output);

rc = Curl_base64_decode("aWlpaQ==", &decoded);
fail_unless(rc == 4, "return code should be 4");
verify_memory(decoded, "iiii", 4);
Curl_safefree(decoded);

rc = Curl_base64_decode("aWlp", &decoded);
fail_unless(rc == 3, "return code should be 3");
verify_memory(decoded, "iii", 3);
Curl_safefree(decoded);

rc = Curl_base64_decode("aWk=", &decoded);
fail_unless(rc == 2, "return code should be 2");
verify_memory(decoded, "ii", 2);
Curl_safefree(decoded);

rc = Curl_base64_decode("aQ==", &decoded);
fail_unless(rc == 1, "return code should be 1");
verify_memory(decoded, "i", 2);
Curl_safefree(decoded);

/* this is an illegal input */
decoded = NULL;
rc = Curl_base64_decode("aQ", &decoded);
fail_unless(rc == 0, "return code should be 0");
fail_if(decoded, "returned pointer should be NULL");

/* this is garbage input that libcurl decodes as far as possible */
rc = Curl_base64_decode("a\x1f==", &decoded);
fail_unless(rc == 1, "return code should be 1");
Curl_safefree(decoded);

UNITTEST_STOP
