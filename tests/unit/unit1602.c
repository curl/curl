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

#define ENABLE_CURLX_PRINTF
#include "curlx.h"

#include "hash.h"

#include "memdebug.h" /* LAST include file */

 static CURLcode unit_setup( void )
{
  return CURLE_OK;
}

static void unit_stop( void )
{

}

static void mydtor(void *p)
{
  int *ptr = (int*)p;
  free(ptr);
}

UNITTEST_START
  int *value;
  int *value2;
  size_t klen = sizeof(int);

  struct curl_hash hash_static;
  int key = 20;
  int key2 = 25;
  int rc = 0;

  rc = Curl_hash_init(&hash_static, 7, Curl_hash_str,
                        Curl_str_key_compare, mydtor);

  if(rc)
  {
    fail("Curl_hash_init failed to initialize static hash!");
    goto unit_test_abort;
  }

  value = malloc(sizeof(int));
  value2 = malloc(sizeof(int));

  *value = 199;
  *value2 = 204;
  Curl_hash_add(&hash_static, &key, klen, value);
  
  Curl_hash_clean(&hash_static);

  /* Attempt to add another key/value pair */
  Curl_hash_add(&hash_static, &key2, klen, value2);

  Curl_hash_destroy(&hash_static);
  
UNITTEST_STOP
