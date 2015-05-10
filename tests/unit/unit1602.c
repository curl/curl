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
  int *value = malloc(sizeof(int));
  int *value2 = malloc(sizeof(int));
  size_t klen = sizeof(int);

  struct curl_hash *myhash = Curl_hash_alloc(5, Curl_hash_str, Curl_str_key_compare, mydtor);
  int key = 20;
  int key2 = 25;

  *value = 199;
  *value2 = 204;
  Curl_hash_add(myhash, &key, klen, value);
  
  Curl_hash_clean(myhash);

  /* Attempt to add another key/value pair */
  Curl_hash_add(myhash, &key2, klen, value2);

  Curl_hash_destroy(myhash);
UNITTEST_STOP
