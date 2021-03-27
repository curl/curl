/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2021, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/
#include "test.h"

#include "memdebug.h"

int test(char *URL)
{
  const unsigned char a[] = {0x2f, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                             0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7};
  CURLcode res = CURLE_OK;
  char *ptr = NULL;
  int asize;
  int outlen = 0;
  char *raw;

  (void)URL; /* we don't use this */

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  asize = (int)sizeof(a);
  ptr = curl_easy_escape(NULL, (char *)a, asize);
  printf("%s\n", ptr);
  curl_free(ptr);

  /* deprecated API */
  ptr = curl_escape((char *)a, asize);
  if(!ptr) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  printf("%s\n", ptr);

  raw = curl_easy_unescape(NULL, ptr, (int)strlen(ptr), &outlen);
  printf("outlen == %d\n", outlen);
  printf("unescape == original? %s\n",
         memcmp(raw, a, outlen) ? "no" : "YES");
  curl_free(raw);

  /* deprecated API */
  raw = curl_unescape(ptr, (int)strlen(ptr));
  if(!raw) {
    res = TEST_ERR_MAJOR_BAD;
    goto test_cleanup;
  }
  outlen = (int)strlen(raw);
  printf("[old] outlen == %d\n", outlen);
  printf("[old] unescape == original? %s\n",
         memcmp(raw, a, outlen) ? "no" : "YES");
  curl_free(raw);
  curl_free(ptr);

  /* weird input length */
  ptr = curl_easy_escape(NULL, (char *)a, -1);
  printf("escape -1 length: %s\n", ptr);

  /* weird input length */
  outlen = 2017; /* just a value */
  ptr = curl_easy_unescape(NULL, (char *)"moahahaha", -1, &outlen);
  printf("unescape -1 length: %s %d\n", ptr, outlen);

test_cleanup:
  curl_free(ptr);
  curl_global_cleanup();

  return (int)res;
}
