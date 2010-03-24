/*****************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 *
 * Based on Alex Fishman's bug report on September 30, 2007
 */

#include "test.h"

#include "memdebug.h"

int test(char *URL)
{
  unsigned char a[] = {0x9c, 0x26, 0x4b, 0x3d, 0x49, 0x4, 0xa1, 0x1,
                       0xe0, 0xd8, 0x7c,  0x20, 0xb7, 0xef, 0x53, 0x29, 0xfa,
                       0x1d, 0x57, 0xe1};

  CURL *easy;
  int asize;
  char *s;
  (void)URL;

  if ((easy = curl_easy_init()) == NULL) {
    fprintf(stderr, "curl_easy_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  asize = (int)sizeof(a);

  s = curl_easy_escape(easy, (char*)a, asize);

  printf("%s\n", s);

  curl_free(s);
  curl_easy_cleanup(easy);

  return 0;
}
