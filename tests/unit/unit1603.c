/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "url.h"

/* Prototype of main function we're going to test. This function is undeclared
 * in url.h because it's not intended to be publicly callable--but we do need
 * to call it here to prove it works correctly. This function has static
 * linkage in normal builds, but is globally visible in debug builds to make
 * it available to our unit test. */
curl_off_t utf8len(const char *str);


CURL *easy;

static CURLcode unit_setup(void)
{
  easy = curl_easy_init();
  return CURLE_OK;
}

static void unit_stop(void)
{
  curl_easy_cleanup(easy);
}


UNITTEST_START

#ifdef USE_LIBIDN
  fail_unless( utf8len(NULL) == -1, "null string should be an error" );
  
  fail_unless( utf8len("") == 0, "empty string should get utf8len == 0" );
  
  fail_unless( utf8len("\r\n") == 2, "ordinary ascii should get utf8len =="
      " strlen, even if it contains control chars");

  /* Mixture of normal and double-byte sequences as used in latin langs. */
  fail_unless( utf8len("\xC2\xA9 2001, Chang\xC3\xA9 Corp.") == 20,
      "utf8len should handle valid latin 1");

  /* Japanese, Russian, Greek 2- and 3-byte sequences -- with a little ASCII */
  fail_unless( utf8len("\xE5\xA4\x89\xE3\x82\x8F\xD1\x81\xD0\xB2 ascii "
      "\xD1\x8F\xD0\xB7\xCF\x8E\xCF\x81\xCE\xB1") == 16,
      "utf8len should support a mix of several interesting languages");

  /* overlong encoding of the Euro sign */
  fail_unless( utf8len("\xF0\x82\x82\xAC") == -1,
      "utf8len should reject overlong encodings");

  /* overlong encoding of embedded null */
  fail_unless( utf8len("with embedded null \xC0\x80 <<there") == -1,
      "utf8len must disallow embedded null with overlong encoding, which is"
      " known as 'modified utf8' in some circles but which is dangerous when"
      " passed to libidn");

  /* surrogate pair */
  fail_unless(utf8len("\xED\xA0\x81\xED\xB0\x80") == -1,
      "utf8len must disallow CESU-8-style surrogate pairs (see"
      " http://j.mp/1HzJPBY)");

  /* invalid trail bytes, per table 3.7 in the Unicode Standard v7, Section
     Conformance 3.9, Table 3-7, Well-Formed UTF-8 Byte Sequences.
     
       http://www.unicode.org/versions/Unicode7.0.0/ch03.pdf#G7404
       
     These cases catch the same issues as the ones tested above, but the table
     doesn't make it obvious which sort of malformation it's preventing. It
     seems prudent to prove that the table and our algorithm and our named
     scenarios all have the same scope...
  */
  fail_unless(utf8len("\xE0\x9F\xB1") == -1, "bad 2nd byte");
  fail_unless(utf8len("\xED\xA0\xB1") == -1, "bad 2nd byte");
  fail_unless(utf8len("\xF0\x85\xB1\xB1") == -1, "bad 2nd byte");
  fail_unless(utf8len("\xF4\x90\xB1\xB1") == -1, "bad 2nd byte");
  
  /* Up to this point, we've just proved that our validation logic is
   * accurate. Now we need to prove that it actually gets invoked when we
   * use libidn. We do this by setting up a connection to a url with a
   * hostname that contains invalid utf8, and verifying that we get back
   * an error that shows that our validation logic rejected it.
   */
  struct SessionHandle * curl;
  CURLcode ret = Curl_open(&curl);
  fail_unless(ret == 0, "serious error");
  ret = curl_easy_setopt(curl, CURLOPT_URL, "http://x\xC0\x80.com/");
  fail_unless(ret == 0, "shouldn't complain yet");
  ret = curl_easy_perform(curl);
  fail_unless(ret != 0, "should get error about invalid hostname");
  /*printf("%s\n", curl_easy_strerror(ret));*/
#else
  /*printf("test skipped; libidn not active\n");*/
#endif

UNITTEST_STOP
