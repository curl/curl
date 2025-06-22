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
#include "first.h"

#include "memdebug.h"

/* This test attempts to use all form API features that are not
 * used elsewhere.
 */

/* curl_formget callback to count characters. */
static size_t count_chars(void *userp, const char *buf, size_t len)
{
  size_t *pcounter = (size_t *) userp;

  (void) buf;
  *pcounter += len;
  return len;
}

static CURLcode test_lib650(char *URL)
{
  CURL *curl = NULL;
  CURLcode res = TEST_ERR_MAJOR_BAD;
  CURLFORMcode formrc;
  struct curl_slist *headers, *headers2 = NULL;
  struct curl_httppost *formpost = NULL;
  struct curl_httppost *lastptr = NULL;
  struct curl_forms formarray[3];
  size_t formlength = 0;
  char flbuf[32];
  long contentlength = 0;

  static const char testname[] = "fieldname";
  static char testdata[] =
    "this is what we post to the silly web server";

  if(curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
    curl_mfprintf(stderr, "curl_global_init() failed\n");
    return TEST_ERR_MAJOR_BAD;
  }

  /* Check proper name and data copying, as well as headers. */
  headers = curl_slist_append(NULL, "X-customheader-1: Header 1 data");
  if(!headers) {
    goto test_cleanup;
  }
  headers2 = curl_slist_append(headers, "X-customheader-2: Header 2 data");
  if(!headers2) {
    goto test_cleanup;
  }
  headers = headers2;
  headers2 = curl_slist_append(headers, "Content-Type: text/plain");
  if(!headers2) {
    goto test_cleanup;
  }
  headers = headers2;
  formrc = curl_formadd(&formpost, &lastptr,
                        CURLFORM_COPYNAME, &testname,
                        CURLFORM_COPYCONTENTS, &testdata,
                        CURLFORM_CONTENTHEADER, headers,
                        CURLFORM_END);
  if(formrc) {
    curl_mprintf("curl_formadd(1) = %d\n", (int) formrc);
    goto test_cleanup;
  }

  contentlength = (long)(strlen(testdata) - 1);

  /* Use a form array for the non-copy test. */
  formarray[0].option = CURLFORM_PTRCONTENTS;
  formarray[0].value = testdata;
  formarray[1].option = CURLFORM_CONTENTSLENGTH;
  formarray[1].value = (char *)(size_t)contentlength;
  formarray[2].option = CURLFORM_END;
  formarray[2].value = NULL;
  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_PTRNAME, testname,
                        CURLFORM_NAMELENGTH, strlen(testname) - 1,
                        CURLFORM_ARRAY, formarray,
                        CURLFORM_FILENAME, "remotefile.txt",
                        CURLFORM_END);

  if(formrc) {
    curl_mprintf("curl_formadd(2) = %d\n", (int) formrc);
    goto test_cleanup;
  }

  /* Now change in-memory data to affect CURLOPT_PTRCONTENTS value.
     Copied values (first field) must not be affected.
     CURLOPT_PTRNAME actually copies the name thus we do not test this here. */
  testdata[0]++;

  /* Check multi-files and content type propagation. */
  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_COPYNAME, "multifile",
                        CURLFORM_FILE, libtest_arg2,    /* Set in first.c. */
                        CURLFORM_FILE, libtest_arg2,
                        CURLFORM_CONTENTTYPE, "text/whatever",
                        CURLFORM_FILE, libtest_arg2,
                        CURLFORM_END);

  if(formrc) {
    curl_mprintf("curl_formadd(3) = %d\n", (int) formrc);
    goto test_cleanup;
  }

  /* Check data from file content. */
  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_COPYNAME, "filecontents",
                        CURLFORM_FILECONTENT, libtest_arg2,
                        CURLFORM_END);
  if(formrc) {
    curl_mprintf("curl_formadd(4) = %d\n", (int) formrc);
    goto test_cleanup;
  }

  /* Measure the current form length.
   * This is done before including stdin data because we want to reuse it
   * and stdin cannot be rewound.
   */
  curl_formget(formpost, (void *) &formlength, count_chars);

  /* Include length in data for external check. */
  curl_msnprintf(flbuf, sizeof(flbuf), "%lu", (unsigned long) formlength);

  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_COPYNAME, "formlength",
                        CURLFORM_COPYCONTENTS, &flbuf,
                        CURLFORM_END);

  if(formrc) {
    curl_mprintf("curl_formadd(5) = %d\n", (int) formrc);
    goto test_cleanup;
  }

  /* Check stdin (may be problematic on some platforms). */
  formrc = curl_formadd(&formpost,
                        &lastptr,
                        CURLFORM_COPYNAME, "standardinput",
                        CURLFORM_FILE, "-",
                        CURLFORM_END);

  if(formrc) {
    curl_mprintf("curl_formadd(6) = %d\n", (int) formrc);
    goto test_cleanup;
  }

  curl = curl_easy_init();
  if(!curl) {
    curl_mfprintf(stderr, "curl_easy_init() failed\n");
    goto test_cleanup;
  }

  /* First set the URL that is about to receive our POST. */
  test_setopt(curl, CURLOPT_URL, URL);

  /* send a multi-part formpost */
  test_setopt(curl, CURLOPT_HTTPPOST, formpost);

  /* get verbose debug output please */
  test_setopt(curl, CURLOPT_VERBOSE, 1L);

  test_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  test_setopt(curl, CURLOPT_POSTREDIR, (long)CURL_REDIR_POST_301);

  /* include headers in the output */
  test_setopt(curl, CURLOPT_HEADER, 1L);

  /* Perform the request, res will get the return code */
  res = curl_easy_perform(curl);

test_cleanup:

  /* always cleanup */
  curl_easy_cleanup(curl);

  /* now cleanup the formpost chain */
  curl_formfree(formpost);
  curl_slist_free_all(headers);

  curl_global_cleanup();

  return res;
}
