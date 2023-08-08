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

#include <stdlib.h>
#pragma enum(int)
#include "curl_setup.h"
#include "urldata.h"

/* The following defines indicate the expected dupstring enum values in
 * curl_easy_setopt_ccsid() in packages/OS400/ccsidcurl.c. If a mismatch is
 * flagged during the build, it indicates that curl_easy_setopt_ccsid() may
 * need updating to perform data EBCDIC to ASCII data conversion on the
 * string.
 *
 * Once any applicable changes to curl_easy_setopt_ccsid() have been
 * made, the EXPECTED_STRING_LASTZEROTERMINATED/EXPECTED_STRING_LAST
 * values can be updated to match the latest enum values in urldata.h.
 */
#define EXPECTED_STRING_LASTZEROTERMINATED  (STRING_HAPROXY_CLIENT_IP + 1)
#define EXPECTED_STRING_LAST                (STRING_COPYPOSTFIELDS + 1)

int main(int argc, char *argv[])
{
  int rc = 0;

  if(STRING_LASTZEROTERMINATED != EXPECTED_STRING_LASTZEROTERMINATED) {
    fprintf(stderr,
            "STRING_LASTZEROTERMINATED(%d) is not expected value(%d).\n",
            STRING_LASTZEROTERMINATED, EXPECTED_STRING_LASTZEROTERMINATED);
    rc += 1;
  }
  if(STRING_LAST != EXPECTED_STRING_LAST) {
    fprintf(stderr, "STRING_LAST(%d) is not expected value(%d).\n",
            STRING_LAST, EXPECTED_STRING_LAST);
    rc += 2;
  }
  if(rc) {
    fprintf(stderr, "curl_easy_setopt_ccsid() in packages/OS400/ccsidcurl.c"
            " may need updating if new strings are provided as"
            " input via the curl API.\n");
  }
  return rc;
}
