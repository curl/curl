/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* Testing CURLOPT_PROTOCOLS_STR */

#include "test.h"

#include "memdebug.h"

struct pair {
  const char *in;
  CURLcode exp;
};

int test(char *URL)
{
  CURL *curl = NULL;
  int res = 0;
  CURLcode result = CURLE_OK;
  int i;

  struct pair prots[] = {
    {"goobar", CURLE_BAD_FUNCTION_ARGUMENT},
    {"http ", CURLE_BAD_FUNCTION_ARGUMENT},
    {" http", CURLE_BAD_FUNCTION_ARGUMENT},
    {"http", CURLE_OK},
    {"http,", CURLE_OK},
    {"https,", CURLE_OK},
    {"https,http", CURLE_OK},
    {"http,http", CURLE_OK},
    {"HTTP,HTTP", CURLE_OK},
    {",HTTP,HTTP", CURLE_OK},
    {"http,http,ft", CURLE_BAD_FUNCTION_ARGUMENT},
    {"", CURLE_BAD_FUNCTION_ARGUMENT},
    {",,", CURLE_BAD_FUNCTION_ARGUMENT},
    {"DICT,FILE,FTP,FTPS,GOPHER,GOPHERS,HTTP,HTTPS,IMAP,IMAPS,LDAP,LDAPS,"
     "POP3,POP3S,RTMP,RTMPE,RTMPS,RTMPT,RTMPTE,RTMPTS,RTSP,SCP,SFTP,SMB,"
     "SMBS,SMTP,SMTPS,TELNET,TFTP", CURLE_OK},
    {"all", CURLE_OK},
    {NULL, CURLE_OK},
  };
  (void)URL;

  global_init(CURL_GLOBAL_ALL);

  easy_init(curl);

  for(i = 0; prots[i].in; i++) {
    result = curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, prots[i].in);
    if(result != prots[i].exp) {
      printf("unexpectedly '%s' returned %u\n",
             prots[i].in, result);
      break;
    }
  }
  printf("Tested %u strings\n", i);
  res = (int)result;

  test_cleanup:
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return (int)result;
}
