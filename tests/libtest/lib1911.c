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
#include "test.h"

#include "testutil.h"
#include "warnless.h"
#include "memdebug.h"

/* The maximum string length limit (CURL_MAX_INPUT_LENGTH) is an internal
   define not publicly exposed so we set our own */
#define MAX_INPUT_LENGTH 8000000

static char buffer[MAX_INPUT_LENGTH + 2];

int test(char *URL)
{
  const struct curl_easyoption *o;
  CURL *easy;
  int error = 0;
  (void)URL;

  curl_global_init(CURL_GLOBAL_ALL);
  easy = curl_easy_init();
  if(!easy) {
    curl_global_cleanup();
    return 1;
  }

  /* make it a null-terminated C string with just As */
  memset(buffer, 'A', MAX_INPUT_LENGTH + 1);
  buffer[MAX_INPUT_LENGTH + 1] = 0;

  printf("string length: %d\n", (int)strlen(buffer));

  for(o = curl_easy_option_next(NULL);
      o;
      o = curl_easy_option_next(o)) {
    if(o->type == CURLOT_STRING) {
      CURLcode result;
      /*
       * Whitelist string options that are safe for abuse
       */
      CURL_IGNORE_DEPRECATION(
        switch(o->id) {
        case CURLOPT_PROXY_TLSAUTH_TYPE:
        case CURLOPT_TLSAUTH_TYPE:
        case CURLOPT_RANDOM_FILE:
        case CURLOPT_EGDSOCKET:
          continue;
        default:
          /* check this */
          break;
        }
      )

      /* This is a string. Make sure that passing in a string longer
         CURL_MAX_INPUT_LENGTH returns an error */
      result = curl_easy_setopt(easy, o->id, buffer);
      switch(result) {
      case CURLE_BAD_FUNCTION_ARGUMENT: /* the most normal */
      case CURLE_UNKNOWN_OPTION: /* left out from the build */
      case CURLE_NOT_BUILT_IN: /* not supported */
      case CURLE_UNSUPPORTED_PROTOCOL: /* detected by protocol2num() */
        break;
      default:
        /* all other return codes are unexpected */
        fprintf(stderr, "curl_easy_setopt(%s...) returned %d\n",
                o->name, (int)result);
        error++;
        break;
      }
    }
  }
  curl_easy_cleanup(easy);
  curl_global_cleanup();
  return error;
}
