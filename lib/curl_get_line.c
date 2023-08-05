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

#include "curl_setup.h"

#if !defined(CURL_DISABLE_COOKIES) || !defined(CURL_DISABLE_ALTSVC) ||  \
  !defined(CURL_DISABLE_HSTS) || !defined(CURL_DISABLE_NETRC)

#include "curl_get_line.h"
#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/*
 * Curl_get_line() makes sure to only return complete whole lines that fit in
 * 'len' bytes and end with a newline.
 */
char *Curl_get_line(char *buf, int len, FILE *input)
{
  bool partial = FALSE;
  while(1) {
    char *b = fgets(buf, len, input);

    if(b) {
      size_t rlen = strlen(b);

      if(!rlen)
        break;

      if(b[rlen-1] == '\n') {
        /* b is \n terminated */
        if(partial) {
          partial = FALSE;
          continue;
        }
        return b;
      }
      else if(feof(input)) {
        if(partial)
          /* Line is already too large to return, ignore rest */
          break;

        if(rlen + 1 < (size_t) len) {
          /* b is EOF terminated, insert missing \n */
          b[rlen] = '\n';
          b[rlen + 1] = '\0';
          return b;
        }
        else
          /* Maximum buffersize reached + EOF
           * This line is impossible to add a \n to so we'll ignore it
           */
          break;
      }
      else
        /* Maximum buffersize reached */
        partial = TRUE;
    }
    else
      break;
  }
  return NULL;
}

#endif /* if not disabled */
