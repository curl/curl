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
#ifdef BUILDING_LIBCURL
#include "curl_memory.h"
#endif
/* The last #include file should be: */
#include "memdebug.h"

/*
 * Curl_get_line() makes sure to only return complete whole lines that end
 * newlines.
 */
int Curl_get_line(struct dynbuf *buf, FILE *input)
{
  CURLcode result;
  char buffer[128];
  Curl_dyn_reset(buf);
  while(1) {
    char *b = fgets(buffer, sizeof(buffer), input);

    if(b) {
      size_t rlen = strlen(b);

      if(!rlen)
        break;

      result = Curl_dyn_addn(buf, b, rlen);
      if(result)
        /* too long line or out of memory */
        return 0; /* error */

      else if(b[rlen-1] == '\n')
        /* end of the line */
        return 1; /* all good */

      else if(feof(input)) {
        /* append a newline */
        result = Curl_dyn_addn(buf, "\n", 1);
        if(result)
          /* too long line or out of memory */
          return 0; /* error */
        return 1; /* all good */
      }
    }
    else
      break;
  }
  return 0;
}

#endif /* if not disabled */
